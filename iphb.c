/*
 * linux/net/ipv4/netfilter/iphb.c
 *
 * Netfilter module to delay outgoing TCP keepalive messages.
 *
 * Copyright (C) 2008-2010 Nokia Corporation. All rights reserved.
 * Written by Jukka Rissanen <jukka.rissanen@nokia.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#ifdef CONFIG_IP_NF_HB_DEBUG
#define DEBUG
#endif

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/notifier.h>
#include <linux/netfilter.h>
#include <linux/miscdevice.h>
#include <linux/device.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <net/ip.h>

#include <linux/version.h>


#define MY_NAME "iphb"
#define MAX_KEEPALIVES 20
#define IPV6_HDR_LEN 40
#define MAX_FLUSH_VALUE 180 /* 3 minutes */
#define MAX_RECV_LEN 15


/* Linked list that keeps track of the queued keepalives */
struct keepalives {
	struct list_head list;
	int num_keeps;  /* current number of keepalives in the list */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
	struct net *net;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
	struct sock *sk;
#endif
	struct sk_buff *skb;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0)
	int (*okfn)(struct sk_buff *);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
	int (*okfn)(struct sock *, struct sk_buff *);
#else
	int (*okfn)(struct net *, struct sock *, struct sk_buff *);
#endif
};


/*
 * Separate list of packets to be sent. This is a separate list so that
 * no message is sent while being holding the bh lock.
 */
struct packets {
	struct list_head list;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
	struct net *net;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
	struct sock *sk;
#endif
	struct sk_buff *skb;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0)
	int (*okfn)(struct sk_buff *);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
	int (*okfn)(struct sock *, struct sk_buff *);
#else
	int (*okfn)(struct net *, struct sock *, struct sk_buff *);
#endif
};


static struct keepalives keepalives; /* List of keepalive messages */
static DEFINE_SPINLOCK(keepalives_lock);  /* protects the keepalive list */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
static time64_t last_notification;
#else
static unsigned long last_notification;
#endif

static unsigned int flush_notification = MAX_FLUSH_VALUE;
static int trigger_poll;
static DECLARE_WAIT_QUEUE_HEAD(iphb_pollq);

static int iphb_is_enabled;
static struct device *iphb_dev;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0)
static void timed_flush(unsigned long not_used);
static DEFINE_TIMER(flush_timer, timed_flush, 0, 0);
#else
static void timed_flush(struct timer_list *unused);
static struct timer_list flush_timer;
#endif

static void flush_keepalives(int notify)
{
	struct list_head *p, *q;
	struct keepalives *entry;
	struct packets packets, *packet;

	if (keepalives.num_keeps > 0)
		dev_dbg(iphb_dev, "Flush (%d)\n", keepalives.num_keeps);

	/* Check if we need to notify user space about the flush */
	if (notify) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
		time64_t current_time = ktime_get_real_seconds();
#else
		unsigned long current_time = get_seconds();
#endif
		if (current_time >
		    (last_notification + flush_notification)) {
			dev_dbg(iphb_dev, "Wake up daemon\n");
			last_notification = current_time;
			trigger_poll = 1;
			wake_up_interruptible(&iphb_pollq);
		}
	}


	INIT_LIST_HEAD(&packets.list);

	spin_lock_bh(&keepalives_lock);

	list_for_each_safe(p, q, &keepalives.list) {
		entry = list_entry(p, struct keepalives, list);

		/*
		 * Create a separate list for keepalives to be
		 * sent outside.
		 */
		packet = kzalloc(sizeof(struct packets), GFP_ATOMIC);
		if (!packet) {
			spin_unlock_bh(&keepalives_lock);
			return;
		}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
		packet->net = entry->net;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
		packet->sk = entry->sk;
#endif
		packet->skb = entry->skb;
		packet->okfn = entry->okfn;
		list_add_tail(&packet->list, &packets.list);

		keepalives.num_keeps--;
		list_del(p);
		kfree(entry);
	}
	keepalives.num_keeps = 0;

	spin_unlock_bh(&keepalives_lock);

	/*
	 * We can remove the flush timer now as there is no need for it
	 * anymore. A new outgoing keepalive packet will re-create it.
	 */
	del_timer(&flush_timer);


	/*
	 * Send the packets to net from outside of locked area
	 * so that we wont be scheduled while atomic.
	 */
	list_for_each_safe(p, q, &packets.list) {
		int ret;
		packet = list_entry(p, struct packets, list);
		/* Send the keepalive to network */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0)
		ret = packet->okfn(packet->skb);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
		ret = packet->okfn(packet->sk, packet->skb);
#else
		ret = packet->okfn(packet->net, packet->sk, packet->skb);
#endif
		list_del(p);
		kfree(packet);
	}
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0)
static void timed_flush(unsigned long not_used)
#else
static void timed_flush(struct timer_list *unused)
#endif
{
	flush_keepalives(1);
}


static int iphbd_open(struct inode *inode, struct file *file)
{
	if (iphb_is_enabled)
		return -EBUSY;

	iphb_is_enabled = 1;

	return 0;
}


static unsigned int iphbd_poll(struct file *file, poll_table *wait)
{
	unsigned int mask = 0;
	poll_wait(file, &iphb_pollq, wait);
	if (trigger_poll) {
		mask |= POLLIN | POLLRDNORM;
		mask |= POLLOUT | POLLWRNORM;
		/*
		 * Keep compatible with fremantle iphbd, which doesn't do reads
		 */
		trigger_poll = 0;
	}
	return mask;
}


static int iphbd_release(struct inode *inode, struct file *file)
{
	flush_keepalives(0);
	last_notification = 0;
	trigger_poll = 0;
	iphb_is_enabled = 0;
	return 0;
}


static ssize_t iphbd_write(struct file *filp,
			   const char __user *buff,
			   size_t len,
			   loff_t *off)
{
	/* If userland writes to the device, then we flush. */
	long val;
	char received[MAX_RECV_LEN + 1];
	int r;

	r = copy_from_user(received, buff, min((size_t)MAX_RECV_LEN, len + 1));
	if (r < 0)
		return r;

	/* conversion errors are ignored and they will cause a flush */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0)
	kstrtol(received, 10, &val);
#else
	strict_strtol(received, 10, &val);
#endif

	if (val > 0) {
		if (val > MAX_FLUSH_VALUE)
			val = MAX_FLUSH_VALUE;
		dev_dbg(iphb_dev, "Setting flush notification to %ld secs\n",
			val);
		flush_notification = (unsigned int)val;
	}
	flush_keepalives(0);
	return 0;
}


static ssize_t iphbd_read(struct file *filp,
			  char __user *buff,
			  size_t len,
			  loff_t *off)
{
	/*
	 * If userspace reads the device, we clear the polling status so that
	 * it can poll again.
	 */
	trigger_poll = 0;
	return 0;
}


#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
static unsigned int net_out_hook(unsigned int hook,
				 struct sk_buff *skb,
				 const struct net_device *indev,
				 const struct net_device *outdev,
				 int (*okfn)(struct sk_buff *))
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0)
static unsigned int net_out_hook(const struct nf_hook_ops *ops,
				 struct sk_buff *skb,
				 const struct net_device *indev,
				 const struct net_device *outdev,
				 int (*okfn)(struct sk_buff *))
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
static unsigned int net_out_hook(const struct nf_hook_ops *ops,
				 struct sk_buff *skb,
				 const struct nf_hook_state *state)
#else
static unsigned int net_out_hook(void *priv,
				 struct sk_buff *skb,
				 const struct nf_hook_state *state)
#endif
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
	unsigned int hook = state->hook;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0)
	unsigned int hook = ops->hooknum;
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0)
	int (*okfn)(struct sk_buff *) = state->okfn;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
	int (*okfn)(struct sock *, struct sk_buff *) = state->okfn;
#else
	int (*okfn)(struct net *, struct sock *, struct sk_buff *) =
		state->okfn;
#endif
	struct keepalives *keepalive;
	struct iphdr *ip;
	struct ipv6hdr *ip6 = NULL;
	struct tcphdr *tcp;
	struct tcp_sock *tsk;
	unsigned char proto;
	unsigned int len, hlen;
	unsigned char version;

	if (!iphb_is_enabled)
		return NF_ACCEPT;

	if (hook != NF_INET_POST_ROUTING)
		return NF_ACCEPT;

	if (keepalives.num_keeps >= MAX_KEEPALIVES) {
		dev_dbg(iphb_dev, "Max keepalives (%d), flushing\n",
		       keepalives.num_keeps);
		flush_keepalives(1);
		return NF_ACCEPT;
	}

	ip = ip_hdr(skb);
	ip6 = ipv6_hdr(skb);
	if (ip)
		version = ip->version;
	else {
		flush_keepalives(1);
		return NF_ACCEPT;
	}

	if (version == 6) {
		len = ntohs(ip6->payload_len);
		hlen = IPV6_HDR_LEN;
		proto = (unsigned char)ip6->nexthdr;
	} else if (version == 4) {
		len = ntohs(ip->tot_len);
		hlen = ip->ihl << 2;
		proto = (unsigned char)ip->protocol;
	} else {
		flush_keepalives(1);
		return NF_ACCEPT;
	}

	/* We are only interested in TCP traffic (keepalives) */
	if (proto != IPPROTO_TCP) {
		flush_keepalives(1);
		return NF_ACCEPT;
	}

	tsk = tcp_sk(skb->sk);
	tcp = tcp_hdr(skb);

	if (!tcp || !tsk) {
		flush_keepalives(1);
		return NF_ACCEPT;
	}

	len -= hlen;           /* ip4/6 header len     */
	len -= tcp->doff << 2; /* tcp header + options */

	/* Is it keepalive? */
	if (!(tcp->ack && (len == 0 || len == 1) &&
	      (ntohl(tcp->seq) == (tsk->snd_nxt - 1)) &&
	      !(tcp->syn || tcp->fin || tcp->rst))) {
		flush_keepalives(1);
		return NF_ACCEPT;
	}

	keepalive = kzalloc(sizeof(struct keepalives), GFP_ATOMIC);
	if (!keepalive)
		return NF_ACCEPT;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
	keepalive->net = state->net;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
	keepalive->sk = state->sk;
#endif
	keepalive->skb = skb;
	keepalive->okfn = okfn;

	spin_lock_bh(&keepalives_lock);
	keepalives.num_keeps++;
	list_add_tail(&keepalive->list, &keepalives.list);
	spin_unlock_bh(&keepalives_lock);

	/*
	 * If the flush timer is not yet set, then update it
	 * to flush the queue after a timeout (typically 30 sec).
	 */
	if (!timer_pending(&flush_timer)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
		struct timespec64 timeout = { .tv_sec = flush_notification,
					      .tv_nsec = 0 };
		unsigned long future = timespec64_to_jiffies(&timeout);
#else
		struct timeval timeout = { .tv_sec = flush_notification,
					   .tv_usec = 0 };
		unsigned long future = timeval_to_jiffies(&timeout);
#endif
		mod_timer(&flush_timer, round_jiffies(jiffies + future));
		dev_dbg(iphb_dev, "Timer to %lu (%lu + %lu)\n",
			flush_timer.expires, jiffies, future);
	}

	return NF_STOLEN;
}



#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
static unsigned int net_in_hook(unsigned int hook,
				struct sk_buff *skb,
				const struct net_device *indev,
				const struct net_device *outdev,
				int (*okfn)(struct sk_buff *))
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0)
static unsigned int net_in_hook(const struct nf_hook_ops *ops,
				struct sk_buff *skb,
				const struct net_device *indev,
				const struct net_device *outdev,
				int (*okfn)(struct sk_buff *))
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
static unsigned int net_in_hook(const struct nf_hook_ops *ops,
				struct sk_buff *skb,
				const struct nf_hook_state *state)
#else
static unsigned int net_in_hook(void *priv,
				struct sk_buff *skb,
				const struct nf_hook_state *state)
#endif
{
	if (!iphb_is_enabled)
		return NF_ACCEPT;

	/*
	 * Packets coming in will automatically flush output queue
	 * because radio is now on.
	 */
	flush_keepalives(1);

	return NF_ACCEPT;
}


/*
 * The user space daemon (iphbd) needs the interface for communicating
 * with this module.
 */
static const struct file_operations iphb_fops = {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
	.owner = THIS_MODULE,
#endif
	.write = iphbd_write,
	.read = iphbd_read,
	.poll = iphbd_poll,
	.open = iphbd_open,
	.release = iphbd_release
};

static struct miscdevice iphb_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = MY_NAME,
	.fops  = &iphb_fops
};

/* hook for packets sent to interface */
static struct nf_hook_ops net_out_ops = {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,13,0)
	.list = { NULL, NULL },
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
	.owner = THIS_MODULE,
#endif
	.hook = net_out_hook,
	.pf = PF_INET,
	.hooknum = NF_INET_POST_ROUTING,
	.priority = NF_IP_PRI_LAST
};
static struct nf_hook_ops net_out6_ops = {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,13,0)
	.list = { NULL, NULL },
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
	.owner = THIS_MODULE,
#endif
	.hook = net_out_hook,
	.pf = PF_INET6,
	.hooknum = NF_INET_POST_ROUTING,
	.priority = NF_IP6_PRI_LAST
};

/* hook for packets received from interface */
static struct nf_hook_ops net_in_ops = {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,13,0)
	.list = { NULL, NULL },
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
	.owner = THIS_MODULE,
#endif
	.hook = net_in_hook,
	.pf = PF_INET,
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_FIRST
};
static struct nf_hook_ops net_in6_ops = {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,13,0)
	.list = { NULL, NULL },
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
	.owner = THIS_MODULE,
#endif
	.hook = net_in_hook,
	.pf = PF_INET6,
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = NF_IP6_PRI_FIRST
};


static int __init init(void)
{
	int ret;

	INIT_LIST_HEAD(&keepalives.list);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0)
	init_timer_deferrable(&flush_timer);
#else
	timer_setup(&flush_timer, timed_flush, TIMER_DEFERRABLE);
#endif
	ret = misc_register(&iphb_misc);
	if (ret < 0) {
		pr_err(MY_NAME ": Cannot create device (%d)\n", ret);
		return -ENODEV;
	}

	iphb_dev = iphb_misc.this_device;
	if (!iphb_dev) {
		pr_err(MY_NAME ": Cannot create device\n");
		return -ENODEV;
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,13,0)
	nf_register_hook(&net_out_ops);
	nf_register_hook(&net_in_ops);
	nf_register_hook(&net_out6_ops);
	nf_register_hook(&net_in6_ops);
#else
	nf_register_net_hook(&init_net, &net_out_ops);
	nf_register_net_hook(&init_net, &net_in_ops);
	nf_register_net_hook(&init_net, &net_out6_ops);
	nf_register_net_hook(&init_net, &net_in6_ops);
#endif
	pr_info(MY_NAME ": Keepalive handler module registered\n");

	return 0;
}


static void __exit fini(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,13,0)
	nf_unregister_hook(&net_out_ops);
	nf_unregister_hook(&net_in_ops);
	nf_unregister_hook(&net_out6_ops);
	nf_unregister_hook(&net_in6_ops);
#else
	nf_unregister_net_hook(&init_net, &net_out_ops);
	nf_unregister_net_hook(&init_net, &net_in_ops);
	nf_unregister_net_hook(&init_net, &net_out6_ops);
	nf_unregister_net_hook(&init_net, &net_in6_ops);
#endif
	flush_keepalives(0);

	misc_deregister(&iphb_misc);

	iphb_is_enabled = 0;

	pr_info(MY_NAME ": Keepalive handler module unregistered\n");
}

module_init(init);
module_exit(fini);

MODULE_AUTHOR("Jukka Rissanen <jukka.rissanen@nokia.com>");
MODULE_DESCRIPTION("netfilter module for delaying TCP keepalive packets");
MODULE_LICENSE("GPL");
