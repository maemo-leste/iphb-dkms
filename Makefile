obj-m += iphb.o

all:

install:
	mkdir -p $(DESTDIR)/usr/src/iphb-1.2
	cp -a iphb.c Makefile dkms.conf $(DESTDIR)/usr/src/iphb-1.2/
