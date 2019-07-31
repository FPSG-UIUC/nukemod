obj-m += nuke.o
nuke-objs := nuke_mod.o util.o
CFLAGS_nuke.o := -O0
CFLAGS_nuke_mod.o := -O0

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

# Some tutorials use M= instead of SUBDIRS= You may need to be root to
# compile the module. You must be root to insert it.
# V=1 causes verbose output
default:
	$(MAKE) V=1 -C $(KDIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
