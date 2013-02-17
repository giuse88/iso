# builds the kprobes example kernel modules;
# then to use one (as root):  insmod <module_name.ko>

#obj-$(CONFIG_SAMPLE_KPROBES) += kprobe_example.o jprobe_example.o
#obj-$(CONFIG_SAMPLE_KRETPROBES) += kretprobe_example.o
# This is taken straight from Documentation/kprobes.txt

obj-m := trace.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
clean:
	rm -rf *.mod.c *.ko *.o Module.symvers modules.order .trace.* .tmp_versions   
