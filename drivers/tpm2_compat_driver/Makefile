#KERNEL_SRC=~/work/linux
#KERNEL_SRC=/usr/src/linux-headers-5.15.0-40-generic

KDIR := /lib/modules/$(shell uname -r)/build
SRCDIR := /usr/src/$(shell uname -r)/include

obj-m += tpm2_compat.o
tpm2_compat-y := tpm2_driver.o tpm2_driver_utils.o tpm2_axiado.o tpm2_axiado_handler.o tpm2_compat_handler.o
EXTRA_CFLAGS += -I$(SRCDIR) -I$(PWD) -I$(PWD)/../shared_headers -I$(PWD)/../tpm2_shared -DAXIADO_KERNEL

.PHONY: test unload

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
	rm -f *.c~
	rm -f *.h~

test: all
	-sudo rmmod tpm2_compat.ko
	sudo dmesg -C
	sudo insmod tpm2_compat.ko
	sudo dmesg
	./create_device.sh

unload:
	-sudo rmmod tpm2_compat.ko
	./remove_device.sh
