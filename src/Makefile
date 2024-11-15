KDIR ?= $(HOME)/src/linux
TESTIMG_dir := ../test-img
BUILD_DIR := build

obj-m += edudev.o

.PHONY: all
all:
	make LLVM=1 -C $(HOME)/src/linux M=$(PWD) modules

clean:
	make -C $(HOME)/src/linux M=$(PWD) clean

img: all
	cd $(TESTIMG_DIR) && $(KDIR)/usr/gen_init_cpio initramfs.preset > initramfs.img

run: img
	qemu-system-x86_64 \
	-kernel $(KDIR)/arch/x86/boot/bzImage \
	-initrd ../test-img/initramfs.img \
	-device edu \
	-device edu \
	-nographic -append "console=ttyS0 nokaslr"
