KDIR ?= $(HOME)/src/linux
TESTIMG_IMG := initramfs.img

.PHONY: all

clean:
	rm -f $(TESTIMG_IMG)

img:
	$(KDIR)/usr/gen_init_cpio initramfs.preset > $(TESTIMG_IMG)

run: img
	qemu-system-x86_64 \
	-kernel $(KDIR)/arch/x86/boot/bzImage \
	-initrd $(TESTIMG_IMG) \
	-device edu \
	-device edu \
	-append "console=ttyS0 nokaslr" \
	-nographic 
