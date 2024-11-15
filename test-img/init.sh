#! /bin/sh

# curl https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox > busybox

busybox echo "Sys init!"
busybox mkdir /proc /sys
busybox mount -t sysfs sysfs /sys
busybox mount -t proc none /proc
busybox insmod edudev.ko
busybox echo '========'
busybox ls /dev/
busybox lspci -v
busybox lspci -vvv -d 1234:11e8
busybox echo '========'
busybox cat /proc/interrupts
busybox echo '========'
busybox /bin/educli /dev/edudev check 5
busybox /bin/educli /dev/edudev calc 5
busybox echo '========'
busybox ls /sys/class/edudev/edu0
busybox echo '========'
busybox echo "5" >/sys/class/edudev/edu0/liveness
busybox cat /sys/class/edudev/edu0/liveness
busybox echo '========'
busybox echo "5" >/sys/class/edudev/edu0/trigger_irq
busybox echo '========'
busybox rmmod edudev
busybox echo '========'
busybox ls /dev/
busybox ls /sys/class/edudev/
busybox poweroff -f
