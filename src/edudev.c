/*
 * Copyright 2024 Nikos Leivadaris <nikosleiv@gmail.com>.
 * SPDX-License-Identifier: GPL-2.0
 */

#include <linux/mutex.h>
#include <linux/dma-direction.h>
#include <linux/gfp_types.h>
#include <linux/wait.h>
#include <linux/device.h>
#include <linux/device/class.h>
#include <linux/kobject.h>
#include <linux/cdev.h>
#include <linux/dma-mapping.h>
#include <linux/fs.h>
#include <linux/interrupt.h>
#include <linux/irqreturn.h>
#include <linux/stddef.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/printk.h>

#include "educmd.h"

#define EDU_PCI_VENDOR_ID 0x1234
#define EDU_PCI_DEVICE_ID 0x11e8

#define EDU_MAX_DEVICES 4

#define EDU_DMA_MASK 28
#define EDU_DMA_SIZE 4096
#define EDU_DMA_OFFSET 0x40000

#define EDU_DMA_CMD_START_XFER 1
#define EDU_DMA_CMD_RAM_TO_DEV 0
#define EDU_DMA_CMD_DEV_TO_RAM 2
#define EDU_DMA_CMD_RAISE_IRQ 4

#define EDU_DMA_CMD_XFER_TO_DEV                            \
	(EDU_DMA_CMD_START_XFER | EDU_DMA_CMD_RAM_TO_DEV | \
	 EDU_DMA_CMD_RAISE_IRQ)

#define EDU_DMA_CMD_XFER_TO_RAM                            \
	(EDU_DMA_CMD_START_XFER | EDU_DMA_CMD_DEV_TO_RAM | \
	 EDU_DMA_CMD_RAISE_IRQ)

#define EDU_STATUS_COMPUTING 0x01
#define EDU_STATUS_RAISE_IRQ 0x80

#define EDU_ADDR_IDENT 0x0
#define EDU_ADDR_LIVENESS 0x04
#define EDU_ADDR_FACTORIAL 0x08
#define EDU_ADDR_STATUS 0x20
#define EDU_ADDR_IRQ_STATUS 0x24
#define EDU_ADDR_IRQ_RAISE 0x60
#define EDU_ADDR_IRQ_ACK 0x64
#define EDU_ADDR_DMA_SRC 0x80
#define EDU_ADDR_DMA_DST 0x88
#define EDU_ADDR_DMA_COUNT 0x90
#define EDU_ADDR_DMA_CMD 0x98

#define EDU_ID_MAJOR(n) (((n)&0xff000000) >> 24)
#define EDU_ID_MINOR(n) (((n)&0x00ff0000) >> 16)

#define EDU_BUF_VERSION_MAX_LEN 8
#define EDU_BUF_NUM_MAX_LEN 16
#define EDU_BUF_INPUT_MAX_LEN 5

struct edu_version {
	u8 major;
	u8 minor;
};

struct edu_stats {
	u32 reads;
	u32 writes;
};

struct edu_data {
	char __iomem *iomem;
	void *dma;
	dma_addr_t dma_handle;
};

struct edu_device {
	int id;
	dev_t nod;
	int irq;
	struct cdev cdev;
	struct class *class;
	wait_queue_head_t wq;

	struct edu_data data;
	struct device *device;
	struct pci_dev *pdev;
};

struct edu_module {
	dev_t major;
	int cnt;
	struct class *class;
	struct edu_device *devices[EDU_MAX_DEVICES];
};

static struct mutex edu_mutex;

static struct edu_module *edu_mod = NULL;

static struct pci_device_id edu_pci_tbl[] = { { PCI_DEVICE(EDU_PCI_VENDOR_ID,
							   EDU_PCI_DEVICE_ID) },
					      { 0 } };
MODULE_DEVICE_TABLE(pci, edu_pci_tbl);

static void edu_module_init(struct edu_module *mod)
{
	mod->major = 0;
	mod->cnt = 0;
	mod->class = NULL;

	memset(&mod->devices, 0, sizeof(mod->devices));
}

static int edu_device_init(struct edu_device *mod)
{
	mod->irq = 0;

	init_waitqueue_head(&mod->wq);

	mod->data.iomem = NULL;
	mod->data.dma = NULL;

	return 0;
}

static inline struct edu_version init_edu_version(u32 id)
{
	struct edu_version ver = {
		.major = EDU_ID_MAJOR(id),
		.minor = EDU_ID_MINOR(id),
	};

	return ver;
}

static inline u32 edu_mmio_get_id(const struct edu_data *data)
{
	return ioread32(data->iomem + EDU_ADDR_IDENT);
}

static inline void edu_mmio_trigger_irq(struct edu_data *data, u32 i)
{
	iowrite32(i, data->iomem + EDU_ADDR_IRQ_RAISE);
}

static inline unsigned int edu_mmio_irq_status(const struct edu_data *data)
{
	return ioread32(data->iomem + EDU_ADDR_IRQ_STATUS);
}

static inline void edu_mmio_irq_ack(const struct edu_data *data, u32 i)
{
	iowrite32(i, data->iomem + EDU_ADDR_IRQ_ACK);
}

static inline unsigned int edu_mmio_get_liveness(const struct edu_data *data)
{
	return ioread32(data->iomem + EDU_ADDR_LIVENESS);
}

static inline void edu_mmio_set_liveness(const struct edu_data *data, u32 l)
{
	iowrite32(l, data->iomem + EDU_ADDR_LIVENESS);
}

static inline unsigned int edu_mmio_get_factorial(const struct edu_data *data)
{
	return ioread32(data->iomem + EDU_ADDR_FACTORIAL);
}

static inline void edu_mmio_set_factorial(const struct edu_data *data, u32 f)
{
	iowrite32(f, data->iomem + EDU_ADDR_FACTORIAL);
}

static inline void edu_mmio_expect_irq(const struct edu_data *data)
{
	iowrite32(EDU_STATUS_RAISE_IRQ, data->iomem + EDU_ADDR_STATUS);
}

static inline bool edu_mmio_is_computing(const struct edu_data *data)
{
	return ioread32(data->iomem + EDU_ADDR_STATUS) & EDU_STATUS_COMPUTING;
}

static inline bool edu_mmio_is_xfer_active(const struct edu_data *data)
{
	return ioread32(data->iomem + EDU_ADDR_DMA_CMD) &
	       EDU_DMA_CMD_START_XFER;
}

static int edu_mmio_init_dma(struct edu_device *dev, void *buffer, u32 count,
			     enum dma_data_direction dir)
{
	if (count > EDU_DMA_SIZE) {
		return -EINVAL;
	}

	struct edu_data *data = &dev->data;
	if (edu_mmio_is_xfer_active(data)) {
		return -EBUSY;
	}

	dma_addr_t buf_dma = dev->data.dma_handle;
	// 	dma_map_single(&mod->pdev->dev, buffer, count, dir);
	// int rc = dma_mapping_error(&mod->pdev->dev, buf_dma);
	// if (unlikely(rc)) {
	// 	return -ENOMEM;
	// }

	pr_info("edudev: dma map single 0x%08x\n", buf_dma);

	u32 cmd = 0;
	dma_addr_t src = 0;
	dma_addr_t dst = 0;

	switch (dir) {
	case DMA_TO_DEVICE: {
		src = buf_dma;
		dst = EDU_DMA_OFFSET;
		cmd = EDU_DMA_CMD_XFER_TO_DEV;
		break;
	}
	case DMA_FROM_DEVICE: {
		src = EDU_DMA_OFFSET;
		dst = buf_dma;
		cmd = EDU_DMA_CMD_XFER_TO_RAM;
		break;
	}
	default:
		return -EINVAL;
	}

	iowrite32(src, data->iomem + EDU_ADDR_DMA_SRC);
	iowrite32(dst, data->iomem + EDU_ADDR_DMA_DST);
	iowrite32(count, data->iomem + EDU_ADDR_DMA_COUNT);
	iowrite32(cmd, data->iomem + EDU_ADDR_DMA_CMD);

	wait_event_interruptible(dev->wq, !edu_mmio_is_xfer_active(data));

	// dma_unmap_single(&mod->pdev->dev, buf_dma, count, dir);

	return 0;
}

static irqreturn_t edu_irq_handler(int irq, void *dev_id)
{
	pr_info("edudev: irq interrupt received\n");

	struct edu_device *dev = (struct edu_device *)dev_id;
	struct edu_data *data = &dev->data;

	unsigned int intr = edu_mmio_irq_status(data);
	pr_info("edudev: irq status %d\n", intr);

	edu_mmio_irq_ack(data, intr);

	wake_up_interruptible(&dev->wq);

	return IRQ_HANDLED;
}

static int edu_open(struct inode *in, struct file *f)
{
	unsigned int idx = iminor(in);
	if (idx >= EDU_MAX_DEVICES) {
		return -ENODEV;
	}

	mutex_lock(&edu_mutex);
	struct edu_device *dev = edu_mod->devices[idx];
	mutex_unlock(&edu_mutex);

	f->private_data = dev;

	return 0;
}

static ssize_t edu_write(struct file *f, const char __user *buf, size_t count,
			 loff_t *off)
{
	if (count > EDU_DMA_SIZE) {
		return -EINVAL;
	}

	struct edu_device *dev = (struct edu_device *)f->private_data;

	struct edu_stats *st = (struct edu_stats *)kmalloc(
		sizeof(struct edu_stats), GFP_ATOMIC);
	if (!st) {
		return -ENOMEM;
	}

	edu_mmio_init_dma(dev, st, count, DMA_FROM_DEVICE);

	pr_info("edudev: dma writes %d\n", st->writes);

	st->writes += 1;

	edu_mmio_init_dma(dev, st, count, DMA_TO_DEVICE);

	kfree(st);

	*off += (ssize_t)count;
	return (ssize_t)count;
}

static ssize_t edu_read(struct file *f, char __user *buf, size_t count,
			loff_t *off)
{
	if (count > EDU_DMA_SIZE) {
		return -EINVAL;
	}

	struct edu_device *dev = (struct edu_device *)f->private_data;

	// struct edu_stats *st = (struct edu_stats *)kmalloc(
	// 	sizeof(struct edu_stats), GFP_ATOMIC);
	// if (!st) {
	// 	return -ENOMEM;
	// }

	struct edu_stats *st = (struct edu_stats *)dev->data.dma;
	edu_mmio_init_dma(dev, st, sizeof(struct edu_stats), DMA_FROM_DEVICE);

	pr_info("edudev: dma read %d\n", st->reads);

	st->reads += 1;

	edu_mmio_init_dma(dev, st, sizeof(struct edu_stats), DMA_TO_DEVICE);

	// kfree(st);

	*off += (ssize_t)count;
	return 0;
}

static long edu_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	struct edu_device *dev = (struct edu_device *)f->private_data;
	struct edu_data *data = &dev->data;

	u32 val = 0;

	switch (cmd) {
	case EDUCMD_LIVENESS: {
		if (copy_from_user(&val, (u32 *)arg, sizeof(val))) {
			return -EFAULT;
		}

		edu_mmio_set_liveness(data, val);
		val = edu_mmio_get_liveness(data);

		long int rc = copy_to_user((u32 *)arg, &val, sizeof(val)) ?
				      -EFAULT :
				      0;
		return rc;
	}
	case EDUCMD_FACTORIAL: {
		if (copy_from_user(&val, (u32 *)arg, sizeof(val))) {
			return -EFAULT;
		}

		edu_mmio_set_factorial(data, val);

		edu_mmio_expect_irq(data);
		wait_event_interruptible(dev->wq, !edu_mmio_is_computing(data));

		val = edu_mmio_get_factorial(data);

		return copy_to_user((u32 *)arg, &val, sizeof(val)) ? -EFAULT :
								     0;
	}

	default:
		return -EINVAL;
	}
}

static int edu_uevent(const struct device *dev, struct kobj_uevent_env *env)
{
	pr_info("edudev: uevent\n");
	return add_uevent_var(env, "DEVMODE=%#o", S_IRUGO | S_IWUGO);
}

// sysfs

static ssize_t version_show(struct device *dev, struct device_attribute *attr,
			    char *buf)
{
	struct edu_data *data = dev_get_drvdata(dev);

	u32 id = edu_mmio_get_id(data);
	struct edu_version ver = init_edu_version(id);

	return snprintf(buf, EDU_BUF_VERSION_MAX_LEN, "%d.%d\n", ver.major,
			ver.minor);
}
DEVICE_ATTR_RO(version);

static ssize_t liveness_show(struct device *dev, struct device_attribute *attr,
			     char *buf)
{
	struct edu_data *data = dev_get_drvdata(dev);
	u32 liv = edu_mmio_get_liveness(data);

	return snprintf(buf, EDU_BUF_NUM_MAX_LEN, "%d\n", liv);
}

static ssize_t liveness_store(struct device *dev, struct device_attribute *attr,
			      const char *buf, size_t count)
{
	if (count > EDU_BUF_INPUT_MAX_LEN) {
		return -EINVAL;
	}

	int l = 0;
	sscanf(buf, "%du", &l);

	struct edu_data *data = dev_get_drvdata(dev);
	edu_mmio_set_liveness(data, l);

	return (ssize_t)count;
}

DEVICE_ATTR_RW(liveness);

static ssize_t trigger_irq_store(struct device *dev,
				 struct device_attribute *attr, const char *buf,
				 size_t count)
{
	if (count > EDU_BUF_INPUT_MAX_LEN) {
		return -EINVAL;
	}

	int l = 0;
	struct edu_data *data = dev_get_drvdata(dev);

	sscanf(buf, "%du", &l);
	edu_mmio_trigger_irq(data, l);

	return (ssize_t)count;
}

DEVICE_ATTR_WO(trigger_irq);

static ssize_t irq_status_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct edu_data *data = dev_get_drvdata(dev);
	u32 irq = edu_mmio_irq_status(data);

	return sprintf(buf, "%d\n", irq);
}

DEVICE_ATTR_RO(irq_status);

static struct attribute *edu_attrs[] = {
	&dev_attr_liveness.attr,
	&dev_attr_trigger_irq.attr,
	&dev_attr_irq_status.attr,
	&dev_attr_version.attr,
	NULL,
};

ATTRIBUTE_GROUPS(edu);

// dev

static struct file_operations edu_fops = {
	.open = edu_open,
	.write = edu_write,
	.read = edu_read,
	.unlocked_ioctl = edu_ioctl,
};

static int edu_cdev_init(struct edu_device *dev, struct class *cls, dev_t major,
			 int idx)
{
	int rc = 0;

	dev->id = idx;
	dev->nod = MKDEV(major, idx);
	dev->class = cls;

	cdev_init(&dev->cdev, &edu_fops);
	dev->cdev.owner = THIS_MODULE;

	rc = cdev_add(&dev->cdev, dev->nod, 1);
	if (rc < 0) {
		pr_err("cdev_add failed\n");
		return rc;
	}

	dev->device =
		device_create(cls, NULL, dev->nod, &dev->data, "edu%d", idx);
	if (IS_ERR(dev->device)) {
		pr_err("device_create failed\n");
		rc = (int)PTR_ERR(dev->device);
		goto cdev_cleanup;
	}

	return 0;

cdev_cleanup:
	cdev_del(&dev->cdev);
	return rc;
}

static void edu_cdev_remove(struct edu_device *dev)
{
	cdev_del(&dev->cdev);
	device_destroy(dev->class, dev->nod);
}

static int edu_class_init(struct edu_module *mod)
{
	int rc = 0;

	mod->class = class_create(KBUILD_MODNAME);
	if (IS_ERR(mod->class)) {
		pr_err("class_create failed\n");
		rc = (int)PTR_ERR(mod->class);
		return rc;
	}
	mod->class->dev_groups = edu_groups;
	mod->class->dev_uevent = edu_uevent;

	return 0;
}

static int edu_driver_probe(struct pci_dev *pdev,
			    const struct pci_device_id *dev_id)
{
	pr_info("edudev: probe\n");

	int rc = 0;
	int irq_nr = 0;

	rc = pcim_enable_device(pdev);
	if (rc < 0) {
		pr_err("pci_enable_device failed\n");
		return rc;
	}

	struct edu_device *dev =
		devm_kzalloc(&pdev->dev, sizeof(*dev), GFP_KERNEL);
	if (!dev) {
		return -ENOMEM;
	}

	edu_device_init(dev);
	pci_set_drvdata(pdev, dev);

	pci_set_master(pdev);

	rc = pcim_iomap_regions(pdev, BIT(0), KBUILD_MODNAME);
	if (rc < 0) {
		pr_err("pci request region failed\n");
		return rc;
	}

	dev->pdev = pdev;

	dev->data.iomem = pcim_iomap_table(pdev)[0];

	dma_set_mask_and_coherent(&(pdev->dev), DMA_BIT_MASK(EDU_DMA_MASK));
	dev->data.dma = dmam_alloc_coherent(&pdev->dev, EDU_DMA_SIZE,
					    &dev->data.dma_handle, GFP_KERNEL);

	if (!dev->data.dma) {
		pci_err(pdev, "dmam_alloc_coherent failed\n");
		return -ENOMEM;
	}

	rc = pci_alloc_irq_vectors(pdev, 1, 1, PCI_IRQ_ALL_TYPES);
	if (rc < 0) {
		pci_err(pdev, "pci_alloc_irq_vectors failed\n");
		return rc;
	}

	irq_nr = pci_irq_vector(pdev, 0);
	if (irq_nr < 0) {
		pci_err(pdev, "pci_irq_vector failed\n");
		rc = irq_nr;

		goto free_irq_vec;
	}

	dev->irq = irq_nr;
	rc = request_irq(irq_nr, edu_irq_handler, 0, KBUILD_MODNAME, dev);
	if (rc < 0) {
		pci_err(pdev, "devm_request_irq failed\n");
		goto free_irq_vec;
	}

	mutex_lock(&edu_mutex);
	if (edu_mod->cnt >= EDU_MAX_DEVICES) {
		pr_err("edu_dev_init %d failed\n", edu_mod->cnt);
		rc = -EINVAL;
		goto irq_cleanup;
	}

	rc = edu_cdev_init(dev, edu_mod->class, edu_mod->major, edu_mod->cnt);
	if (rc < 0) {
		pr_err("edu_dev_init %d failed\n", edu_mod->cnt);
		goto irq_cleanup;
	}

	edu_mod->devices[edu_mod->cnt] = dev;
	edu_mod->cnt += 1;
	mutex_unlock(&edu_mutex);

	return 0;

irq_cleanup:
	mutex_unlock(&edu_mutex);
	free_irq(irq_nr, dev);
free_irq_vec:
	pci_free_irq_vectors(pdev);
	devm_kfree(&pdev->dev, dev);

	return rc;
}

static void edu_driver_remove(struct pci_dev *pdev)
{
	pr_info("edudev: cleanup\n");

	struct edu_device *dev = pci_get_drvdata(pdev);
	int id = dev->id;

	pr_info("edudev: remove\n");
	edu_cdev_remove(dev);

	pr_info("free irq\n");
	free_irq(dev->irq, dev);
	pci_free_irq_vectors(pdev);

	mutex_lock(&edu_mutex);
	// TODO: edu_mod->cnt -= 1;
	edu_mod->devices[id] = NULL;
	mutex_unlock(&edu_mutex);
}

static struct pci_driver edu_driver = {
	.name = KBUILD_MODNAME,
	.id_table = edu_pci_tbl,
	.probe = edu_driver_probe,
	.remove = edu_driver_remove,
};

static int __init edu_init(void)
{
	pr_info("Edu module loaded.");

	int rc = 0;

	edu_mod = kzalloc(sizeof(*edu_mod), GFP_KERNEL);
	edu_module_init(edu_mod);

	mutex_init(&edu_mutex);

	dev_t mjr = 0;

	rc = alloc_chrdev_region(&mjr, 0, EDU_MAX_DEVICES, "edu");
	if (rc < 0) {
		pr_err("alloc_chrdev_region failed\n");
		goto free_alloc;
	}

	edu_mod->major = MAJOR(mjr);

	rc = edu_class_init(edu_mod);
	if (rc < 0) {
		pr_err("edu_class_init failed\n");
		goto unregister_chrdev;
	}

	rc = pci_register_driver(&edu_driver);
	if (rc < 0) {
		pr_err("pci_register_driver failed\n");
		goto remove_class;
	}

	return rc;

remove_class:
	class_destroy(edu_mod->class);
unregister_chrdev:
	unregister_chrdev_region(edu_mod->major, EDU_MAX_DEVICES);
free_alloc:
	kfree(edu_mod);
	return rc;
}

static void __exit edu_exit(void)
{
	pr_info("Edu module exit...");
	pci_unregister_driver(&edu_driver);
	unregister_chrdev_region(edu_mod->major, EDU_MAX_DEVICES);
	class_destroy(edu_mod->class);
	kfree(edu_mod);
}

module_init(edu_init);
module_exit(edu_exit);

MODULE_AUTHOR("Nikos Leivadaris <nikosleiv@gmail.com>");
MODULE_DESCRIPTION("EDU driver");
MODULE_LICENSE("GPL-2.0");
