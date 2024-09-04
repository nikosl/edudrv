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

struct edu_procfs {
	struct proc_dir_entry *proc_dir;
	struct proc_dir_entry *proc_version;
};

struct edu_device {
	struct class *class;
	struct device *device;
};

struct edu_module {
	int irq;
	dev_t major;
	struct cdev cdev;
	wait_queue_head_t wq;

	struct edu_data data;
	struct edu_device dev;
	struct pci_dev *pdev;
};

static struct edu_module *edu_mod = NULL;

static struct pci_device_id edu_pci_tbl[] = { { PCI_DEVICE(EDU_PCI_VENDOR_ID,
							   EDU_PCI_DEVICE_ID) },
					      { 0 } };
MODULE_DEVICE_TABLE(pci, edu_pci_tbl);

static int edu_module_init(struct edu_module *mod)
{
	mod->irq = 0;
	mod->major = 0;

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

static int edu_mmio_init_dma(struct edu_module *mod, void *buffer, u32 count,
			     enum dma_data_direction dir)
{
	if (count > EDU_DMA_SIZE) {
		return -EINVAL;
	}

	struct edu_data *data = &mod->data;
	if (edu_mmio_is_xfer_active(data)) {
		return -EBUSY;
	}

	dma_addr_t addr = EDU_DMA_OFFSET;

	dma_addr_t buf_dma = mod->data.dma_handle;
	// 	dma_map_single(&mod->pdev->dev, buffer, count, dir);
	// int rc = dma_mapping_error(&mod->pdev->dev, buf_dma);
	// if (unlikely(rc)) {
	// 	return -ENOMEM;
	// }

	pr_info("edudev: dma map single 0x%08x\n", buf_dma);

	switch (dir) {
	case DMA_TO_DEVICE: {
		iowrite32(buf_dma, data->iomem + EDU_ADDR_DMA_SRC);
		iowrite32(addr, data->iomem + EDU_ADDR_DMA_DST);
		iowrite32(count, data->iomem + EDU_ADDR_DMA_COUNT);
		iowrite32(EDU_DMA_CMD_XFER_TO_DEV,
			  data->iomem + EDU_ADDR_DMA_CMD);
		break;
	}
	case DMA_FROM_DEVICE: {
		iowrite32(addr, data->iomem + EDU_ADDR_DMA_SRC);
		iowrite32(buf_dma, data->iomem + EDU_ADDR_DMA_DST);
		iowrite32(count, data->iomem + EDU_ADDR_DMA_COUNT);
		iowrite32(EDU_DMA_CMD_XFER_TO_RAM,
			  data->iomem + EDU_ADDR_DMA_CMD);
		break;
	}
	default:
		return -EINVAL;
	}

	wait_event_interruptible(edu_mod->wq, !edu_mmio_is_xfer_active(data));

	// dma_unmap_single(&mod->pdev->dev, buf_dma, count, dir);

	return 0;
}

static irqreturn_t edu_irq_handler(int irq, void *dev_id)
{
	pr_info("edudev: irq interrupt received\n");

	struct edu_data *data = (struct edu_data *)dev_id;

	unsigned int intr = edu_mmio_irq_status(data);
	pr_info("edudev: irq status %d\n", intr);

	edu_mmio_irq_ack(data, intr);

	wake_up_interruptible(&edu_mod->wq);

	return IRQ_HANDLED;
}

static int edu_open(struct inode *in, struct file *f)
{
	nonseekable_open(in, f);
	struct edu_module *mod =
		container_of(in->i_cdev, struct edu_module, cdev);
	f->private_data = mod;

	return 0;
}

static ssize_t edu_write(struct file *f, const char __user *buf, size_t count,
			 loff_t *off)
{
	if (count > EDU_DMA_SIZE) {
		return -EINVAL;
	}

	struct edu_module *mod = (struct edu_module *)f->private_data;

	struct edu_stats *st = (struct edu_stats *)kmalloc(
		sizeof(struct edu_stats), GFP_ATOMIC);
	if (!st) {
		return -ENOMEM;
	}

	edu_mmio_init_dma(mod, st, count, DMA_FROM_DEVICE);

	pr_info("edudev: dma writes %d\n", st->writes);

	st->writes += 1;

	edu_mmio_init_dma(mod, st, count, DMA_TO_DEVICE);

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

	struct edu_module *mod = (struct edu_module *)f->private_data;

	// struct edu_stats *st = (struct edu_stats *)kmalloc(
	// 	sizeof(struct edu_stats), GFP_ATOMIC);
	// if (!st) {
	// 	return -ENOMEM;
	// }

	struct edu_stats *st = (struct edu_stats *)edu_mod->data.dma;
	edu_mmio_init_dma(mod, st, sizeof(struct edu_stats), DMA_FROM_DEVICE);

	pr_info("edudev: dma read %d\n", st->reads);

	st->reads += 1;

	edu_mmio_init_dma(mod, st, sizeof(struct edu_stats), DMA_TO_DEVICE);

	// kfree(st);

	*off += (ssize_t)count;
	return 0;
}

static long int edu_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	struct edu_module *mod = (struct edu_module *)f->private_data;
	struct edu_data *data = &mod->data;

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
		wait_event_interruptible(mod->wq, !edu_mmio_is_computing(data));

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

static int edu_cdev_init(struct edu_module *dev)
{
	int rc = 0;

	rc = alloc_chrdev_region(&dev->major, 0, 1, "edu");
	if (rc < 0) {
		pr_err("alloc_chrdev_region failed\n");
		return rc;
	}

	cdev_init(&dev->cdev, &edu_fops);
	dev->cdev.owner = THIS_MODULE;

	rc = cdev_add(&dev->cdev, dev->major, 1);
	if (rc < 0) {
		pr_err("cdev_add failed\n");
		return rc;
	}

	return 0;
}

static void edu_cdev_remove(struct edu_module *dev)
{
	cdev_del(&dev->cdev);
	unregister_chrdev_region(dev->major, 1);
}

static int edu_dev_init(struct edu_module *mod)
{
	int rc = 0;
	struct edu_device *dev = &mod->dev;
	struct edu_data *data = &mod->data;

	dev->class = class_create(KBUILD_MODNAME);
	if (IS_ERR(dev->class)) {
		pr_err("class_create failed\n");
		rc = (int)PTR_ERR(dev->class);
		return rc;
	}
	dev->class->dev_groups = edu_groups;
	dev->class->dev_uevent = edu_uevent;

	dev->device =
		device_create(dev->class, NULL, mod->major, data, "edu%d", 0);
	if (IS_ERR(dev->device)) {
		pr_err("device_create failed\n");
		rc = (int)PTR_ERR(dev->device);
		goto class_cleanup;
	}

	return 0;

class_cleanup:
	class_destroy(dev->class);
	return rc;
}

static void edu_dev_cleanup(struct edu_module *mod)
{
	struct edu_device *dev = &mod->dev;

	device_destroy(dev->class, MKDEV(mod->major, 0));
	class_destroy(dev->class);
}

static int edu_driver_probe(struct pci_dev *dev,
			    const struct pci_device_id *dev_id)
{
	pr_info("edudev: probe\n");

	int rc = 0;
	int irq_nr = 0;

	rc = pcim_enable_device(dev);
	if (rc < 0) {
		pr_err("pci_enable_device failed\n");
		return rc;
	}

	edu_mod = devm_kzalloc(&dev->dev, sizeof(*edu_mod), GFP_KERNEL);
	if (!edu_mod) {
		return -ENOMEM;
	}

	edu_module_init(edu_mod);

	pci_set_master(dev);

	rc = pcim_iomap_regions(dev, BIT(0), KBUILD_MODNAME);
	if (rc < 0) {
		pr_err("pci request region failed\n");
		return rc;
	}

	edu_mod->pdev = dev;

	edu_mod->data.iomem = pcim_iomap_table(dev)[0];

	dma_set_mask_and_coherent(&(dev->dev), DMA_BIT_MASK(EDU_DMA_MASK));
	edu_mod->data.dma = dmam_alloc_coherent(
		&dev->dev, EDU_DMA_SIZE, &edu_mod->data.dma_handle, GFP_KERNEL);

	if (!edu_mod->data.dma) {
		pci_err(dev, "dmam_alloc_coherent failed\n");
		return -ENOMEM;
	}

	rc = pci_alloc_irq_vectors(dev, 1, 1, PCI_IRQ_ALL_TYPES);
	if (rc < 0) {
		pci_err(dev, "pci_alloc_irq_vectors failed\n");
		return rc;
	}

	irq_nr = pci_irq_vector(dev, 0);
	if (irq_nr < 0) {
		pci_err(dev, "pci_irq_vector failed\n");
		rc = irq_nr;

		goto free_irq_vec;
	}

	edu_mod->irq = irq_nr;
	rc = request_irq(irq_nr, edu_irq_handler, 0, KBUILD_MODNAME,
			 &edu_mod->data);
	if (rc < 0) {
		pci_err(dev, "devm_request_irq failed\n");
		goto free_irq_vec;
	}

	rc = edu_cdev_init(edu_mod);
	if (rc < 0) {
		pr_err("edu_dev_init failed\n");
		goto irq_cleanup;
	}

	rc = edu_dev_init(edu_mod);
	if (rc < 0) {
		pr_err("edu_dev_init failed\n");
		goto cdev_cleanup;
	}

	return 0;

cdev_cleanup:
	edu_cdev_remove(edu_mod);
irq_cleanup:
	free_irq(irq_nr, edu_mod);
free_irq_vec:
	pci_free_irq_vectors(dev);
	devm_kfree(&dev->dev, edu_mod);

	return rc;
}

static void edu_driver_remove(struct pci_dev *dev)
{
	pr_info("edudev: cleanup\n");

	pr_info("cleanup dev\n");
	edu_dev_cleanup(edu_mod);

	pr_info("edudev: remove\n");
	edu_cdev_remove(edu_mod);

	pr_info("free irq\n");
	free_irq(edu_mod->irq, &edu_mod->data);
	pci_free_irq_vectors(dev);
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

	rc = alloc_chrdev_region(&edu_mod->major, 0, 1, "edu");
	if (rc < 0) {
		pr_err("alloc_chrdev_region failed\n");
		return rc;
	}

	return pci_register_driver(&edu_driver);
}

static void __exit edu_exit(void)
{
	pr_info("Edu module exit...");
	pci_unregister_driver(&edu_driver);
	unregister_chrdev_region(edu_mod->major, EDU_MAX_DEVICES);
	kfree(edu_mod);
}

module_init(edu_init);
module_exit(edu_exit);

MODULE_AUTHOR("N3kr4");
MODULE_DESCRIPTION("EDU driver");
MODULE_LICENSE("GPL");
