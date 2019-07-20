/**
 * @file:   xfpga.c
 * @author: ppatel
 *
 * @brief:  Xilinx FPGA Configuration and I/O Driver
 *          Tested with Octeon III CN7010X SoC and Xilinx Aria 7 FPGA wired through the 8-bit bootbus on Octeon Linux 5.1
 *          Todo: Retrieve GPIOs, CS and physical address through device-tree; update to use GPIO descriptor structure
 */

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/poll.h>
#include <linux/gpio.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/firmware.h>
#include <linux/wait.h>
#include <linux/uaccess.h>

#define FPGA_DEVICE             "xfpga"

#define FPGA_IO_PHYS_ADDR       (0x1000080000000ULL)
#define FPGA_IO_PHYS_SIZE       (0x10000ULL)

#define GPIO_BASE               (480)
#define FPGA_PROG_N_GPIO        (GPIO_BASE + 2)
#define FPGA_INIT_N_GPIO        (GPIO_BASE + 11)
#define FPGA_DONE_N_GPIO        (GPIO_BASE + 3)
#define FPGA_IRQ_N_GPIO         (GPIO_BASE + 12)
#define FPGA_RESET_N_GPIO       (GPIO_BASE + 4)

MODULE_AUTHOR("Parag Patel");
MODULE_DESCRIPTION("Xilinx FPGA config and I/O");
MODULE_LICENSE("GPL");

static char *bitfile;
module_param(bitfile, charp, S_IRUGO);
MODULE_PARM_DESC(bitfile, "FPGA bitfile");

struct fpga_dev_data_t
{
    dev_t                       dev;
    struct cdev                 cdev;
    struct class                *class;
    struct device               *device;
    struct fasync_struct        *async_queue;
    wait_queue_head_t           wait_queue;
    void __iomem                *iomem;
    spinlock_t                  lock;
    int                         prog_n_gpio;
    int                         init_n_gpio;
    int                         done_n_gpio;
    int                         irq_n_gpio;
    int                         reset_n_gpio;
    int                         irq;
    unsigned long               irq_enabled;
    atomic_t                    irq_count;
};

static struct fpga_dev_data_t *fpga_dev_data;

/**
 * GPIO I/O pins and IO bus
 */
static int init_io(struct fpga_dev_data_t *dev_data)
{
    int err = 0;

    if ((err = gpio_request_one(FPGA_PROG_N_GPIO, GPIOF_OUT_INIT_HIGH | GPIOF_OPEN_DRAIN, "prog_n_gpio")))
    {
        return err;
    }

    dev_data->prog_n_gpio = FPGA_PROG_N_GPIO;

    if ((err = gpio_request_one(FPGA_INIT_N_GPIO, GPIOF_IN, "init_n_gpio")))
    {
        return err;
    }

    dev_data->init_n_gpio = FPGA_INIT_N_GPIO;

    if ((err = gpio_request_one(FPGA_DONE_N_GPIO, GPIOF_IN, "done_n_gpio")))
    {
        return err;
    }

    dev_data->done_n_gpio = FPGA_DONE_N_GPIO;

    if ((err = gpio_request_one(FPGA_IRQ_N_GPIO, GPIOF_IN | GPIOF_ACTIVE_LOW, "irq_n_gpio")))
    {
        return err;
    }

    dev_data->irq_n_gpio = FPGA_IRQ_N_GPIO;

    if ((err = gpio_export(dev_data->irq_n_gpio, false)))
    {
        return err;
    }

    if ((err = gpio_request_one(FPGA_RESET_N_GPIO, GPIOF_OUT_INIT_HIGH | GPIOF_OPEN_DRAIN, "reset_n_gpio")))
    {
        return err;
    }

    dev_data->reset_n_gpio = FPGA_RESET_N_GPIO;

    if ((err = gpio_export(dev_data->reset_n_gpio, false)))
    {
        return err;
    }

    dev_data->iomem = ioremap_nocache(FPGA_IO_PHYS_ADDR, FPGA_IO_PHYS_SIZE);

    return 0;
}

/**
 * Read bitstream to memory
 */
static void read_bitstream(u8 *bitdata, u8 *buf, unsigned *offset, unsigned rdsize)
{
    memcpy(buf, bitdata + *offset, rdsize);
    *offset += rdsize;
}

/**
 * Read from header section of bitstream
 */
static void read_info(u8 *bitdata, u8 *buf, unsigned *offset)
{
    u8 tbuf[2];
    unsigned len;

    /* read section ID */
    read_bitstream(bitdata, tbuf, offset, 1);

    /* read section length */
    read_bitstream(bitdata, tbuf, offset, 2);
    len = tbuf[0] << 8 | tbuf[1];

    /* read section info */
    read_bitstream(bitdata, buf, offset, len);
    buf[len] = '\0';
}

struct fpga_image_t
{
    const struct firmware   *fw;
    unsigned long           size;
    u8                      *data;
};

static const u8 XILINX_HDR[] =
{
    0x00, 0x09, 0x0f, 0xf0, 0x0f, 0xf0, 0x0f, 0xf0, 0x0f, 0xf0, 0x00, 0x00, 0x01
};

/**
 * Load the FPGA bitfile
 */
static int load_bitfile(struct fpga_image_t *fimage)
{
    u8 *bitdata;
    unsigned offset;
    u8 buf[256];

    offset = 0;

    /* read 13-byte Xilinx header */
    bitdata = (u8 *)(fimage->fw->data);
    read_bitstream(bitdata, buf, &offset, 13);

    if (memcmp(buf, XILINX_HDR, 13))
    {
        return -EINVAL;
    }

    read_info(bitdata, buf, &offset);
    pr_info(FPGA_DEVICE ": file: %s\n", (char *)buf);
    read_info(bitdata, buf, &offset);
    pr_info(FPGA_DEVICE ": part: %s\n", (char *)buf);
    read_info(bitdata, buf, &offset);
    pr_info(FPGA_DEVICE ": date: %s\n", (char *)buf);
    read_info(bitdata, buf, &offset);
    pr_info(FPGA_DEVICE ": time: %s\n", (char *)buf);
    read_bitstream(bitdata, buf, &offset, 1);

    if ((char)(buf[0]) != 'e')
    {
        return -EINVAL;
    }

    /* read 4-byte length */
    read_bitstream(bitdata, buf, &offset, 4);
    fimage->size = (((unsigned long)(buf[0]) << 24) & 0xff000000UL) | (((unsigned long)(buf[1]) << 16) & 0x00ff0000UL) |
                   (((unsigned long)(buf[2]) << 8 ) & 0x0000ff00UL) | ((unsigned long)(buf[3]) & 0x000000ffUL);
    pr_info(FPGA_DEVICE ": size: %u\n", (unsigned)fimage->size);

    if (fimage->fw->size != fimage->size + offset)
    {
        return -EINVAL;
    }

    fimage->data = bitdata + offset;

    return 0;
}

/**
 * Bit-reverse byte
 */
static inline u8 reverse_bits(u8 x)
{
    return ((x >> 7) & 0x01) | ((x >> 5) & 0x02) | ((x >> 3) & 0x04) | ((x >> 1) & 0x08) |
           ((x << 1) & 0x10) | ((x << 3) & 0x20) | ((x << 5) & 0x40) | ((x << 7) & 0x80);
}

/**
 * Write image to FPGA
 */
static int download_image(struct fpga_dev_data_t *dev_data, struct fpga_image_t *fimage)
{
    u8 *bitdata;
    unsigned size;
    unsigned i;

    bitdata = (u8 *)fimage->data;
    size = fimage->size;

    /* Configuration reset */
    gpio_set_value(dev_data->prog_n_gpio, 1);
    msleep(20);
    gpio_set_value(dev_data->prog_n_gpio, 0);
    msleep(20);
    gpio_set_value(dev_data->prog_n_gpio, 1);
    i = 0;

    while (gpio_get_value(dev_data->init_n_gpio) == 0)
    {
        if (i++ > 1000)
        {
            pr_err(FPGA_DEVICE ": FPGA initialization error\n");

            return -EIO;
        }

        msleep(1);
    }

    /* Write each byte (bit-reversed) to the I/O bus */
    for (i = 0; i < size; i++)
    {
        iowrite8(reverse_bits(bitdata[i]), dev_data->iomem);
    }

    /* Check init_b */
    if (gpio_get_value(dev_data->init_n_gpio) == 0)
    {
        pr_err(FPGA_DEVICE ": FPGA write error\n");

        return -EIO;
    }

    /* Wait for configuration done */
    i = 0;

    while (gpio_get_value(dev_data->done_n_gpio) == 0)
    {
        if (i++ > 1000)
        {
            pr_err(FPGA_DEVICE ": FPGA download error\n");

            return -EIO;
        }

        msleep(1);
    }

    return 0;
}

/**
 * Configure the FPGA with the provided bitfile
 */
static int fpga_config(struct fpga_dev_data_t *dev_data, char *file)
{
    int err = 0;
    struct fpga_image_t *fimage;
    struct device dev;

    if (PTR_ERR_OR_ZERO(fimage = kzalloc(sizeof(struct fpga_image_t), GFP_KERNEL)))
    {
        pr_err(FPGA_DEVICE ": out of mem\n");
        err = -ENOMEM;
        goto out;
    }

    /* Use Linux Firmware API to request file from userspace */
    if ((err = request_firmware(&fimage->fw, kbasename(file), &dev)))
    {
        pr_err(FPGA_DEVICE ": %s file request error\n", file);
        goto out;
    }

    if (PTR_ERR_OR_ZERO(fimage->fw) || PTR_ERR_OR_ZERO(fimage->fw->data))
    {
        pr_err(FPGA_DEVICE ": firmware error\n");
        err = -ENOENT;
        goto out;
    }

    if ((err = load_bitfile(fimage)))
    {
        pr_err(FPGA_DEVICE ": bitfile error\n");
        goto out;
    }

    if ((err = download_image(dev_data, fimage)))
    {
        pr_err(FPGA_DEVICE ": download error\n");
        goto out;
    }

out:

    if (fimage)
    {
        if (fimage->fw)
        {
            release_firmware(fimage->fw);
        }

        kfree(fimage);
    }

    return err;
}

/**
 * Interrupt Service Routine
 */
static irqreturn_t fpga_io_irq_handler(int irq, void *dev_id)
{
    struct fpga_dev_data_t *dev_data = fpga_dev_data;

    spin_lock(&dev_data->lock);

    if (test_and_clear_bit(0, &dev_data->irq_enabled))
    {
        disable_irq_nosync(dev_data->irq);
    }

    spin_unlock(&dev_data->lock);
    atomic_inc(&dev_data->irq_count);
    kill_fasync(&dev_data->async_queue, SIGIO, POLL_IN);
    wake_up_interruptible(&dev_data->wait_queue);

    return IRQ_HANDLED;
}

static const struct vm_operations_struct fpga_io_vm_ops =
{
};

struct fpga_file_data_t
{
    struct fpga_dev_data_t      *dev_data;
    atomic_t                    event_count;
};

/**
 * Open device from userspace
 */
static int fpga_io_open(struct inode *inode, struct file *filp)
{
    struct fpga_file_data_t *file_data;

    if (PTR_ERR_OR_ZERO(file_data = kzalloc(sizeof(struct fpga_file_data_t), GFP_KERNEL)))
    {
        return -ENOMEM;
    }

    file_data->dev_data = fpga_dev_data;
    atomic_set(&file_data->event_count, atomic_read(&fpga_dev_data->irq_count));
    filp->private_data = (void *)file_data;

    return 0;
}

/**
 * Release device from userspace
 */
static int fpga_io_release(struct inode *inode, struct file *filp)
{
    struct fpga_file_data_t *file_data = (struct fpga_file_data_t *)(filp->private_data);
    struct fpga_dev_data_t *dev_data = file_data->dev_data;

    fasync_helper(-1, filp, 0, &dev_data->async_queue);
    kfree(file_data);

    return 0;
}

/**
 * Map FPGA registers to userspace
 */
static int fpga_io_mmap(struct file *filp, struct vm_area_struct *vma)
{
    struct fpga_file_data_t *file_data = (struct fpga_file_data_t *)(filp->private_data);
    struct fpga_dev_data_t *dev_data = file_data->dev_data;
    int err = 0;

    if ((vma->vm_end - vma->vm_start) != FPGA_IO_PHYS_SIZE)
    {
        pr_err(FPGA_DEVICE ": FPGA IO invalid range\n");

        return -EINVAL;
    }

    vma->vm_ops = &fpga_io_vm_ops;
    vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
    err = remap_pfn_range(vma, vma->vm_start, (unsigned long)(dev_data->iomem) >> PAGE_SHIFT, FPGA_IO_PHYS_SIZE, vma->vm_page_prot);

    if (err)
    {
        pr_err(FPGA_DEVICE ": FPGA IO remap error\n");

        return -EAGAIN;
    }

    return 0;
}

/**
 * Read from userspace; blocks until IRQ triggers
 */
static ssize_t fpga_io_read(struct file *filp, char __user *buf, size_t count, loff_t *ppos)
{
    struct fpga_file_data_t *file_data = (struct fpga_file_data_t *)(filp->private_data);
    struct fpga_dev_data_t *dev_data = file_data->dev_data;
    u32 event_count;

    if (!dev_data->irq)
    {
        return -EIO;
    }

    if (count != sizeof(u32))
    {
        return -EINVAL;
    }

    event_count = (u32)atomic_read(&file_data->event_count);
    wait_event_interruptible(dev_data->wait_queue, event_count != (u32)(atomic_read(&dev_data->irq_count)));
    atomic_set(&file_data->event_count, atomic_read(&dev_data->irq_count));
    event_count = (u32)atomic_read(&file_data->event_count);

    if (copy_to_user(buf, &event_count, sizeof(u32)))
    {
        return -EFAULT;
    }

    return (ssize_t)count;
}

/**
 * Enable/disable IRQ by writing '1'/'0' from userspace
 */
static ssize_t fpga_io_write(struct file *filp, const char __user *buf, size_t count, loff_t *offp)
{
    struct fpga_file_data_t *file_data = (struct fpga_file_data_t *)(filp->private_data);
    struct fpga_dev_data_t *dev_data = file_data->dev_data;
    char irq_on[2];
    unsigned long flags;

    if (!dev_data->irq)
    {
        return -EIO;
    }

    if (count == 0 || count > 2)
    {
        return -EINVAL;
    }

    if (copy_from_user(irq_on, buf, count))
    {
        return -EFAULT;
    }

    spin_lock_irqsave(&dev_data->lock, flags);

    if (irq_on[0] == '1')
    {
        if (!test_and_set_bit(0, &dev_data->irq_enabled))
        {
            enable_irq(dev_data->irq);
        }
    }
    else if (irq_on[0] == '0')
    {
        if (test_and_clear_bit(0, &dev_data->irq_enabled))
        {
            disable_irq(dev_data->irq);
        }
    }

    spin_unlock_irqrestore(&dev_data->lock, flags);

    return (ssize_t)count;
}

/**
 * Poll
 */
static unsigned int fpga_io_poll(struct file *filp, poll_table *wait)
{
    struct fpga_file_data_t *file_data = (struct fpga_file_data_t *)(filp->private_data);
    struct fpga_dev_data_t *dev_data = file_data->dev_data;
    unsigned int mask;

    if (!dev_data->irq)
    {
        return 0;
    }

    mask = POLLOUT | POLLWRNORM;
    poll_wait(filp, &dev_data->wait_queue, wait);

    if (atomic_read(&file_data->event_count) != atomic_read(&dev_data->irq_count))
    {
        mask |= POLLIN | POLLRDNORM;
    }

    return mask;
}

/**
 * Async
 */
static int fpga_io_fasync(int fd, struct file *filp, int mode)
{
    struct fpga_file_data_t *file_data = (struct fpga_file_data_t *)(filp->private_data);
    struct fpga_dev_data_t *dev_data = file_data->dev_data;

    return fasync_helper(fd, filp, mode, &dev_data->async_queue);
}

static const struct file_operations fpga_io_fops =
{
    .owner          = THIS_MODULE,
    .open           = fpga_io_open,
    .release        = fpga_io_release,
    .mmap           = fpga_io_mmap,
    .read           = fpga_io_read,
    .write          = fpga_io_write,
    .poll           = fpga_io_poll,
    .fasync         = fpga_io_fasync
};

/**
 * Register the device for userspace access
 */
static int register_device(struct fpga_dev_data_t *dev_data)
{
    int err = 0;

    if ((err = alloc_chrdev_region(&dev_data->dev, 0, 1, FPGA_DEVICE)))
    {
        return err;
    }

    if (PTR_ERR_OR_ZERO(dev_data->class = class_create(THIS_MODULE, FPGA_DEVICE)))
    {
        return -ENOSYS;
    }

    if (PTR_ERR_OR_ZERO(dev_data->device = device_create(dev_data->class, NULL, dev_data->dev, (void *)dev_data, FPGA_DEVICE)))
    {
        return -ENOSYS;
    }

    cdev_init(&dev_data->cdev, &fpga_io_fops);

    if ((err = cdev_add(&dev_data->cdev, dev_data->dev, 1)))
    {
        return err;
    }

    if ((err = gpio_export_link(dev_data->device, "reset_n", dev_data->reset_n_gpio)))
    {
        return err;
    }

    init_waitqueue_head(&dev_data->wait_queue);
    atomic_set(&dev_data->irq_count, 0);
    set_bit(0, &dev_data->irq_enabled);
    dev_data->irq = gpio_to_irq(dev_data->irq_n_gpio);

    if ((err = request_irq(dev_data->irq, fpga_io_irq_handler, IRQF_TRIGGER_LOW | IRQF_ONESHOT, FPGA_DEVICE, NULL)))
    {
        dev_data->irq = 0;
        pr_err(FPGA_DEVICE ": request_irq error\n");

        return err;
    }

    if ((err = gpio_export_link(dev_data->device, "irq_n", dev_data->irq_n_gpio)))
    {
        return err;
    }

    return 0;
}

/**
 * Cleanup and free resources
 */
static void cleanup(struct fpga_dev_data_t **dev_data)
{
    if (PTR_ERR_OR_ZERO(*dev_data))
    {
        return;
    }

    if ((*dev_data)->irq > 0)
    {
        if (test_bit(0, &((*dev_data)->irq_enabled)))
        {
            disable_irq((*dev_data)->irq);
        }

        free_irq((*dev_data)->irq, NULL);
    }

    if ((*dev_data)->prog_n_gpio)
    {
        gpio_set_value((*dev_data)->prog_n_gpio, 1);
        msleep(20);
        gpio_set_value((*dev_data)->prog_n_gpio, 0);
        msleep(20);
        gpio_set_value((*dev_data)->prog_n_gpio, 1);
        gpio_free((*dev_data)->prog_n_gpio);
    }

    if ((*dev_data)->init_n_gpio)
    {
        gpio_free((*dev_data)->init_n_gpio);
    }

    if ((*dev_data)->done_n_gpio)
    {
        gpio_free((*dev_data)->done_n_gpio);
    }

    if ((*dev_data)->irq_n_gpio)
    {
        gpio_unexport((*dev_data)->irq_n_gpio);
        gpio_free((*dev_data)->irq_n_gpio);
    }

    if ((*dev_data)->reset_n_gpio)
    {
        gpio_unexport((*dev_data)->reset_n_gpio);
        gpio_set_value((*dev_data)->reset_n_gpio, 1);
        gpio_free((*dev_data)->reset_n_gpio);
    }

    if (!PTR_ERR_OR_ZERO((*dev_data)->class))
    {
        device_destroy((*dev_data)->class, (*dev_data)->dev);
        class_destroy((*dev_data)->class);
    }

    if (!PTR_ERR_OR_ZERO((*dev_data)->iomem))
    {
        iounmap((*dev_data)->iomem);
    }

    cdev_del(&((*dev_data)->cdev));
    unregister_chrdev_region((*dev_data)->dev, 1);
    kfree(*dev_data);
    *dev_data = NULL;
}

/**
 * Initialize driver
 */
static int __init xfpga_init(void)
{
    int err = 0;

    pr_info(FPGA_DEVICE ": FPGA bitfile: %s\n", bitfile);

    if (PTR_ERR_OR_ZERO(fpga_dev_data = kzalloc(sizeof(struct fpga_dev_data_t), GFP_KERNEL)))
    {
        pr_err(FPGA_DEVICE ": out of mem\n");
        err = -ENOMEM;
        goto out;
    }

    spin_lock_init(&fpga_dev_data->lock);

    if ((err = init_io(fpga_dev_data)))
    {
        pr_err(FPGA_DEVICE ": I/O init fail\n");
        goto out;
    }

    if ((err = fpga_config(fpga_dev_data, bitfile)))
    {
        pr_err(FPGA_DEVICE ": FPGA config fail\n");
        goto out;
    }

    if ((err = register_device(fpga_dev_data)))
    {
        pr_err(FPGA_DEVICE ": device registration fail\n");
        goto out;
    }

    pr_info(FPGA_DEVICE ": ready\n");

out:

    if (err)
    {
        cleanup(&fpga_dev_data);
    }

    return err;
}

/**
 * Remove driver
 */
static void __exit xfpga_exit(void)
{
    cleanup(&fpga_dev_data);
}

module_init(xfpga_init);
module_exit(xfpga_exit);
