#include <linux/dm-dirty-log.h>
#include <linux/filter.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/version.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("luribina");
MODULE_DESCRIPTION("Simple linux module for os lab");
MODULE_VERSION("1.0");

#define BUFSIZE 100
#define proc_file_name "lab2out"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
#define HAVE_PROC_OPS
#endif

static struct proc_dir_entry *out_file;

static ssize_t lab2_read(struct file *file, char __user *ubuf, size_t count, loff_t *ppos)
{
    printk(KERN_INFO "Proc file %s is being read\n", proc_file_name);
    return 0;
}

static ssize_t lab2_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos)
{
    printk(KERN_INFO "Proc file %s is being written\n", proc_file_name);
    return 0;
}

#ifdef HAVE_PROC_OPS
static const struct proc_ops proc_file_ops = {
    .proc_read = lab2_read,
    .proc_write = lab2_write};
#else
static const struct file_operations proc_file_ops = {
    .owner = THIS_MODULE,
    .read = lab2_read,
    .write = lab2_write};
#endif

static int __init lab2_init(void)
{
    printk(KERN_INFO "Loaded lab2 module\n");
    printk(KERN_INFO "Module can read info to procfs from bpf_redirect_info and dm_dirty_log_type\n");

    out_file = proc_create(proc_file_name, 0644, NULL, &proc_file_ops);

    return 0;
}

static void __exit lab2_exit(void)
{
    proc_remove(out_file);
    printk(KERN_INFO "Unloaded lab2 module\n");
}

module_init(lab2_init);
module_exit(lab2_exit);
