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

#define BUF_MAX_SIZE 1024
#define PROC_FILE_NAME "lab2out"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
#define HAVE_PROC_OPS
#endif

static struct proc_dir_entry *out_file;
static char lab2_buffer[BUF_MAX_SIZE];
static size_t lab2_buffer_size = 0;

static ssize_t lab2_read(struct file *file_ptr, char __user *ubuffer, size_t buf_length, loff_t *offset)
{
    pr_info("Proc file %s is being read\n", PROC_FILE_NAME);
    char hui[5] = "hui\n";
    hui[4] = '\0';
    int len = sizeof(hui);
    ssize_t ret = len;

    if (*offset >= len || copy_to_user(ubuffer, hui, len))
    {
        pr_info("Read finish\n");
        ret = 0;
    }
    else
    {
        pr_info("Procfile read succeed %s\n", file_ptr->f_path.dentry->d_name.name);
        *offset += len;
    }
    return ret;
}

static ssize_t lab2_write(struct file *file_ptr, const char __user *ubuffer, size_t buf_length, loff_t *offset)
{
    pr_info("Proc file %s is being written\n", PROC_FILE_NAME);

    lab2_buffer_size = buf_length;
    if (lab2_buffer_size > BUF_MAX_SIZE)
    {
        lab2_buffer_size = BUF_MAX_SIZE;
    }

    if (copy_from_user(lab2_buffer, ubuffer, lab2_buffer_size))
    {
        return -EFAULT;
    }

    pr_info("Proc file wriеe end %s\n", lab2_buffer);
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
    pr_info("Loaded lab2 module\n");
    pr_info("Module can read info to procfs from bpf_redirect_info and dm_dirty_log_type\n");

    out_file = proc_create(PROC_FILE_NAME, 0644, NULL, &proc_file_ops);

    if (out_file == NULL)
    {
        pr_alert("Could not create file for some reason\n");
        return -EIO;
    }
    pr_info("Created file\n");
    return 0;
}

static void __exit lab2_exit(void)
{
    proc_remove(out_file);
    pr_info("Unloaded lab2 module\n");
}

module_init(lab2_init);
module_exit(lab2_exit);
