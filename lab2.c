#include <linux/dm-dirty-log.h>
#include <linux/filter.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "util.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("luribina");
MODULE_DESCRIPTION("Simple linux module for os lab");
MODULE_VERSION("1.0");

#define BUF_MIN_SIZE 128

#define PROC_FILE_NAME "lab2out"

#define NO_MODE_MESSAGE "No mode is currently set\n"
#define NO_MODE_LENGTH sizeof(NO_MODE_MESSAGE)

#define ERROR_MESSAGE "Error happened, check kernel logs\n"
#define ERROR_LENGTH sizeof(ERROR_MESSAGE)

#define DM_DIRTY_LOG_MESSAGE "Current dirty log type names in system:\n"
#define BPF_MESSAGE "bpf_redirect_info params:\ntgt_index: %d\nflags: "

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
#define HAVE_PROC_OPS
#endif

static struct proc_dir_entry *out_file;
static char lab2_read_buffer[BUF_MIN_SIZE];
static char lab2_write_buffer[BUF_MIN_SIZE];
static struct list_head * log_head = NULL;
static bool is_ready = false;
static bool is_bpf = false;
static bool is_dm_dirty_log_type = false;

// literally copied from net/core/filter.c:2413
enum oleg
{
    BPF_F_NEIGH = (1ULL << 1),
    BPF_F_PEER = (1ULL << 2),
    BPF_F_NEXTHOP = (1ULL << 3),
};

static struct bpf_redirect_info * get_bpf_redirect_info(void);

static int get_dm_dirty_log_type_head(void);

static ssize_t lab2_read(struct file *file_ptr, char __user *ubuffer, size_t buf_length, loff_t *offset)
{
    int len;
    struct bpf_redirect_info * bpf;
    struct dm_dirty_log_type *log_type;

    pr_info("Proc file %s is being read\n", PROC_FILE_NAME);
    pr_info("Buffer read size %zu\n", buf_length);

    if (*offset > 0) {
        pr_info("is ready %d\n", is_ready);
        pr_info("All done\n");
        return 0;
    }

    if (buf_length < BUF_MIN_SIZE)
    {
        pr_info("Read finish\n");
        pr_info("Buffer not enough size\n");
        return 0;
    }
    
    if (!is_ready) {
        if (copy_to_user(ubuffer, NO_MODE_MESSAGE, NO_MODE_LENGTH)) {
            pr_info("Didnt copy buffer message\n");
            return -EFAULT;
        }
        *offset += NO_MODE_LENGTH;
        return *offset;
    }

    if (is_bpf) {
        pr_info("bpf info is requested\n");
        bpf = get_bpf_redirect_info();
        sprintf(lab2_read_buffer, BPF_MESSAGE, bpf->tgt_index);
        if (bpf->flags == 0) {
            strcat(lab2_read_buffer, "none");
        }

        if (bpf->flags & BPF_F_NEIGH) {
            strcat(lab2_read_buffer, "BPF_F_NEIGH ");
        }

        if (bpf->flags & BPF_F_PEER) {
            strcat(lab2_read_buffer, "BPF_F_PEER ");
        }

        if (bpf->flags & BPF_F_NEXTHOP) {
            strcat(lab2_read_buffer, "BPF_F_NEXTHOP ");
        }

        strcat(lab2_read_buffer, "\n");
    }

    if (is_dm_dirty_log_type) {
        pr_info("dm dirty log type is requested\n");
        if (log_head == NULL) {
            if (copy_to_user(ubuffer, ERROR_MESSAGE, ERROR_LENGTH)) {
                pr_info("Didnt copy log error message %s\n", log_type->name);
                return -EFAULT;
            }
            *offset += ERROR_LENGTH;
            return *offset;
        }
        strcpy(lab2_read_buffer, DM_DIRTY_LOG_MESSAGE);
        list_for_each_entry(log_type, log_head, list)
        {
            if (log_type != NULL) {
                pr_info("Log name %s\n", log_type->name);
                strcat(lab2_read_buffer, log_type->name);
                strcat(lab2_read_buffer, "\n");
            }
        }
    }

    pr_info("info %s\n", lab2_read_buffer);

    is_ready = false;
    is_bpf = false;
    is_dm_dirty_log_type = false;

    len = strlen(lab2_read_buffer) + 1;
    *offset += len;
    if (copy_to_user(ubuffer, lab2_read_buffer, len)) {
        pr_info("Didnt copy buffer message\n");
        return -EFAULT;
    }
    return *offset;
}

static ssize_t lab2_write(struct file *file_ptr, const char __user *ubuffer, size_t buf_length, loff_t *offset)
{
    int r, mode;
    size_t len = buf_length;

    pr_info("Proc file %s is being written\n", PROC_FILE_NAME);
    pr_info("Buffer write size %zu\n", buf_length);

    if (buf_length > BUF_MIN_SIZE - 1) {
        len = BUF_MIN_SIZE - 1;
    }

    if (copy_from_user(lab2_write_buffer, ubuffer, len)) {
        return -EFAULT;
    }

    is_ready = false;

    r = sscanf(lab2_write_buffer, "%d", &mode);
    if (r != 1) {
        pr_info("Got non matching input\n");
        return buf_length;
    }

    if (mode < 0 || mode >=OPTION_COUNT) {
        pr_info("Not supported mode %d\n", mode);
        is_bpf = false;
        is_dm_dirty_log_type = false;
    }

    if (mode == BPF_REDIRECT_INFO) {
        is_ready = true;
        is_bpf = true;
        is_dm_dirty_log_type = false;
    }

    if (mode == DM_DIRTY_LOG_TYPE) {
        is_ready = true;
        is_bpf = false;
        is_dm_dirty_log_type = true;
    }

    if (is_ready) {
        pr_info("Current mode %d\n", mode);
    }

    pr_info("Proc file write end %s\n", lab2_write_buffer);
    return buf_length;
}

#ifdef HAVE_PROC_OPS
static const struct proc_ops proc_file_ops = {
    .proc_read = lab2_read,
    .proc_write = lab2_write
};
#else
static const struct file_operations proc_file_ops = {
    .owner = THIS_MODULE,
    .read = lab2_read,
    .write = lab2_write
};
#endif

static int __init lab2_init(void)
{
    int r;
    pr_info("Loaded lab2 module\n");
    pr_info("Module can read info to procfs from bpf_redirect_info and dm_dirty_log_type\n");

    out_file = proc_create(PROC_FILE_NAME, 0666, NULL, &proc_file_ops);

    if (out_file == NULL) {
        pr_alert("Could not create file for some reason\n");
        return -EIO;
    }

    r = get_dm_dirty_log_type_head();
    if (r) {
        pr_info("Could not obtain dm info\n");
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

static struct bpf_redirect_info * get_bpf_redirect_info(void)
{
    struct bpf_redirect_info * ri = this_cpu_ptr(&bpf_redirect_info);
    return ri;
}

static struct dm_dirty_log_type lab2_log = {
	.name = "lab2log",
	.module = THIS_MODULE,
	.ctr = NULL,
	.dtr = NULL,
	.resume = NULL,
	.get_region_size = NULL,
	.is_clean = NULL,
	.in_sync = NULL,
	.flush = NULL,
	.mark_region = NULL,
	.clear_region = NULL,
	.get_resync_work = NULL,
	.set_region_sync = NULL,
	.get_sync_count = NULL,
	.status = NULL,
};

// possible names for log types based on kernel code
// - core (load dm-log)
// - disk (load dm-log)
// - userspace(probably need to load another module, but im not sure which one)

// We register and unregister useless log_type in order to get 
// list_head _logtypes(see drivers/md/dm-log.c:19 v.5.15.5)
// Later we can use it in list_for_each_entry to iterate 
// over all registered dm_dirty_log_type instances
static int get_dm_dirty_log_type_head(void)
{
    // dm dirty hack
    int r;

    r = dm_dirty_log_type_register(&lab2_log);
    if (r) { return r; }

    log_head = lab2_log.list.prev; // очевидно пиздец, кто такие варики выдает бля

    r = dm_dirty_log_type_unregister(&lab2_log);
    if (r) { return r; }

    return 0;
}
