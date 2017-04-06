#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/slab.h>     // kmalloc()
#include <linux/fs.h>       // file operation functions in kernel mode
#include <asm/uaccess.h>    // userspace memory access functions (get/set_fs())

#define MODULENAME "Devilish"
#define MAX_LEN 256
#define PROC_VERSION "/proc/version"

MODULE_LICENSE("Dual MIT/GPL");

char* get_kernel_version(char* buf) {
    // Calling 'uname -r' from the kernel doesn't quite worki
    struct file* fp = NULL;
    char* kernel_version;
    mm_segment_t fs_state;

    fs_state = get_fs();
    set_fs(KERNEL_DS);

    fp = filp_open(PROC_VERSION, O_RDONLY, 0);
    if (IS_ERR(fp) || (fp == NULL)) {
        printk(KERN_EMERG "Unable to open %s\n", PROC_VERSION);
        return NULL;
    }

    // Guarantee that the buffer is zeroed
    memset(buf, 0, MAX_LEN);
    vfs_read(fp, buf, MAX_LEN, &(fp->f_pos));

    filp_close(fp, 0);
    set_fs(fs_state);

    return kernel_version;
}

static int __init loader(void) {
    char* kernel_version;

    printk(KERN_EMERG "Loaded %s\n", MODULENAME);

    kernel_version = kmalloc(MAX_LEN, GFP_KERNEL);
    kernel_version = get_kernel_version(kernel_version);

    printk(KERN_INFO "Kernel version: %s\n", kernel_version);

    return 0;
}

static void __exit reset(void) {
    printk(KERN_INFO "Unloaded %s\n", MODULENAME);
}

module_init(loader);
module_exit(reset);
