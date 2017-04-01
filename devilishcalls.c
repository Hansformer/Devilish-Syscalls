#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("Dual MIT/GPL");
MODULE_DESCRIPTION("Reassign system calls in a devilish way.");

static int __init loader(void) {
    printk(KERN_INFO "This is where the fun begins");
    return 0;
}

static void __exit reset(void) {
    printk(KERN_IFNO "System call table restored");
}

module_init(loader);
module_exit(reset);
