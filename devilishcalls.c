#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>		// kmalloc()
#include <linux/fs.h>		// file operation functions in kernel mode
#include <linux/uaccess.h>	// userspace memory access functions (get/set_fs())
#include <linux/string.h>	// necessary evil
#include <linux/syscalls.h>	// System calls
#include <linux/types.h>	// ULLONG_MAX
#include <linux/linkage.h>	// asmlinkage
#include <linux/delay.h>

#include <asm/paravirt.h>	// write/read_cr0
#include <asm/page.h>		// PAGE_OFFSET
#include <asm/unistd.h>		// System call numbers

#ifndef MODULE_NAME
#define MODULE_NAME "Devilish"
#endif
#define MAX_LEN 256
#define SYMBOLS "/proc/kallsyms"

MODULE_AUTHOR("Mikael Heino");
MODULE_LICENSE("Dual MIT/GPL");

unsigned long *sys_reboot_address;
unsigned long **sct = NULL;

asmlinkage long (* orig_reboot) (int, int);

asmlinkage long new_reboot(int a0, int a1)
{
	printk(KERN_EMERG "sys_reboot hooked!\n");
	printk(KERN_EMERG "now we wait...\n");
	ssleep(5);
	return orig_shutdown(a0, a1);
}

static int find_address_sct(void)
{
	unsigned long offset = PAGE_OFFSET;	// Start of kernel RAM

	printk(KERN_INFO "sys_reboot_address = %p\n", sys_reboot_address);
	printk(KERN_INFO "looking for sct address\n");
	while (offset < ULLONG_MAX) {
		sct = (unsigned long **)offset;

		if (sct[__NR_reboot] == sys_reboot_address) {
			printk(KERN_INFO "found sct[__NR_reboot]");
			return 0;
		}

		offset += sizeof(void *);
	}
	// Couldn't find it
	return -1;
}

static int find_address_reboot(void)
{
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
	while(vfs_read(fp, ptr+i, 1, &fp->f_pos) == 1) {
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
				// Separate the address field from the string
				strncpy(tmp, strsep(&ptr, " "), MAX_LEN);
				sys_shutdown_address = (unsigned long *)
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
	write_cr0(read_cr0() & (~ 0x10000));		// Swap the ro flag to rw
	orig_reboot = (void *) sct[__NR_reboot];	// save for later
	sct[__NR_reboot] = (long *) new_reboot;	// assign our own function
	write_cr0(read_cr0() | 0x10000);
	return 0;
}

static int unassign_hook(void) {
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
