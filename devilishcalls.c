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

#include <asm/paravirt.h>	// write/read_cr0
#include <asm/page.h>		// PAGE_OFFSET
#include <asm/unistd.h>		// System call number numbers

#ifndef MODULE_NAME
#define MODULE_NAME "Devilish"
#endif
#define MAX_LEN 256
#define SYMBOLS "/proc/kallsyms"

MODULE_LICENSE("Dual MIT/GPL");

unsigned long original_cr0;
unsigned long *sys_write_address;
unsigned long **sct = NULL;

asmlinkage long (* orig_write) (unsigned int, const char __user *, size_t);

asmlinkage long new_write(unsigned int fd, const char __user *buf, size_t count)
{
	printk(KERN_INFO "Write hook!\n");
	return orig_write(fd, buf, count);
}

static int find_address_sct(void)
{
	unsigned long offset = PAGE_OFFSET;	// Start of kernel RAM

	printk(KERN_INFO "looking for sct address\n");
	while (offset < ULLONG_MAX) {
		sct = (unsigned long **)offset;

		printk(KERN_INFO "offset = %lx\n", offset);
		if (sct[__NR_write] == sys_write_address) {
			return 0;
		}

		offset += sizeof(void *);
	}
	// Couldn't find it
	return -1;
}

static int find_address_write(void)
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
			if ((strstr(ptr, "sys_write") != NULL)) {
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
				sys_write_address = (unsigned long *)
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
	printk(KERN_INFO "Attempting to hook sys_write\n");
	write_cr0(original_cr0 & ~0x10000);		// Swap the ro flag to rw
	orig_write = (void *) sct[__NR_write];		// save for later
	sct[__NR_write] = (long *) new_write;		// assign our own function
	write_cr0(original_cr0);
	return 0;
}

static int unassign_hook(void) {
	printk(KERN_INFO "Removing sys_write hook\n");
	write_cr0(original_cr0 & ~0x10000);
	sct[__NR_write] = (void *) orig_write;
	write_cr0(original_cr0);
	return 0;
}

static int __init loader(void)
{
	original_cr0 = read_cr0();

	printk(KERN_EMERG "Loading %s\n", MODULE_NAME);
	if (find_address_write() < 0)
		return -EIO;
	if (find_address_sct() < 0) {
		printk(KERN_INFO "Failed to retrieve sct\n");
	} else {
		printk(KERN_INFO "System call table found!\n");
		assign_hook(sct);
	}
	printk(KERN_EMERG "Loaded %s successfully\n", MODULE_NAME);
	return 0;
}

static void __exit reset(void)
{
	unassign_hook();
	printk(KERN_INFO "Unloaded %s\n", MODULENAME);
}

module_init(loader);
module_exit(reset);
