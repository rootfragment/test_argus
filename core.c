#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include "process.h"
#include "modules.h"
#include "socket.h"

MODULE_LICENSE("GPL");

static struct proc_dir_entry *proc_ps;
static struct proc_dir_entry *proc_mods;
static struct proc_dir_entry *proc_sockets;


static int show_ps(struct seq_file *m, void *v)
{
	process_list(m);
	return 0;
}

static int open_ps(struct inode *inode, struct file *file)
{
	return single_open(file, show_ps, NULL);
}

static const struct file_operations ps_fops = {
	.open = open_ps,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};


static int show_mods(struct seq_file *m, void *v)
{
	module_list(m);
	return 0;
}

static int open_mods(struct inode *inode, struct file *file)
{
	return single_open(file, show_mods, NULL);
}

static const struct file_operations mods_fops = {
	.open = open_mods,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int show_sockets(struct seq_file *m, void *v)
{
	socket_list(m);
	return 0;
}

static int open_sockets(struct inode *inode, struct file *file)
{
	return single_open(file, show_sockets, NULL);
}

static const struct file_operations sockets_fops = {
	.open = open_sockets,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int __init rk_init(void)
{
	pr_info("Rootkit Detector: Initializing.\n");

	proc_ps = proc_create("rk_ps", 0444, NULL, &ps_fops);
	if (!proc_ps) {
		pr_err("Failed to create /proc/rk_ps\n");
		return -ENOMEM;
	}

	proc_mods = proc_create("rk_mods", 0444, NULL, &mods_fops);
	if (!proc_mods) {
		proc_remove(proc_ps); 
		pr_err("Failed to create /proc/rk_mods\n");
		return -ENOMEM;
	}

	proc_sockets = proc_create("rk_sockets", 0444, NULL, &sockets_fops);
	if (!proc_sockets) {
		proc_remove(proc_ps);
		proc_remove(proc_mods);
		pr_err("Failed to create /proc/rk_sockets\n");
		return -ENOMEM;
	}

	pr_info("Rootkit Detector: Proc files created.\n");
	return 0;
}

static void __exit rk_exit(void)
{
	proc_remove(proc_ps);
	proc_remove(proc_mods);
	proc_remove(proc_sockets);
	pr_info("Rootkit Detector: Exiting and cleaning up proc files.\n");
}

module_init(rk_init);
module_exit(rk_exit);
