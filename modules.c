#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include "modules.h"
#include "kallsyms.h"

void module_list(struct seq_file *m)
{
	struct module *mod;
	struct list_head *modules_list = get_modules_list();

	if (!modules_list)
		return;

	rcu_read_lock();
	list_for_each_entry_rcu(mod, modules_list, list) {
		if (mod->state == MODULE_STATE_LIVE) {
			seq_printf(m, "%s\n", mod->name);
		}
	}
	rcu_read_unlock();
}
