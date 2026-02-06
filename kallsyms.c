#include <linux/kallsyms.h>
#include "kallsyms.h"

static unsigned long kallsyms_modules_list_addr;

struct list_head *get_modules_list(void)
{
	if (!kallsyms_modules_list_addr)
		kallsyms_modules_list_addr = kallsyms_lookup_name("modules");

	return (struct list_head *)kallsyms_modules_list_addr;
}
