#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/sched/signal.h>
#include "process.h"
void process_list(struct seq_file *m){
	struct task_struct *task;
	rcu_read_lock();
	for_each_process(task){
	seq_printf(m, "%d %s\n", task->pid, task->comm);
	}
	rcu_read_unlock();
}	
