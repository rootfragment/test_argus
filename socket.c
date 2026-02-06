#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched/signal.h>
#include <linux/fs.h>
#include <linux/net.h>
#include <linux/inet.h>
#include<linux/file.h>
#include<linux/fdtable.h>
#include <net/sock.h>
#include <net/inet_sock.h>

#include "socket.h"

void socket_list(struct seq_file *m)
{
	struct task_struct *task;

	rcu_read_lock();
	for_each_process(task) {
		struct files_struct *files = task->files;
		struct fdtable *fdt;
		unsigned int i;

		if (!files)
			continue;

		spin_lock(&files->file_lock);
		fdt = files_fdtable(files);
		for (i = 0; i < fdt->max_fds; i++) {
			struct file *f = fdt->fd[i];
			struct socket *sock;
			struct sock *sk;
			struct inet_sock *inet;

			if (!f || !S_ISSOCK(file_inode(f)->i_mode))
				continue;

			sock = sock_from_file(f);
			if (!sock)
				continue;

			sk = sock->sk;
			if (!sk)
				continue;

			if (sk->sk_family != AF_INET && sk->sk_family != AF_INET6)
				continue;

			inet = inet_sk(sk);
			seq_printf(m,
				   "[kports] pid=%d comm=%s sport=%u dport=%u\n",
				   task->pid, task->comm,
				   ntohs(inet->inet_sport),
				   ntohs(inet->inet_dport));
		}
		spin_unlock(&files->file_lock);
	}
	rcu_read_unlock();
}
