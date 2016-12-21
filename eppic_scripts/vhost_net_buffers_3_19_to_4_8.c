string
vhost_opt()
{
	    return "l";
}

string
vhost_usage()
{
	    return "\n";
}

static void
vhost_showusage()
{
	    printf("usage : net_ %s", vhost_usage());
}

string
vhost_help()
{
	    return "Help";
}

void
vhost_net(struct vhost_net *net)
{
	int i;

	for (i = 0; i < 2; i++) {
		struct vhost_net_virtqueue *nvq = &net->vqs[i];
		struct vhost_virtqueue *vq = &nvq->vq;
		struct socket *sock = (struct socket *)vq->private_data;
		struct sock *sk = sock->sk;

		struct sk_buff_head *head = &(sk->sk_receive_queue);
		struct sk_buff *next = sk->sk_receive_queue.next;

		while (next != head)
		{
			struct sk_buff *buff = (struct sk_buff *) next;

			if (buff->data_len) {
				memset((char *)buff->data, 'L', buff->data_len);
				memset((char *)&(buff->data_len), 'L', 0x4);
			}

			/*
			 * .next is the first entry.
			 */
			next = (struct sk_buff *)(unsigned long)*buff;
		}

		head = (struct sk_buff_head *)&(sk->sk_write_queue);
		next = (struct sk_buff *)sk->sk_write_queue.next;

		while (next != head)
		{
			struct sk_buff *buff = (struct sk_buff *) next;

			if (buff->data_len) {
				memset((char *)buff->data, 'L', buff->data_len);
				memset((char *)&(buff->data_len), 'L', 0x4);
			}

			/*
			 * .next is the first entry.
			 */
			next = (struct sk_buff *)(unsigned long)*buff;
		}
	}
}

int
vhost()
{
	struct list_head *head, *next;
	struct task_struct *tsk;

	tsk = &init_task;

	head = (struct list_head *) &(tsk->tasks);
	next = (struct list_head *) tsk->tasks.next;

	while (next != head)
	{
		int i;
		struct task_struct *task, *off = 0;

		task = (struct task_struct *)((unsigned long)next - ((unsigned long)&(off->tasks)));

		if (task->files && task->files->fdt) {
			for (i = 0; i < task->files->fdt->max_fds; i++) {
				if (task->files->fdt->fd[i] && task->files->fdt->fd[i]->f_op
					&& task->files->fdt->fd[i]->f_op->open == &vhost_net_open)
					vhost_net((struct vhost_net *)task->files->fdt->fd[i]->private_data);
			}
		}

		next = (struct list_head *)task->tasks.next;
	}

	return 1;
}
