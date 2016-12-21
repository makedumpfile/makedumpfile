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
	    printf("usage : vhost %s", vhost_usage());
}

string
vhost_help()
{
	    return "Help";
}

void
vhost_scsi(struct vhost_scsi *vs)
{
	if (vs == NULL)
		return;

	for (i = 0; i < 128; i++) {
		struct vhost_virtqueue *vq = (struct vhost_virtqueue *)vs->vqs[i].vq;

		for (j = 0; j < 1024; j++) {

			if (vq->iov[j].iov_len) {
				memset((char *)vq->iov[j].iov_base, 'L', vq->iov[j].iov_len);
				memset((char *)&(vq->iov[j].iov_len), 'L', 0x8);
			}
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
					&& task->files->fdt->fd[i]->f_op->open == &vhost_scsi_open)
					vhost_scsi((struct vhost_scsi *)task->files->fdt->fd[i]->private_data);
			}
		}


		next = (struct list_head *)task->tasks.next;
	}

	return 1;
}
