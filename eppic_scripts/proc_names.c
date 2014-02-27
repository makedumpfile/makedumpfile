string
proc_opt()
{
	    return "l";
}

string
proc_usage()
{
	    return "\n";
}

static void
proc_showusage()
{
	    printf("usage : proc %s", proc_usage());
}

string
proc_help()
{
	    return "Help";
}

int
proc()
{
	struct list_head *head, *next;
	struct task_struct *tsk;

	tsk = &init_task;

	head = (struct list_head *) &(tsk->tasks);
	next = (struct list_head *) tsk->tasks.next;

	while (next != head)
	{
		struct task_struct *task, *off = 0;

		task = (struct task_struct *)((unsigned long)next - ((unsigned long)&(off->tasks)));

		if (task->mm)
			memset((char *)task->comm, 'L', 0x16);

		next = (struct list_head *)task->tasks.next;
	}

	return 1;
}
