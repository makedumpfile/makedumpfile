#include <stdio.h>
#include <stdlib.h>
#include "../makedumpfile.h"
#include "../btf_info.h"
#include "../kallsyms.h"
#include "../extension.h"
#include "../erase_info.h"

INIT_MOD_STRUCT_MEMBER(vmlinux, task_struct, tasks);
INIT_MOD_STRUCT_MEMBER(vmlinux, task_struct, thread_node);
INIT_MOD_STRUCT_MEMBER(vmlinux, task_struct, signal);
INIT_MOD_STRUCT_MEMBER(vmlinux, signal_struct, thread_head);
INIT_MOD_STRUCT_MEMBER(vmlinux, task_struct, comm);
INIT_MOD_SYM(vmlinux, init_task);

#define MOD_MEMBER_OFF(MOD, S, M) \
	GET_MOD_STRUCT_MEMBER_MOFF(MOD, S, M) / 8
#define KERN_MEMBER_OFF(S, M) MOD_MEMBER_OFF(vmlinux, S, M)
#define GET_KERN_STRUCT_MEMBER_MSIZE(S, M) \
	GET_MOD_STRUCT_MEMBER_MSIZE(vmlinux, S, M)
#define GET_KERN_SYM(SYM) GET_MOD_SYM(vmlinux, SYM)

/* task_struct.comm eraser */
static bool erase_task_struct_comm(void)
{
	uint64_t task_list, init_task, comm, signal, thread_head, thread_list;
	uint32_t size;

	init_task = GET_KERN_SYM(init_task);
	size = GET_KERN_STRUCT_MEMBER_MSIZE(task_struct, comm);
	task_list = init_task + KERN_MEMBER_OFF(task_struct, tasks);

	/* Iterate all tasks */
	do {
		thread_list = task_list - KERN_MEMBER_OFF(task_struct, tasks) +
			KERN_MEMBER_OFF(task_struct, thread_node);
		if (!readmem(VADDR, task_list - KERN_MEMBER_OFF(task_struct, tasks) +
			KERN_MEMBER_OFF(task_struct, signal), &signal, sizeof(uint64_t))) {
			ERRMSG("Can't get task_struct member signal!\n");
			goto out;
		}
		thread_head = signal + KERN_MEMBER_OFF(signal_struct, thread_head);

		/* Iterate all threads of the task */
		do {
			comm = thread_list - KERN_MEMBER_OFF(task_struct, thread_node) +
				KERN_MEMBER_OFF(task_struct, comm);

			if (!update_filter_info_raw(comm, 'X', size)) {
				ERRMSG("Failed update filter info!\n");
				goto out;
			}

			thread_list = next_list(thread_list);
		} while (thread_list != thread_head);

		task_list = next_list(task_list);
	} while (task_list != init_task + KERN_MEMBER_OFF(task_struct, tasks));

	return true;
out:
	return false;
}

void extension_init(void)
{
	if (!erase_task_struct_comm()) {
		ERRMSG("erase_sample.so: erase fail!\n");
		goto out;
	}
	MSG("erase_sample.so: erase success!\n");
out:
	return;
}

__attribute__((destructor))
void extension_cleanup(void) { }

