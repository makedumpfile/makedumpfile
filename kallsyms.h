#ifndef _KALLSYMS_H
#define _KALLSYMS_H

#include <stdint.h>
#include <stdbool.h>

struct ksym_info {
	/********in******/
	char *modname;
	char *symname;
	bool sym_required;
	/********out*****/
	uint64_t value;
	int index;	// -1 if sym not found
};

#define INIT_MOD_SYM_RQD(MOD, SYM, R)			\
	struct ksym_info _##MOD##_##SYM = {		\
		#MOD, #SYM, R, 0, -1			\
	};						\
	__attribute__((section(".init_ksyms"), used))	\
	struct ksym_info * _ptr_##MOD##_##SYM = &_##MOD##_##SYM

#define GET_MOD_SYM(MOD, SYM) (_##MOD##_##SYM.value)
#define GET_MOD_SYM_PTR(MOD, SYM) (&_##MOD##_##SYM)
#define MOD_SYM_EXIST(MOD, SYM) (_##MOD##_##SYM.index >= 0)
#define SYM_EXIST(p) ((p)->index >= 0)

/*
 * Required syms will be checked automatically before extension running.
 * Optinal syms should be checked manually at extension runtime.
 */
#define INIT_MOD_SYM(MOD, SYM) INIT_MOD_SYM_RQD(MOD, SYM, 1)
#define INIT_OPT_MOD_SYM(MOD, SYM) INIT_MOD_SYM_RQD(MOD, SYM, 0)

struct section_range {
	char *start;
	char *stop;
};

#define REGISTER_SECTION(T)						\
bool register_##T##_section(char *start, char *stop)			\
{									\
	struct section_range *new_sr;					\
	struct T##_info **p;						\
	bool ret = false;						\
									\
	if (!start || !stop) {						\
		ERRMSG("Invalid section start/stop\n");			\
		goto out;						\
	}								\
									\
	for (p = (struct T##_info **)start;				\
	     p < (struct T##_info **)stop;				\
	     p++) {							\
		if (!add_##T##_modname((*p)->modname))			\
			goto out;					\
	}								\
									\
	new_sr = malloc(sizeof(struct section_range));			\
	if (!new_sr) {							\
		ERRMSG("Not enough memory!\n");				\
		goto out;						\
	}								\
	new_sr->start = start;						\
	new_sr->stop = stop;						\
	if (!add_to_arr((void ***)&sr, &sr_len, &sr_cap, new_sr)) {	\
		free(new_sr);						\
		goto out;						\
	}								\
	ret = true;							\
out:									\
	return ret;							\
}

bool add_to_arr(void ***arr, int *arr_len, int *arr_cap, void *elem);
bool push_uniq_str(void ***arr, int *arr_len, int *arr_cap, char *str);
bool check_ksyms_require_modname(char *modname, int *total);
bool register_ksym_section(char *start, char *stop);
bool read_vmcoreinfo_kallsyms(void);
bool init_kernel_kallsyms(void);
uint64_t next_list(uint64_t list);
bool init_module_kallsyms(void);
void cleanup_kallsyms(void);
#endif /* _KALLSYMS_H */

