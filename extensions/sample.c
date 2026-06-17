#include "../makedumpfile.h"
#include "../btf_info.h"
#include "../kallsyms.h"
#include "../extension.h"

/*
 * Declare the kernel symbols/types that will be used by the extension later.
 * The btf/kallsyms component of makedumpfile will resolve these requested
 * info automatically during extension loading.
 *
 * The symbol/types declared by non-OPT macros as INIT_MOD_XX are must-have for
 * the extension, any missing of these will lead to load-fail of the extension.
 * This is useful to skip one extension as early. E.g. exit the amdgpu mm filtering
 * extension when filtering against a vmcore dumpped by a machine which have
 * no amdgpu hardware.
 *
 * The symbol/types declared by OPT macros as INIT_OPT_MOD_XX are optional,
 * meaning the existence of these are checked during extension runtime. This
 * is useful to cover different kernel versions where some of the data structure
 * are slightly different.
 */
/* All kernel will have init_task and task_struct.mm */
INIT_MOD_SYM(vmlinux, init_task);
INIT_MOD_STRUCT_MEMBER(vmlinux, task_struct, mm);
/*
 * Older kernels use mm_struct.mm_rb,
 * later ones use mm_struct.mm_mt
 */
INIT_OPT_MOD_STRUCT_MEMBER(vmlinux, mm_struct, mm_mt);
INIT_OPT_MOD_STRUCT_MEMBER(vmlinux, mm_struct, mm_rb);

/*
 * Extension callback when makedumpfile is doing page filtering,
 * extension should decide whether the given page should be kept(PG_INCLUDE),
 * discarded(PG_EXCLUDE) or undecided(PG_UNDECID). Here we simply return
 * PG_UNDECID to let every page fallbacks to traditinal page-flags
 * check routine or let other extensions make the decision.
 */
int extension_callback(unsigned long pfn, const void *pcache)
{
	return PG_UNDECID;
}

/* Entry of extension */
void extension_init(void)
{
	MSG("sample.so: The address of init_task is: %lx\n",
		GET_MOD_SYM(vmlinux, init_task));
	MSG("sample.so: The size of task_struct is: %d bytes\n",
		GET_MOD_STRUCT_MEMBER_SSIZE(vmlinux, task_struct, mm));
	MSG("sample.so: The offset of member mm within task_struct is: %d bytes\n",
		GET_MOD_STRUCT_MEMBER_MOFF(vmlinux, task_struct, mm) / 8 );
	MSG("sample.so: The size of member mm within task_struct is: %d bytes\n",
		GET_MOD_STRUCT_MEMBER_MSIZE(vmlinux, task_struct, mm));
	if (MOD_STRUCT_MEMBER_EXIST(vmlinux, mm_struct, mm_mt)) {
		MSG("sample.so: Your kernel is using maple tree in mm_struct\n");
	}
	if (MOD_STRUCT_MEMBER_EXIST(vmlinux, mm_struct, mm_rb)) {
		MSG("sample.so: Your kernel is using rb tree in mm_struct\n");
	}
}

/*
 * This function is called when the extension is unloaded.
 * If desired, perform any cleanups here.
 */
__attribute__((destructor))
void extension_cleanup(void) { }

