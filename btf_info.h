#ifndef _BTF_INFO_H
#define _BTF_INFO_H
#include <stdint.h>
#include <stdbool.h>

struct ktype_info {
	/********in******/
	char *modname;		// Set to search within the module, in case
				// name conflict of different modules
	char *struct_name;	// Search by struct name
	char *member_name;	// Search by member name
	bool struct_required : 1;
	bool member_required : 1;
	/********out*****/
	uint32_t member_bit_offset;	// member offset in bits
	uint32_t member_bit_sz;	// member width in bits
	uint32_t member_size;	// member size in bytes
	uint32_t struct_size;	// struct size in bytes
	int index;		// -1 if type not found
};

bool check_ktypes_require_modname(char *modname, int *total);
bool register_ktype_section(char *start, char *stop);
bool init_kernel_btf(void);
bool init_module_btf(void);
void cleanup_btf(void);

#define _GEN_NAME_PTR_IMPL(PTR, NAME)		PTR##NAME
#define _GEN_NAME_PTR(PTR, NAME)		_GEN_NAME_PTR_IMPL(PTR, NAME)
#define ___GEN_NAME_2(MOD, S)			_##MOD##_##S
#define ___GEN_NAME_3(MOD, S, M)		_##MOD##_##S##_##M
#define __GEN_NAME_SELECTOR(_1, _2, _3, NAME, ...) NAME
#define _GEN_NAME(...) __GEN_NAME_SELECTOR(__VA_ARGS__, ___GEN_NAME_3, ___GEN_NAME_2)(__VA_ARGS__)

#define _INIT_MOD_STRUCT_MEMBER_RQD(MOD, S, M, R)		\
	struct ktype_info _GEN_NAME(MOD, S, M) = {		\
		#MOD, #S, #M, R, R, 0, 0, 0, 0, -1		\
	};							\
	__attribute__((section(".init_ktypes"), used))		\
	struct ktype_info * _GEN_NAME_PTR(_ptr, _GEN_NAME(MOD, S, M)) = &_GEN_NAME(MOD, S, M)

/*
 * Required types will be checked automatically before extension running.
 * Optinal types should be checked manually at extension runtime.
 */
#define INIT_MOD_STRUCT_MEMBER(MOD, S, M) \
	_INIT_MOD_STRUCT_MEMBER_RQD(MOD, S, M, 1)
#define INIT_OPT_MOD_STRUCT_MEMBER(MOD, S, M) \
	_INIT_MOD_STRUCT_MEMBER_RQD(MOD, S, M, 0)

#define DECLARE_MOD_STRUCT_MEMBER(MOD, S, M) \
	extern struct ktype_info _GEN_NAME(MOD, S, M)

#define GET_MOD_STRUCT_MEMBER_MOFF(MOD, S, M)	(_GEN_NAME(MOD, S, M).member_bit_offset)
#define GET_MOD_STRUCT_MEMBER_MSIZE(MOD, S, M)	(_GEN_NAME(MOD, S, M).member_size)
#define GET_MOD_STRUCT_MEMBER_SSIZE(MOD, S, M)	(_GEN_NAME(MOD, S, M).struct_size)
#define MOD_STRUCT_MEMBER_EXIST(MOD, S, M)	(_GEN_NAME(MOD, S, M).index >= 0)
#define TYPE_EXIST(p)				((p)->index >= 0)


#define _INIT_MOD_STRUCT_RQD(MOD, S, R)				\
	struct ktype_info _GEN_NAME(MOD, S) = {			\
		#MOD, #S, 0, R, 0, 0, 0, 0, 0, -1		\
	};							\
	__attribute__((section(".init_ktypes"), used))		\
	struct ktype_info * _GEN_NAME_PTR(_ptr, _GEN_NAME(MOD, S)) = &_GEN_NAME(MOD, S)

#define INIT_MOD_STRUCT(MOD, S)		_INIT_MOD_STRUCT_RQD(MOD, S, 1)
#define INIT_OPT_MOD_STRUCT(MOD, S)	_INIT_MOD_STRUCT_RQD(MOD, S, 0)

#define DECLARE_MOD_STRUCT(MOD, S)	extern struct ktype_info _GEN_NAME(MOD, S);

#define GET_MOD_STRUCT_SSIZE(MOD, S)	(_GEN_NAME(MOD, S).struct_size)
#define MOD_STRUCT_EXIST(MOD, S)	(_GEN_NAME(MOD, S).index >= 0)

#endif /* _BTF_INFO_H */

