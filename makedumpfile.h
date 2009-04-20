/*
 * makedumpfile.h
 *
 * Copyright (C) 2006, 2007, 2008, 2009  NEC Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <gelf.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <zlib.h>
#include <elfutils/libdw.h>
#include <libelf.h>
#include <dwarf.h>
#include <byteswap.h>
#include <getopt.h>
#include "diskdump_mod.h"

/*
 * Result of command
 */
#define COMPLETED	(0)
#define FAILED		(1)
#define WRONG_RELEASE	(2)	/* utsname.release does not match. */
#define ANALYSIS_FAILED	(3)	/* detected illegal page descriptor. */
#define OUTPUT_FAILED	(4)	/* detected an output error. */

/*
 * Type of memory management
 */
enum {
	NOT_FOUND_MEMTYPE,
	SPARSEMEM,
	SPARSEMEM_EX,
	DISCONTIGMEM,
	FLATMEM
};

/*
 * Page flags
 *
 * The flag values of page.flags have been defined by enum since linux-2.6.26.
 * The following values are for linux-2.6.25 or former.
 */
#define PG_lru_ORIGINAL	 	(5)
#define PG_private_ORIGINAL	(11)	/* Has something at ->private */
#define PG_swapcache_ORIGINAL	(15)	/* Swap page: swp_entry_t in private */

#define PAGE_MAPPING_ANON	(1)

#define LSEEKED_BITMAP	(1)
#define LSEEKED_PDESC	(2)
#define LSEEKED_PDATA	(3)

/*
 * Memory flags
 */
#define MEMORY_PAGETABLE_4L	(1 << 0)
#define MEMORY_PAGETABLE_3L	(1 << 1)
#define MEMORY_X86_PAE		(1 << 2)
#define MEMORY_XEN		(1 << 3)

/*
 * Type of address
 */
enum {
	VADDR,
	PADDR,
	VADDR_XEN,
	MADDR_XEN
};


static inline int
test_bit(int nr, unsigned long addr)
{
	int mask;

	mask = 1 << (nr & 0x1f);
	return ((mask & addr) != 0);
}

#define isLRU(flags)		test_bit(NUMBER(PG_lru), flags)
#define isPrivate(flags)	test_bit(NUMBER(PG_private), flags)
#define isSwapCache(flags)	test_bit(NUMBER(PG_swapcache), flags)

static inline int
isAnon(unsigned long mapping)
{
	return ((unsigned long)mapping & PAGE_MAPPING_ANON) != 0;
}

#define PAGESIZE()		(info->page_size)
#define PAGESHIFT()		(info->page_shift)
#define PAGEOFFSET(X)		(((unsigned long)(X)) & (PAGESIZE() - 1))
#define PAGEBASE(X)		(((unsigned long)(X)) & ~(PAGESIZE() - 1))
#define _2MB_PAGE_MASK		(~((2*1048576)-1))

/*
 * for SPARSEMEM
 */
#define SECTION_SIZE_BITS()	(info->section_size_bits)
#define MAX_PHYSMEM_BITS()	(info->max_physmem_bits)
#define PFN_SECTION_SHIFT()	(SECTION_SIZE_BITS() - PAGESHIFT())
#define PAGES_PER_SECTION()	(1UL << PFN_SECTION_SHIFT())
#define _SECTIONS_PER_ROOT()	(1)
#define _SECTIONS_PER_ROOT_EXTREME()	(info->page_size / SIZE(mem_section))
#define SECTIONS_PER_ROOT()	(info->sections_per_root)
#define SECTION_ROOT_MASK()	(SECTIONS_PER_ROOT() - 1)
#define SECTION_NR_TO_ROOT(sec)	((sec) / SECTIONS_PER_ROOT())
#define SECTION_MAP_LAST_BIT	(1UL<<2)
#define SECTION_MAP_MASK	(~(SECTION_MAP_LAST_BIT-1))
#define NR_SECTION_ROOTS()	divideup(num_section, SECTIONS_PER_ROOT())
#define SECTION_NR_TO_PFN(sec)	((sec) << PFN_SECTION_SHIFT())
#define SECTIONS_SHIFT()	(MAX_PHYSMEM_BITS() - SECTION_SIZE_BITS())
#define NR_MEM_SECTIONS()	(1UL << SECTIONS_SHIFT())

/*
 * Incorrect address
 */
#define NOT_MEMMAP_ADDR	(0x0)
#define NOT_KV_ADDR	(0x0)
#define NOT_PADDR	(ULONGLONG_MAX)

/*
 * Dump Level
 */
#define MIN_DUMP_LEVEL		(0)
#define MAX_DUMP_LEVEL		(31)
#define NUM_ARRAY_DUMP_LEVEL	(MAX_DUMP_LEVEL + 1) /* enough to allocate
							all the dump_level */
#define DL_EXCLUDE_ZERO		(0x001) /* Exclude Pages filled with Zeros */
#define DL_EXCLUDE_CACHE	(0x002) /* Exclude Cache Pages
				           without Private Pages */
#define DL_EXCLUDE_CACHE_PRI	(0x004) /* Exclude Cache Pages
				           with Private Pages */
#define DL_EXCLUDE_USER_DATA	(0x008) /* Exclude UserProcessData Pages */
#define DL_EXCLUDE_FREE		(0x010)	/* Exclude Free Pages */

/*
 * Message Level
 */
#define MIN_MSG_LEVEL		(0)
#define MAX_MSG_LEVEL		(31)
#define DEFAULT_MSG_LEVEL	(7)	/* Print the progress indicator, the
					   common message, the error message */
#define ML_PRINT_PROGRESS	(0x001) /* Print the progress indicator */
#define ML_PRINT_COMMON_MSG	(0x002)	/* Print the common message */
#define ML_PRINT_ERROR_MSG	(0x004)	/* Print the error message */
#define ML_PRINT_DEBUG_MSG	(0x008) /* Print the debugging message */
#define ML_PRINT_REPORT_MSG	(0x010) /* Print the report message */
extern int message_level;

#define MSG(x...) \
do { \
	if (message_level & ML_PRINT_COMMON_MSG) { \
		if (info->flag_flatten) \
			fprintf(stderr, x); \
		else \
			fprintf(stdout, x); \
	} \
} while (0)

#define ERRMSG(x...) \
do { \
	if (message_level & ML_PRINT_ERROR_MSG) { \
		fprintf(stderr, __FUNCTION__); \
		fprintf(stderr, ": "); \
		fprintf(stderr, x); \
	} \
} while (0)

#define PROGRESS_MSG(x...) \
do { \
	if (message_level & ML_PRINT_PROGRESS) { \
		fprintf(stderr, x); \
	} \
} while (0)

#define DEBUG_MSG(x...) \
do { \
	if (message_level & ML_PRINT_DEBUG_MSG) { \
		if (info->flag_flatten) \
			fprintf(stderr, x); \
		else \
			fprintf(stdout, x); \
	} \
} while (0)

#define REPORT_MSG(x...) \
do { \
	if (message_level & ML_PRINT_REPORT_MSG) { \
		if (info->flag_flatten) \
			fprintf(stderr, x); \
		else \
			fprintf(stdout, x); \
	} \
} while (0)


/*
 * For parse_line()
 */
#define NULLCHAR	('\0')
#define MAXARGS		(100)   /* max number of arguments to one function */
#define LASTCHAR(s)	(s[strlen(s)-1])

#define BITPERBYTE		(8)
#define PGMM_CACHED		(512)
#define PFN_EXCLUDED		(256)
#define BUFSIZE_FGETS		(1500)
#define BUFSIZE_BITMAP		(4096)
#define PFN_BUFBITMAP		(BITPERBYTE*BUFSIZE_BITMAP)
#define FILENAME_BITMAP		"/tmp/kdump_bitmapXXXXXX"
#define FILENAME_STDOUT		"STDOUT"

/*
 * Minimam vmcore has 2 ProgramHeaderTables(PT_NOTE and PT_LOAD).
 */
#define MIN_ELF32_HEADER_SIZE \
	sizeof(Elf32_Ehdr)+sizeof(Elf32_Phdr)+sizeof(Elf32_Phdr)
#define MIN_ELF64_HEADER_SIZE \
	sizeof(Elf64_Ehdr)+sizeof(Elf64_Phdr)+sizeof(Elf64_Phdr)
#define MIN_ELF_HEADER_SIZE \
	MAX(MIN_ELF32_HEADER_SIZE, MIN_ELF64_HEADER_SIZE)
#define STRNEQ(A, B)	(A && B && \
	(strncmp((char *)(A), (char *)(B), strlen((char *)(B))) == 0))

#define UINT(ADDR)	*((unsigned int *)(ADDR))
#define ULONG(ADDR)	*((unsigned long *)(ADDR))

/*
 * for symbol
 */
#define NOT_FOUND_SYMBOL	(0)
#define INVALID_SYMBOL_DATA	(ULONG_MAX)
#define SYMBOL(X)		(symbol_table.X)
#define SYMBOL_INIT(symbol, str_symbol) \
do { \
	SYMBOL(symbol) = get_symbol_addr(str_symbol); \
} while (0)
#define SYMBOL_INIT_NEXT(symbol, str_symbol) \
do { \
	SYMBOL(symbol) = get_next_symbol_addr(str_symbol); \
} while (0)
#define WRITE_SYMBOL(str_symbol, symbol) \
do { \
	if (SYMBOL(symbol) != NOT_FOUND_SYMBOL) { \
		fprintf(info->file_vmcoreinfo, "%s%llx\n", \
		    STR_SYMBOL(str_symbol), SYMBOL(symbol)); \
	} \
} while (0)
#define READ_SYMBOL(str_symbol, symbol) \
do { \
	if (SYMBOL(symbol) == NOT_FOUND_SYMBOL) { \
		SYMBOL(symbol) = read_vmcoreinfo_symbol(STR_SYMBOL(str_symbol)); \
		if (SYMBOL(symbol) == INVALID_SYMBOL_DATA) \
			return FALSE; \
	} \
} while (0)

/*
 * for structure
 */
#define NOT_FOUND_LONG_VALUE	(-1)
#define NOT_FOUND_STRUCTURE	(NOT_FOUND_LONG_VALUE)
#define FAILED_DWARFINFO	(-2)
#define INVALID_STRUCTURE_DATA	(-3)
#define FOUND_ARRAY_TYPE	(LONG_MAX - 1)

#define SIZE(X)			(size_table.X)
#define OFFSET(X)		(offset_table.X)
#define ARRAY_LENGTH(X)		(array_table.X)
#define SIZE_INIT(X, Y) \
do { \
	if ((SIZE(X) = get_structure_size(Y, 0)) == FAILED_DWARFINFO) \
		return FALSE; \
} while (0)
#define TYPEDEF_SIZE_INIT(X, Y) \
do { \
	if ((SIZE(X) = get_structure_size(Y, 1)) == FAILED_DWARFINFO) \
		return FALSE; \
} while (0)
#define OFFSET_INIT(X, Y, Z) \
do { \
	if ((OFFSET(X) = get_member_offset(Y, Z, DWARF_INFO_GET_MEMBER_OFFSET)) \
	     == FAILED_DWARFINFO) \
		return FALSE; \
} while (0)
#define OFFSET_IN_UNION_INIT(X, Y, Z) \
do { \
	if ((OFFSET(X) = get_member_offset(Y, Z, DWARF_INFO_GET_MEMBER_OFFSET_IN_UNION)) \
	     == FAILED_DWARFINFO) \
		return FALSE; \
} while (0)
#define SYMBOL_ARRAY_LENGTH_INIT(X, Y) \
do { \
	if ((ARRAY_LENGTH(X) = get_array_length(Y, NULL, DWARF_INFO_GET_SYMBOL_ARRAY_LENGTH)) == FAILED_DWARFINFO) \
		return FALSE; \
} while (0)
#define SYMBOL_ARRAY_TYPE_INIT(X, Y) \
do { \
	if ((ARRAY_LENGTH(X) = get_array_length(Y, NULL, DWARF_INFO_CHECK_SYMBOL_ARRAY_TYPE)) == FAILED_DWARFINFO) \
		return FALSE; \
} while (0)
#define MEMBER_ARRAY_LENGTH_INIT(X, Y, Z) \
do { \
	if ((ARRAY_LENGTH(X) = get_array_length(Y, Z, DWARF_INFO_GET_MEMBER_ARRAY_LENGTH)) == FAILED_DWARFINFO) \
		return FALSE; \
} while (0)

#define WRITE_STRUCTURE_SIZE(str_structure, structure) \
do { \
	if (SIZE(structure) != NOT_FOUND_STRUCTURE) { \
		fprintf(info->file_vmcoreinfo, "%s%ld\n", \
		    STR_SIZE(str_structure), SIZE(structure)); \
	} \
} while (0)
#define WRITE_MEMBER_OFFSET(str_member, member) \
do { \
	if (OFFSET(member) != NOT_FOUND_STRUCTURE) { \
		fprintf(info->file_vmcoreinfo, "%s%ld\n", \
		    STR_OFFSET(str_member), OFFSET(member)); \
	} \
} while (0)
#define WRITE_ARRAY_LENGTH(str_array, array) \
do { \
	if (ARRAY_LENGTH(array) != NOT_FOUND_STRUCTURE) { \
		fprintf(info->file_vmcoreinfo, "%s%ld\n", \
		    STR_LENGTH(str_array), ARRAY_LENGTH(array)); \
	} \
} while (0)
#define READ_STRUCTURE_SIZE(str_structure, structure) \
do { \
	if (SIZE(structure) == NOT_FOUND_STRUCTURE) { \
		SIZE(structure) = read_vmcoreinfo_long(STR_SIZE(str_structure)); \
		if (SIZE(structure) == INVALID_STRUCTURE_DATA) \
			return FALSE; \
	} \
} while (0)
#define READ_MEMBER_OFFSET(str_member, member) \
do { \
	if (OFFSET(member) == NOT_FOUND_STRUCTURE) { \
		OFFSET(member) = read_vmcoreinfo_long(STR_OFFSET(str_member)); \
		if (OFFSET(member) == INVALID_STRUCTURE_DATA) \
			return FALSE; \
	} \
} while (0)
#define READ_ARRAY_LENGTH(str_array, array) \
do { \
	if (ARRAY_LENGTH(array) == NOT_FOUND_STRUCTURE) { \
		ARRAY_LENGTH(array) = read_vmcoreinfo_long(STR_LENGTH(str_array)); \
		if (ARRAY_LENGTH(array) == INVALID_STRUCTURE_DATA) \
			return FALSE; \
	} \
} while (0)

/*
 * for number
 */
#define NOT_FOUND_NUMBER	(NOT_FOUND_LONG_VALUE)
#define NUMBER(X)		(number_table.X)

#define ENUM_NUMBER_INIT(number, str_number)	\
do {\
	NUMBER(number) = get_enum_number(str_number); \
	if (NUMBER(number) == FAILED_DWARFINFO) \
		return FALSE; \
} while (0)
#define WRITE_NUMBER(str_number, number) \
do { \
	if (NUMBER(number) != NOT_FOUND_NUMBER) { \
		fprintf(info->file_vmcoreinfo, "%s%ld\n", \
		    STR_NUMBER(str_number), NUMBER(number)); \
	} \
} while (0)
#define READ_NUMBER(str_number, number) \
do { \
	if (NUMBER(number) == NOT_FOUND_NUMBER) { \
		NUMBER(number) = read_vmcoreinfo_long(STR_NUMBER(str_number)); \
		if (NUMBER(number) == INVALID_STRUCTURE_DATA) \
			return FALSE; \
	} \
} while (0)

/*
 * for source file name
 */
#define SRCFILE(X)		(srcfile_table.X)
#define	TYPEDEF_SRCFILE_INIT(decl_name, str_decl_name) \
do { \
	get_source_filename(str_decl_name, SRCFILE(decl_name), DWARF_INFO_GET_TYPEDEF_SRCNAME); \
} while (0)

#define WRITE_SRCFILE(str_decl_name, decl_name) \
do { \
	if (strlen(SRCFILE(decl_name))) { \
		fprintf(info->file_vmcoreinfo, "%s%s\n", \
		    STR_SRCFILE(str_decl_name), SRCFILE(decl_name)); \
	} \
} while (0)

#define READ_SRCFILE(str_decl_name, decl_name) \
do { \
	if (strlen(SRCFILE(decl_name)) == 0) { \
		if (!read_vmcoreinfo_string(STR_SRCFILE(str_decl_name), SRCFILE(decl_name))) \
			return FALSE; \
	} \
} while (0)

/*
 * Macro for getting splitting info.
 */
#define SPLITTING_DUMPFILE(i)	info->splitting_info[i].name_dumpfile
#define SPLITTING_FD_BITMAP(i)	info->splitting_info[i].fd_bitmap
#define SPLITTING_START_PFN(i)	info->splitting_info[i].start_pfn
#define SPLITTING_END_PFN(i)	info->splitting_info[i].end_pfn

/*
 * kernel version
 *
 * NOTE: the format of kernel_version is as follows
 *   8 bits major version
 *   8 bits minor version
 *  16 bits release
 * so version 2.6.18 would be encoded as 0x02060012
 * These macros will let us decode that easier
 */
#define KVER_MAJ_SHIFT 24
#define KVER_MIN_SHIFT 16
#define KERNEL_VERSION(x,y,z) (((x) << KVER_MAJ_SHIFT) | ((y) << KVER_MIN_SHIFT) | (z))
#define OLDEST_VERSION		(0x0206000f)	/* linux-2.6.15 */
#define LATEST_VERSION		(0x0206001d)	/* linux-2.6.29 */
#define VERSION_LINUX_2_6_26	(0x0206001a)	/* linux-2.6.26 */
#define VERSION_LINUX_2_6_27	(0x0206001b)	/* linux-2.6.27 */

/*
 * vmcoreinfo in /proc/vmcore
 */
#define VMCOREINFO_BYTES		(4096)
#define VMCOREINFO_NOTE_NAME		"VMCOREINFO"
#define VMCOREINFO_NOTE_NAME_BYTES	(sizeof(VMCOREINFO_NOTE_NAME))
#define FILENAME_VMCOREINFO		"/tmp/vmcoreinfoXXXXXX"
#define VMCOREINFO_XEN_NOTE_NAME	"VMCOREINFO_XEN"
#define VMCOREINFO_XEN_NOTE_NAME_BYTES	(sizeof(VMCOREINFO_XEN_NOTE_NAME))

/*
 * field name of vmcoreinfo file
 */
#define STR_OSRELEASE		"OSRELEASE="
#define STR_PAGESIZE		"PAGESIZE="
#define STR_CRASHTIME		"CRASHTIME="
#define STR_SYMBOL(X)		"SYMBOL("X")="
#define STR_SIZE(X)		"SIZE("X")="
#define STR_OFFSET(X)		"OFFSET("X")="
#define STR_LENGTH(X)		"LENGTH("X")="
#define STR_NUMBER(X)		"NUMBER("X")="
#define STR_SRCFILE(X)		"SRCFILE("X")="
#define STR_CONFIG_X86_PAE	"CONFIG_X86_PAE=y"
#define STR_CONFIG_PGTABLE_4	"CONFIG_PGTABLE_4=y"
#define STR_CONFIG_PGTABLE_3	"CONFIG_PGTABLE_3=y"

/*
 * common value
 */
#define TRUE		(1)
#define FALSE		(0)
#define NOSPACE		(-1)    /* code of write-error due to nospace */
#define MAX(a,b)	((a) > (b) ? (a) : (b))
#define MIN(a,b)	((a) < (b) ? (a) : (b))
#define LONG_MAX	((long)(~0UL>>1))
#define ULONG_MAX	(~0UL)
#define ULONGLONG_MAX	(~0ULL)
#define DEFAULT_ORDER	(4)
#define TIMEOUT_STDIN	(600)
#define SIZE_BUF_STDIN	(4096)
#define ELF32		(1)
#define ELF64		(2)
#define STRLEN_OSRELEASE (65)	/* same length as diskdump.h */

#define XEN_ELFNOTE_CRASH_INFO	(0x1000001)
#define SIZE_XEN_CRASH_INFO_V2	(sizeof(unsigned long) * 10)

/*
 * The value of dependence on machine
 */
#define PAGE_OFFSET		(info->page_offset)

#ifdef __x86__
#define __PAGE_OFFSET		(0xc0000000)
#define __VMALLOC_RESERVE       (128 << 20)
#define MAXMEM                  (-PAGE_OFFSET-__VMALLOC_RESERVE)
#define KVBASE_MASK		(0x7fffff)
#define KVBASE			(SYMBOL(_stext) & ~KVBASE_MASK)
#define _SECTION_SIZE_BITS	(26)
#define _SECTION_SIZE_BITS_PAE_ORIG	(30)
#define _SECTION_SIZE_BITS_PAE_2_6_26	(29)
#define _MAX_PHYSMEM_BITS	(32)
#define _MAX_PHYSMEM_BITS_PAE	(36)

#define PGDIR_SHIFT_3LEVEL	(30)
#define PTRS_PER_PTE_3LEVEL	(512)
#define PTRS_PER_PGD_3LEVEL	(4)
#define PMD_SHIFT		(21)  /* only used by PAE translators */
#define PTRS_PER_PMD		(512) /* only used by PAE translators */
#define PTE_SHIFT		(12)  /* only used by PAE translators */
#define PTRS_PER_PTE		(512) /* only used by PAE translators */

#define pgd_index_PAE(address)  (((address) >> PGDIR_SHIFT_3LEVEL) & (PTRS_PER_PGD_3LEVEL - 1))
#define pmd_index(address)  (((address) >> PMD_SHIFT) & (PTRS_PER_PMD - 1))
#define pte_index(address)  (((address) >> PTE_SHIFT) & (PTRS_PER_PTE - 1))

#define _PAGE_PRESENT		(0x001)
#define _PAGE_PSE		(0x080)

#define ENTRY_MASK		(~0x8000000000000fffULL)

#endif /* x86 */

#ifdef __x86_64__
#define __PAGE_OFFSET_ORIG	(0xffff810000000000) /* linux-2.6.26, or former */
#define __PAGE_OFFSET_2_6_27	(0xffff880000000000) /* linux-2.6.27, or later */
#define VMALLOC_START		(0xffffc20000000000)
#define VMALLOC_END		(0xffffe1ffffffffff)
#define VMEMMAP_START		(0xffffe20000000000)
#define VMEMMAP_END		(0xffffe2ffffffffff)

#define __START_KERNEL_map	(0xffffffff80000000)
#define MODULES_VADDR		(0xffffffff88000000)
#define MODULES_END		(0xfffffffffff00000)
#define KVBASE			PAGE_OFFSET
#define _SECTION_SIZE_BITS	(27)
#define _MAX_PHYSMEM_BITS_ORIG		(40)
#define _MAX_PHYSMEM_BITS_2_6_26	(44)

/*
 * 4 Levels paging
 */
#define PML4_SHIFT		(39)
#define PTRS_PER_PML4		(512)
#define PGDIR_SHIFT		(30)
#define PTRS_PER_PGD		(512)
#define PMD_SHIFT		(21)
#define PTRS_PER_PMD		(512)
#define PTRS_PER_PTE		(512)
#define PTE_SHIFT		(12)

#define pml4_index(address) (((address) >> PML4_SHIFT) & (PTRS_PER_PML4 - 1))
#define pgd_index(address)  (((address) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))
#define pmd_index(address)  (((address) >> PMD_SHIFT) & (PTRS_PER_PMD - 1))
#define pte_index(address)  (((address) >> PTE_SHIFT) & (PTRS_PER_PTE - 1))

#define _PAGE_PRESENT		(0x001)
#define _PAGE_PSE		(0x080)    /* 2MB page */

#define __PHYSICAL_MASK_SHIFT	(40)
#define __PHYSICAL_MASK		((1UL << __PHYSICAL_MASK_SHIFT) - 1)
#define PHYSICAL_PAGE_MASK	(~(PAGESIZE()-1) & (__PHYSICAL_MASK << PAGESHIFT()))

#endif /* x86_64 */

#ifdef __powerpc__
#define __PAGE_OFFSET		(0xc000000000000000)
#define KERNELBASE		PAGE_OFFSET
#define VMALLOCBASE     	(0xD000000000000000)
#define KVBASE			(SYMBOL(_stext))
#define _SECTION_SIZE_BITS	(24)
#define _MAX_PHYSMEM_BITS	(44)
#endif

#ifdef __ia64__ /* ia64 */
#define REGION_SHIFT		(61)

#define KERNEL_CACHED_REGION	(7)
#define KERNEL_UNCACHED_REGION	(6)
#define KERNEL_VMALLOC_REGION	(5)
#define USER_STACK_REGION	(4)
#define USER_DATA_REGION	(3)
#define USER_TEXT_REGION	(2)
#define USER_SHMEM_REGION	(1)
#define USER_IA32_EMUL_REGION	(0)

#define KERNEL_CACHED_BASE	((unsigned long)KERNEL_CACHED_REGION << REGION_SHIFT)
#define KERNEL_UNCACHED_BASE	((unsigned long)KERNEL_UNCACHED_REGION << REGION_SHIFT)
#define KERNEL_VMALLOC_BASE	((unsigned long)KERNEL_VMALLOC_REGION << REGION_SHIFT)

#define KVBASE			KERNEL_VMALLOC_BASE
#define _PAGE_SIZE_64M		(26)
#define KERNEL_TR_PAGE_SIZE	(1 << _PAGE_SIZE_64M)
#define KERNEL_TR_PAGE_MASK	(~(KERNEL_TR_PAGE_SIZE - 1))
#define DEFAULT_PHYS_START	(KERNEL_TR_PAGE_SIZE * 1)
#define _SECTION_SIZE_BITS	(30)
#define _MAX_PHYSMEM_BITS	(50)

/*
 * 3 Levels paging
 */
#define _PAGE_PPN_MASK		(((1UL << _MAX_PHYSMEM_BITS) - 1) & ~0xfffUL)
#define PTRS_PER_PTD_SHIFT	(PAGESHIFT() - 3)

#define PMD_SHIFT		(PAGESHIFT() + PTRS_PER_PTD_SHIFT)
#define PGDIR_SHIFT_3L		(PMD_SHIFT   + PTRS_PER_PTD_SHIFT)

#define MASK_POFFSET	((1UL << PAGESHIFT()) - 1)
#define MASK_PTE	((1UL << PMD_SHIFT) - 1) &~((1UL << PAGESHIFT()) - 1)
#define MASK_PMD	((1UL << PGDIR_SHIFT_3L) - 1) &~((1UL << PMD_SHIFT) - 1)
#define MASK_PGD_3L	((1UL << REGION_SHIFT) - 1) & (~((1UL << PGDIR_SHIFT_3L) - 1))

/*
 * 4 Levels paging
 */
#define PUD_SHIFT		(PMD_SHIFT + PTRS_PER_PTD_SHIFT)
#define PGDIR_SHIFT_4L		(PUD_SHIFT + PTRS_PER_PTD_SHIFT)

#define MASK_PUD   	((1UL << REGION_SHIFT) - 1) & (~((1UL << PUD_SHIFT) - 1))
#define MASK_PGD_4L	((1UL << REGION_SHIFT) - 1) & (~((1UL << PGDIR_SHIFT_4L) - 1))

/*
 * Key for distinguishing PGTABLE_3L or PGTABLE_4L.
 */
#define STR_PUD_T_3L	"include/asm-generic/pgtable-nopud.h"
#define STR_PUD_T_4L	"include/asm/page.h"

#endif          /* ia64 */

/*
 * The function of dependence on machine
 */
#ifdef __x86__
int get_machdep_info_x86(void);
int get_versiondep_info_x86(void);
unsigned long long vaddr_to_paddr_x86(unsigned long vaddr);
#define get_phys_base()		TRUE
#define get_machdep_info()	get_machdep_info_x86()
#define get_versiondep_info()	get_versiondep_info_x86()
#define vaddr_to_paddr(X)	vaddr_to_paddr_x86(X)
#endif /* x86 */

#ifdef __x86_64__
int get_phys_base_x86_64(void);
int get_machdep_info_x86_64(void);
int get_versiondep_info_x86_64(void);
unsigned long long vaddr_to_paddr_x86_64(unsigned long vaddr);
#define get_phys_base()		get_phys_base_x86_64()
#define get_machdep_info()	get_machdep_info_x86_64()
#define get_versiondep_info()	get_versiondep_info_x86_64()
#define vaddr_to_paddr(X)	vaddr_to_paddr_x86_64(X)
#endif /* x86_64 */

#ifdef __powerpc__ /* powerpc */
int get_machdep_info_ppc64(void);
#define get_phys_base()		TRUE
#define get_machdep_info()	get_machdep_info_ppc64()
#define get_versiondep_info()	TRUE
#define vaddr_to_paddr(X)	vaddr_to_paddr_general(X)
#endif          /* powerpc */

#ifdef __ia64__ /* ia64 */
int get_phys_base_ia64(void);
int get_machdep_info_ia64(void);
unsigned long long vaddr_to_paddr_ia64(unsigned long vaddr);
#define get_machdep_info()	get_machdep_info_ia64()
#define get_phys_base()		get_phys_base_ia64()
#define get_versiondep_info()	TRUE
#define vaddr_to_paddr(X)	vaddr_to_paddr_ia64(X)
#define VADDR_REGION(X)		(((unsigned long)(X)) >> REGION_SHIFT)
#endif          /* ia64 */

struct pt_load_segment {
	off_t			file_offset;
	unsigned long long	phys_start;
	unsigned long long	phys_end;
	unsigned long long	virt_start;
	unsigned long long	virt_end;
};

struct mem_map_data {
	unsigned long long	pfn_start;
	unsigned long long	pfn_end;
	unsigned long	mem_map;
};

struct dump_bitmap {
	int		fd;
	int		no_block;
	char		*file_name;
	char		buf[BUFSIZE_BITMAP];
	off_t		offset;
};

struct cache_data {
	int	fd;
	char	*file_name;
	char	*buf;
	size_t	buf_size;
	size_t	cache_size;
	off_t	offset;
};

/*
 * makedumpfile header
 *   For re-arranging the dump data on different architecture, all the
 *   variables are defined by 64bits. The size of signature is aligned
 *   to 64bits, and change the values to big endian.
 */
#define MAKEDUMPFILE_SIGNATURE	"makedumpfile"
#define NUM_SIG_MDF		(sizeof(MAKEDUMPFILE_SIGNATURE) - 1)
#define SIZE_SIG_MDF		roundup(sizeof(char) * NUM_SIG_MDF, 8)
#define SIG_LEN_MDF		(SIZE_SIG_MDF / sizeof(char))
#define MAX_SIZE_MDF_HEADER	(4096) /* max size of makedumpfile_header */
#define TYPE_FLAT_HEADER	(1)    /* type of flattened format */
#define VERSION_FLAT_HEADER	(1)    /* current version of flattened format */
#define END_FLAG_FLAT_HEADER	(-1)

struct makedumpfile_header {
	char	signature[SIG_LEN_MDF];	/* = "makedumpfile" */
	int64_t	type;
	int64_t	version;
};

struct makedumpfile_data_header {
	int64_t	offset;
	int64_t	buf_size;
};

struct splitting_info {
	char			*name_dumpfile;
	int 			fd_bitmap;
	unsigned long long	start_pfn;
	unsigned long long	end_pfn;
} splitting_info_t;

struct DumpInfo {
	int32_t		kernel_version;      /* version of first kernel*/
	struct timeval	timestamp;

	/*
	 * General info:
	 */
	int		dump_level;          /* current dump level */
	int		max_dump_level;      /* maximum dump level */
	int		num_dump_level;      /* number of dump level */
	int		array_dump_level[NUM_ARRAY_DUMP_LEVEL];
	int		flag_compress;       /* flag of compression */
	int		flag_elf64_memory;   /* flag of ELF64 memory */
	int		flag_elf_dumpfile;   /* flag of creating ELF dumpfile */
	int		flag_generate_vmcoreinfo;/* flag of generating vmcoreinfo file */
	int		flag_read_vmcoreinfo;    /* flag of reading vmcoreinfo file */
	int		flag_show_usage;     /* flag of showing usage */
	int		flag_show_version;   /* flag of showing version */
	int		flag_flatten;        /* flag of outputting flattened
						format to a standard out */
	int		flag_rearrange;      /* flag of creating dumpfile from
						flattened format */
	int		flag_split;	     /* splitting vmcore */
	int		flag_reassemble;     /* reassemble multiple dumpfiles into one */
	int		flag_force;	     /* overwrite existing stuff */
	int		flag_exclude_xen_dom;/* exclude Domain-U from xen-kdump */
	int             flag_dmesg;          /* dump the dmesg log out of the vmcore file */
	int		flag_nospace;	     /* the flag of "No space on device" error */
	unsigned long	vaddr_for_vtop;      /* virtual address for debugging */
	long		page_size;           /* size of page */
	long		page_shift;
	unsigned long long	max_mapnr;   /* number of page descriptor */
	unsigned long   page_offset;
	unsigned long   section_size_bits;
	unsigned long   max_physmem_bits;
	unsigned long   sections_per_root;
	unsigned long	phys_base;
	unsigned long   kernel_start;
	unsigned long   vmalloc_start;

	/*
	 * diskdimp info:
	 */
	int		block_order;
	off_t		offset_bitmap1;
	unsigned long	len_bitmap;          /* size of bitmap(1st and 2nd) */
	struct dump_bitmap 		*bitmap1;
	struct dump_bitmap 		*bitmap2;
	struct disk_dump_header		*dump_header;

	/*
	 * ELF header info:
	 */
	unsigned int		num_load_memory;
	unsigned int		num_load_dumpfile;
	size_t			offset_load_memory;
	size_t			offset_load_dumpfile;
	struct pt_load_segment	*pt_load_segments;

	/*
	 * mem_map info:
	 */
	unsigned int		num_mem_map;
	struct mem_map_data	*mem_map_data;

	int			fd_vmlinux;
	char			*name_vmlinux;

	int			fd_xen_syms;
	char			*name_xen_syms;

	/*
	 * Dump memory image info:
	 */
	int			fd_memory;
	char			*name_memory;

	/*
	 * Dump file info:
	 */
	int			fd_dumpfile;
	char			*name_dumpfile;
	int			num_dumpfile;
	struct splitting_info	*splitting_info;

	/*
	 * bitmap info:
	 */
	int			fd_bitmap;
	char			*name_bitmap;

	/*
	 * vmcoreinfo file info:
	 */
	FILE			*file_vmcoreinfo;
	char			*name_vmcoreinfo;	     /* vmcoreinfo file */
	char			release[STRLEN_OSRELEASE];

	/*
	 * vmcoreinfo in dump memory image info:
	 */
	off_t			offset_vmcoreinfo;
	unsigned long		size_vmcoreinfo;
	off_t			offset_vmcoreinfo_xen;
	unsigned long		size_vmcoreinfo_xen;

	/*
	 * for Xen extraction
	 */
	off_t			offset_xen_crash_info;
	unsigned long		size_xen_crash_info;
	unsigned long xen_phys_start;
	unsigned long xen_heap_start;	/* start mfn of xen heap area */
	unsigned long xen_heap_end;	/* end mfn(+1) of xen heap area */
	unsigned long frame_table_vaddr;
	unsigned long max_page;
	unsigned long alloc_bitmap;
	unsigned long dom0;
	int	num_domain;
	struct domain_list *domain_list;

	/*
	 * for splitting
	 */
	unsigned long long split_start_pfn;  
	unsigned long long split_end_pfn;  
};
extern struct DumpInfo		*info;

/*
 * kernel VM-related data
 */
struct vm_table {
	int		numnodes;
	unsigned long	*node_online_map;
	int		node_online_map_len;
	unsigned int	mem_flags;
};
extern struct vm_table		vt;

struct symbol_table {
	unsigned long long	mem_map;
	unsigned long long	vmem_map;
	unsigned long long	mem_section;
	unsigned long long	pkmap_count;
	unsigned long long	pkmap_count_next;
	unsigned long long	system_utsname;
	unsigned long long	init_uts_ns;
	unsigned long long 	_stext;
	unsigned long long 	swapper_pg_dir;
	unsigned long long 	init_level4_pgt;
	unsigned long long 	vmlist;
	unsigned long long 	phys_base;
	unsigned long long 	node_online_map;
	unsigned long long 	node_states;
	unsigned long long 	node_memblk;
	unsigned long long 	node_data;
	unsigned long long 	pgdat_list;
	unsigned long long 	contig_page_data;
	unsigned long long   	log_buf;
	unsigned long long   	log_buf_len;
	unsigned long long   	log_end;

	/*
	 * for Xen extraction
	 */
	unsigned long long	dom_xen;
	unsigned long long	dom_io;
	unsigned long long	domain_list;
	unsigned long long	frame_table;
	unsigned long long	xen_heap_start;
	unsigned long long	pgd_l2;
	unsigned long long	pgd_l3;
	unsigned long long	pgd_l4;
	unsigned long long	xenheap_phys_end;
	unsigned long long	xen_pstart;
	unsigned long long	frametable_pg_dir;
	unsigned long long	max_page;
	unsigned long long	alloc_bitmap;
};

struct size_table {
	long	page;
	long	mem_section;
	long	pglist_data;
	long	zone;
	long	free_area;
	long	list_head;
	long	node_memblk_s;
	long	nodemask_t;

	/*
	 * for Xen extraction
	 */
	long	page_info;
	long	domain;
};

struct offset_table {
	struct page {
		long	flags;
		long	_count;
		long	mapping;
		long	lru;
	} page;
	struct mem_section {
		long	section_mem_map;
	} mem_section;
	struct zone {
		long	free_pages;
		long	free_area;
		long	vm_stat;
		long	spanned_pages;
	} zone;
	struct pglist_data {
		long	node_zones;
		long	nr_zones;
		long	node_mem_map;
		long	node_start_pfn;
		long	node_spanned_pages;
		long	pgdat_next;
	} pglist_data;
	struct free_area {
		long	free_list;
	} free_area;
	struct list_head {
		long	next;
		long	prev;
	} list_head;
	struct node_memblk_s {
		long	start_paddr;
		long	size;
		long	nid;
	} node_memblk_s;
	struct vm_struct {
		long	addr;
	} vm_struct;

	/*
	 * for Xen extraction
	 */
	struct page_info {
		long	count_info;
		long	_domain;
	} page_info;
	struct domain {
		long	domain_id;
		long	next_in_list;
	} domain;

};

/*
 * The number of array
 */
struct array_table {
	/*
	 * Symbol
	 */
	long	node_data;
	long	pgdat_list;
	long	mem_section;
	long	node_memblk;

	/*
	 * Structure
	 */
	struct zone_at {
		long	free_area;
	} zone;
	struct free_area_at {
		long	free_list;
	} free_area;
};

struct number_table {
	long	NR_FREE_PAGES;
	long	N_ONLINE;

	/*
 	* Page flags
	 */
	long	PG_lru;
	long	PG_private;
	long	PG_swapcache;
};

#define LEN_SRCFILE				(100)
struct srcfile_table {
	/*
	 * typedef
	 */
	char	pud_t[LEN_SRCFILE];
};

extern struct symbol_table	symbol_table;
extern struct size_table	size_table;
extern struct offset_table	offset_table;
extern struct array_table	array_table;
extern struct number_table	number_table;
extern struct srcfile_table	srcfile_table;

/*
 * Debugging information
 */
enum {
	DWARF_INFO_GET_STRUCT_SIZE,
	DWARF_INFO_GET_MEMBER_OFFSET,
	DWARF_INFO_GET_MEMBER_OFFSET_IN_UNION,
	DWARF_INFO_GET_MEMBER_OFFSET_1ST_UNION,
	DWARF_INFO_GET_MEMBER_ARRAY_LENGTH,
	DWARF_INFO_GET_SYMBOL_ARRAY_LENGTH,
	DWARF_INFO_GET_TYPEDEF_SIZE,
	DWARF_INFO_GET_TYPEDEF_SRCNAME,
	DWARF_INFO_GET_ENUM_NUMBER,
	DWARF_INFO_CHECK_SYMBOL_ARRAY_TYPE
};

struct dwarf_info {
	unsigned int	cmd;		/* IN */
	int	fd_debuginfo;		/* IN */
	char	*name_debuginfo;	/* IN */
	char	*struct_name;		/* IN */
	char	*symbol_name;		/* IN */
	char	*member_name;		/* IN */
	char	*enum_name;		/* IN */
	long	struct_size;		/* OUT */
	long	member_offset;		/* OUT */
	long	array_length;		/* OUT */
	long	enum_number;		/* OUT */
	char	src_name[LEN_SRCFILE];	/* OUT */
};

extern struct dwarf_info	dwarf_info;

int readmem(int type_addr, unsigned long long addr, void *bufptr, size_t size);
off_t paddr_to_offset(unsigned long long paddr);
unsigned long long vaddr_to_paddr_general(unsigned long long vaddr);
int check_elf_format(int fd, char *filename, int *phnum, int *num_load);
int get_elf64_phdr(int fd, char *filename, int num, Elf64_Phdr *phdr);
int get_elf32_phdr(int fd, char *filename, int num, Elf32_Phdr *phdr);
int get_str_osrelease_from_vmlinux(void);
int get_pt_note_info(off_t off_note, unsigned long sz_note);
int read_vmcoreinfo_xen(void);
int exclude_xen_user_domain(void);
unsigned long long get_num_dumpable(void);
void close_vmcoreinfo(void);
int close_files_for_creating_dumpfile(void);


/*
 * for Xen extraction
 */
struct domain_list {
	unsigned long domain_addr;
	unsigned int  domain_id;
	unsigned int  pickled_id;
};

#define PAGES_PER_MAPWORD (sizeof(unsigned long) * 8)

#ifdef __x86__
#define HYPERVISOR_VIRT_START_PAE	(0xF5800000UL)
#define HYPERVISOR_VIRT_START		(0xFC000000UL)
#define HYPERVISOR_VIRT_END		(0xFFFFFFFFUL)
#define DIRECTMAP_VIRT_START		(0xFF000000UL)
#define DIRECTMAP_VIRT_END		(0xFFC00000UL)

#define is_xen_vaddr(x) \
	((x) >= HYPERVISOR_VIRT_START_PAE && (x) < HYPERVISOR_VIRT_END)
#define is_direct(x) \
	((x) >= DIRECTMAP_VIRT_START && (x) < DIRECTMAP_VIRT_END)

unsigned long long kvtop_xen_x86(unsigned long kvaddr);
#define kvtop_xen(X)	kvtop_xen_x86(X)

int get_xen_info_x86(void);
#define get_xen_info_arch(X) get_xen_info_x86(X)

#endif	/* __x86__ */

#ifdef __x86_64__

#define ENTRY_MASK	(~0x8000000000000fffULL)

#define HYPERVISOR_VIRT_START (0xffff800000000000)
#define HYPERVISOR_VIRT_END   (0xffff880000000000)
#define DIRECTMAP_VIRT_START  (0xffff830000000000)
#define DIRECTMAP_VIRT_END    (0xffff840000000000)
#define XEN_VIRT_START        (0xffff828c80000000)

#define is_xen_vaddr(x) \
        ((x) >= HYPERVISOR_VIRT_START && (x) < HYPERVISOR_VIRT_END)
#define is_direct(x) \
        ((x) >= DIRECTMAP_VIRT_START && (x) < DIRECTMAP_VIRT_END)
#define is_xen_text(x) \
        ((x) >= XEN_VIRT_START && (x) < DIRECTMAP_VIRT_START)

unsigned long long kvtop_xen_x86_64(unsigned long kvaddr);
#define kvtop_xen(X)	kvtop_xen_x86_64(X)

int get_xen_info_x86_64(void);
#define get_xen_info_arch(X) get_xen_info_x86_64(X)

#endif	/* __x86_64__ */

#ifdef __ia64__
#define HYPERVISOR_VIRT_START	(0xe800000000000000)
#define HYPERVISOR_VIRT_END	(0xf800000000000000)
#define DEFAULT_SHAREDINFO_ADDR	(0xf100000000000000)
#define PERCPU_PAGE_SIZE	65536
#define PERCPU_ADDR		(DEFAULT_SHAREDINFO_ADDR - PERCPU_PAGE_SIZE)
#define DIRECTMAP_VIRT_START	(0xf000000000000000)
#define DIRECTMAP_VIRT_END	PERCPU_ADDR
#define VIRT_FRAME_TABLE_ADDR	(0xf300000000000000)
#define VIRT_FRAME_TABLE_END	(0xf400000000000000)

#define is_xen_vaddr(x) \
	((x) >= HYPERVISOR_VIRT_START && (x) < HYPERVISOR_VIRT_END)
#define is_direct(x) \
	((x) >= DIRECTMAP_VIRT_START && (x) < DIRECTMAP_VIRT_END)
#define is_frame_table_vaddr(x) \
	((x) >= VIRT_FRAME_TABLE_ADDR && (x) < VIRT_FRAME_TABLE_END)

#define PGDIR_SHIFT	(PAGESHIFT() + 2 * (PAGESHIFT() - 3))
#define PTRS_PER_PGD	(1UL << (PAGESHIFT() - 3))
#define PTRS_PER_PMD	(1UL << (PAGESHIFT() - 3))
#define PTRS_PER_PTE	(1UL << (PAGESHIFT() - 3))

#define IA64_MAX_PHYS_BITS	50
#define _PAGE_P		(1)
#define _PFN_MASK	(((1UL << IA64_MAX_PHYS_BITS) - 1) & ~0xfffUL)

unsigned long long kvtop_xen_ia64(unsigned long kvaddr);
#define kvtop_xen(X)	kvtop_xen_ia64(X)

int get_xen_info_ia64(void);
#define get_xen_info_arch(X) get_xen_info_ia64(X)

#endif	/* __ia64 */

#ifdef __powerpc__ /* powerpc */
#define kvtop_xen(X)	FALSE
#define get_xen_info_arch(X) FALSE
#endif	/* powerpc */

