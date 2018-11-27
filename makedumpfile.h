/*
 * makedumpfile.h
 *
 * Copyright (C) 2006, 2007, 2008, 2009, 2011  NEC Corporation
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
#ifndef _MAKEDUMPFILE_H
#define _MAKEDUMPFILE_H

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
#include <libelf.h>
#include <byteswap.h>
#include <getopt.h>
#include <sys/mman.h>
#ifdef USELZO
#include <lzo/lzo1x.h>
#endif
#ifdef USESNAPPY
#include <snappy-c.h>
#endif
#include "common.h"
#include "dwarf_info.h"
#include "diskdump_mod.h"
#include "print_info.h"
#include "sadump_mod.h"
#include <pthread.h>
#include <semaphore.h>
#include <inttypes.h>

#define VMEMMAPSTART 0xffffea0000000000UL
#define BITS_PER_WORD 64

/*
 * Result of command
 */
#define COMPLETED	(0)
#define FAILED		(1)
#define WRONG_RELEASE	(2)	/* utsname.release does not match. */

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

int get_mem_type(void);

/*
 * Page flags
 *
 * The flag values of page.flags have been defined by enum since linux-2.6.26.
 * The following values are for linux-2.6.25 or former.
 */
#define PG_lru_ORIGINAL	 	(5)
#define PG_slab_ORIGINAL	(7)
#define PG_private_ORIGINAL	(11)	/* Has something at ->private */
#define PG_compound_ORIGINAL	(14)	/* Is part of a compound page */
#define PG_swapcache_ORIGINAL	(15)	/* Swap page: swp_entry_t in private */

#define PAGE_BUDDY_MAPCOUNT_VALUE_v2_6_38	(-2)
#define PAGE_BUDDY_MAPCOUNT_VALUE_v2_6_39_to_latest_version	(-128)

#define PAGE_FLAGS_SIZE_v2_6_27_to_latest_version	(4)

#define PAGE_MAPPING_ANON	(1)

#define LSEEKED_BITMAP	(1)
#define LSEEKED_PDESC	(2)
#define LSEEKED_PDATA	(3)

/*
 * Xen page flags
 */
#define BITS_PER_LONG (BITPERBYTE * sizeof(long))
#define PG_shift(idx)	(BITS_PER_LONG - (idx))
#define PG_mask(x, idx)	(x ## UL << PG_shift(idx))
 /* Cleared when the owning guest 'frees' this page. */
#define PGC_allocated       PG_mask(1, 1)
 /* Page is Xen heap? */
#define PGC_xen_heap        PG_mask(1, 2)
 /* Page is broken? */
#define PGC_broken          PG_mask(1, 7)
 /* Mutually-exclusive page states: { inuse, offlining, offlined, free }. */
#define PGC_state           PG_mask(3, 9)
#define PGC_state_inuse     PG_mask(0, 9)
#define PGC_state_offlining PG_mask(1, 9)
#define PGC_state_offlined  PG_mask(2, 9)
#define PGC_state_free      PG_mask(3, 9)
#define page_state_is(ci, st) (((ci)&PGC_state) == PGC_state_##st)

 /* Count of references to this frame. */
#define PGC_count_width   PG_shift(9)
#define PGC_count_mask    ((1UL<<PGC_count_width)-1)

/*
 * Memory flags
 */
#define MEMORY_PAGETABLE_4L	(1 << 0)
#define MEMORY_PAGETABLE_3L	(1 << 1)
#define MEMORY_X86_PAE		(1 << 2)

/*
 * Type of address
 */
enum {
	VADDR,
	PADDR,
	VADDR_XEN,
};

/*
 * State of mmap(2)
 */
enum {
	MMAP_DISABLE,
	MMAP_TRY,
	MMAP_ENABLE,
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
#define isCompoundHead(flags)   (!!((flags) & NUMBER(PG_head_mask)))
#define isSwapCache(flags)	test_bit(NUMBER(PG_swapcache), flags)
#define isSwapBacked(flags)	test_bit(NUMBER(PG_swapbacked), flags)
#define isHWPOISON(flags)	(test_bit(NUMBER(PG_hwpoison), flags) \
				&& (NUMBER(PG_hwpoison) != NOT_FOUND_NUMBER))

static inline int
isAnon(unsigned long mapping)
{
	return ((unsigned long)mapping & PAGE_MAPPING_ANON) != 0;
}

#define PTOB(X)			(((unsigned long long)(X)) << PAGESHIFT())
#define BTOP(X)			(((unsigned long long)(X)) >> PAGESHIFT())

#define PAGESIZE()		(info->page_size)
#define PAGESHIFT()		(info->page_shift)
#define PAGEOFFSET(X)		(((unsigned long long)(X)) & (PAGESIZE() - 1))
#define PAGEBASE(X)		(((unsigned long long)(X)) & ~(PAGESIZE() - 1))

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
#define SECTION_MARKED_PRESENT  (1UL<<0)
#define SECTION_IS_ONLINE	(1UL<<2)
/*
 * SECTION_MAP_LAST_BIT was 1UL<<2 before Linux 4.13.0.
 * However, we always use the higher value, because:
 *  1. at least one distributor backported commit 2d070eab2e82 to kernel
 *     version 4.12,
 *  2. it has been verified that (1UL<<2) was never set, so it is
 *     safe to mask that bit off even in old kernels.
 */
#define SECTION_MAP_LAST_BIT	(1UL<<3)
#define SECTION_MAP_MASK	(~(SECTION_MAP_LAST_BIT-1))
#define NR_SECTION_ROOTS()	divideup(num_section, SECTIONS_PER_ROOT())
#define SECTION_NR_TO_PFN(sec)	((sec) << PFN_SECTION_SHIFT())
#define SECTIONS_SHIFT()	(MAX_PHYSMEM_BITS() - SECTION_SIZE_BITS())
#define NR_MEM_SECTIONS()	(1UL << SECTIONS_SHIFT())

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
 * For parse_line()
 */
#define NULLCHAR	('\0')
#define MAXARGS		(100)   /* max number of arguments to one function */
#define LASTCHAR(s)	(s[strlen(s)-1])

#define BITPERBYTE		(8)
#define PGMM_CACHED		(512)
#define PFN_EXCLUDED		(256)
#define BUFSIZE			(1024)
#define BUFSIZE_FGETS		(1500)
#define BUFSIZE_BITMAP		(4096)
#define PFN_BUFBITMAP		(BITPERBYTE*BUFSIZE_BITMAP)
#define FILENAME_BITMAP		"kdump_bitmapXXXXXX"
#define FILENAME_STDOUT		"STDOUT"
#define MAP_REGION		(4096*1024)

/*
 * Minimam vmcore has 2 ProgramHeaderTables(PT_NOTE and PT_LOAD).
 */
#define MIN_ELF32_HEADER_SIZE \
	sizeof(Elf32_Ehdr)+sizeof(Elf32_Phdr)+sizeof(Elf32_Phdr)
#define MIN_ELF64_HEADER_SIZE \
	sizeof(Elf64_Ehdr)+sizeof(Elf64_Phdr)+sizeof(Elf64_Phdr)
#define MIN_ELF_HEADER_SIZE \
	MAX(MIN_ELF32_HEADER_SIZE, MIN_ELF64_HEADER_SIZE)
static inline int string_exists(char *s) { return (s ? TRUE : FALSE); }
#define STREQ(A, B) (string_exists((char *)A) && 	\
		     string_exists((char *)B) && 	\
	(strcmp((char *)(A), (char *)(B)) == 0))
#define STRNEQ(A, B)(string_exists((char *)(A)) &&	\
		     string_exists((char *)(B)) &&	\
	(strncmp((char *)(A), (char *)(B), strlen((char *)(B))) == 0))

#define UCHAR(ADDR)	*((unsigned char *)(ADDR))
#define USHORT(ADDR)	*((unsigned short *)(ADDR))
#define UINT(ADDR)	*((unsigned int *)(ADDR))
#define ULONG(ADDR)	*((unsigned long *)(ADDR))
#define ULONGLONG(ADDR)	*((unsigned long long *)(ADDR))


/*
 * for symbol
 */
#define INVALID_SYMBOL_DATA	(ULONG_MAX)
#define SYMBOL(X)		(symbol_table.X)
#define SYMBOL_INIT(symbol, str_symbol) \
do { \
	SYMBOL(symbol) = get_symbol_addr(str_symbol); \
	if (SYMBOL(symbol) != NOT_FOUND_SYMBOL) \
		SYMBOL(symbol) += info->kaslr_offset; \
} while (0)
#define SYMBOL_INIT_NEXT(symbol, str_symbol) \
do { \
	SYMBOL(symbol) = get_next_symbol_addr(str_symbol); \
	if (SYMBOL(symbol) != NOT_FOUND_SYMBOL) \
		SYMBOL(symbol) += info->kaslr_offset; \
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
		if (info->read_text_vmcoreinfo && \
		    (SYMBOL(symbol) != NOT_FOUND_SYMBOL) && \
		    (SYMBOL(symbol) != INVALID_SYMBOL_DATA)) \
			SYMBOL(symbol) += info->kaslr_offset; \
	} \
} while (0)

/*
 * for structure
 */
#define SIZE(X)			(size_table.X)
#define OFFSET(X)		(offset_table.X)
#define ARRAY_LENGTH(X)		(array_table.X)
#define SIZE_INIT(X, Y) \
do { \
	if ((SIZE(X) = get_structure_size(Y, DWARF_INFO_GET_STRUCT_SIZE))	\
		== FAILED_DWARFINFO) \
		return FALSE; \
} while (0)
#define TYPEDEF_SIZE_INIT(X, Y) \
do { \
	if ((SIZE(X) = get_structure_size(Y, DWARF_INFO_GET_TYPEDEF_SIZE)) \
		== FAILED_DWARFINFO) \
		return FALSE; \
} while (0)
#define ENUM_TYPE_SIZE_INIT(X, Y) \
do { \
	if ((SIZE(X) = get_structure_size(Y,	\
		DWARF_INFO_GET_ENUMERATION_TYPE_SIZE))	\
			== FAILED_DWARFINFO)				\
	return FALSE; \
} while (0)
#define OFFSET_INIT(X, Y, Z) \
do { \
	if ((OFFSET(X) = get_member_offset(Y, Z, DWARF_INFO_GET_MEMBER_OFFSET)) \
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
#define WRITE_NUMBER_UNSIGNED(str_number, number) \
do { \
	if (NUMBER(number) != NOT_FOUND_NUMBER) { \
		fprintf(info->file_vmcoreinfo, "%s%lu\n", \
		    STR_NUMBER(str_number), NUMBER(number)); \
	} \
} while (0)
#define READ_NUMBER_UNSIGNED(str_number, number) \
do { \
	if (NUMBER(number) == NOT_FOUND_NUMBER) { \
		NUMBER(number) = read_vmcoreinfo_ulong(STR_NUMBER(str_number)); \
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
#define SPLITTING_OFFSET_EI(i)	info->splitting_info[i].offset_eraseinfo
#define SPLITTING_SIZE_EI(i)	info->splitting_info[i].size_eraseinfo

/*
 * Macro for getting parallel info.
 */
#define FD_MEMORY_PARALLEL(i)		info->parallel_info[i].fd_memory
#define FD_BITMAP_MEMORY_PARALLEL(i)	info->parallel_info[i].fd_bitmap_memory
#define FD_BITMAP_PARALLEL(i)		info->parallel_info[i].fd_bitmap
#define BUF_PARALLEL(i)			info->parallel_info[i].buf
#define BUF_OUT_PARALLEL(i)		info->parallel_info[i].buf_out
#define MMAP_CACHE_PARALLEL(i)		info->parallel_info[i].mmap_cache
#define ZLIB_STREAM_PARALLEL(i)		info->parallel_info[i].zlib_stream
#ifdef USELZO
#define WRKMEM_PARALLEL(i)		info->parallel_info[i].wrkmem
#endif
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
#define OLDEST_VERSION		KERNEL_VERSION(2, 6, 15) /* linux-2.6.15 */
#define LATEST_VERSION		KERNEL_VERSION(4, 19, 4) /* linux-4.19.4 */

/*
 * vmcoreinfo in /proc/vmcore
 */
#define VMCOREINFO_BYTES		(4096)
#define FILENAME_VMCOREINFO		"/tmp/vmcoreinfoXXXXXX"

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
#define STR_KERNELOFFSET	"KERNELOFFSET="

/*
 * common value
 */
#define NOSPACE		(-1)    /* code of write-error due to nospace */
#define DEFAULT_ORDER	(4)
#define TIMEOUT_STDIN	(600)
#define SIZE_BUF_STDIN	(4096)
#define STRLEN_OSRELEASE (65)	/* same length as diskdump.h */

/*
 * The value of dependence on machine
 */
#define PAGE_OFFSET		(info->page_offset)
#define VMALLOC_START		(info->vmalloc_start)
#define VMALLOC_END		(info->vmalloc_end)
#define VMEMMAP_START		(info->vmemmap_start)
#define VMEMMAP_END		(info->vmemmap_end)
#define PMASK			(0x7ffffffffffff000UL)

#ifdef __aarch64__
unsigned long get_kvbase_arm64(void);
#define KVBASE			get_kvbase_arm64()
#define __START_KERNEL_map	(0xffffffff80000000UL)

#endif /* aarch64 */

#ifdef __arm__
#define KVBASE_MASK		(0xffff)
#define KVBASE			(SYMBOL(_stext) & ~KVBASE_MASK)
#define _SECTION_SIZE_BITS	(28)
#define _MAX_PHYSMEM_BITS	(32)
#define ARCH_PFN_OFFSET		(info->phys_base >> PAGESHIFT())

#define PTRS_PER_PTE		(512)
#define PGDIR_SHIFT		(21)
#define PMD_SHIFT		(21)
#define PMD_SIZE		(1UL << PMD_SHIFT)
#define PMD_MASK		(~(PMD_SIZE - 1))

#define _PAGE_PRESENT		(1 << 0)

#endif /* arm */

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

/* Physical addresses are up to 52 bits (AMD64).
 * Mask off bits 52-62 (reserved) and bit 63 (NX).
 */
#define ENTRY_MASK		(~0xfff0000000000fffULL)

#endif /* x86 */

#ifdef __x86_64__
#define __PAGE_OFFSET_ORIG	(0xffff810000000000) /* 2.6.26, or former */
#define __PAGE_OFFSET_2_6_27	(0xffff880000000000) /* 2.6.27, or later  */
#define __PAGE_OFFSET_5LEVEL	(0xff10000000000000) /* 5-level page table */

#define VMALLOC_START_ORIG	(0xffffc20000000000) /* 2.6.30, or former */
#define VMALLOC_START_2_6_31	(0xffffc90000000000) /* 2.6.31, or later  */
#define VMALLOC_START_5LEVEL	(0xffa0000000000000) /* 5-level page table */
#define VMALLOC_END_ORIG	(0xffffe1ffffffffff) /* 2.6.30, or former */
#define VMALLOC_END_2_6_31	(0xffffe8ffffffffff) /* 2.6.31, or later  */
#define VMALLOC_END_5LEVEL	(0xffd1ffffffffffff) /* 5-level page table */

#define VMEMMAP_START_ORIG	(0xffffe20000000000) /* 2.6.30, or former */
#define VMEMMAP_START_2_6_31	(0xffffea0000000000) /* 2.6.31, or later  */
#define VMEMMAP_START_5LEVEL	(0xffd4000000000000) /* 5-level page table */
#define VMEMMAP_END_ORIG	(0xffffe2ffffffffff) /* 2.6.30, or former */
#define VMEMMAP_END_2_6_31	(0xffffeaffffffffff) /* 2.6.31, or later  */
#define VMEMMAP_END_5LEVEL	(0xffd5ffffffffffff) /* 5-level page table */

#define __START_KERNEL_map	(0xffffffff80000000)
#define KVBASE			PAGE_OFFSET
#define _SECTION_SIZE_BITS	(27)
#define _MAX_PHYSMEM_BITS_ORIG		(40)
#define _MAX_PHYSMEM_BITS_2_6_26	(44)
#define _MAX_PHYSMEM_BITS_2_6_31	(46)
#define _MAX_PHYSMEM_BITS_5LEVEL	(52)

/*
 * 4 Levels paging
 */
#define PGD_SHIFT		(39)
#define PUD_SHIFT		(30)
#define PMD_SHIFT		(21)
#define PTE_SHIFT		(12)

#define PTRS_PER_PGD		(512)
#define PTRS_PER_PUD		(512)
#define PTRS_PER_PMD		(512)
#define PTRS_PER_PTE		(512)

#define PUD_SIZE		(1UL << PUD_SHIFT)
#define PUD_MASK		(~(PUD_SIZE - 1))
#define PMD_SIZE		(1UL << PMD_SHIFT)
#define PMD_MASK		(~(PMD_SIZE - 1))

/*
 * 5 Levels paging
 */
#define PGD_SHIFT_5LEVEL	(48)
#define P4D_SHIFT		(39)

#define PTRS_PER_PGD_5LEVEL	(512)
#define PTRS_PER_P4D		(512)

#define pgd5_index(address)  (((address) >> PGD_SHIFT_5LEVEL) & (PTRS_PER_PGD_5LEVEL - 1))
#define pgd_index(address)  (((address) >> PGD_SHIFT) & (PTRS_PER_PGD - 1))
#define p4d_index(address)  (((address) >> P4D_SHIFT) & (PTRS_PER_P4D - 1))
#define pud_index(address)  (((address) >> PUD_SHIFT) & (PTRS_PER_PUD - 1))
#define pmd_index(address)  (((address) >> PMD_SHIFT) & (PTRS_PER_PMD - 1))
#define pte_index(address)  (((address) >> PTE_SHIFT) & (PTRS_PER_PTE - 1))

#define _PAGE_PRESENT		(0x001)
#define _PAGE_PSE		(0x080)    /* 2MB or 1GB page */

#endif /* x86_64 */

#ifdef __powerpc64__
#define __PAGE_OFFSET		(0xc000000000000000)
#define KERNELBASE		PAGE_OFFSET
#define VMALLOCBASE     	(0xD000000000000000)
#define KVBASE			(SYMBOL(_stext))
#define _SECTION_SIZE_BITS	(24)
#define _MAX_PHYSMEM_BITS_ORIG  (44)
#define _MAX_PHYSMEM_BITS_3_7   (46)
#define _MAX_PHYSMEM_BITS_4_19  (47)
#define REGION_SHIFT            (60UL)
#define VMEMMAP_REGION_ID       (0xfUL)

/* 4-level page table support */

/* 4K pagesize */
#define PTE_INDEX_SIZE_L4_4K  9
#define PMD_INDEX_SIZE_L4_4K  7
#define PUD_INDEX_SIZE_L4_4K  7
#define PGD_INDEX_SIZE_L4_4K  9
#define PUD_INDEX_SIZE_L4_4K_3_7  9
#define PTE_INDEX_SIZE_RADIX_4K  9
#define PMD_INDEX_SIZE_RADIX_4K  9
#define PUD_INDEX_SIZE_RADIX_4K  9
#define PGD_INDEX_SIZE_RADIX_4K  13
#define PTE_RPN_SHIFT_L4_4K  17
#define PTE_RPN_SHIFT_L4_4K_4_5  18
#define PGD_MASKED_BITS_4K  0
#define PUD_MASKED_BITS_4K  0
#define PMD_MASKED_BITS_4K  0

/* 64K pagesize */
#define PTE_INDEX_SIZE_L4_64K   12
#define PMD_INDEX_SIZE_L4_64K   12
#define PUD_INDEX_SIZE_L4_64K   0
#define PGD_INDEX_SIZE_L4_64K   4
#define PTE_INDEX_SIZE_L4_64K_3_10  8
#define PMD_INDEX_SIZE_L4_64K_3_10  10
#define PGD_INDEX_SIZE_L4_64K_3_10  12
#define PMD_INDEX_SIZE_L4_64K_4_6  5
#define PUD_INDEX_SIZE_L4_64K_4_6  5
#define PMD_INDEX_SIZE_L4_64K_4_12 10
#define PUD_INDEX_SIZE_L4_64K_4_12 7
#define PGD_INDEX_SIZE_L4_64K_4_12 8
#define PUD_INDEX_SIZE_L4_64K_4_17 10
#define PTE_INDEX_SIZE_RADIX_64K  5
#define PMD_INDEX_SIZE_RADIX_64K  9
#define PUD_INDEX_SIZE_RADIX_64K  9
#define PGD_INDEX_SIZE_RADIX_64K  13
#define PTE_RPN_SHIFT_L4_64K_V1  32
#define PTE_RPN_SHIFT_L4_64K_V2  30
#define PGD_MASKED_BITS_64K  0
#define PUD_MASKED_BITS_64K  0x1ff
#define PMD_MASKED_BITS_64K  0x1ff
#define PMD_MASKED_BITS_64K_3_11 0xfff
#define PGD_MASKED_BITS_64K_4_6  0xc0000000000000ffUL
#define PUD_MASKED_BITS_64K_4_6  0xc0000000000000ffUL
#define PMD_MASKED_BITS_64K_4_6  0xc0000000000000ffUL

#define PTE_RPN_MASK_DEFAULT  0xffffffffffffffffUL
#define PTE_RPN_SIZE_L4_4_6   (info->page_size == 65536 ? 41 : 45)
#define PTE_RPN_MASK_L4_4_6   (((1UL << PTE_RPN_SIZE_L4_4_6) - 1) << info->page_shift)
#define PTE_RPN_SHIFT_L4_4_6  info->page_shift

#define PGD_MASKED_BITS_4_7  0xc0000000000000ffUL
#define PUD_MASKED_BITS_4_7  0xc0000000000000ffUL
#define PMD_MASKED_BITS_4_7  0xc0000000000000ffUL

#define PTE_RPN_SIZE_L4_4_11  53
#define PTE_RPN_MASK_L4_4_11   \
	(((1UL << PTE_RPN_SIZE_L4_4_11) - 1) & ~((1UL << info->page_shift) - 1))
#define PTE_RPN_SHIFT_L4_4_11  info->page_shift

/*
 * Supported MMU types
 */
#define STD_MMU         0x0
/*
 * The flag bit for radix MMU in cpu_spec.mmu_features
 * in the kernel. Use the same flag here.
 */
#define RADIX_MMU       0x40


#define PGD_MASK_L4		\
	(info->kernel_version >= KERNEL_VERSION(3, 10, 0) ? (info->ptrs_per_pgd - 1) : 0x1ff)
#define PGD_OFFSET_L4(vaddr)	((vaddr >> (info->l4_shift)) & PGD_MASK_L4)

#define PUD_OFFSET_L4(vaddr)	\
	((vaddr >> (info->l3_shift)) & (info->ptrs_per_l3 - 1))

#define PMD_OFFSET_L4(vaddr)	\
	((vaddr >> (info->l2_shift)) & (info->ptrs_per_l2 - 1))

#define _PAGE_PRESENT		\
	(info->kernel_version >= KERNEL_VERSION(4, 6, 0) ? \
	(0x1UL << 63) : (info->kernel_version >= KERNEL_VERSION(4, 5, 0) ? \
			0x2UL : 0x1UL))

#endif

#ifdef __powerpc32__

#define __PAGE_OFFSET		(0xc0000000)
#define KERNELBASE		PAGE_OFFSET
#define VMALL_START     	(info->vmalloc_start)
#define KVBASE			(SYMBOL(_stext))
#define _SECTION_SIZE_BITS	(24)
#define _MAX_PHYSMEM_BITS	(44)

#endif

#ifdef __s390x__
#define __PAGE_OFFSET		(info->page_size - 1)
#define KERNELBASE		(0)
#define KVBASE			KERNELBASE
#define _SECTION_SIZE_BITS	(28)
#define _MAX_PHYSMEM_BITS_ORIG          (42)
#define _MAX_PHYSMEM_BITS_3_3           (46)

/* Bits in the segment/region table address-space-control-element */
#define _ASCE_TYPE_MASK		0x0c
#define _ASCE_TABLE_LENGTH	0x03	/* region table length  */

#define TABLE_LEVEL(x)		(((x) & _ASCE_TYPE_MASK) >> 2)
#define TABLE_LENGTH(x)		((x) & _ASCE_TABLE_LENGTH)

/* Bits in the region table entry */
#define _REGION_ENTRY_ORIGIN	~0xfffUL	/* region table origin*/
#define _REGION_ENTRY_TYPE_MASK	0x0c	/* region table type mask */
#define _REGION_ENTRY_INVALID	0x20	/* invalid region table entry */
#define _REGION_ENTRY_LENGTH	0x03	/* region table length */
#define _REGION_ENTRY_LARGE	0x400
#define _REGION_OFFSET_MASK	0x7ffUL	/* region/segment table offset mask */

#define RSG_TABLE_LEVEL(x)	(((x) & _REGION_ENTRY_TYPE_MASK) >> 2)
#define RSG_TABLE_LENGTH(x)	((x) & _REGION_ENTRY_LENGTH)

/* Bits in the segment table entry */
#define _SEGMENT_ENTRY_ORIGIN	~0x7ffUL
#define _SEGMENT_ENTRY_LARGE	0x400
#define _SEGMENT_ENTRY_CO	0x100
#define _SEGMENT_PAGE_SHIFT	31
#define _SEGMENT_INDEX_SHIFT	20

/* Hardware bits in the page table entry */
#define _PAGE_ZERO		0x800	/* Bit pos 52 must conatin zero */
#define _PAGE_INVALID		0x400	/* HW invalid bit */
#define _PAGE_INDEX_SHIFT	12
#define _PAGE_OFFSET_MASK	0xffUL	/* page table offset mask */

#endif /* __s390x__ */

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

#ifdef __sparc64__

#define KVBASE			(SYMBOL(_stext))
#define KVBASE_MASK		(0xffff)
#define _SECTION_SIZE_BITS	(30)
#define _MAX_PHYSMEM_BITS_L3	(49)
#define _MAX_PHYSMEM_BITS_L4	(53)
#define VMALLOC_START_SPARC64	(0x0000000100000000UL)
#define VMEMMAP_BASE_SPARC64	(0x0000010000000000UL)
#define VMEMMAP_CHUNK_SHIFT	(22)
#define VMEMMAP_CHUNK		(1UL << VMEMMAP_CHUNK_SHIFT)
#define VMEMMAP_CHUNK_MASK	(~(VMEMMAP_CHUNK - 1UL))

#define PAGE_SHIFT		13
#define PAGE_SIZE		(1UL << PAGE_SHIFT)
#define PAGE_MASK		(~(PAGE_SIZE - 1))

#define MAX_PHYS_ADDRESS_LOBITS	(41)
#define NR_CHUNKS_SHIFT		(MAX_PHYS_ADDRESS_LOBITS - PAGE_SHIFT + 6)
#define NR_CHUNKS_MASK		(~((1UL << NR_CHUNKS_SHIFT) - 1))

#define PMD_SHIFT		(PAGE_SHIFT + (PAGE_SHIFT - 3))
#define PMD_SIZE		(1UL << PMD_SHIFT)
#define PMD_MASK		(~(PMD_SIZE - 1))
#define PMD_BITS		(PAGE_SHIFT - 3)

#define PUD_SHIFT		(PMD_SHIFT + PMD_BITS)
#define PUD_SIZE		(1UL << PUD_SHIFT)
#define PUD_MASK		(~(PUD_SIZE - 1))
#define PUD_BITS		(PAGE_SHIFT - 3)

#define PGDIR_SHIFT_L4		(PUD_SHIFT + PUD_BITS)
#define PGDIR_SIZE_L4		(1UL << PGDIR_SHIFT_L4)
#define PGDIR_MASK_L4		(~(PGDIR_SIZE_L4 - 1))

#define PGDIR_SHIFT_L3		(PMD_SHIFT + PMD_BITS)
#define PGDIR_SIZE_L3		(1UL << PGDIR_SHIFT_L3)
#define PGDIR_MASK_L3		(~(PGDIR_SIZE_L3 - 1))

#define PGDIR_BITS		(PAGE_SHIFT - 3)

#define PTRS_PER_PTE		(1UL << (PAGE_SHIFT - 3))
#define PTRS_PER_PMD		(1UL << PMD_BITS)
#define PTRS_PER_PUD		(1UL << PUD_BITS)
#define PTRS_PER_PGD		(1UL << PGDIR_BITS)

#define _PAGE_PMD_HUGE		(0x0100000000000000UL)
#define _PAGE_PUD_HUGE		_PAGE_PMD_HUGE
#define _PAGE_PADDR_4V		(0x00FFFFFFFFFFE000UL)
#define _PAGE_PRESENT_4V	(0x0000000000000010UL)

typedef unsigned long pte_t;
typedef unsigned long pmd_t;
typedef unsigned long pud_t;
typedef unsigned long pgd_t;

#define pud_none(pud)		(!(pud))
#define pgd_none(pgd)		(!(pgd))
#define pmd_none(pmd)		(!(pmd))

#define pte_to_pa(pte) (pte & _PAGE_PADDR_4V)

#define pgd_index_l4(addr) (((addr) >> PGDIR_SHIFT_L4) & (PTRS_PER_PGD - 1))
#define pgd_offset_l4(pgdir,addr)	((unsigned long) \
				 ((pgd_t *)pgdir + pgd_index_l4(addr)))

#define pgd_index_l3(addr) (((addr) >> PGDIR_SHIFT_L3) & (PTRS_PER_PGD - 1))
#define pgd_offset_l3(pgdir,addr)	((unsigned long) \
				 ((pgd_t *)pgdir + pgd_index_l3(addr)))

#define pud_index(addr)		(((addr) >> PUD_SHIFT) & (PTRS_PER_PUD - 1))
#define pud_offset(pgdp, addr)	((unsigned long) \
				 ((pud_t *)pgdp + pud_index(addr)))
#define pud_large(pud)		(pud & _PAGE_PUD_HUGE)

#define pmd_index(addr)		(((addr) >> PMD_SHIFT) & (PTRS_PER_PMD - 1))
#define pmd_offset(pudp, addr)	((unsigned long) \
				 ((pmd_t *)pudp + pmd_index(addr)))
#define pmd_large(pmd)		(pmd & _PAGE_PMD_HUGE)

#define pte_index(addr)		(((addr) >> PAGE_SHIFT) & (PTRS_PER_PTE - 1))
#define pte_offset(pmdp, addr)	((unsigned long) \
				 ((pte_t *)(pte_to_pa(pmdp) + pte_index(addr))))
#define pte_present(pte)	(pte & _PAGE_PRESENT_4V)

#endif          /* sparc64 */

/*
 * The function of dependence on machine
 */
static inline int stub_true() { return TRUE; }
static inline int stub_true_ul(unsigned long x) { return TRUE; }
static inline int stub_false() { return FALSE; }
#define paddr_to_vaddr_general(X) ((X) + PAGE_OFFSET)

#ifdef __aarch64__
int get_phys_base_arm64(void);
int get_machdep_info_arm64(void);
unsigned long long vaddr_to_paddr_arm64(unsigned long vaddr);
int get_versiondep_info_arm64(void);
int get_xen_basic_info_arm64(void);
int get_xen_info_arm64(void);
unsigned long get_kaslr_offset_arm64(unsigned long vaddr);
#define paddr_to_vaddr_arm64(X) (((X) - info->phys_base) | PAGE_OFFSET)

#define find_vmemmap()		stub_false()
#define vaddr_to_paddr(X)	vaddr_to_paddr_arm64(X)
#define paddr_to_vaddr(X)	paddr_to_vaddr_arm64(X)
#define get_phys_base()		get_phys_base_arm64()
#define get_machdep_info()	get_machdep_info_arm64()
#define get_versiondep_info()	get_versiondep_info_arm64()
#define get_kaslr_offset(X)	get_kaslr_offset_arm64(X)
#define get_xen_basic_info_arch(X) get_xen_basic_info_arm64(X)
#define get_xen_info_arch(X) get_xen_info_arm64(X)
#define is_phys_addr(X)		stub_true_ul(X)
#define arch_crashkernel_mem_size()	stub_false()
#endif /* aarch64 */

#ifdef __arm__
int get_phys_base_arm(void);
int get_machdep_info_arm(void);
unsigned long long vaddr_to_paddr_arm(unsigned long vaddr);
#define find_vmemmap()		stub_false()
#define get_phys_base()		get_phys_base_arm()
#define get_machdep_info()	get_machdep_info_arm()
#define get_versiondep_info()	stub_true()
#define get_kaslr_offset(X)	stub_false()
#define vaddr_to_paddr(X)	vaddr_to_paddr_arm(X)
#define paddr_to_vaddr(X)	paddr_to_vaddr_general(X)
#define is_phys_addr(X)		stub_true_ul(X)
#define arch_crashkernel_mem_size()	stub_false()
#endif /* arm */

#ifdef __x86__
int get_machdep_info_x86(void);
int get_versiondep_info_x86(void);
unsigned long long vaddr_to_paddr_x86(unsigned long vaddr);
#define find_vmemmap()		stub_false()
#define get_phys_base()		stub_true()
#define get_machdep_info()	get_machdep_info_x86()
#define get_versiondep_info()	get_versiondep_info_x86()
#define get_kaslr_offset(X)	stub_false()
#define vaddr_to_paddr(X)	vaddr_to_paddr_x86(X)
#define paddr_to_vaddr(X)	paddr_to_vaddr_general(X)
#define is_phys_addr(X)		stub_true_ul(X)
#define arch_crashkernel_mem_size()	stub_false()
#endif /* x86 */

#ifdef __x86_64__
unsigned long get_kaslr_offset_x86_64(unsigned long vaddr);
int get_phys_base_x86_64(void);
int get_machdep_info_x86_64(void);
int get_versiondep_info_x86_64(void);
unsigned long long vtop4_x86_64(unsigned long vaddr);
unsigned long long vtop4_x86_64_pagetable(unsigned long vaddr, unsigned long pagetable);
#define find_vmemmap()		find_vmemmap_x86_64()
#define get_phys_base()		get_phys_base_x86_64()
#define get_machdep_info()	get_machdep_info_x86_64()
#define get_versiondep_info()	get_versiondep_info_x86_64()
#define get_kaslr_offset(X)	get_kaslr_offset_x86_64(X)
#define vaddr_to_paddr(X)	vtop4_x86_64(X)
#define paddr_to_vaddr(X)	paddr_to_vaddr_general(X)
#define is_phys_addr(X)		stub_true_ul(X)
#define arch_crashkernel_mem_size()	stub_false()
#endif /* x86_64 */

#ifdef __powerpc64__ /* powerpc64 */
int get_machdep_info_ppc64(void);
int get_versiondep_info_ppc64(void);
unsigned long long vaddr_to_paddr_ppc64(unsigned long vaddr);
int arch_crashkernel_mem_size_ppc64(void);
#define find_vmemmap()		stub_false()
#define get_phys_base()		stub_true()
#define get_machdep_info()	get_machdep_info_ppc64()
#define get_versiondep_info()	get_versiondep_info_ppc64()
#define get_kaslr_offset(X)	stub_false()
#define vaddr_to_paddr(X)	vaddr_to_paddr_ppc64(X)
#define paddr_to_vaddr(X)	paddr_to_vaddr_general(X)
#define is_phys_addr(X)		stub_true_ul(X)
#define arch_crashkernel_mem_size()	arch_crashkernel_mem_size_ppc64()
#endif          /* powerpc64 */

#ifdef __powerpc32__ /* powerpc32 */
int get_machdep_info_ppc(void);
unsigned long long vaddr_to_paddr_ppc(unsigned long vaddr);
#define find_vmemmap()		stub_false()
#define get_phys_base()		stub_true()
#define get_machdep_info()	get_machdep_info_ppc()
#define get_versiondep_info()	stub_true()
#define get_kaslr_offset(X)	stub_false()
#define vaddr_to_paddr(X)	vaddr_to_paddr_ppc(X)
#define paddr_to_vaddr(X)	paddr_to_vaddr_general(X)
#define is_phys_addr(X)		stub_true_ul(X)
#define arch_crashkernel_mem_size()	stub_false()
#endif          /* powerpc32 */

#ifdef __s390x__ /* s390x */
int get_machdep_info_s390x(void);
unsigned long long vaddr_to_paddr_s390x(unsigned long vaddr);
int is_iomem_phys_addr_s390x(unsigned long addr);
#define find_vmemmap()		stub_false()
#define get_phys_base()		stub_true()
#define get_machdep_info()	get_machdep_info_s390x()
#define get_versiondep_info()	stub_true()
#define get_kaslr_offset(X)	stub_false()
#define vaddr_to_paddr(X)	vaddr_to_paddr_s390x(X)
#define paddr_to_vaddr(X)	paddr_to_vaddr_general(X)
#define is_phys_addr(X)		is_iomem_phys_addr_s390x(X)
#define arch_crashkernel_mem_size()	stub_false()
#endif          /* s390x */

#ifdef __ia64__ /* ia64 */
int get_phys_base_ia64(void);
int get_machdep_info_ia64(void);
unsigned long long vaddr_to_paddr_ia64(unsigned long vaddr);
#define find_vmemmap()		stub_false()
#define get_machdep_info()	get_machdep_info_ia64()
#define get_phys_base()		get_phys_base_ia64()
#define get_versiondep_info()	stub_true()
#define get_kaslr_offset(X)	stub_false()
#define vaddr_to_paddr(X)	vaddr_to_paddr_ia64(X)
#define paddr_to_vaddr(X)	paddr_to_vaddr_general(X)
#define VADDR_REGION(X)		(((unsigned long)(X)) >> REGION_SHIFT)
#define is_phys_addr(X)		stub_true_ul(X)
#define arch_crashkernel_mem_size()	stub_false()
#endif          /* ia64 */

#ifdef __sparc64__ /* sparc64 */
int get_versiondep_info_sparc64(void);
int get_phys_base_sparc64(void);
unsigned long long vaddr_to_paddr_sparc64(unsigned long vaddr);
#define find_vmemmap()          stub_false()
#define get_machdep_info()      TRUE
#define get_phys_base()         get_phys_base_sparc64()
#define get_versiondep_info()   get_versiondep_info_sparc64()
#define vaddr_to_paddr(X)       vaddr_to_paddr_sparc64(X)
#define paddr_to_vaddr(X)	paddr_to_vaddr_general(X)
#define is_phys_addr(X)		stub_true_ul(X)
#define arch_crashkernel_mem_size()	stub_false()
#endif		/* sparc64 */

typedef unsigned long long mdf_pfn_t;

#ifndef ARCH_PFN_OFFSET
#define ARCH_PFN_OFFSET		0
#endif
#define paddr_to_pfn(X) \
	(((unsigned long long)(X) >> PAGESHIFT()) - ARCH_PFN_OFFSET)
#define pfn_to_paddr(X) \
	(((mdf_pfn_t)(X) + ARCH_PFN_OFFSET) << PAGESHIFT())

/* Format of Xen crash info ELF note */
typedef struct {
	unsigned long xen_major_version;
	unsigned long xen_minor_version;
	unsigned long xen_extra_version;
	unsigned long xen_changeset;
	unsigned long xen_compiler;
	unsigned long xen_compile_date;
	unsigned long xen_compile_time;
	unsigned long tainted;
} xen_crash_info_com_t;

typedef struct {
	xen_crash_info_com_t com;
#if defined(__x86__) || defined(__x86_64__)
	/* added by changeset 2b43fb3afb3e: */
	unsigned long dom0_pfn_to_mfn_frame_list_list;
#endif
#if defined(__ia64__)
	/* added by changeset d7c3b12014b3: */
	unsigned long dom0_mm_pgd_mfn;
#endif
} xen_crash_info_t;

/* changeset 439a3e9459f2 added xen_phys_start
 * to the middle of the struct... */
typedef struct {
	xen_crash_info_com_t com;
#if defined(__x86__) || defined(__x86_64__)
	unsigned long xen_phys_start;
	unsigned long dom0_pfn_to_mfn_frame_list_list;
#endif
#if defined(__ia64__)
	unsigned long dom0_mm_pgd_mfn;
#endif
} xen_crash_info_v2_t;

struct mem_map_data {
	mdf_pfn_t	pfn_start;
	mdf_pfn_t	pfn_end;
	unsigned long	mem_map;
};

struct dump_bitmap {
	int		fd;
	int		no_block;
	char		*file_name;
	char		*buf;
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
typedef unsigned long int ulong;
typedef unsigned long long int ulonglong;

/*
 * for parallel process
 */

#define PAGE_FLAG_NUM	(20)
#define PAGE_DATA_NUM	(5)
#define WAIT_TIME	(60 * 10)
#define PTHREAD_FAIL	((void *)-2)
#define THREAD_REGION	(200 * 1024)

struct mmap_cache {
	char	*mmap_buf;
	off_t	mmap_start_offset;
	off_t   mmap_end_offset;
};

enum {
	FLAG_UNUSED,
	FLAG_READY,
	FLAG_FILLING
};
struct page_flag {
	mdf_pfn_t pfn;
	char zero;
	char ready;
	short index;
	struct page_flag *next;
};

struct page_data
{
	long size;
	unsigned char *buf;
	int flags;
	int used;
};

struct thread_args {
	int thread_num;
	unsigned long len_buf_out;
	struct cycle *cycle;
	struct page_data *page_data_buf;
	struct page_flag *page_flag_buf;
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
	mdf_pfn_t		start_pfn;
	mdf_pfn_t		end_pfn;
	off_t			offset_eraseinfo;
	unsigned long		size_eraseinfo;
} splitting_info_t;

struct parallel_info {
	int			fd_memory;
	int 			fd_bitmap_memory;
	int			fd_bitmap;
	unsigned char		*buf;
	unsigned char 		*buf_out;
	struct mmap_cache	*mmap_cache;
	z_stream		zlib_stream;
#ifdef USELZO
	lzo_bytep		wrkmem;
#endif
} parallel_info_t;

struct ppc64_vmemmap {
	unsigned long		phys;
	unsigned long		virt;
};

struct DumpInfo {
	int32_t		kernel_version;      /* version of first kernel*/
	struct timeval	timestamp;
	struct utsname	system_utsname;

	/*
	 * General info:
	 */
	int		dump_level;          /* current dump level */
	int		max_dump_level;      /* maximum dump level */
	int		num_dump_level;      /* number of dump level */
	int		array_dump_level[NUM_ARRAY_DUMP_LEVEL];
	int		flag_compress;       /* flag of compression */
	int		flag_lzo_support;    /* flag of LZO compression support */
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
	int		flag_cyclic;	     /* multi-cycle processing is necessary */
	int		flag_usemmap;	     /* /proc/vmcore supports mmap(2) */
	int		flag_reassemble;     /* reassemble multiple dumpfiles into one */
	int		flag_refiltering;    /* refilter from kdump-compressed file */
	int		flag_force;	     /* overwrite existing stuff */
	int		flag_exclude_xen_dom;/* exclude Domain-U from xen-kdump */
	int             flag_dmesg;          /* dump the dmesg log out of the vmcore file */
	int             flag_partial_dmesg;  /* dmesg dump only from the last cleared index*/
	int             flag_mem_usage;  /*show the page number of memory in different use*/
	int		flag_use_printk_log; /* did we read printk_log symbol name? */
	int		flag_nospace;	     /* the flag of "No space on device" error */
	int		flag_vmemmap;        /* kernel supports vmemmap address space */
	int		flag_excludevm;      /* -e - excluding unused vmemmap pages */
	int		flag_use_count;      /* _refcount is named _count in struct page */
	unsigned long	vaddr_for_vtop;      /* virtual address for debugging */
	long		page_size;           /* size of page */
	long		page_shift;
	mdf_pfn_t	max_mapnr;   /* number of page descriptor */
	unsigned long   page_offset;
	unsigned long   section_size_bits;
	unsigned long   max_physmem_bits;
	unsigned long   sections_per_root;
	unsigned long	phys_base;
	unsigned long   kernel_start;
	unsigned long   vmalloc_start;
	unsigned long   vmalloc_end;
	unsigned long	vmemmap_start;
	unsigned long	vmemmap_end;
	int		vmemmap_psize;
	int		vmemmap_cnt;
	struct ppc64_vmemmap	*vmemmap_list;
	unsigned long	kaslr_offset;

	/*
	 * page table info for ppc64
	 */
	int		cur_mmu_type;
	int		ptrs_per_pgd;
	uint		l4_index_size;
	uint		l3_index_size;
	uint		l2_index_size;
	uint		l1_index_size;
	uint		ptrs_per_l4;
	uint		ptrs_per_l3;
	uint		ptrs_per_l2;
	uint		ptrs_per_l1;
	uint		l4_shift;
	uint		l3_shift;
	uint		l2_shift;
	uint		l1_shift;
	uint		pte_rpn_shift;
	ulong		pte_rpn_mask;
	ulong		pgd_masked_bits;
	ulong		pud_masked_bits;
	ulong		pmd_masked_bits;
	ulong		kernel_pgd;
	char		*page_buf; /* Page buffer to read page tables */

	/*
	 * Filter config file containing filter commands to filter out kernel
	 * data from vmcore.
	 */
	char		*name_filterconfig;
	FILE		*file_filterconfig;

	/*
	 * Filter config file containing eppic language filtering rules
	 * to filter out kernel data from vmcore
	 */
	char		*name_eppic_config;

	/*
	 * diskdimp info:
	 */
	int		block_order;
	off_t		offset_bitmap1;
	unsigned long	len_bitmap;          /* size of bitmap(1st and 2nd) */
	struct dump_bitmap 		*bitmap1;
	struct dump_bitmap 		*bitmap2;
	struct disk_dump_header		*dump_header;
	struct kdump_sub_header		sub_header;

	/*
	 * ELF header info:
	 */
	unsigned int		num_load_dumpfile;
	size_t			offset_load_dumpfile;

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
	struct disk_dump_header	*dh_memory;
	struct kdump_sub_header	*kh_memory;
	struct dump_bitmap 		*bitmap_memory;
	unsigned long			*valid_pages;

	/*
	 * Dump file info:
	 */
	int			fd_dumpfile;
	char			*name_dumpfile;
	int			num_dumpfile;
	struct splitting_info	*splitting_info;
	struct parallel_info	*parallel_info;

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
	int			read_text_vmcoreinfo;

	/*
	 * ELF NOTE section in dump memory image info:
	 */
	off_t			offset_note_dumpfile;

	/*
	 * erased information in dump memory image info:
	 */
	unsigned long           size_elf_eraseinfo;

	/*
	 * for Xen extraction
	 */
	union {				/* Both versions of Xen crash info: */
		xen_crash_info_com_t *com;   /* common fields */
		xen_crash_info_t *v1;	     /* without xen_phys_start */
		xen_crash_info_v2_t *v2;     /* changeset 439a3e9459f2 */
	} xen_crash_info;
	int xen_crash_info_v;		/* Xen crash info version:
					 *   0 .. xen_crash_info_com_t
					 *   1 .. xen_crash_info_t
					 *   2 .. xen_crash_info_v2_t */

	mdf_pfn_t	dom0_mapnr;	/* The number of page in domain-0.
					 * Different from max_mapnr.
					 * max_mapnr is the number of page
					 * in system. */
	unsigned long xen_phys_start;
	unsigned long xen_heap_start;	/* start mfn of xen heap area */
	unsigned long xen_heap_end;	/* end mfn(+1) of xen heap area */
	unsigned long frame_table_vaddr;
	unsigned long max_page;
	unsigned long alloc_bitmap;
	unsigned long dom0;
	unsigned long p2m_frames;
	unsigned long *p2m_mfn_frame_list;
	int	num_domain;
	struct domain_list *domain_list;
#if defined(__x86_64__)
	unsigned long xen_virt_start;
	unsigned long directmap_virt_end;
#endif

	/*
	 * for splitting
	 */
	mdf_pfn_t split_start_pfn;
	mdf_pfn_t split_end_pfn;

	/*
	 * for cyclic processing
	 */
	char	           *working_dir;	     /* working directory for bitmap */
	mdf_pfn_t          num_dumpable;
	unsigned long      bufsize_cyclic;
	unsigned long      pfn_cyclic;

	/*
	 * for mmap
	 */
	char	*mmap_buf;
	off_t	mmap_start_offset;
	off_t	mmap_end_offset;
	off_t   mmap_region_size;

	/*
	 * sadump info:
	 */
	int flag_sadump_diskset;
	enum sadump_format_type flag_sadump;         /* sadump format type */
	/*
	 * for filtering free pages managed by buddy system:
	 */
	int (*page_is_buddy)(unsigned long flags, unsigned int _mapcount,
			     unsigned long private, unsigned int _count);
	/*
	 * for cyclic_splitting mode, setup splitblock_size
	 */
	long long splitblock_size;
	/*
	 * for parallel process
	 */
	int num_threads;
	int num_buffers;
	pthread_t **threads;
	struct thread_args *kdump_thread_args;
	struct page_data *page_data_buf;
	struct page_flag **page_flag_buf;
	sem_t page_flag_buf_sem;
	pthread_rwlock_t usemmap_rwlock;
	mdf_pfn_t current_pfn;
	pthread_mutex_t current_pfn_mutex;
	pthread_mutex_t page_data_mutex;
	pthread_mutex_t filter_mutex;
};
extern struct DumpInfo		*info;

/*
 * for cyclic_splitting mode,Manage memory by splitblock
 */
#define DEFAULT_SPLITBLOCK_SIZE (1LL << 30)

struct SplitBlock {
	char *table;
	long long num;
	long long page_per_splitblock;
	int entry_size;                 /* counted by byte */
};

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

/*
 * Loaded module symbols info.
 */
#define MOD_NAME_LEN	64
#define IN_RANGE(addr, mbase, sz) \
	(((unsigned long)(addr) >= (unsigned long)mbase) \
	&& ((unsigned long)addr < (unsigned long)(mbase + sz)))

struct symbol_info {
	char			*name;
	unsigned long long	value;
};

struct module_info {
	char			name[MOD_NAME_LEN];
	unsigned int		num_syms;
	struct symbol_info	*sym_info;
};


struct symbol_table {
	unsigned long long	mem_map;
	unsigned long long	vmem_map;
	unsigned long long	mem_section;
	unsigned long long	pkmap_count;
	unsigned long long	pkmap_count_next;
	unsigned long long	system_utsname;
	unsigned long long	init_uts_ns;
	unsigned long long	_stext;
	unsigned long long	swapper_pg_dir;
	unsigned long long	init_level4_pgt;
	unsigned long long	level4_kernel_pgt;
	unsigned long long	init_top_pgt;
	unsigned long long	vmlist;
	unsigned long long	vmap_area_list;
	unsigned long long	phys_base;
	unsigned long long	node_online_map;
	unsigned long long	node_states;
	unsigned long long	node_memblk;
	unsigned long long	node_data;
	unsigned long long	pgdat_list;
	unsigned long long	contig_page_data;
	unsigned long long	log_buf;
	unsigned long long	log_buf_len;
	unsigned long long	log_end;
	unsigned long long	log_first_idx;
	unsigned long long	clear_idx;
	unsigned long long	log_next_idx;
	unsigned long long	max_pfn;
	unsigned long long	node_remap_start_vaddr;
	unsigned long long	node_remap_end_vaddr;
	unsigned long long	node_remap_start_pfn;
	unsigned long long      free_huge_page;

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

	/*
	 * for loading module symbol data
	 */

	unsigned long long	modules;

	/*
	 * vmalloc_start address on s390x arch
	 */
	unsigned long long	high_memory;

	/*
	 * for sadump
	 */
	unsigned long long	linux_banner;
	unsigned long long	bios_cpu_apicid;
	unsigned long long	x86_bios_cpu_apicid;
	unsigned long long	x86_bios_cpu_apicid_early_ptr;
	unsigned long long	x86_bios_cpu_apicid_early_map;
	unsigned long long	crash_notes;
	unsigned long long	__per_cpu_offset;
	unsigned long long	__per_cpu_load;
	unsigned long long	cpu_online_mask;
	unsigned long long	__cpu_online_mask;
	unsigned long long	kexec_crash_image;
	unsigned long long	divide_error;
	unsigned long long	idt_table;
	unsigned long long	saved_command_line;
	unsigned long long	pti_init;
	unsigned long long	kaiser_init;

	/*
	 * symbols on ppc64 arch
	 */
	unsigned long long		vmemmap_list;
	unsigned long long		mmu_vmemmap_psize;
	unsigned long long		mmu_psize_defs;
	unsigned long long		cpu_pgd;
	unsigned long long		demote_segment_4k;
	unsigned long long		cur_cpu_spec;

	/*
	 * symbols on sparc64 arch
	 */
	unsigned long long		vmemmap_table;
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
	long	printk_log;

	/*
	 * for Xen extraction
	 */
	long	page_info;
	long	domain;

	/*
	 * for loading module symbol data
	 */
	long	module;

	/*
	 * for sadump
	 */
	long	percpu_data;
	long	elf_prstatus;
	long	user_regs_struct;
	long	cpumask;
	long	cpumask_t;
	long	kexec_segment;
	long	elf64_hdr;

	/*
	 * symbols on ppc64 arch
	 */
	long	vmemmap_backing;
	long	mmu_psize_def;
	long	cpu_spec;

	long	pageflags;
};

struct offset_table {
	struct page {
		long	flags;
		long	_refcount;
		long	mapping;
		long	lru;
		long	_mapcount;
		long	private;
		long	compound_dtor;
		long	compound_order;
		long	compound_head;
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
	struct vmap_area {
		long	va_start;
		long	list;
	} vmap_area;

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

	/*
	 * for loading module symbol data
	 */
	struct module {
		long	list;
		long	name;
		long	module_core;
		long	core_size;
		long	module_init;
		long	init_size;
		long	num_symtab;
		long	symtab;
		long	strtab;
	} module;

	/*
	 * for loading elf_prstaus symbol data
	 */
	struct elf_prstatus_s {
		long	pr_reg;
	} elf_prstatus;

	/*
	 * for loading user_regs_struct symbol data
	 */
	struct user_regs_struct_s {
		long	r15;
		long	r14;
		long	r13;
		long	r12;
		long	bp;
		long	bx;
		long	r11;
		long	r10;
		long	r9;
		long	r8;
		long	ax;
		long	cx;
		long	dx;
		long	si;
		long	di;
		long	orig_ax;
		long	ip;
		long	cs;
		long	flags;
		long	sp;
		long	ss;
		long	fs_base;
		long	gs_base;
		long	ds;
		long	es;
		long	fs;
		long	gs;
	} user_regs_struct;

	struct kimage_s {
		long	segment;
	} kimage;

	struct kexec_segment_s {
		long	mem;
	} kexec_segment;

	struct elf64_hdr_s {
		long	e_phnum;
		long	e_phentsize;
		long	e_phoff;
	} elf64_hdr;

	struct elf64_phdr_s {
		long	p_type;
		long	p_offset;
		long	p_paddr;
		long	p_memsz;
	} elf64_phdr;

	struct printk_log_s {
		long ts_nsec;
		long len;
		long text_len;
	} printk_log;

	/*
	 * symbols on ppc64 arch
	 */
	struct mmu_psize_def_s {
		long	shift;
	} mmu_psize_def;

	struct vmemmap_backing_s {
		long	phys;
		long	virt_addr;
		long	list;
	} vmemmap_backing;

	struct cpu_spec_s {
		long	mmu_features;
	} cpu_spec;
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
	long	__per_cpu_offset;
	long	node_remap_start_pfn;

	/*
	 * Structure
	 */
	struct zone_at {
		long	free_area;
	} zone;
	struct free_area_at {
		long	free_list;
	} free_area;
	struct kimage_at {
		long	segment;
	} kimage;
};

struct number_table {
	long	NR_FREE_PAGES;
	long	N_ONLINE;
	long	pgtable_l5_enabled;

	/*
 	* Page flags
	 */
	long	PG_lru;
	long	PG_private;
	long	PG_head;
	long	PG_head_mask;
	long	PG_swapcache;
	long	PG_swapbacked;
	long	PG_buddy;
	long	PG_slab;
	long    PG_hwpoison;

	long	PAGE_BUDDY_MAPCOUNT_VALUE;
	long	SECTION_SIZE_BITS;
	long	MAX_PHYSMEM_BITS;
	long    HUGETLB_PAGE_DTOR;
	long	phys_base;
#ifdef __aarch64__
	long 	VA_BITS;
	unsigned long	PHYS_OFFSET;
	unsigned long	kimage_voffset;
#endif
};

struct srcfile_table {
	/*
	 * typedef
	 */
	char	pud_t[LEN_SRCFILE];
};

/*
 * This structure records where the vmemmap page structures reside, and which
 * pfn's are represented by those page structures.
 * The actual pages containing the page structures are 2MB pages, so their pfn's
 * will all be multiples of 0x200.
 * The page structures are 7 64-bit words in length (0x38) so they overlap the
 * 2MB boundaries. Each page structure represents a 4k page.
 * A 4k page is here defined to be represented on a 2MB page if its page structure
 * 'ends' on that page (even if it began on the page before).
 */
struct vmap_pfns {
       struct vmap_pfns *next;
       struct vmap_pfns *prev;
       /*
	* These (start/end) are literal pfns of 2MB pages on which the page
	* structures reside, not start and end+1.
	*/
       unsigned long vmap_pfn_start;
       unsigned long vmap_pfn_end;
       /*
	* These (start/end) are literal pfns represented on these pages, not
	* start and end+1.
	* The starting page struct is at least partly on the first page; the
	* ending page struct is entirely on the last page.
	*/
       unsigned long rep_pfn_start;
       unsigned long rep_pfn_end;
};

/* for saving a list of pfns to a buffer, and then to a file if necessary */
struct save_control {
       int sc_fd;
       char *sc_filename;
       char *sc_buf;
       long sc_buflen; /* length of buffer never changes */
       long sc_bufposition; /* offset of next slot for write, or next to be read */
       long sc_filelen; /* length of valid data written */
       long sc_fileposition; /* offset in file of next entry to be read */
};
/* one entry in the buffer and file */
struct sc_entry {
       unsigned long startpfn;
       unsigned long numpfns;
};

extern struct symbol_table	symbol_table;
extern struct size_table	size_table;
extern struct offset_table	offset_table;
extern struct array_table	array_table;
extern struct number_table	number_table;
extern struct srcfile_table	srcfile_table;

struct memory_range {
	unsigned long long start, end;
};

#define CRASH_RESERVED_MEM_NR   8
struct memory_range crash_reserved_mem[CRASH_RESERVED_MEM_NR];
int crash_reserved_mem_nr;

unsigned long read_vmcoreinfo_symbol(char *str_symbol);
int readmem(int type_addr, unsigned long long addr, void *bufptr, size_t size);
int get_str_osrelease_from_vmlinux(void);
int read_vmcoreinfo_xen(void);
int exclude_xen_user_domain(void);
mdf_pfn_t get_num_dumpable(void);
int __read_disk_dump_header(struct disk_dump_header *dh, char *filename);
int read_disk_dump_header(struct disk_dump_header *dh, char *filename);
int read_kdump_sub_header(struct kdump_sub_header *kh, char *filename);
void close_vmcoreinfo(void);
int close_files_for_creating_dumpfile(void);
int iomem_for_each_line(char *match, int (*callback)(void *data, int nr,
						     char *str,
						     unsigned long base,
						     unsigned long length),
			void *data);
int is_bigendian(void);
int get_symbol_info(void);

/*
 * for Xen extraction
 */
struct domain_list {
	unsigned long domain_addr;
	unsigned int  domain_id;
	unsigned int  pickled_id;
};

#define PAGES_PER_MAPWORD 	(sizeof(unsigned long) * 8)
#define MFNS_PER_FRAME		(info->page_size / sizeof(unsigned long))

#ifdef __aarch64__
unsigned long long kvtop_xen_arm64(unsigned long kvaddr);
#define kvtop_xen(X)	kvtop_xen_arm64(X)
#endif /* aarch64 */

#ifdef __arm__
#define kvtop_xen(X)	FALSE
#define get_xen_basic_info_arch(X) FALSE
#define get_xen_info_arch(X) FALSE
#endif	/* arm */

#ifdef __x86__
#define HYPERVISOR_VIRT_START_PAE	(0xF5800000UL)
#define HYPERVISOR_VIRT_START		(0xFC000000UL)
#define HYPERVISOR_VIRT_END		(0xFFFFFFFFUL)
#define DIRECTMAP_VIRT_START		(0xFF000000UL)
#define DIRECTMAP_VIRT_END		(0xFFC00000UL)
#define FRAMETABLE_VIRT_START		(0xF6800000UL)

#define is_xen_vaddr(x) \
	((x) >= HYPERVISOR_VIRT_START_PAE && (x) < HYPERVISOR_VIRT_END)
#define is_direct(x) \
	((x) >= DIRECTMAP_VIRT_START && (x) < DIRECTMAP_VIRT_END)

unsigned long long kvtop_xen_x86(unsigned long kvaddr);
#define kvtop_xen(X)	kvtop_xen_x86(X)

int get_xen_basic_info_x86(void);
#define get_xen_basic_info_arch(X) get_xen_basic_info_x86(X)
int get_xen_info_x86(void);
#define get_xen_info_arch(X) get_xen_info_x86(X)

#endif	/* __x86__ */

#ifdef __x86_64__

/* The architectural limit for physical addresses is 52 bits.
 * Mask off bits 52-62 (available for OS use) and bit 63 (NX).
 */
#define ENTRY_MASK		(~0xfff0000000000fffULL)
#define MAX_X86_64_FRAMES	(info->page_size / sizeof(unsigned long))

#define PAGE_OFFSET_XEN_DOM0		(0xffff880000000000) /* different from linux */
#define HYPERVISOR_VIRT_START		(0xffff800000000000)
#define HYPERVISOR_VIRT_END		(0xffff880000000000)
#define DIRECTMAP_VIRT_START		(0xffff830000000000)
#define DIRECTMAP_VIRT_END_V3		(0xffff840000000000)
#define DIRECTMAP_VIRT_END_V4		(0xffff880000000000)
#define DIRECTMAP_VIRT_END		(info->directmap_virt_end)
#define XEN_VIRT_START			(info->xen_virt_start)
#define XEN_VIRT_END			(XEN_VIRT_START + (1UL << 30))
#define FRAMETABLE_VIRT_START_V3	0xffff82f600000000
#define FRAMETABLE_VIRT_START_V4_3	0xffff82e000000000

#define is_xen_vaddr(x) \
	((x) >= HYPERVISOR_VIRT_START && (x) < HYPERVISOR_VIRT_END)
#define is_direct(x) \
	((x) >= DIRECTMAP_VIRT_START && (x) < DIRECTMAP_VIRT_END)
#define is_xen_text(x) \
	((x) >= XEN_VIRT_START && (x) < XEN_VIRT_END)

unsigned long long kvtop_xen_x86_64(unsigned long kvaddr);
#define kvtop_xen(X)	kvtop_xen_x86_64(X)

int get_xen_basic_info_x86_64(void);
#define get_xen_basic_info_arch(X) get_xen_basic_info_x86_64(X)
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

int get_xen_basic_info_ia64(void);
#define get_xen_basic_info_arch(X) get_xen_basic_info_ia64(X)
int get_xen_info_ia64(void);
#define get_xen_info_arch(X) get_xen_info_ia64(X)

#endif	/* __ia64 */

#if defined(__powerpc64__) || defined(__powerpc32__) /* powerpcXX */
#define kvtop_xen(X)	FALSE
#define get_xen_basic_info_arch(X) FALSE
#define get_xen_info_arch(X) FALSE
#endif	/* powerpcXX */

#ifdef __s390x__ /* s390x */
#define kvtop_xen(X)	FALSE
#define get_xen_basic_info_arch(X) FALSE
#define get_xen_info_arch(X) FALSE
#endif	/* s390x */

#ifdef __sparc64__ /* sparc64 */
#define kvtop_xen(X)	FALSE
#define get_xen_basic_info_arch(X) FALSE
#define get_xen_info_arch(X) FALSE
#endif	/* sparc64 */

struct cycle {
	mdf_pfn_t start_pfn;
	mdf_pfn_t end_pfn;

	/* for excluding multi-page regions */
	mdf_pfn_t exclude_pfn_start;
	mdf_pfn_t exclude_pfn_end;
	mdf_pfn_t *exclude_pfn_counter;
};

static inline int
is_on(char *bitmap, mdf_pfn_t i)
{
	return bitmap[i>>3] & (1 << (i & 7));
}

static inline int
is_cyclic_region(mdf_pfn_t pfn, struct cycle *cycle)
{
	if (pfn < cycle->start_pfn || cycle->end_pfn <= pfn)
		return FALSE;
	else
		return TRUE;
}

static inline int
is_dumpable_buffer(struct dump_bitmap *bitmap, mdf_pfn_t pfn, struct cycle *cycle)
{
	if (!is_cyclic_region(pfn, cycle))
		return FALSE;
	else
		return is_on(bitmap->buf, pfn - cycle->start_pfn);
}

static inline int
is_dumpable_file(struct dump_bitmap *bitmap, mdf_pfn_t pfn)
{
	off_t offset;
	ssize_t rcode;
	if (pfn == 0 || bitmap->no_block != pfn/PFN_BUFBITMAP) {
		offset = bitmap->offset + BUFSIZE_BITMAP*(pfn/PFN_BUFBITMAP);
		if (lseek(bitmap->fd, offset, SEEK_SET) < 0 ) {
			ERRMSG("Can't seek the bitmap(%s). %s\n",
				bitmap->file_name, strerror(errno));
			return FALSE;
		}

		rcode = read(bitmap->fd, bitmap->buf, BUFSIZE_BITMAP);
		if (rcode != BUFSIZE_BITMAP)
			ERRMSG("Can't read the bitmap(%s). %s\n",
				bitmap->file_name, strerror(errno));
		if (pfn == 0)
			bitmap->no_block = 0;
		else
			bitmap->no_block = pfn/PFN_BUFBITMAP;
	}
	return is_on(bitmap->buf, pfn%PFN_BUFBITMAP);
}

static inline int
is_dumpable(struct dump_bitmap *bitmap, mdf_pfn_t pfn, struct cycle *cycle)
{
	if (bitmap->fd < 0) {
		return is_dumpable_buffer(bitmap, pfn, cycle);
	} else {
		return is_dumpable_file(bitmap, pfn);
	}
}

static inline int
is_zero_page(unsigned char *buf, long page_size)
{
	size_t i;
	unsigned long long *vect = (unsigned long long *) buf;
	long page_len = page_size / sizeof(unsigned long long);

	for (i = 0; i < page_len; i++)
		if (vect[i])
			return FALSE;
	return TRUE;
}

void write_vmcoreinfo_data(void);
int set_bit_on_1st_bitmap(mdf_pfn_t pfn, struct cycle *cycle);
int clear_bit_on_1st_bitmap(mdf_pfn_t pfn, struct cycle *cycle);

#ifdef __x86__

struct user_regs_struct {
	unsigned long bx;
	unsigned long cx;
	unsigned long dx;
	unsigned long si;
	unsigned long di;
	unsigned long bp;
	unsigned long ax;
	unsigned long ds;
	unsigned long es;
	unsigned long fs;
	unsigned long gs;
	unsigned long orig_ax;
	unsigned long ip;
	unsigned long cs;
	unsigned long flags;
	unsigned long sp;
	unsigned long ss;
};

struct elf_prstatus {
	char pad1[72];
	struct user_regs_struct pr_reg;
	char pad2[4];
};

#endif

#ifdef __x86_64__

struct user_regs_struct {
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long bp;
	unsigned long bx;
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long ax;
	unsigned long cx;
	unsigned long dx;
	unsigned long si;
	unsigned long di;
	unsigned long orig_ax;
	unsigned long ip;
	unsigned long cs;
	unsigned long flags;
	unsigned long sp;
	unsigned long ss;
	unsigned long fs_base;
	unsigned long gs_base;
	unsigned long ds;
	unsigned long es;
	unsigned long fs;
	unsigned long gs;
};

struct elf_prstatus {
	char pad1[112];
	struct user_regs_struct pr_reg;
	char pad2[4];
};

#endif

/*
 * Below are options which getopt_long can recognize. From OPT_START options are
 * non-printable, just used for implementation.
 */
#define OPT_BLOCK_ORDER         'b'
#define OPT_COMPRESS_ZLIB       'c'
#define OPT_DEBUG               'D'
#define OPT_DUMP_LEVEL          'd'
#define OPT_ELF_DUMPFILE        'E'
#define OPT_EXCLUDE_UNUSED_VM   'e'
#define OPT_FLATTEN             'F'
#define OPT_FORCE               'f'
#define OPT_GENERATE_VMCOREINFO 'g'
#define OPT_HELP                'h'
#define OPT_READ_VMCOREINFO     'i'
#define OPT_COMPRESS_LZO        'l'
#define OPT_COMPRESS_SNAPPY     'p'
#define OPT_REARRANGE           'R'
#define OPT_VERSION             'v'
#define OPT_EXCLUDE_XEN_DOM     'X'
#define OPT_VMLINUX             'x'
#define OPT_START               256
#define OPT_SPLIT               OPT_START+0
#define OPT_REASSEMBLE          OPT_START+1
#define OPT_XEN_SYMS            OPT_START+2
#define OPT_XEN_VMCOREINFO      OPT_START+3
#define OPT_XEN_PHYS_START      OPT_START+4
#define OPT_MESSAGE_LEVEL       OPT_START+5
#define OPT_VTOP                OPT_START+6
#define OPT_DUMP_DMESG          OPT_START+7
#define OPT_CONFIG              OPT_START+8
#define OPT_DISKSET             OPT_START+9
#define OPT_CYCLIC_BUFFER       OPT_START+10
#define OPT_EPPIC               OPT_START+11
#define OPT_NON_MMAP            OPT_START+12
#define OPT_MEM_USAGE           OPT_START+13
#define OPT_SPLITBLOCK_SIZE     OPT_START+14
#define OPT_WORKING_DIR         OPT_START+15
#define OPT_NUM_THREADS         OPT_START+16
#define OPT_PARTIAL_DMESG       OPT_START+17

/*
 * Function Prototype.
 */
mdf_pfn_t get_num_dumpable_cyclic(void);
mdf_pfn_t get_num_dumpable_cyclic_withsplit(void);
int get_loads_dumpfile_cyclic(void);
int initial_xen(void);
unsigned long long ptom_xen(unsigned long long paddr);
unsigned long long get_free_memory_size(void);
int calculate_cyclic_buffer_size(void);
int prepare_splitblock_table(void);
int initialize_zlib(z_stream *stream, int level);
int finalize_zlib(z_stream *stream);

int parse_line(char *str, char *argv[]);
char *shift_string_left(char *s, int cnt);
char *clean_line(char *line);
char *strip_linefeeds(char *line);
char *strip_beginning_whitespace(char *line);
char *strip_ending_whitespace(char *line);
ulong htol(char *s, int flags);
int hexadecimal(char *s, int count);
int decimal(char *s, int count);
int file_exists(char *file);

#endif /* MAKEDUMPFILE_H */
