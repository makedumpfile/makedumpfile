/*
 * sadump_info.h
 *
 * Created by: HATAYAMA, Daisuke <d.hatayama@jp.fujitsu.com>
 *
 * Copyright (C) 2011  FUJITSU LIMITED
 * Copyright (C) 2011  NEC Corporation
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

#ifndef _SADUMP_INFO_H
#define _SADUMP_INFO_H

#include "makedumpfile.h"

#ifdef __x86_64__

int sadump_virt_phys_base(void);

#else

static inline int sadump_virt_phys_base(void)
{
	return TRUE;
}

#endif

#if defined(__x86__) || defined(__x86_64__)

int check_and_get_sadump_header_info(char *filename);
int sadump_copy_1st_bitmap_from_memory(void);
int sadump_initialize_bitmap_memory(void);
int sadump_num_online_cpus(void);
int sadump_set_timestamp(struct timeval *ts);
mdf_pfn_t sadump_get_max_mapnr(void);
int readpage_sadump(unsigned long long paddr, void *bufptr);
int sadump_check_debug_info(void);
int sadump_generate_vmcoreinfo_from_vmlinux(size_t *vmcoreinfo_size);
int sadump_generate_elf_note_from_dumpfile(void);
int sadump_copy_1st_bitmap_from_memory(void);
int sadump_add_diskset_info(char *name_memory);
int sadump_read_elf_note(char *buf, size_t size_note);
long sadump_page_size(void);
char *sadump_head_disk_name_memory(void);
char *sadump_format_type_name(void);
void free_sadump_info(void);
void sadump_kdump_backup_region_init(void);

static inline int sadump_is_supported_arch(void)
{
	return TRUE;
}

#else

static inline int check_and_get_sadump_header_info(char *filename)
{
	info->flag_sadump = SADUMP_UNKNOWN;

	DEBUG_MSG("sadump: unsupported architecture\n");

	return TRUE;
}

static inline int sadump_copy_1st_bitmap_from_memory(void)
{
	return FALSE;
}

static inline int sadump_initialize_bitmap_memory(void)
{
	return FALSE;
}

static inline int sadump_num_online_cpus(void)
{
	return 0;
}

static inline int sadump_set_timestamp(struct timeval *ts)
{
	return FALSE;
}

static inline mdf_pfn_t sadump_get_max_mapnr(void)
{
	return 0;
}

static inline int
readpage_sadump(unsigned long long paddr, void *bufptr)
{
	return FALSE;
}

static inline int sadump_check_debug_info(void)
{
	return FALSE;
}

static inline int
sadump_generate_vmcoreinfo_from_vmlinux(size_t *vmcoreinfo_size)
{
	return FALSE;
}

static inline int sadump_generate_elf_note_from_dumpfile(void)
{
	return FALSE;
}

static inline int sadump_add_diskset_info(char *name_memory)
{
	return TRUE;
}

static inline int sadump_read_elf_note(char *buf, size_t size_note)
{
	return FALSE;
}

static inline long sadump_page_size(void)
{
	return 0;
}

static inline char *
sadump_head_disk_name_memory(void)
{
	return NULL;
}

static inline char *sadump_format_type_name(void)
{
	return "";
}

static inline void free_sadump_info(void)
{
	return;
}

static inline int sadump_is_supported_arch(void)
{
	return FALSE;
}

static inline void sadump_kdump_backup_region_init(void)
{
	return;
}

#endif

#endif /* _SADUMP_INFO_H */
