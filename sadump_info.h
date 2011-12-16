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

#if defined(__x86__) || defined(__x86_64__)

int check_and_get_sadump_header_info(char *filename);
int sadump_initialize_bitmap_memory(void);
int sadump_get_nr_cpus(int *nr_cpus);
int sadump_set_timestamp(struct timeval *ts);
unsigned long long sadump_get_max_mapnr(void);
int sadump_add_diskset_info(char *name_memory);
long sadump_page_size(void);
char *sadump_head_disk_name_memory(void);
char *sadump_format_type_name(void);
void free_sadump_info(void);

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

static inline int sadump_initialize_bitmap_memory(void)
{
	return FALSE;
}

static inline int sadump_get_nr_cpus(int *nr_cpus)
{
	return 0;
}

static inline int sadump_set_timestamp(struct timeval *ts)
{
	return FALSE;
}

static inline unsigned long long sadump_get_max_mapnr(void)
{
	return 0;
}

static inline int sadump_add_diskset_info(char *name_memory)
{
	return TRUE;
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
	return NULL;
}

static inline void free_sadump_info(void)
{
	return;
}

static inline int sadump_is_supported_arch(void)
{
	return FALSE;
}

#endif

#endif /* _SADUMP_INFO_H */
