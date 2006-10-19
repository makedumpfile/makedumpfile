/* 
 * ia64.c
 *
 * Copyright (C) 2006  NEC Corporation
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
#ifdef __ia64__

#include "makedumpfile.h"

extern struct symbol_table	symbol_table;
extern struct size_table	size_table;
extern struct offset_table	offset_table;

int
get_phys_base_ia64(struct DumpInfo *info)
{
	int i;
	struct pt_load_segment *pls;

	/*
	 *  Default to 64MB.
	 */
	info->phys_base = DEFAULT_PHYS_START;

	for (i = 0; i < info->num_load_memory; i++) {
		pls = &info->pt_load_segments[i];
		if (VADDR_REGION(pls->virt_start) == KERNEL_VMALLOC_REGION) {

			info->phys_base = pls->phys_start;
			break;
                }
        }
	return TRUE;
}

int
get_machdep_info_ia64(struct DumpInfo *info)
{
	info->section_size_bits = _SECTION_SIZE_BITS;

	return TRUE;
}

#endif /* ia64 */

