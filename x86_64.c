/* 
 * x86_64.c
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
#ifdef __x86_64__

#include "makedumpfile.h"

/*
 *  Include both vmalloc'd and module address space as VMALLOC space.
 */
int
is_vmalloc_addr(ulong vaddr)
{
	return ((vaddr >= VMALLOC_START && vaddr <= VMALLOC_END) ||
	    (vaddr >= MODULES_VADDR && vaddr <= MODULES_END));
}

int
get_phys_base_x86_64(struct DumpInfo *info)
{
	int i;
	struct pt_load_segment *pls;

	/*
	 * Get the relocatable offset
	 */
	info->phys_base = 0; /* default/traditional */

	for (i = 0; i < info->num_load_memory; i++) {
		pls = &info->pt_load_segments[i];
		if ((pls->virt_start >= __START_KERNEL_map) &&
		    !(is_vmalloc_addr(pls->virt_start))) {

			info->phys_base = pls->phys_start -
			    (pls->virt_start & ~(__START_KERNEL_map));

			break;
		}
	}

	return TRUE;
}

int
get_machdep_info_x86_64(struct DumpInfo *info)
{
	info->section_size_bits = _SECTION_SIZE_BITS;
	info->max_physmem_bits  = _MAX_PHYSMEM_BITS;

	return TRUE;
}

off_t
vaddr_to_offset_x86_64(struct DumpInfo *info,  unsigned long vaddr)
{
	int i;
	off_t offset;
	unsigned long paddr, phys_base;
	struct pt_load_segment *pls;

	/*
	 * Check the relocatable kernel.
	 */
	if (SYMBOL(phys_base) != NOT_FOUND_SYMBOL)
		phys_base = info->phys_base;
	else
		phys_base = 0;

	if (vaddr >= __START_KERNEL_map)
		paddr = vaddr - __START_KERNEL_map + phys_base;
	else
		paddr = vaddr - PAGE_OFFSET;

	for (i = offset = 0; i < info->num_load_memory; i++) {
		pls = &info->pt_load_segments[i];
		if ((paddr >= pls->phys_start)
		    && (paddr < pls->phys_end)) {
			offset = (off_t)(paddr - pls->phys_start) +
				pls->file_offset;
				break;
		}
	}
	return offset;
}

#endif /* x86_64 */

