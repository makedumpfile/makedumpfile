/*
 * x86.c
 *
 * Copyright (C) 2006, 2007  NEC Corporation
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
#ifdef __x86__

#include "makedumpfile.h"

int
get_machdep_info_x86(void)
{
	/* PAE */
	if ((vt.mem_flags & MEMORY_X86_PAE)
	    || ((SYMBOL(pkmap_count) != NOT_FOUND_SYMBOL)
	      && (SYMBOL(pkmap_count_next) != NOT_FOUND_SYMBOL)
	      && ((SYMBOL(pkmap_count_next)-SYMBOL(pkmap_count))/sizeof(int))
	      == 512)) {
		DEBUG_MSG("\n");
		DEBUG_MSG("PAE          : ON\n");
		info->section_size_bits = _SECTION_SIZE_BITS_PAE;
		info->max_physmem_bits  = _MAX_PHYSMEM_BITS_PAE;
	} else {
		DEBUG_MSG("\n");
		DEBUG_MSG("PAE          : OFF\n");
		info->section_size_bits = _SECTION_SIZE_BITS;
		info->max_physmem_bits  = _MAX_PHYSMEM_BITS;
	}
	info->page_offset = __PAGE_OFFSET;

	return TRUE;
}

/*
 * for Xen extraction
 */
unsigned long long
kvtop_xen_x86(unsigned long kvaddr)
{
	unsigned long long dirp, entry;

	if (!is_xen_vaddr(kvaddr))
		return NOT_PADDR;

	if (is_direct(kvaddr))
		return (unsigned long)kvaddr - DIRECTMAP_VIRT_START;

	if ((dirp = kvtop_xen_x86(SYMBOL(pgd_l3))) == NOT_PADDR)
		return NOT_PADDR;
	dirp += ((kvaddr >> PGDIR_SHIFT_3LEVEL) & (PTRS_PER_PGD_3LEVEL - 1)) * sizeof(unsigned long long);
	if (!readmem(PADDR, dirp, &entry, sizeof(entry)))
		return NOT_PADDR;

	if (!(entry & _PAGE_PRESENT))
		return NOT_PADDR;

	dirp = entry & ENTRY_MASK;
	dirp += ((kvaddr >> PMD_SHIFT) & (PTRS_PER_PMD - 1)) * sizeof(unsigned long long);
	if (!readmem(PADDR, dirp, &entry, sizeof(entry)))
		return NOT_PADDR;

	if (!(entry & _PAGE_PRESENT))
		return NOT_PADDR;

	if (entry & _PAGE_PSE) {
		entry = (entry & ENTRY_MASK) + (kvaddr & ((1UL << PMD_SHIFT) - 1));
		return entry;
	}
	dirp = entry & ENTRY_MASK;
	dirp += ((kvaddr >> PTE_SHIFT) & (PTRS_PER_PTE - 1)) * sizeof(unsigned long long);
	if (!readmem(PADDR, dirp, &entry, sizeof(entry)))
		return NOT_PADDR;

	if (!(entry & _PAGE_PRESENT)) {
		return NOT_PADDR;
	}

	entry = (entry & ENTRY_MASK) + (kvaddr & ((1UL << PTE_SHIFT) - 1));

	return entry;
}

int get_xen_info_x86(void)
{
	unsigned long frame_table_vaddr;
	unsigned long xen_end;
	int i;

	if (SYMBOL(pgd_l2) == NOT_FOUND_SYMBOL &&
	    SYMBOL(pgd_l3) == NOT_FOUND_SYMBOL) {
		ERRMSG("Can't get pgd.\n");
		return FALSE;
	}

	if (SYMBOL(pgd_l3) == NOT_FOUND_SYMBOL) {
		ERRMSG("non-PAE not support right now.\n");
		return FALSE;
	}

	if (SYMBOL(frame_table) == NOT_FOUND_SYMBOL) {
		ERRMSG("Can't get the symbol of frame_table.\n");
		return FALSE;
	}
	if (!readmem(VADDR_XEN, SYMBOL(frame_table), &frame_table_vaddr,
	    sizeof(frame_table_vaddr))) {
		ERRMSG("Can't get the value of frame_table.\n");
		return FALSE;
	}
	info->frame_table_vaddr = frame_table_vaddr;

	if (SYMBOL(xenheap_phys_end) == NOT_FOUND_SYMBOL) {
		ERRMSG("Can't get the symbol of xenheap_phys_end.\n");
		return FALSE;
	}
	if (!readmem(VADDR_XEN, SYMBOL(xenheap_phys_end), &xen_end,
	    sizeof(xen_end))) {
		ERRMSG("Can't get the value of xenheap_phys_end.\n");
		return FALSE;
	}
	info->xen_heap_end = (xen_end >> PAGESHIFT());
	info->xen_heap_start = 0;

	/*
	 * pickled_id == domain addr for x86
	 */
	for (i = 0; i < info->num_domain; i++) {
		info->domain_list[i].pickled_id =
			info->domain_list[i].domain_addr;
	}

	return TRUE;
}
#endif /* x86 */

