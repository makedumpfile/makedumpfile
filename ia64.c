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


/*
 *  vmalloc() starting address is either the traditional 0xa000000000000000 or
 *  bumped up in 2.6 to 0xa000000200000000.
 */
int
is_vmalloc_addr_ia64(struct DumpInfo *info, unsigned long vaddr)
{
	return ((vaddr >= info->vmalloc_start) &&
			(vaddr < (unsigned long)KERNEL_UNCACHED_BASE));
}

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
	info->max_physmem_bits  = _MAX_PHYSMEM_BITS;

	/*
	 * Get kernel_start and vmalloc_start.
	 */
	if (SYMBOL(_stext) == NOT_FOUND_SYMBOL)
		return FALSE;

	info->kernel_start = SYMBOL(_stext);

	if (VADDR_REGION(info->kernel_start) == KERNEL_VMALLOC_REGION)
		info->vmalloc_start = info->kernel_start + 4*1024UL*1024UL*1024UL;
	else
		info->vmalloc_start = KERNEL_VMALLOC_BASE;

	/*
	 * Check the pgtable (3 Levels or 4 Levels).
	 */
	if (!strncmp(SRCFILE(pud_t), STR_PUD_T_4L, strlen(STR_PUD_T_4L)))
		info->mem_flags |= MEMORY_PAGETABLE_4L;

	else if (!strncmp(SRCFILE(pud_t), STR_PUD_T_3L, strlen(STR_PUD_T_3L)))
		info->mem_flags |= MEMORY_PAGETABLE_3L;

	else
		MSG("Can't distinguish the pgtable.\n");

	return TRUE;
}

/*
 * Translate a virtual address to a physical address by using 3 levels paging.
 */
unsigned long
ia64_vtop3(struct DumpInfo *info, unsigned long long vaddr)
{
	unsigned long paddr, temp, page_dir, pgd_pte, page_middle, pmd_pte;
	unsigned long page_table, pte;

	if (SYMBOL(swapper_pg_dir) == NOT_FOUND_SYMBOL) {
		ERRMSG("Can't get the symbol of swapper_pg_dir.\n");
		return 0x0;
	}

	/*
	 * Get PGD
	 */
	temp = vaddr & MASK_PGD_3L;
	temp = temp >> (PGDIR_SHIFT_3L - 3);
	page_dir = SYMBOL(swapper_pg_dir) + temp;
	if (!readmem(info, page_dir, &pgd_pte, sizeof pgd_pte)) {
		ERRMSG("Can't get pgd_pte (page_dir:%lx).\n", page_dir);
		return 0x0;
	}

	/*
	 * Get PMD
	 */
	temp = vaddr & MASK_PMD;
	temp = temp >> (PMD_SHIFT - 3);
	page_middle = pgd_pte + temp;
	page_middle = paddr_to_vaddr(info, page_middle);
	if (!readmem(info, page_middle, &pmd_pte, sizeof pmd_pte)) {
		ERRMSG("Can't get pmd_pte (page_middle:%lx).\n", page_middle);
		return 0x0;
	}

	/*
	 * Get PTE
	 */
	temp = vaddr & MASK_PTE;
	temp = temp >> (PAGE_SHIFT - 3);
	page_table = pmd_pte + temp;
	page_table = paddr_to_vaddr(info, page_table);
	if (!readmem(info, page_table, &pte, sizeof pte)) {
		ERRMSG("Can't get pte (page_table:%lx).\n", page_table);
		return 0x0;
	}

	/*
	 * Get physical address
	 */
	temp = vaddr & MASK_POFFSET;
	paddr = (pte & _PAGE_PPN_MASK) + temp;

	return paddr;
}

/*
 * Translate a virtual address to a physical address by using 4 levels paging.
 */
unsigned long
ia64_vtop4(struct DumpInfo *info, unsigned long long vaddr)
{
	unsigned long paddr, temp, page_dir, pgd_pte, page_upper, pud_pte;
	unsigned long page_middle, pmd_pte, page_table, pte;

	if (SYMBOL(swapper_pg_dir) == NOT_FOUND_SYMBOL) {
		ERRMSG("Can't get the symbol of swapper_pg_dir.\n");
		return 0x0;
	}

	/*
	 * Get PGD
	 */
	temp = vaddr & MASK_PGD_4L;
	temp = temp >> (PGDIR_SHIFT_4L - 3);
	page_dir = SYMBOL(swapper_pg_dir) + temp;
	if (!readmem(info, page_dir, &pgd_pte, sizeof pgd_pte)) {
		ERRMSG("Can't get pgd_pte (page_dir:%lx).\n", page_dir);
		return 0x0;
	}

	/*
	 * Get PUD
	 */
	temp = vaddr & MASK_PUD;
	temp = temp >> (PUD_SHIFT - 3);
	page_upper = pgd_pte + temp;
	page_upper = paddr_to_vaddr(info, page_upper);
	if (!readmem(info, page_upper, &pud_pte, sizeof pud_pte)) {
		ERRMSG("Can't get pud_pte (page_upper:%lx).\n", page_upper);
		return 0x0;
	}

	/*
	 * Get PMD
	 */
	temp = vaddr & MASK_PMD;
	temp = temp >> (PMD_SHIFT - 3);
	page_middle = pud_pte + temp;
	page_middle = paddr_to_vaddr(info, page_middle);
	if (!readmem(info, page_middle, &pmd_pte, sizeof pmd_pte)) {
		ERRMSG("Can't get pmd_pte (page_middle:%lx).\n", page_middle);
		return 0x0;
	}

	/*
	 * Get PTE
	 */
	temp = vaddr & MASK_PTE;
	temp = temp >> (PAGE_SHIFT - 3);
	page_table = pmd_pte + temp;
	page_table = paddr_to_vaddr(info, page_table);
	if (!readmem(info, page_table, &pte, sizeof pte)) {
		ERRMSG("Can't get pte (page_table:%lx).\n", page_table);
		return 0x0;
	}

	/*
	 * Get physical address
	 */
	temp = vaddr & MASK_POFFSET;
	paddr = (pte & _PAGE_PPN_MASK) + temp;

	return paddr;
}

unsigned long
ia64_vtop(struct DumpInfo *info, unsigned long long vaddr)
{
	unsigned long paddr;

	if (VADDR_REGION(vaddr) != KERNEL_VMALLOC_REGION) {
		ERRMSG("vaddr(%llx) is not KERNEL_VMALLOC_REGION.\n", vaddr);
		return 0x0;
	}
	paddr = vaddr_to_paddr(info, vaddr);
	if (paddr)
		return paddr;

	if (!is_vmalloc_addr_ia64(info, vaddr)) {
		paddr = vaddr - info->kernel_start +
			(info->phys_base & KERNEL_TR_PAGE_MASK);
		return paddr;
	}

	if (info->mem_flags & MEMORY_PAGETABLE_4L)
		return ia64_vtop4(info, vaddr);
	else
		return ia64_vtop3(info, vaddr);
}

/*
 * Translate a virtual address to a file offset.
 */
off_t
vaddr_to_offset_ia64(struct DumpInfo *info, unsigned long long vaddr)
{
	unsigned long paddr;

	switch (VADDR_REGION(vaddr)) {
		case KERNEL_CACHED_REGION:
			paddr = vaddr - (ulong)(KERNEL_CACHED_BASE);
			break;

		case KERNEL_UNCACHED_REGION:
			paddr = vaddr - (ulong)(KERNEL_UNCACHED_BASE);
			break;

		case KERNEL_VMALLOC_REGION:
			paddr = ia64_vtop(info, vaddr);
			break;

		default:
			ERRMSG("Unknown region (%ld)\n", VADDR_REGION(vaddr));
			return 0x0;
	}
	return paddr_to_offset(info, paddr);
}

#endif /* ia64 */

