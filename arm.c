/*
 * arm.c
 *
 * Created by: Mika Westerberg <ext-mika.1.westerberg@nokia.com>
 * Copyright (C) 2010 Nokia Corporation
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
#ifdef __arm__

#include "makedumpfile.h"

#define PMD_TYPE_MASK	3
#define PMD_TYPE_SECT	2
#define PMD_TYPE_TABLE	1

#define pgd_index(vaddr) ((vaddr) >> PGDIR_SHIFT)
#define pte_index(vaddr) ((vaddr >> PAGESHIFT()) & (PTRS_PER_PTE - 1))

#define pgd_offset(pgdir, vaddr) \
	((pgdir) + pgd_index(vaddr) * 2 * sizeof(unsigned long))
#define pmd_offset(dir, vaddr) (dir)
#define pte_offset(pmd, vaddr) \
	(pmd_page_vaddr(pmd) + pte_index(vaddr) * sizeof(unsigned long))

/*
 * These only work for kernel directly mapped addresses.
 */
#define __va(paddr) ((paddr) - info->phys_base + info->page_offset)
#define __pa(vaddr) ((vaddr) - info->page_offset + info->phys_base)

static inline unsigned long
pmd_page_vaddr(unsigned long pmd)
{
	unsigned long ptr;

	ptr = pmd & ~(PTRS_PER_PTE * sizeof(void *) - 1);
	ptr += PTRS_PER_PTE * sizeof(void *);

	return __va(ptr);
}

int
get_phys_base_arm(void)
{
	unsigned long phys_base = ULONG_MAX;
	int i;

	/*
	 * We resolve phys_base from PT_LOAD segments. LMA contains physical
	 * address of the segment, and we use the first one.
	 */
	for (i = 0; i < info->num_load_memory; i++) {
		const struct pt_load_segment *pls = &info->pt_load_segments[i];

		if (pls->phys_start < phys_base)
			phys_base = pls->phys_start;
	}

	if (phys_base == ULONG_MAX) {
		ERRMSG("Can't determine phys_base.\n");
		return FALSE;
	}

	info->phys_base = phys_base;
	DEBUG_MSG("phys_base    : %lx\n", phys_base);

	return TRUE;
}

int
get_machdep_info_arm(void)
{
	unsigned long vmlist, vmalloc_start;

	info->page_offset = SYMBOL(_stext) & 0xffff0000UL;
	info->max_physmem_bits = _MAX_PHYSMEM_BITS;
	info->kernel_start = SYMBOL(_stext);
	info->section_size_bits = _SECTION_SIZE_BITS;

	/*
	 * For the compatibility, makedumpfile should run without the symbol
	 * vmlist and the offset of vm_struct.addr if they are not necessary.
	 */
	if ((SYMBOL(vmlist) == NOT_FOUND_SYMBOL) ||
		OFFSET(vm_struct.addr) == NOT_FOUND_STRUCTURE) {
		return TRUE;
	}

	if (!readmem(VADDR, SYMBOL(vmlist), &vmlist, sizeof(vmlist))) {
		ERRMSG("Can't get vmlist.\n");
		return FALSE;
	}
	if (!readmem(VADDR, vmlist + OFFSET(vm_struct.addr), &vmalloc_start,
		     sizeof(vmalloc_start))) {
		ERRMSG("Can't get vmalloc_start.\n");
		return FALSE;
	}

	info->vmalloc_start = vmalloc_start;

	DEBUG_MSG("page_offset  : %lx\n", info->page_offset);
	DEBUG_MSG("kernel_start : %lx\n", info->kernel_start);
	DEBUG_MSG("vmalloc_start: %lx\n", vmalloc_start);

	return TRUE;
}

static int
is_vmalloc_addr_arm(unsigned long vaddr)
{
	return (info->vmalloc_start && vaddr >= info->vmalloc_start);
}

/*
 * vtop_arm() - translate arbitrary virtual address to physical
 * @vaddr: virtual address to translate
 *
 * Function translates @vaddr into physical address using page tables. This
 * address can be any virtual address. Returns physical address of the
 * corresponding virtual address or %NOT_PADDR when there is no translation.
 */
static unsigned long long
vtop_arm(unsigned long vaddr)
{
	unsigned long long paddr = NOT_PADDR;
	unsigned long ptr, pgd, pte, pmd;

	if (SYMBOL(swapper_pg_dir) == NOT_FOUND_SYMBOL) {
		ERRMSG("Can't get the symbol of swapper_pg_dir.\n");
		return NOT_PADDR;
	}

	ptr = pgd_offset(SYMBOL(swapper_pg_dir), vaddr);
	if (!readmem(VADDR, ptr, &pgd, sizeof(pmd))) {
		ERRMSG("Can't read pgd\n");
		return NOT_PADDR;
	}

	if (info->vaddr_for_vtop == vaddr)
		MSG("  PGD : %08lx => %08lx\n", ptr, pgd);

	pmd = pmd_offset(pgd, vaddr);

	switch (pmd & PMD_TYPE_MASK) {
	case PMD_TYPE_TABLE: {
		/* 4k small page */
		ptr = pte_offset(pmd, vaddr);
		if (!readmem(VADDR, ptr, &pte, sizeof(pte))) {
			ERRMSG("Can't read pte\n");
			return NOT_PADDR;
		}

		if (info->vaddr_for_vtop == vaddr)
			MSG("  PTE : %08lx => %08lx\n", ptr, pte);

		if (!(pte & _PAGE_PRESENT)) {
			ERRMSG("Can't get a valid pte.\n");
			return NOT_PADDR;
		}

		paddr = PAGEBASE(pte) + (vaddr & (PAGESIZE() - 1));
		break;
	}

	case PMD_TYPE_SECT:
		/* 1MB section */
		pte = pmd & PMD_MASK;
		paddr = pte + (vaddr & (PMD_SIZE - 1));
		break;
	}

	return paddr;
}

unsigned long long
vaddr_to_paddr_arm(unsigned long vaddr)
{
	unsigned long long paddr = vaddr_to_paddr_general(vaddr);

	if (paddr != NOT_PADDR)
		return paddr;

	if (is_vmalloc_addr_arm(vaddr))
		paddr = vtop_arm(vaddr);
	else
		paddr = __pa(vaddr);

	return paddr;
}

#endif /* __arm__ */
