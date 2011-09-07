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

#include "../print_info.h"
#include "../elf_info.h"
#include "../makedumpfile.h"

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
	unsigned long long phys_start;
	int i;

	/*
	 * We resolve phys_base from PT_LOAD segments. LMA contains physical
	 * address of the segment, and we use the first one.
	 */
	for (i = 0; get_pt_load(i, &phys_start, NULL, NULL, NULL); i++) {
		if (phys_start < phys_base)
			phys_base = phys_start;
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
	info->page_offset = SYMBOL(_stext) & 0xffff0000UL;
	info->max_physmem_bits = _MAX_PHYSMEM_BITS;
	info->kernel_start = SYMBOL(_stext);
	info->section_size_bits = _SECTION_SIZE_BITS;

	DEBUG_MSG("page_offset  : %lx\n", info->page_offset);
	DEBUG_MSG("kernel_start : %lx\n", info->kernel_start);

	return TRUE;
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
	/*
	 * Only use translation tables when user has explicitly requested us to
	 * perform translation for a given address. Otherwise we assume that the
	 * translation is done within the kernel direct mapped region.
	 */
	if (info->vaddr_for_vtop == vaddr)
		return vtop_arm(vaddr);

	return __pa(vaddr);
}

#endif /* __arm__ */
