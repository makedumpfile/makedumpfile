/*
 * ia64.c
 *
 * Copyright (C) 2006, 2007, 2008  NEC Corporation
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

#include "../print_info.h"
#include "../elf_info.h"
#include "../makedumpfile.h"


/*
 *  vmalloc() starting address is either the traditional 0xa000000000000000 or
 *  bumped up in 2.6 to 0xa000000200000000.
 */
int
is_vmalloc_addr_ia64(unsigned long vaddr)
{
	return ((vaddr >= info->vmalloc_start) &&
			(vaddr < (unsigned long)KERNEL_UNCACHED_BASE));
}

int
get_phys_base_ia64(void)
{
	int i;
	unsigned long long phys_start;
	unsigned long long virt_start;

	/*
	 *  Default to 64MB.
	 */
	info->phys_base = DEFAULT_PHYS_START;

	for (i = 0; get_pt_load(i, &phys_start, NULL, &virt_start, NULL); i++) {
		if (VADDR_REGION(virt_start) == KERNEL_VMALLOC_REGION) {

			info->phys_base = phys_start;
			break;
		}
	}
	return TRUE;
}

int
get_machdep_info_ia64(void)
{
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
	if ((vt.mem_flags & MEMORY_PAGETABLE_4L)
	    || !strncmp(SRCFILE(pud_t), STR_PUD_T_4L, strlen(STR_PUD_T_4L))) {
		vt.mem_flags |= MEMORY_PAGETABLE_4L;
		DEBUG_MSG("PAGETABLE_4L : ON\n");
	} else if ((vt.mem_flags & MEMORY_PAGETABLE_3L)
	    || !strncmp(SRCFILE(pud_t), STR_PUD_T_3L, strlen(STR_PUD_T_3L))) {
		vt.mem_flags |= MEMORY_PAGETABLE_3L;
		DEBUG_MSG("PAGETABLE_3L : ON\n");
	} else {
		MSG("Can't distinguish the pgtable.\n");
	}

	info->section_size_bits = _SECTION_SIZE_BITS;

	/* Check if we can get MAX_PHYSMEM_BITS from vmcoreinfo */
	if (NUMBER(MAX_PHYSMEM_BITS) != NOT_FOUND_NUMBER)
		info->max_physmem_bits = NUMBER(MAX_PHYSMEM_BITS);
	else
		info->max_physmem_bits  = _MAX_PHYSMEM_BITS;

	return TRUE;
}

/*
 * Translate a virtual address to a physical address by using 3 levels paging.
 */
unsigned long long
vtop3_ia64(unsigned long vaddr)
{
	unsigned long long paddr, temp, page_dir, pgd_pte, page_middle, pmd_pte;
	unsigned long long page_table, pte;

	if (SYMBOL(swapper_pg_dir) == NOT_FOUND_SYMBOL) {
		ERRMSG("Can't get the symbol of swapper_pg_dir.\n");
		return NOT_PADDR;
	}

	/*
	 * Get PGD
	 */
	temp = vaddr & MASK_PGD_3L;
	temp = temp >> (PGDIR_SHIFT_3L - 3);
	page_dir = SYMBOL(swapper_pg_dir) + temp;
	if (!readmem(VADDR, page_dir, &pgd_pte, sizeof pgd_pte)) {
		ERRMSG("Can't get pgd_pte (page_dir:%llx).\n", page_dir);
		return NOT_PADDR;
	}
	if (info->vaddr_for_vtop == vaddr)
		MSG("  PGD : %16llx => %16llx\n", page_dir, pgd_pte);

	/*
	 * Get PMD
	 */
	temp = vaddr & MASK_PMD;
	temp = temp >> (PMD_SHIFT - 3);
	page_middle = pgd_pte + temp;
	if (!readmem(PADDR, page_middle, &pmd_pte, sizeof pmd_pte)) {
		ERRMSG("Can't get pmd_pte (page_middle:%llx).\n", page_middle);
		return NOT_PADDR;
	}
	if (info->vaddr_for_vtop == vaddr)
		MSG("  PMD : %16llx => %16llx\n", page_middle, pmd_pte);

	/*
	 * Get PTE
	 */
	temp = vaddr & MASK_PTE;
	temp = temp >> (PAGESHIFT() - 3);
	page_table = pmd_pte + temp;
	if (!readmem(PADDR, page_table, &pte, sizeof pte)) {
		ERRMSG("Can't get pte (page_table:%llx).\n", page_table);
		return NOT_PADDR;
	}
	if (info->vaddr_for_vtop == vaddr)
		MSG("  PTE : %16llx => %16llx\n", page_table, pte);

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
unsigned long long
vtop4_ia64(unsigned long vaddr)
{
	unsigned long long paddr, temp, page_dir, pgd_pte, page_upper, pud_pte;
	unsigned long long page_middle, pmd_pte, page_table, pte;

	if (SYMBOL(swapper_pg_dir) == NOT_FOUND_SYMBOL) {
		ERRMSG("Can't get the symbol of swapper_pg_dir.\n");
		return NOT_PADDR;
	}

	/*
	 * Get PGD
	 */
	temp = vaddr & MASK_PGD_4L;
	temp = temp >> (PGDIR_SHIFT_4L - 3);
	page_dir = SYMBOL(swapper_pg_dir) + temp;
	if (!readmem(VADDR, page_dir, &pgd_pte, sizeof pgd_pte)) {
		ERRMSG("Can't get pgd_pte (page_dir:%llx).\n", page_dir);
		return NOT_PADDR;
	}
	if (info->vaddr_for_vtop == vaddr)
		MSG("  PGD : %16llx => %16llx\n", page_dir, pgd_pte);

	/*
	 * Get PUD
	 */
	temp = vaddr & MASK_PUD;
	temp = temp >> (PUD_SHIFT - 3);
	page_upper = pgd_pte + temp;
	if (!readmem(PADDR, page_upper, &pud_pte, sizeof pud_pte)) {
		ERRMSG("Can't get pud_pte (page_upper:%llx).\n", page_upper);
		return NOT_PADDR;
	}
	if (info->vaddr_for_vtop == vaddr)
		MSG("  PUD : %16llx => %16llx\n", page_upper, pud_pte);

	/*
	 * Get PMD
	 */
	temp = vaddr & MASK_PMD;
	temp = temp >> (PMD_SHIFT - 3);
	page_middle = pud_pte + temp;
	if (!readmem(PADDR, page_middle, &pmd_pte, sizeof pmd_pte)) {
		ERRMSG("Can't get pmd_pte (page_middle:%llx).\n", page_middle);
		return NOT_PADDR;
	}
	if (info->vaddr_for_vtop == vaddr)
		MSG("  PMD : %16llx => %16llx\n", page_middle, pmd_pte);

	/*
	 * Get PTE
	 */
	temp = vaddr & MASK_PTE;
	temp = temp >> (PAGESHIFT() - 3);
	page_table = pmd_pte + temp;
	if (!readmem(PADDR, page_table, &pte, sizeof pte)) {
		ERRMSG("Can't get pte (page_table:%llx).\n", page_table);
		return NOT_PADDR;
	}
	if (info->vaddr_for_vtop == vaddr)
		MSG("  PTE : %16llx => %16llx\n", page_table, pte);

	/*
	 * Get physical address
	 */
	temp = vaddr & MASK_POFFSET;
	paddr = (pte & _PAGE_PPN_MASK) + temp;

	return paddr;
}

unsigned long long
vtop_ia64(unsigned long vaddr)
{
	unsigned long long paddr;

	if (VADDR_REGION(vaddr) != KERNEL_VMALLOC_REGION) {
		ERRMSG("vaddr(%lx) is not KERNEL_VMALLOC_REGION.\n", vaddr);
		return NOT_PADDR;
	}
	paddr = vaddr_to_paddr_general(vaddr);
	if (paddr != NOT_PADDR)
		return paddr;

	if (!is_vmalloc_addr_ia64(vaddr)) {
		paddr = vaddr - info->kernel_start +
			(info->phys_base & KERNEL_TR_PAGE_MASK);
		if (is_xen_memory())
			paddr = ptom_xen(paddr);
		return paddr;
	}

	if (vt.mem_flags & MEMORY_PAGETABLE_4L)
		return vtop4_ia64(vaddr);
	else
		return vtop3_ia64(vaddr);
}

/*
 * Translate a virtual address to physical address.
 */
unsigned long long
vaddr_to_paddr_ia64(unsigned long vaddr)
{
	unsigned long long paddr;

	switch (VADDR_REGION(vaddr)) {
		case KERNEL_CACHED_REGION:
			paddr = vaddr - (ulong)(KERNEL_CACHED_BASE);
			break;

		case KERNEL_UNCACHED_REGION:
			paddr = vaddr - (ulong)(KERNEL_UNCACHED_BASE);
			break;

		case KERNEL_VMALLOC_REGION:
			paddr = vtop_ia64(vaddr);
			break;

		default:
			ERRMSG("Unknown region (%ld)\n", VADDR_REGION(vaddr));
			return 0x0;
	}
	return paddr;
}

/*
 * for Xen extraction
 */
unsigned long long
kvtop_xen_ia64(unsigned long kvaddr)
{
	unsigned long long addr, dirp, entry;

	if (!is_xen_vaddr(kvaddr))
		return NOT_PADDR;

	if (is_direct(kvaddr))
		return (unsigned long)kvaddr - DIRECTMAP_VIRT_START;

	if (!is_frame_table_vaddr(kvaddr))
		return NOT_PADDR;

	addr = kvaddr - VIRT_FRAME_TABLE_ADDR;

	dirp = SYMBOL(frametable_pg_dir) - DIRECTMAP_VIRT_START;
	dirp += ((addr >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1)) * sizeof(unsigned long long);
	if (!readmem(PADDR, dirp, &entry, sizeof(entry)))
		return NOT_PADDR;

	dirp = entry & _PFN_MASK;
	if (!dirp)
		return NOT_PADDR;

	dirp += ((addr >> PMD_SHIFT) & (PTRS_PER_PMD - 1)) * sizeof(unsigned long long);
	if (!readmem(PADDR, dirp, &entry, sizeof(entry)))
		return NOT_PADDR;

	dirp = entry & _PFN_MASK;
	if (!dirp)
		return NOT_PADDR;

	dirp += ((addr >> PAGESHIFT()) & (PTRS_PER_PTE - 1)) * sizeof(unsigned long long);
	if (!readmem(PADDR, dirp, &entry, sizeof(entry)))
		return NOT_PADDR;

	if (!(entry & _PAGE_P))
		return NOT_PADDR;

	entry = (entry & _PFN_MASK) + (addr & ((1UL << PAGESHIFT()) - 1));

	return entry;
}

int
get_xen_basic_info_ia64(void)
{
	unsigned long xen_start, xen_end;

	info->frame_table_vaddr = VIRT_FRAME_TABLE_ADDR; /* "frame_table" is same value */

	if (!info->xen_crash_info.com ||
	    info->xen_crash_info.com->xen_major_version < 4) {
		if (SYMBOL(xenheap_phys_end) == NOT_FOUND_SYMBOL) {
			ERRMSG("Can't get the symbol of xenheap_phys_end.\n");
			return FALSE;
		}
		if (!readmem(VADDR_XEN, SYMBOL(xenheap_phys_end), &xen_end,
			     sizeof(xen_end))) {
			ERRMSG("Can't get the value of xenheap_phys_end.\n");
			return FALSE;
		}
		if (SYMBOL(xen_pstart) == NOT_FOUND_SYMBOL) {
			ERRMSG("Can't get the symbol of xen_pstart.\n");
			return FALSE;
		}
		if (!readmem(VADDR_XEN, SYMBOL(xen_pstart), &xen_start,
			     sizeof(xen_start))) {
			ERRMSG("Can't get the value of xen_pstart.\n");
			return FALSE;
		}
		info->xen_heap_start = paddr_to_pfn(xen_start);
		info->xen_heap_end   = paddr_to_pfn(xen_end);
	}

	return TRUE;
}

int
get_xen_info_ia64(void)
{
	unsigned long xen_heap_start;
	int i;

	if (SYMBOL(xen_heap_start) == NOT_FOUND_SYMBOL) {
		ERRMSG("Can't get the symbol of xen_heap_start.\n");
		return FALSE;
	}
	if (!readmem(VADDR_XEN, SYMBOL(xen_heap_start), &xen_heap_start,
	      sizeof(xen_heap_start))) {
		ERRMSG("Can't get the value of xen_heap_start.\n");
		return FALSE;
	}
	for (i = 0; i < info->num_domain; i++) {
		info->domain_list[i].pickled_id = (unsigned int)
			(info->domain_list[i].domain_addr - xen_heap_start);
	}

	return TRUE;
}

#endif /* ia64 */

