/*
 * x86.c
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
#ifdef __x86__

#include "../print_info.h"
#include "../elf_info.h"
#include "../makedumpfile.h"

static int max_numnodes;
static unsigned long *remap_start_vaddr;
static unsigned long *remap_end_vaddr;
static unsigned long *remap_start_pfn;

static int
remap_init(void)
{
	int n;

	if (SYMBOL(node_remap_start_vaddr) == NOT_FOUND_SYMBOL)
		return TRUE;
	if (SYMBOL(node_remap_end_vaddr) == NOT_FOUND_SYMBOL)
		return TRUE;
	if (SYMBOL(node_remap_start_pfn) == NOT_FOUND_SYMBOL)
		return TRUE;
	if (ARRAY_LENGTH(node_remap_start_pfn) == NOT_FOUND_STRUCTURE)
		return TRUE;

	n = ARRAY_LENGTH(node_remap_start_pfn);
	remap_start_vaddr = calloc(3 * n, sizeof(unsigned long));
	if (!remap_start_vaddr) {
		ERRMSG("Can't allocate remap allocator info.\n");
		return FALSE;
	}
	remap_end_vaddr = remap_start_vaddr + n;
	remap_start_pfn = remap_end_vaddr + n;

	if (!readmem(VADDR, SYMBOL(node_remap_start_vaddr), remap_start_vaddr,
		     n * sizeof(unsigned long))) {
		ERRMSG("Can't get node_remap_start_vaddr.\n");
		return FALSE;
	}
	if (!readmem(VADDR, SYMBOL(node_remap_end_vaddr), remap_end_vaddr,
		     n * sizeof(unsigned long))) {
		ERRMSG("Can't get node_remap_end_vaddr.\n");
		return FALSE;
	}
	if (!readmem(VADDR, SYMBOL(node_remap_start_pfn), remap_start_pfn,
		     n * sizeof(unsigned long))) {
		ERRMSG("Can't get node_remap_start_pfn.\n");
		return FALSE;
	}

	max_numnodes = n;
	return TRUE;
}

int
get_machdep_info_x86(void)
{
	unsigned long vmlist, vmap_area_list, vmalloc_start;

	/* PAE */
	if ((vt.mem_flags & MEMORY_X86_PAE)
	    || ((SYMBOL(pkmap_count) != NOT_FOUND_SYMBOL)
	      && (SYMBOL(pkmap_count_next) != NOT_FOUND_SYMBOL)
	      && ((SYMBOL(pkmap_count_next)-SYMBOL(pkmap_count))/sizeof(int))
	      == 512)) {
		DEBUG_MSG("\n");
		DEBUG_MSG("PAE          : ON\n");
		vt.mem_flags |= MEMORY_X86_PAE;
		info->max_physmem_bits  = _MAX_PHYSMEM_BITS_PAE;
	} else {
		DEBUG_MSG("\n");
		DEBUG_MSG("PAE          : OFF\n");
		info->max_physmem_bits  = _MAX_PHYSMEM_BITS;
	}

	/* Check if we can get MAX_PHYSMEM_BITS from vmcoreinfo */
	if (NUMBER(MAX_PHYSMEM_BITS) != NOT_FOUND_NUMBER)
		info->max_physmem_bits = NUMBER(MAX_PHYSMEM_BITS);

	info->page_offset = __PAGE_OFFSET;

	if (SYMBOL(_stext) == NOT_FOUND_SYMBOL) {
		ERRMSG("Can't get the symbol of _stext.\n");
		return FALSE;
	}
	info->kernel_start = SYMBOL(_stext) & ~KVBASE_MASK;
	DEBUG_MSG("kernel_start : %lx\n", info->kernel_start);

	if (!remap_init())
		return FALSE;

	/*
	 * Get vmalloc_start value from either vmap_area_list or vmlist.
	 */
	if ((SYMBOL(vmap_area_list) != NOT_FOUND_SYMBOL)
	    && (OFFSET(vmap_area.va_start) != NOT_FOUND_STRUCTURE)
	    && (OFFSET(vmap_area.list) != NOT_FOUND_STRUCTURE)) {
		if (!readmem(VADDR, SYMBOL(vmap_area_list) + OFFSET(list_head.next),
			     &vmap_area_list, sizeof(vmap_area_list))) {
			ERRMSG("Can't get vmap_area_list.\n");
			return FALSE;
		}
		if (!readmem(VADDR, vmap_area_list - OFFSET(vmap_area.list) +
			     OFFSET(vmap_area.va_start), &vmalloc_start,
			     sizeof(vmalloc_start))) {
			ERRMSG("Can't get vmalloc_start.\n");
			return FALSE;
		}
	} else if ((SYMBOL(vmlist) != NOT_FOUND_SYMBOL)
		   && (OFFSET(vm_struct.addr) != NOT_FOUND_STRUCTURE)) {
		if (!readmem(VADDR, SYMBOL(vmlist), &vmlist, sizeof(vmlist))) {
			ERRMSG("Can't get vmlist.\n");
			return FALSE;
		}
		if (!readmem(VADDR, vmlist + OFFSET(vm_struct.addr), &vmalloc_start,
			     sizeof(vmalloc_start))) {
			ERRMSG("Can't get vmalloc_start.\n");
			return FALSE;
		}
	} else {
		/*
		 * For the compatibility, makedumpfile should run without the symbol
		 * used to get vmalloc_start value if they are not necessary.
		 */
		return TRUE;
	}
	info->vmalloc_start = vmalloc_start;
	DEBUG_MSG("vmalloc_start: %lx\n", vmalloc_start);

	return TRUE;
}

int
get_versiondep_info_x86(void)
{
	/*
	 * SECTION_SIZE_BITS of PAE has been changed to 29 from 30 since
	 * linux-2.6.26.
	 */
	if (vt.mem_flags & MEMORY_X86_PAE) {
		if (info->kernel_version < KERNEL_VERSION(2, 6, 26))
			info->section_size_bits = _SECTION_SIZE_BITS_PAE_ORIG;
		else
			info->section_size_bits = _SECTION_SIZE_BITS_PAE_2_6_26;
	} else
		info->section_size_bits = _SECTION_SIZE_BITS;

	return TRUE;
}

unsigned long long
vtop_x86_remap(unsigned long vaddr)
{
	int i;
	for (i = 0; i < max_numnodes; ++i)
		if (vaddr >= remap_start_vaddr[i] &&
		    vaddr < remap_end_vaddr[i])
			return pfn_to_paddr(remap_start_pfn[i]) +
				vaddr - remap_start_vaddr[i];
	return NOT_PADDR;
}

unsigned long long
vtop_x86_PAE(unsigned long vaddr)
{
	unsigned long long page_dir, pgd_pte, pmd_paddr, pmd_pte;
	unsigned long long pte_paddr, pte;

	if (SYMBOL(swapper_pg_dir) == NOT_FOUND_SYMBOL) {
		ERRMSG("Can't get the symbol of swapper_pg_dir.\n");
		return NOT_PADDR;
	}

	page_dir  = SYMBOL(swapper_pg_dir);
	page_dir += pgd_index_PAE(vaddr) * sizeof(unsigned long long);
	if (!readmem(VADDR, page_dir, &pgd_pte, sizeof(pgd_pte))) {
		ERRMSG("Can't get pgd_pte (page_dir:%llx).\n", page_dir);
		return NOT_PADDR;
	}
	if (!(pgd_pte & _PAGE_PRESENT))
		return NOT_PADDR;

	if (info->vaddr_for_vtop == vaddr)
		MSG("  PGD : %16llx => %16llx\n", page_dir, pgd_pte);

	pmd_paddr  = pgd_pte & ENTRY_MASK;
	pmd_paddr += pmd_index(vaddr) * sizeof(unsigned long long);
	if (!readmem(PADDR, pmd_paddr, &pmd_pte, sizeof(pmd_pte))) {
		ERRMSG("Can't get pmd_pte (pmd_paddr:%llx).\n", pmd_paddr);
		return NOT_PADDR;
	}
	if (!(pmd_pte & _PAGE_PRESENT))
		return NOT_PADDR;

	if (info->vaddr_for_vtop == vaddr)
		MSG("  PMD : %16llx => %16llx\n", pmd_paddr, pmd_pte);

	if (pmd_pte & _PAGE_PSE)
		return (pmd_pte & ENTRY_MASK) + (vaddr & ((1UL << PMD_SHIFT) - 1));

	pte_paddr  = pmd_pte & ENTRY_MASK;
	pte_paddr += pte_index(vaddr) * sizeof(unsigned long long);
	if (!readmem(PADDR, pte_paddr, &pte, sizeof(pte)))
		return NOT_PADDR;

	if (!(pte & _PAGE_PRESENT))
		return NOT_PADDR;

	if (info->vaddr_for_vtop == vaddr)
		MSG("  PTE : %16llx => %16llx\n", pte_paddr, pte);

	return (pte & ENTRY_MASK) + (vaddr & ((1UL << PTE_SHIFT) - 1));
}

int
is_vmalloc_addr_x86(unsigned long vaddr)
{
	return (info->vmalloc_start && vaddr >= info->vmalloc_start);
}

unsigned long long
vaddr_to_paddr_x86(unsigned long vaddr)
{
	unsigned long long paddr;

	if ((paddr = vtop_x86_remap(vaddr)) != NOT_PADDR) {
		if (is_xen_memory())
			paddr = ptom_xen(paddr);
		return paddr;
	}

	if ((paddr = vaddr_to_paddr_general(vaddr)) != NOT_PADDR)
		return paddr;

	if (((SYMBOL(vmap_area_list) == NOT_FOUND_SYMBOL)
	     || (OFFSET(vmap_area.va_start) == NOT_FOUND_STRUCTURE)
	     || (OFFSET(vmap_area.list) == NOT_FOUND_STRUCTURE))
	    && ((SYMBOL(vmlist) == NOT_FOUND_SYMBOL)
		|| (OFFSET(vm_struct.addr) == NOT_FOUND_STRUCTURE))) {
		ERRMSG("Can't get necessary information for vmalloc translation.\n");
		return NOT_PADDR;
	}
	if (!is_vmalloc_addr_x86(vaddr)) {
		paddr = vaddr - info->kernel_start;
		if (is_xen_memory())
			paddr = ptom_xen(paddr);
		return paddr;
	}

	if (vt.mem_flags & MEMORY_X86_PAE) {
		paddr = vtop_x86_PAE(vaddr);
	} else {
		/*
		 * TODO: Support vmalloc translation of not-PAE kernel.
		 */
		ERRMSG("This makedumpfile does not support vmalloc translation of not-PAE kernel.\n");
		return NOT_PADDR;
	}

	return paddr;
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
	dirp += pgd_index_PAE(kvaddr) * sizeof(unsigned long long);
	if (!readmem(PADDR, dirp, &entry, sizeof(entry)))
		return NOT_PADDR;

	if (!(entry & _PAGE_PRESENT))
		return NOT_PADDR;

	dirp = entry & ENTRY_MASK;
	dirp += pmd_index(kvaddr) * sizeof(unsigned long long);
	if (!readmem(PADDR, dirp, &entry, sizeof(entry)))
		return NOT_PADDR;

	if (!(entry & _PAGE_PRESENT))
		return NOT_PADDR;

	if (entry & _PAGE_PSE) {
		entry = (entry & ENTRY_MASK) + (kvaddr & ((1UL << PMD_SHIFT) - 1));
		return entry;
	}

	dirp = entry & ENTRY_MASK;
	dirp += pte_index(kvaddr) * sizeof(unsigned long long);
	if (!readmem(PADDR, dirp, &entry, sizeof(entry)))
		return NOT_PADDR;

	if (!(entry & _PAGE_PRESENT)) {
		return NOT_PADDR;
	}

	entry = (entry & ENTRY_MASK) + (kvaddr & ((1UL << PTE_SHIFT) - 1));

	return entry;
}

int get_xen_basic_info_x86(void)
{
	if (SYMBOL(pgd_l2) == NOT_FOUND_SYMBOL &&
	    SYMBOL(pgd_l3) == NOT_FOUND_SYMBOL) {
		ERRMSG("Can't get pgd.\n");
		return FALSE;
	}

	if (SYMBOL(pgd_l3) == NOT_FOUND_SYMBOL) {
		ERRMSG("non-PAE not support right now.\n");
		return FALSE;
	}

	if (SYMBOL(frame_table) != NOT_FOUND_SYMBOL) {
		unsigned long frame_table_vaddr;

		if (!readmem(VADDR_XEN, SYMBOL(frame_table),
		    &frame_table_vaddr, sizeof(frame_table_vaddr))) {
			ERRMSG("Can't get the value of frame_table.\n");
			return FALSE;
		}
		info->frame_table_vaddr = frame_table_vaddr;
	} else
		info->frame_table_vaddr = FRAMETABLE_VIRT_START;

	if (!info->xen_crash_info.com ||
	    info->xen_crash_info.com->xen_major_version < 4) {
		unsigned long xen_end;

		if (SYMBOL(xenheap_phys_end) == NOT_FOUND_SYMBOL) {
			ERRMSG("Can't get the symbol of xenheap_phys_end.\n");
			return FALSE;
		}
		if (!readmem(VADDR_XEN, SYMBOL(xenheap_phys_end), &xen_end,
		    sizeof(xen_end))) {
			ERRMSG("Can't get the value of xenheap_phys_end.\n");
			return FALSE;
		}
		info->xen_heap_start = 0;
		info->xen_heap_end   = paddr_to_pfn(xen_end);
	}

	return TRUE;
}

int get_xen_info_x86(void)
{
	int i;

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

