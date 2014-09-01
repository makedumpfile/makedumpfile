/*
 * x86_64.c
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
#ifdef __x86_64__

#include "../print_info.h"
#include "../elf_info.h"
#include "../makedumpfile.h"

int
is_vmalloc_addr_x86_64(ulong vaddr)
{
	/*
	 *  vmalloc, virtual memmap, and module space as VMALLOC space.
	 */
	return ((vaddr >= VMALLOC_START && vaddr <= VMALLOC_END)
	    || (vaddr >= VMEMMAP_START && vaddr <= VMEMMAP_END)
	    || (vaddr >= MODULES_VADDR && vaddr <= MODULES_END));
}

static unsigned long
get_xen_p2m_mfn(void)
{
	if (info->xen_crash_info_v >= 2)
		return info->xen_crash_info.v2->
			dom0_pfn_to_mfn_frame_list_list;
	if (info->xen_crash_info_v >= 1)
		return info->xen_crash_info.v1->
			dom0_pfn_to_mfn_frame_list_list;
	return NOT_FOUND_LONG_VALUE;
}

int
get_phys_base_x86_64(void)
{
	int i;
	unsigned long long phys_start;
	unsigned long long virt_start;

	/*
	 * Get the relocatable offset
	 */
	info->phys_base = 0; /* default/traditional */

	for (i = 0; get_pt_load(i, &phys_start, NULL, &virt_start, NULL); i++) {
		if ((virt_start >= __START_KERNEL_map) &&
		    !(is_vmalloc_addr_x86_64(virt_start))) {

			info->phys_base = phys_start -
			    (virt_start & ~(__START_KERNEL_map));

			break;
		}
	}

	return TRUE;
}

int
get_machdep_info_x86_64(void)
{
	unsigned long p2m_mfn;
	int i, j, mfns[MAX_X86_64_FRAMES];
	unsigned long frame_mfn[MAX_X86_64_FRAMES];
	unsigned long buf[MFNS_PER_FRAME];

	info->section_size_bits = _SECTION_SIZE_BITS;

	if (!is_xen_memory())
		return TRUE;

	/*
	 * Get the information for translating domain-0's physical
	 * address into machine address.
	 */
	p2m_mfn = get_xen_p2m_mfn();
	if (p2m_mfn == (unsigned long)NOT_FOUND_LONG_VALUE) {
		ERRMSG("Can't get p2m_mfn address.\n");
		return FALSE;
	}
	if (!readmem(MADDR_XEN, pfn_to_paddr(p2m_mfn),
		     &frame_mfn, PAGESIZE())) {
		ERRMSG("Can't read p2m_mfn.\n");
		return FALSE;
	}

	/*
	 * Count the number of p2m frame.
	 */
	for (i = 0; i < MAX_X86_64_FRAMES; i++) {
		mfns[i] = 0;
		if (!frame_mfn[i])
			break;

		if (!readmem(MADDR_XEN, pfn_to_paddr(frame_mfn[i]), &buf,
		    PAGESIZE())) {
			ERRMSG("Can't get frame_mfn[%d].\n", i);
			return FALSE;
		}
		for (j = 0; j < MFNS_PER_FRAME; j++) {
			if (!buf[j])
				break;

			mfns[i]++;
		}
		info->p2m_frames += mfns[i];
	}
	info->p2m_mfn_frame_list
	    = malloc(sizeof(unsigned long) * info->p2m_frames);
	if (info->p2m_mfn_frame_list == NULL) {
		ERRMSG("Can't allocate memory for p2m_mfn_frame_list. %s\n",
		    strerror(errno));
		return FALSE;
	}

	/*
	 * Get p2m_mfn_frame_list.
	 */
	for (i = 0; i < MAX_X86_64_FRAMES; i++) {
		if (!frame_mfn[i])
			break;

		if (!readmem(MADDR_XEN, pfn_to_paddr(frame_mfn[i]),
		    &info->p2m_mfn_frame_list[i * MFNS_PER_FRAME],
		    mfns[i] * sizeof(unsigned long))) {
			ERRMSG("Can't get p2m_mfn_frame_list.\n");
			return FALSE;
		}
		if (mfns[i] != MFNS_PER_FRAME)
			break;
	}
	return TRUE;
}

int
get_versiondep_info_x86_64(void)
{
	/*
	 * On linux-2.6.26, MAX_PHYSMEM_BITS is changed to 44 from 40.
	 */
	if (info->kernel_version < KERNEL_VERSION(2, 6, 26))
		info->max_physmem_bits  = _MAX_PHYSMEM_BITS_ORIG;
	else if (info->kernel_version < KERNEL_VERSION(2, 6, 31))
		info->max_physmem_bits  = _MAX_PHYSMEM_BITS_2_6_26;
	else
		info->max_physmem_bits  = _MAX_PHYSMEM_BITS_2_6_31;

	if (info->kernel_version < KERNEL_VERSION(2, 6, 27))
		info->page_offset = __PAGE_OFFSET_ORIG;
	else
		info->page_offset = __PAGE_OFFSET_2_6_27;

	if (info->kernel_version < KERNEL_VERSION(2, 6, 31)) {
		info->vmalloc_start = VMALLOC_START_ORIG;
		info->vmalloc_end   = VMALLOC_END_ORIG;
		info->vmemmap_start = VMEMMAP_START_ORIG;
		info->vmemmap_end   = VMEMMAP_END_ORIG;
	} else {
		info->vmalloc_start = VMALLOC_START_2_6_31;
		info->vmalloc_end   = VMALLOC_END_2_6_31;
		info->vmemmap_start = VMEMMAP_START_2_6_31;
		info->vmemmap_end   = VMEMMAP_END_2_6_31;
	}

	return TRUE;
}

/*
 * Translate a virtual address to a physical address by using 4 levels paging.
 */
unsigned long long
vtop4_x86_64(unsigned long vaddr)
{
	unsigned long page_dir, pml4, pgd_paddr, pgd_pte, pmd_paddr, pmd_pte;
	unsigned long pte_paddr, pte;

	if (SYMBOL(init_level4_pgt) == NOT_FOUND_SYMBOL) {
		ERRMSG("Can't get the symbol of init_level4_pgt.\n");
		return NOT_PADDR;
	}

	/*
	 * Get PGD.
	 */
	page_dir  = SYMBOL(init_level4_pgt);
	page_dir += pml4_index(vaddr) * sizeof(unsigned long);
	if (!readmem(VADDR, page_dir, &pml4, sizeof pml4)) {
		ERRMSG("Can't get pml4 (page_dir:%lx).\n", page_dir);
		return NOT_PADDR;
	}
	if (info->vaddr_for_vtop == vaddr)
		MSG("  PGD : %16lx => %16lx\n", page_dir, pml4);

	if (!(pml4 & _PAGE_PRESENT)) {
		ERRMSG("Can't get a valid pml4.\n");
		return NOT_PADDR;
	}

	/*
	 * Get PUD.
	 */
	pgd_paddr  = pml4 & ENTRY_MASK;
	pgd_paddr += pgd_index(vaddr) * sizeof(unsigned long);
	if (!readmem(PADDR, pgd_paddr, &pgd_pte, sizeof pgd_pte)) {
		ERRMSG("Can't get pgd_pte (pgd_paddr:%lx).\n", pgd_paddr);
		return NOT_PADDR;
	}
	if (info->vaddr_for_vtop == vaddr)
		MSG("  PUD : %16lx => %16lx\n", pgd_paddr, pgd_pte);

	if (!(pgd_pte & _PAGE_PRESENT)) {
		ERRMSG("Can't get a valid pgd_pte.\n");
		return NOT_PADDR;
	}
	if (pgd_pte & _PAGE_PSE)	/* 1GB pages */
		return (pgd_pte & ENTRY_MASK & PGDIR_MASK) +
			(vaddr & ~PGDIR_MASK);

	/*
	 * Get PMD.
	 */
	pmd_paddr  = pgd_pte & ENTRY_MASK;
	pmd_paddr += pmd_index(vaddr) * sizeof(unsigned long);
	if (!readmem(PADDR, pmd_paddr, &pmd_pte, sizeof pmd_pte)) {
		ERRMSG("Can't get pmd_pte (pmd_paddr:%lx).\n", pmd_paddr);
		return NOT_PADDR;
	}
	if (info->vaddr_for_vtop == vaddr)
		MSG("  PMD : %16lx => %16lx\n", pmd_paddr, pmd_pte);

	if (!(pmd_pte & _PAGE_PRESENT)) {
		ERRMSG("Can't get a valid pmd_pte.\n");
		return NOT_PADDR;
	}
	if (pmd_pte & _PAGE_PSE)	/* 2MB pages */
		return (pmd_pte & ENTRY_MASK & PMD_MASK) +
			(vaddr & ~PMD_MASK);

	/*
	 * Get PTE.
	 */
	pte_paddr  = pmd_pte & ENTRY_MASK;
	pte_paddr += pte_index(vaddr) * sizeof(unsigned long);
	if (!readmem(PADDR, pte_paddr, &pte, sizeof pte)) {
		ERRMSG("Can't get pte (pte_paddr:%lx).\n", pte_paddr);
		return NOT_PADDR;
	}
	if (info->vaddr_for_vtop == vaddr)
		MSG("  PTE : %16lx => %16lx\n", pte_paddr, pte);

	if (!(pte & _PAGE_PRESENT)) {
		ERRMSG("Can't get a valid pte.\n");
		return NOT_PADDR;
	}
	return (pte & ENTRY_MASK) + PAGEOFFSET(vaddr);
}

unsigned long long
vaddr_to_paddr_x86_64(unsigned long vaddr)
{
	unsigned long phys_base;
	unsigned long long paddr;

	/*
	 * Check the relocatable kernel.
	 */
	if (SYMBOL(phys_base) != NOT_FOUND_SYMBOL)
		phys_base = info->phys_base;
	else
		phys_base = 0;

	if (is_vmalloc_addr_x86_64(vaddr)) {
		if ((paddr = vtop4_x86_64(vaddr)) == NOT_PADDR) {
			ERRMSG("Can't convert a virtual address(%lx) to " \
			    "physical address.\n", vaddr);
			return NOT_PADDR;
		}
	} else if (vaddr >= __START_KERNEL_map) {
		paddr = vaddr - __START_KERNEL_map + phys_base;

	} else {
		if (is_xen_memory())
			paddr = vaddr - PAGE_OFFSET_XEN_DOM0;
		else
			paddr = vaddr - PAGE_OFFSET;
	}
	return paddr;
}

/*
 * for Xen extraction
 */
unsigned long long
kvtop_xen_x86_64(unsigned long kvaddr)
{
	unsigned long long dirp, entry;

	if (!is_xen_vaddr(kvaddr))
		return NOT_PADDR;

	if (is_xen_text(kvaddr))
		return (unsigned long)kvaddr - XEN_VIRT_START + info->xen_phys_start;

	if (is_direct(kvaddr))
		return (unsigned long)kvaddr - DIRECTMAP_VIRT_START;

	if ((dirp = kvtop_xen_x86_64(SYMBOL(pgd_l4))) == NOT_PADDR)
		return NOT_PADDR;
	dirp += pml4_index(kvaddr) * sizeof(unsigned long long);
	if (!readmem(MADDR_XEN, dirp, &entry, sizeof(entry)))
		return NOT_PADDR;

	if (!(entry & _PAGE_PRESENT))
		return NOT_PADDR;

	dirp = entry & ENTRY_MASK;
	dirp += pgd_index(kvaddr) * sizeof(unsigned long long);
	if (!readmem(MADDR_XEN, dirp, &entry, sizeof(entry)))
		return NOT_PADDR;

	if (!(entry & _PAGE_PRESENT))
		return NOT_PADDR;

	if (entry & _PAGE_PSE)		/* 1GB pages */
		return (entry & ENTRY_MASK & PGDIR_MASK) +
			(kvaddr & ~PGDIR_MASK);

	dirp = entry & ENTRY_MASK;
	dirp += pmd_index(kvaddr) * sizeof(unsigned long long);
	if (!readmem(MADDR_XEN, dirp, &entry, sizeof(entry)))
		return NOT_PADDR;

	if (!(entry & _PAGE_PRESENT))
		return NOT_PADDR;

	if (entry & _PAGE_PSE)		/* 2MB pages */
		return (entry & ENTRY_MASK & PMD_MASK) +
			(kvaddr & ~PMD_MASK);

	dirp = entry & ENTRY_MASK;
	dirp += pte_index(kvaddr) * sizeof(unsigned long long);
	if (!readmem(MADDR_XEN, dirp, &entry, sizeof(entry)))
		return NOT_PADDR;

	if (!(entry & _PAGE_PRESENT)) {
		return NOT_PADDR;
	}

	return (entry & ENTRY_MASK) + PAGEOFFSET(kvaddr);
}

int get_xen_basic_info_x86_64(void)
{
 	if (!info->xen_phys_start) {
		if (info->xen_crash_info_v < 2) {
			ERRMSG("Can't get Xen physical start address.\n"
			       "Please use the --xen_phys_start option.");
			return FALSE;
		}
		info->xen_phys_start = info->xen_crash_info.v2->xen_phys_start;
	}

	info->xen_virt_start = SYMBOL(domain_list);

	/*
	 * Xen virtual mapping is aligned to 1 GiB boundary.
	 * domain_list lives in bss which sits no more than
	 * 1 GiB below beginning of virtual address space.
	 */
	info->xen_virt_start &= 0xffffffffc0000000;

	if (info->xen_crash_info.com &&
	    info->xen_crash_info.com->xen_major_version >= 4)
		info->directmap_virt_end = DIRECTMAP_VIRT_END_V4;
	else
		info->directmap_virt_end = DIRECTMAP_VIRT_END_V3;

	if (SYMBOL(pgd_l4) == NOT_FOUND_SYMBOL) {
		ERRMSG("Can't get pml4.\n");
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
	} else {
		if (info->xen_crash_info.com &&
		    ((info->xen_crash_info.com->xen_major_version == 4 &&
		      info->xen_crash_info.com->xen_minor_version >= 3) ||
		      info->xen_crash_info.com->xen_major_version > 4))
			info->frame_table_vaddr = FRAMETABLE_VIRT_START_V4_3;
		else
			info->frame_table_vaddr = FRAMETABLE_VIRT_START_V3;
	}

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

int get_xen_info_x86_64(void)
{
	int i;

	if (info->xen_crash_info.com &&
	    (info->xen_crash_info.com->xen_major_version >= 4 ||
	     (info->xen_crash_info.com->xen_major_version == 3 &&
	      info->xen_crash_info.com->xen_minor_version >= 4))) {
		/*
		 * cf. changeset 0858f961c77a
		 */
		for (i = 0; i < info->num_domain; i++) {
			info->domain_list[i].pickled_id =
				(info->domain_list[i].domain_addr -
				 DIRECTMAP_VIRT_START) >> PAGESHIFT();
		}
	} else {
		/*
		 * pickled_id == domain addr for x86_64
		 */
		for (i = 0; i < info->num_domain; i++) {
			info->domain_list[i].pickled_id =
				info->domain_list[i].domain_addr;
		}
	}

	return TRUE;
}

#endif /* x86_64 */

