/*
 * Copyright (C) 2014, 2017 Oracle and/or its affiliates
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation (version 2 of the License).
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifdef __sparc64__

#include "../elf_info.h"
#include "../makedumpfile.h"
#include "../print_info.h"

int get_versiondep_info_sparc64(void)
{
	info->section_size_bits = _SECTION_SIZE_BITS;

	/* Check if we can get MAX_PHYSMEM_BITS from vmcoreinfo */
	if (NUMBER(MAX_PHYSMEM_BITS) != NOT_FOUND_NUMBER)
		info->max_physmem_bits = NUMBER(MAX_PHYSMEM_BITS);
	else if (info->kernel_version >= KERNEL_VERSION(3, 8, 13))
		info->max_physmem_bits = _MAX_PHYSMEM_BITS_L4;
	else
		info->max_physmem_bits = _MAX_PHYSMEM_BITS_L3;

	if (info->kernel_version < KERNEL_VERSION(3, 8, 13)) {
		info->flag_vmemmap = TRUE;
		info->vmemmap_start = VMEMMAP_BASE_SPARC64;
		info->vmemmap_end = VMEMMAP_BASE_SPARC64 +
			((1UL << (info->max_physmem_bits - PAGE_SHIFT)) *
			 SIZE(page));
	}

	return TRUE;
}

int get_phys_base_sparc64(void)
{
	/* Ideally we'd search the pt_load entries until we found one
	 * containing KVBASE (_stext), but get_symbol_info hasn't been
	 * called yet. We'll just go with the first entry.
	 */
	unsigned long long phys_start;
	unsigned long long virt_start;
	unsigned long long virt_end;

	if (get_pt_load(0, &phys_start, NULL, &virt_start, &virt_end)) {
		info->phys_base = phys_start & ~KVBASE_MASK;
		return TRUE;
	}
	ERRMSG("Can't find kernel segment\n");
	return FALSE;
}

int is_vmalloc_addr_sparc64(unsigned long vaddr)
{
	return (vaddr >= VMALLOC_START_SPARC64);
}

int is_vmemmap_addr_sparc64(unsigned long vaddr)
{
	if (info->flag_vmemmap &&
	    (vaddr >= info->vmemmap_start) && (vaddr < info->vmemmap_end))
		return TRUE;

	return FALSE;
}

unsigned long vmemmap_to_phys_sparc64(unsigned long vaddr)
{
	unsigned long vmemmap_table;
	unsigned long offset = vaddr - info->vmemmap_start;
	unsigned long chunk_offset = offset & ~VMEMMAP_CHUNK_MASK;
	unsigned long chunk;
	unsigned long index;
	unsigned long pte;
	unsigned long pte_paddr;
	unsigned long pte_offset;

	vmemmap_table = SYMBOL(vmemmap_table);
	if (vmemmap_table == NOT_FOUND_SYMBOL) {
		ERRMSG("Can't get symbol of vmemmap_table\n");
		return NOT_PADDR;
	}

	index = offset >> NR_CHUNKS_SHIFT;
	if (!readmem(VADDR, vmemmap_table + (index * sizeof(long)),
		     &pte_paddr, sizeof(long))) {
		ERRMSG("Error reading 1st level vmemmap_table\n");
		return NOT_PADDR;
	}
	chunk = (vaddr & ~NR_CHUNKS_MASK) >> VMEMMAP_CHUNK_SHIFT;
	pte_offset = chunk * sizeof(pte);
	pte_paddr += pte_offset;
	if (!readmem(PADDR, pte_paddr, &pte, sizeof(pte))) {
		ERRMSG("Error reading 2nd level vmemmap_table\n");
		return NOT_PADDR;
	}
	return pte_to_pa(pte) | chunk_offset;
}

unsigned long vtop3_sparc64(unsigned long vaddr)
{
	unsigned long pgdir, pgd_paddr, pmd_paddr, pte_paddr;
	unsigned long pgd_pte, pmd_pte, pte;

	pgdir = SYMBOL(swapper_pg_dir);
	if (pgdir == NOT_FOUND_SYMBOL) {
		ERRMSG("Can't get symbol of swapper_pg_dir\n");
		return NOT_PADDR;
	}

	pgd_paddr = pgd_offset_l3(pgdir, vaddr);
	if (!readmem(VADDR, pgd_paddr, &pgd_pte, sizeof pgd_pte)) {
		ERRMSG("Can't get pgd_pte, pgd_paddr = 0x%lx\n", pgd_paddr);
		return NOT_PADDR;
	}
	if (pgd_none(pgd_pte)) {
		ERRMSG("Can't get a valid pgd_pte.\n");
		return NOT_PADDR;
	}

	pmd_paddr = pmd_offset(pgd_pte, vaddr);
	if (!readmem(PADDR, pmd_paddr, &pmd_pte, sizeof pmd_pte)) {
		ERRMSG("Can't get pmd_pte, pmd_paddr = 0x%lx\n", pmd_paddr);
		return NOT_PADDR;
	}
	if (pmd_none(pmd_pte)) {
		ERRMSG("Can't get a valid pmd_pte.\n");
		return NOT_PADDR;
	}

	if (pmd_large(pmd_pte))
		return pte_to_pa(pmd_pte) + (vaddr & ~PMD_MASK);

	pte_paddr = pte_offset(pmd_pte, vaddr);
	if (!readmem(PADDR, pte_paddr, &pte, sizeof pte)) {
		ERRMSG("Can't get pte, pte_paddr = 0x%lx\n", pmd_paddr);
		return NOT_PADDR;
	}
	if (!pte_present(pte)) {
		ERRMSG("Can't get a valid pte.\n");
		return NOT_PADDR;
	}

	return pte_to_pa(pte) + (vaddr & ~PAGE_MASK);
}

unsigned long vtop4_sparc64(unsigned long vaddr)
{
	unsigned long pgdir, pgd_paddr, pud_paddr, pmd_paddr, pte_paddr;
	unsigned long pgd_pte, pud_pte, pmd_pte, pte;

	pgdir = SYMBOL(swapper_pg_dir);
	if (pgdir == NOT_FOUND_SYMBOL) {
		ERRMSG("Can't get symbol of swapper_pg_dir\n");
		return NOT_PADDR;
	}

	pgd_paddr = pgd_offset_l4(pgdir, vaddr);
	if (!readmem(VADDR, pgd_paddr, &pgd_pte, sizeof pgd_pte)) {
		ERRMSG("Can't get pgd_pte, pgd_paddr = 0x%lx\n", pgd_paddr);
		return NOT_PADDR;
	}
	if (pgd_none(pgd_pte)) {
		ERRMSG("Can't get a valid pgd_pte.\n");
		return NOT_PADDR;
	}

	pud_paddr = pud_offset(pgd_pte, vaddr);
	if (!readmem(PADDR, pud_paddr, &pud_pte, sizeof pud_pte)) {
		ERRMSG("Can't get pud_pte, pud_paddr = 0x%lx\n", pud_paddr);
		return NOT_PADDR;
	}
	if (pud_none(pud_pte)) {
		ERRMSG("Can't get a valid pud_pte.\n");
		return NOT_PADDR;
	}

	if (pud_large(pud_pte))
		return pte_to_pa(pud_pte) + (vaddr & ~PUD_MASK);

	pmd_paddr = pmd_offset(pud_pte, vaddr);
	if (!readmem(PADDR, pmd_paddr, &pmd_pte, sizeof pmd_pte)) {
		ERRMSG("Can't get pmd_pte, pmd_paddr = 0x%lx\n", pmd_paddr);
		return NOT_PADDR;
	}
	if (pmd_none(pmd_pte)) {
		ERRMSG("Can't get a valid pmd_pte.\n");
		return NOT_PADDR;
	}

	if (pmd_large(pmd_pte))
		return pte_to_pa(pmd_pte) + (vaddr & ~PMD_MASK);

	pte_paddr = pte_offset(pmd_pte, vaddr);
	if (!readmem(PADDR, pte_paddr, &pte, sizeof pte)) {
		ERRMSG("Can't get pte, pte_paddr = 0x%lx\n", pmd_paddr);
		return NOT_PADDR;
	}
	if (!pte_present(pte)) {
		ERRMSG("Can't get a valid pte.\n");
		return NOT_PADDR;
	}

	return pte_to_pa(pte) + (vaddr & ~PAGE_MASK);
}

unsigned long long vaddr_to_paddr_sparc64(unsigned long vaddr)
{
	unsigned long paddr;

	paddr = vaddr_to_paddr_general(vaddr);
	if (paddr != NOT_PADDR)
		return paddr;

	if (is_vmemmap_addr_sparc64(vaddr))
		paddr = vmemmap_to_phys_sparc64(vaddr);
	else if (is_vmalloc_addr_sparc64(vaddr)) {
		if (info->kernel_version >= KERNEL_VERSION(3, 8, 13))
			paddr = vtop4_sparc64(vaddr);
		else
			paddr = vtop3_sparc64(vaddr);
	}
	if (paddr == NOT_PADDR)
		ERRMSG("vaddr not mapped: 0x%lx\n", vaddr);

	return paddr;
}

#endif /* sparc64 */
