/*
 * riscv64.c
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
#ifdef __riscv64__

#include "../print_info.h"
#include "../elf_info.h"
#include "../makedumpfile.h"

int
get_phys_base_riscv64(void)
{
	if (NUMBER(phys_ram_base) != NOT_FOUND_NUMBER)
		info->phys_base = NUMBER(phys_ram_base);
	else
		/* In case that you are using qemu rv64 env */
		info->phys_base = 0x80200000;

	DEBUG_MSG("phys_base    : %lx\n", info->phys_base);
	return TRUE;
}

int
get_machdep_info_riscv64(void)
{

	if(NUMBER(va_bits) == NOT_FOUND_NUMBER ||  NUMBER(page_offset) == NOT_FOUND_NUMBER ||
	   NUMBER(vmalloc_start) == NOT_FOUND_NUMBER || NUMBER(vmalloc_end) == NOT_FOUND_NUMBER ||
	   NUMBER(vmemmap_start) == NOT_FOUND_NUMBER ||  NUMBER(vmemmap_end) == NOT_FOUND_NUMBER ||
	   NUMBER(modules_vaddr) == NOT_FOUND_NUMBER ||  NUMBER(modules_end) == NOT_FOUND_NUMBER ||
	   NUMBER(kernel_link_addr) == NOT_FOUND_NUMBER || NUMBER(va_kernel_pa_offset) == NOT_FOUND_NUMBER)
		return FALSE;

	if (NUMBER(MAX_PHYSMEM_BITS) != NOT_FOUND_NUMBER)
		info->max_physmem_bits = NUMBER(MAX_PHYSMEM_BITS);
	else
		info->max_physmem_bits = _MAX_PHYSMEM_BITS;

	if (NUMBER(SECTION_SIZE_BITS) != NOT_FOUND_NUMBER)
		info->section_size_bits = NUMBER(SECTION_SIZE_BITS);
	else
		info->section_size_bits = _SECTION_SIZE_BITS;

	info->page_offset = NUMBER(page_offset);

	DEBUG_MSG("va_bits    : %ld\n", NUMBER(va_bits));
	DEBUG_MSG("page_offset   : %lx\n", NUMBER(page_offset));
	DEBUG_MSG("vmalloc_start : %lx\n", NUMBER(vmalloc_start));
	DEBUG_MSG("vmalloc_end   : %lx\n", NUMBER(vmalloc_end));
	DEBUG_MSG("vmemmap_start : %lx\n", NUMBER(vmemmap_start));
	DEBUG_MSG("vmemmap_end   : %lx\n", NUMBER(vmemmap_end));
	DEBUG_MSG("modules_vaddr : %lx\n", NUMBER(modules_vaddr));
	DEBUG_MSG("modules_end   : %lx\n", NUMBER(modules_end));
	DEBUG_MSG("kernel_link_addr    : %lx\n", NUMBER(kernel_link_addr));
	DEBUG_MSG("va_kernel_pa_offset : %lx\n", NUMBER(va_kernel_pa_offset));

	return TRUE;
}

/*
 * For direct memory mapping
 */

#define VTOP(X) ({ 									\
	ulong _X = X;									\
	(_X) >= NUMBER(kernel_link_addr) ? ((_X) - (NUMBER(va_kernel_pa_offset))):	\
	((_X) - PAGE_OFFSET + (info->phys_base));					\
	})

static unsigned long long
vtop_riscv64(pgd_t * pgd, unsigned long vaddr, long va_bits)
{
	unsigned long long paddr = NOT_PADDR;
	pgd_t *pgda;
	p4d_t *p4da;
	pud_t *puda;
	pmd_t *pmda;
	pte_t *ptea;
	ulong pt_val, pt_phys;

#define pgd_index(X) ((va_bits == VA_BITS_SV57) ? pgd_index_l5(X) : 	\
	((va_bits == VA_BITS_SV48) ? pgd_index_l4(X) : pgd_index_l3(X)))

	/* PGD */
	pgda = (pgd_t *)(pgd) + pgd_index(vaddr);
	if (!readmem(PADDR, (unsigned long long)pgda, &pt_val, sizeof(pt_val))) {
		ERRMSG("Can't read pgd\n");
		goto invalid;
	}

	pt_val &= PTE_PFN_PROT_MASK;

	if (!(pt_val & _PAGE_PRESENT)) {
		ERRMSG("Can't get a valid pgd.\n");
		goto invalid;
	}

	pt_phys = (pt_val >> _PAGE_PFN_SHIFT) << PAGESHIFT();

	if (pt_val & _PAGE_LEAF)
		goto out;

	if (va_bits == VA_BITS_SV57)
		goto p4d;
	else if (va_bits == VA_BITS_SV48)
		goto pud;
	else
		goto pmd;
p4d:
	/* P4D */
	p4da = (p4d_t *)(pt_phys) + p4d_index(vaddr);
	if (!readmem(PADDR, (unsigned long long)p4da, &pt_val, sizeof(pt_val))) {
		ERRMSG("Can't read p4d\n");
		goto invalid;
	}

	pt_val &= PTE_PFN_PROT_MASK;

	if (!(pt_val & _PAGE_PRESENT)) {
		ERRMSG("Can't get a valid p4d.\n");
		goto invalid;
	}

	pt_phys = (pt_val >> _PAGE_PFN_SHIFT) << PAGESHIFT();

	if (pt_val & _PAGE_LEAF)
		goto out;
pud:
	/* PUD */
	puda = (pud_t *)(pt_phys) + pud_index(vaddr);
	if (!readmem(PADDR, (unsigned long long)puda, &pt_val, sizeof(pt_val))) {
		ERRMSG("Can't read pud\n");
		goto invalid;
	}

	pt_val &= PTE_PFN_PROT_MASK;

	if (!(pt_val & _PAGE_PRESENT)) {
		ERRMSG("Can't get a valid pud.\n");
		goto invalid;
	}

	pt_phys = (pt_val >> _PAGE_PFN_SHIFT) << PAGESHIFT();

	if(pt_val & _PAGE_LEAF)
		goto out;
pmd:
	/* PMD */
	pmda = (pmd_t *)(pt_phys) + pmd_index(vaddr);
	if (!readmem(PADDR, (unsigned long long)pmda, &pt_val, sizeof(pt_val))) {
		ERRMSG("Can't read pmd\n");
		goto invalid;
	}

	pt_val &= PTE_PFN_PROT_MASK;

	if (!(pt_val & _PAGE_PRESENT)) {
		ERRMSG("Can't get a valid pmd.\n");
		goto invalid;
	}

	pt_phys = (pt_val >> _PAGE_PFN_SHIFT) << PAGESHIFT();

	if (pt_val & _PAGE_LEAF)
		goto out;

	/* PTE */
	ptea = (pte_t *)(pt_phys) + pte_index(vaddr);
	if (!readmem(PADDR, (unsigned long long)ptea, &pt_val, sizeof(pt_val))) {
		ERRMSG("Can't read pte\n");
		goto invalid;
	}

	pt_val &= PTE_PFN_PROT_MASK;

	if (!(pt_val & _PAGE_PRESENT)) {
		ERRMSG("Can't get a valid pte.\n");
		goto invalid;
	}

	pt_phys = (pt_val >> _PAGE_PFN_SHIFT) << PAGESHIFT();

out:
	paddr = pt_phys + PAGEOFFSET(vaddr);
invalid:
	return paddr;
}

unsigned long long
vaddr_to_paddr_riscv64(unsigned long vaddr)
{
	unsigned long long swapper_phys;

	if (vaddr >= PAGE_OFFSET &&
	    !(vaddr >= NUMBER(modules_vaddr) && vaddr <= NUMBER(modules_end))){
		return VTOP(vaddr);
	}

	if (SYMBOL(swapper_pg_dir) == NOT_FOUND_SYMBOL) {
		ERRMSG("Can't get the symbol of swapper_pg_dir.\n");
		return NOT_PADDR;
	}

	swapper_phys = VTOP(SYMBOL(swapper_pg_dir));

	return vtop_riscv64((pgd_t *)swapper_phys, vaddr, NUMBER(va_bits));
}

#endif /* __riscv64__ */
