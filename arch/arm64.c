/*
 * arch/arm64.c : Based on arch/arm.c
 *
 * Copyright (C) 2015 Red Hat, Pratyush Anand <panand@redhat.com>
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

#ifdef __aarch64__

#include "../elf_info.h"
#include "../makedumpfile.h"
#include "../print_info.h"

typedef struct {
	unsigned long pgd;
} pgd_t;

typedef struct {
	pgd_t pgd;
} pud_t;

typedef struct {
	pud_t pud;
} pmd_t;

typedef struct {
	unsigned long pte;
} pte_t;

static int pgtable_level;
static int va_bits;

#define SZ_4K			(4 * 1024)
#define SZ_16K			(16 * 1024)
#define SZ_64K			(64 * 1024)

#define pgd_val(x)		((x).pgd)
#define pud_val(x)		(pgd_val((x).pgd))
#define pmd_val(x)		(pud_val((x).pud))
#define pte_val(x)		((x).pte)

#define PAGE_MASK		(~(PAGESIZE() - 1))
#define PGDIR_SHIFT		((PAGESHIFT() - 3) * pgtable_level + 3)
#define PUD_SHIFT		PGDIR_SHIFT
#define PUD_SIZE		(1UL << PUD_SHIFT)
#define PTRS_PER_PGD		(1 << (va_bits - PGDIR_SHIFT))
#define PTRS_PER_PTE		(1 << (PAGESHIFT() - 3))
#define PMD_SHIFT		((PAGESHIFT() - 3) * 2 + 3)
#define PMD_SIZE		(1UL << PMD_SHIFT)
#define PMD_MASK		(~(PMD_SIZE - 1))
#define PTRS_PER_PMD		PTRS_PER_PTE

#define PAGE_PRESENT		(1 << 0)
#define SECTIONS_SIZE_BITS	30
/* Highest possible physical address supported */
#define PHYS_MASK_SHIFT		48
#define PHYS_MASK		((1UL << PHYS_MASK_SHIFT) - 1)
/*
 * Remove the highest order bits that are not a part of the
 * physical address in a section
 */
#define PMD_SECTION_MASK	((1UL << 40) - 1)

#define PMD_TYPE_MASK		3
#define PMD_TYPE_SECT		1
#define PMD_TYPE_TABLE		3

#define __va(paddr) 			((paddr) - info->phys_base + PAGE_OFFSET)
#define __pa(vaddr) 			((vaddr) - PAGE_OFFSET + info->phys_base)

#define pgd_index(vaddr) 		(((vaddr) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))
#define pgd_offset(pgdir, vaddr)	((pgd_t *)(pgdir) + pgd_index(vaddr))

#define pte_index(vaddr) 		(((vaddr) >> PAGESHIFT()) & (PTRS_PER_PTE - 1))
#define pmd_page_vaddr(pmd)		(__va(pmd_val(pmd) & PHYS_MASK & (int32_t)PAGE_MASK))
#define pte_offset(dir, vaddr) 		((pte_t*)pmd_page_vaddr((*dir)) + pte_index(vaddr))

#define pmd_index(vaddr)		(((vaddr) >> PMD_SHIFT) & (PTRS_PER_PMD - 1))
#define pud_page_vaddr(pud)		(__va(pud_val(pud) & PHYS_MASK & (int32_t)PAGE_MASK))
#define pmd_offset_pgtbl_lvl_2(pud, vaddr) ((pmd_t *)pud)
#define pmd_offset_pgtbl_lvl_3(pud, vaddr) ((pmd_t *)pud_page_vaddr((*pud)) + pmd_index(vaddr))

/* kernel struct page size can be kernel version dependent, currently
 * keep it constant.
 */
#define KERN_STRUCT_PAGE_SIZE		get_structure_size("page", DWARF_INFO_GET_STRUCT_SIZE)

#define ALIGN(x, a) 			(((x) + (a) - 1) & ~((a) - 1))
#define PFN_DOWN(x)			((x) >> PAGESHIFT())
#define VMEMMAP_SIZE			ALIGN((1UL << (va_bits - PAGESHIFT())) * KERN_STRUCT_PAGE_SIZE, PUD_SIZE)
#define MODULES_END			PAGE_OFFSET
#define MODULES_VADDR			(MODULES_END - 0x4000000)

static pmd_t *
pmd_offset(pud_t *puda, pud_t *pudv, unsigned long vaddr)
{
	if (pgtable_level == 2) {
		return pmd_offset_pgtbl_lvl_2(puda, vaddr);
	} else {
		return pmd_offset_pgtbl_lvl_3(pudv, vaddr);
	}
}

static int calculate_plat_config(void)
{
	va_bits = NUMBER(VA_BITS);

	/* derive pgtable_level as per arch/arm64/Kconfig */
	if ((PAGESIZE() == SZ_16K && va_bits == 36) ||
			(PAGESIZE() == SZ_64K && va_bits == 42)) {
		pgtable_level = 2;
	} else if ((PAGESIZE() == SZ_64K && va_bits == 48) ||
			(PAGESIZE() == SZ_4K && va_bits == 39) ||
			(PAGESIZE() == SZ_16K && va_bits == 47)) {
		pgtable_level = 3;
	} else if ((PAGESIZE() != SZ_64K && va_bits == 48)) {
		pgtable_level = 4;
	} else {
		ERRMSG("PAGE SIZE %#lx and VA Bits %d not supported\n",
				PAGESIZE(), va_bits);
		return FALSE;
	}

	return TRUE;
}

static int
is_vtop_from_page_table_arm64(unsigned long vaddr)
{
	/* If virtual address lies in vmalloc, vmemmap or module space
	 * region then, get the physical address from page table.
	 */
	return ((vaddr >= VMALLOC_START && vaddr <= VMALLOC_END)
		|| (vaddr >= VMEMMAP_START && vaddr <= VMEMMAP_END)
		|| (vaddr >= MODULES_VADDR && vaddr <= MODULES_END));
}

int
get_phys_base_arm64(void)
{
	info->phys_base = NUMBER(PHYS_OFFSET);

	DEBUG_MSG("phys_base    : %lx\n", info->phys_base);

	return TRUE;
}

int
get_machdep_info_arm64(void)
{
	if (!calculate_plat_config()) {
		ERRMSG("Can't determine platform config values\n");
		return FALSE;
	}

	info->max_physmem_bits = PHYS_MASK_SHIFT;
	info->section_size_bits = SECTIONS_SIZE_BITS;
	info->page_offset = 0xffffffffffffffffUL << (va_bits - 1);
	info->vmalloc_start = 0xffffffffffffffffUL << va_bits;
	info->vmalloc_end = PAGE_OFFSET - PUD_SIZE - VMEMMAP_SIZE - 0x10000;
	info->vmemmap_start = VMALLOC_END + 0x10000;
	info->vmemmap_end = VMEMMAP_START + VMEMMAP_SIZE;

	DEBUG_MSG("max_physmem_bits : %lx\n", info->max_physmem_bits);
	DEBUG_MSG("section_size_bits: %lx\n", info->section_size_bits);
	DEBUG_MSG("page_offset      : %lx\n", info->page_offset);
	DEBUG_MSG("vmalloc_start    : %lx\n", info->vmalloc_start);
	DEBUG_MSG("vmalloc_end      : %lx\n", info->vmalloc_end);
	DEBUG_MSG("vmemmap_start    : %lx\n", info->vmemmap_start);
	DEBUG_MSG("vmemmap_end      : %lx\n", info->vmemmap_end);
	DEBUG_MSG("modules_start    : %lx\n", MODULES_VADDR);
	DEBUG_MSG("modules_end      : %lx\n", MODULES_END);

	return TRUE;
}

unsigned long long
kvtop_xen_arm64(unsigned long kvaddr)
{
	return ERROR;
}

int
get_xen_basic_info_arm64(void)
{
	return ERROR;
}

int
get_xen_info_arm64(void)
{
	return ERROR;
}

int
get_versiondep_info_arm64(void)
{
	return TRUE;
}

/*
 * vtop_arm64() - translate arbitrary virtual address to physical
 * @vaddr: virtual address to translate
 *
 * Function translates @vaddr into physical address using page tables. This
 * address can be any virtual address. Returns physical address of the
 * corresponding virtual address or %NOT_PADDR when there is no translation.
 */
static unsigned long long
vtop_arm64(unsigned long vaddr)
{
	unsigned long long paddr = NOT_PADDR;
	pgd_t	*pgda, pgdv;
	pud_t	*puda, pudv;
	pmd_t	*pmda, pmdv;
	pte_t 	*ptea, ptev;

	if (SYMBOL(swapper_pg_dir) == NOT_FOUND_SYMBOL) {
		ERRMSG("Can't get the symbol of swapper_pg_dir.\n");
		return NOT_PADDR;
	}

	pgda = pgd_offset(SYMBOL(swapper_pg_dir), vaddr);
	if (!readmem(VADDR, (unsigned long long)pgda, &pgdv, sizeof(pgdv))) {
		ERRMSG("Can't read pgd\n");
		return NOT_PADDR;
	}

	pudv.pgd = pgdv;
	puda = (pud_t *)pgda;

	pmda = pmd_offset(puda, &pudv, vaddr);
	if (!readmem(VADDR, (unsigned long long)pmda, &pmdv, sizeof(pmdv))) {
		ERRMSG("Can't read pmd\n");
		return NOT_PADDR;
	}

	switch (pmd_val(pmdv) & PMD_TYPE_MASK) {
	case PMD_TYPE_TABLE:
		ptea = pte_offset(&pmdv, vaddr);
		/* 64k page */
		if (!readmem(VADDR, (unsigned long long)ptea, &ptev, sizeof(ptev))) {
			ERRMSG("Can't read pte\n");
			return NOT_PADDR;
		}

		if (!(pte_val(ptev) & PAGE_PRESENT)) {
			ERRMSG("Can't get a valid pte.\n");
			return NOT_PADDR;
		} else {

			paddr = (PAGEBASE(pte_val(ptev)) & PHYS_MASK)
					+ (vaddr & (PAGESIZE() - 1));
		}
		break;
	case PMD_TYPE_SECT:
		/* 1GB section */
		paddr = (pmd_val(pmdv) & (PMD_MASK & PMD_SECTION_MASK))
					+ (vaddr & (PMD_SIZE - 1));
		break;
	}

	return paddr;
}

unsigned long long
vaddr_to_paddr_arm64(unsigned long vaddr)
{
	/*
	 * use translation tables when a) user has explicitly requested us to
	 * perform translation for a given address. b) virtual address lies in
	 * vmalloc, vmemmap or modules memory region. Otherwise we assume that
	 * the translation is done within the kernel direct mapped region.
	 */
	if ((info->vaddr_for_vtop == vaddr) ||
			is_vtop_from_page_table_arm64(vaddr))
		return vtop_arm64(vaddr);

	return __pa(vaddr);
}
#endif /* __aarch64__ */
