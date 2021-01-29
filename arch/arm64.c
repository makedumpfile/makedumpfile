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

#define __pte(x)	((pte_t) { (x) } )
#define __pmd(x)	((pmd_t) { (x) } )
#define __pud(x)	((pud_t) { (x) } )
#define __pgd(x)	((pgd_t) { (x) } )

static int lpa_52_bit_support_available;
static int pgtable_level;
static int va_bits;
static int vabits_actual;
static int flipped_va;
static unsigned long kimage_voffset;

#define SZ_4K			4096
#define SZ_16K			16384
#define SZ_64K			65536

#define PAGE_OFFSET_36		((0xffffffffffffffffUL) << 36)
#define PAGE_OFFSET_39		((0xffffffffffffffffUL) << 39)
#define PAGE_OFFSET_42		((0xffffffffffffffffUL) << 42)
#define PAGE_OFFSET_47		((0xffffffffffffffffUL) << 47)
#define PAGE_OFFSET_48		((0xffffffffffffffffUL) << 48)

#define pgd_val(x)		((x).pgd)
#define pud_val(x)		(pgd_val((x).pgd))
#define pmd_val(x)		(pud_val((x).pud))
#define pte_val(x)		((x).pte)

/* See 'include/uapi/linux/const.h' for definitions below */
#define __AC(X,Y)	(X##Y)
#define _AC(X,Y)	__AC(X,Y)
#define _AT(T,X)	((T)(X))

/* See 'include/asm/pgtable-types.h' for definitions below */
typedef unsigned long pteval_t;
typedef unsigned long pmdval_t;
typedef unsigned long pudval_t;
typedef unsigned long pgdval_t;

#define PAGE_SHIFT	PAGESHIFT()

/* See 'arch/arm64/include/asm/pgtable-hwdef.h' for definitions below */

#define ARM64_HW_PGTABLE_LEVEL_SHIFT(n)	((PAGE_SHIFT - 3) * (4 - (n)) + 3)

#define PTRS_PER_PTE		(1 << (PAGE_SHIFT - 3))

/*
 * PMD_SHIFT determines the size a level 2 page table entry can map.
 */
#define PMD_SHIFT		ARM64_HW_PGTABLE_LEVEL_SHIFT(2)
#define PMD_SIZE		(_AC(1, UL) << PMD_SHIFT)
#define PMD_MASK		(~(PMD_SIZE-1))
#define PTRS_PER_PMD		PTRS_PER_PTE

/*
 * PUD_SHIFT determines the size a level 1 page table entry can map.
 */
#define PUD_SHIFT		ARM64_HW_PGTABLE_LEVEL_SHIFT(1)
#define PUD_SIZE		(_AC(1, UL) << PUD_SHIFT)
#define PUD_MASK		(~(PUD_SIZE-1))
#define PTRS_PER_PUD		PTRS_PER_PTE

/*
 * PGDIR_SHIFT determines the size a top-level page table entry can map
 * (depending on the configuration, this level can be 0, 1 or 2).
 */
#define PGDIR_SHIFT		ARM64_HW_PGTABLE_LEVEL_SHIFT(4 - (pgtable_level))
#define PGDIR_SIZE		(_AC(1, UL) << PGDIR_SHIFT)
#define PGDIR_MASK		(~(PGDIR_SIZE-1))
#define PTRS_PER_PGD		(1 << ((va_bits) - PGDIR_SHIFT))

/*
 * Section address mask and size definitions.
 */
#define SECTIONS_SIZE_BITS	30

/*
 * Hardware page table definitions.
 *
 * Level 1 descriptor (PUD).
 */
#define PUD_TYPE_TABLE		(_AT(pudval_t, 3) << 0)
#define PUD_TABLE_BIT		(_AT(pudval_t, 1) << 1)
#define PUD_TYPE_MASK		(_AT(pudval_t, 3) << 0)
#define PUD_TYPE_SECT		(_AT(pudval_t, 1) << 0)

/*
 * Level 2 descriptor (PMD).
 */
#define PMD_TYPE_MASK		(_AT(pmdval_t, 3) << 0)
#define PMD_TYPE_FAULT		(_AT(pmdval_t, 0) << 0)
#define PMD_TYPE_TABLE		(_AT(pmdval_t, 3) << 0)
#define PMD_TYPE_SECT		(_AT(pmdval_t, 1) << 0)
#define PMD_TABLE_BIT		(_AT(pmdval_t, 1) << 1)

/*
 * Level 3 descriptor (PTE).
 */
#define PTE_ADDR_LOW		(((_AT(pteval_t, 1) << (48 - PAGE_SHIFT)) - 1) << PAGE_SHIFT)
#define PTE_ADDR_HIGH		(_AT(pteval_t, 0xf) << 12)

static inline unsigned long
get_pte_addr_mask_arm64(void)
{
	if (lpa_52_bit_support_available)
		return (PTE_ADDR_LOW | PTE_ADDR_HIGH);
	else
		return PTE_ADDR_LOW;
}

#define PTE_ADDR_MASK		get_pte_addr_mask_arm64()

#define PAGE_MASK		(~(PAGESIZE() - 1))
#define PAGE_PRESENT		(1 << 0)

/* Helper API to convert between a physical address and its placement
 * in a page table entry, taking care of 52-bit addresses.
 */
static inline unsigned long
__pte_to_phys(pte_t pte)
{
	if (lpa_52_bit_support_available)
		return ((pte_val(pte) & PTE_ADDR_LOW) | ((pte_val(pte) & PTE_ADDR_HIGH) << 36));
	else
		return (pte_val(pte) & PTE_ADDR_MASK);
}

/* Find an entry in a page-table-directory */
#define pgd_index(vaddr)		(((vaddr) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))

static inline pte_t
pgd_pte(pgd_t pgd)
{
	return __pte(pgd_val(pgd));
}

#define __pgd_to_phys(pgd)		__pte_to_phys(pgd_pte(pgd))
#define pgd_offset(pgd, vaddr)		((pgd_t *)(pgd) + pgd_index(vaddr))

static inline pte_t pud_pte(pud_t pud)
{
	return __pte(pud_val(pud));
}

static inline unsigned long
pgd_page_paddr(pgd_t pgd)
{
	return __pgd_to_phys(pgd);
}

/* Find an entry in the first-level page table. */
#define pud_index(vaddr)		(((vaddr) >> PUD_SHIFT) & (PTRS_PER_PUD - 1))
#define __pud_to_phys(pud)		__pte_to_phys(pud_pte(pud))

static inline unsigned long
pud_page_paddr(pud_t pud)
{
	return __pud_to_phys(pud);
}

/* Find an entry in the second-level page table. */
#define pmd_index(vaddr)		(((vaddr) >> PMD_SHIFT) & (PTRS_PER_PMD - 1))

static inline pte_t pmd_pte(pmd_t pmd)
{
	return __pte(pmd_val(pmd));
}

#define __pmd_to_phys(pmd)		__pte_to_phys(pmd_pte(pmd))

static inline unsigned long
pmd_page_paddr(pmd_t pmd)
{
	return __pmd_to_phys(pmd);
}

/* Find an entry in the third-level page table. */
#define pte_index(vaddr)		(((vaddr) >> PAGESHIFT()) & (PTRS_PER_PTE - 1))
#define pte_offset(dir, vaddr)		(pmd_page_paddr((*dir)) + pte_index(vaddr) * sizeof(pte_t))

/*
 * The linear kernel range starts at the bottom of the virtual address
 * space. Testing the top bit for the start of the region is a
 * sufficient check and avoids having to worry about the tag.
 */
#define is_linear_addr(addr)	(flipped_va ?	\
	(!((unsigned long)(addr) & (1UL << (vabits_actual - 1)))) : \
	(!!((unsigned long)(addr) & (1UL << (vabits_actual - 1)))))

static unsigned long long
__pa(unsigned long vaddr)
{
	if (kimage_voffset == NOT_FOUND_NUMBER || is_linear_addr(vaddr))
		return ((vaddr & ~PAGE_OFFSET) + info->phys_base);
	else
		return (vaddr - kimage_voffset);
}

static pud_t *
pud_offset(pgd_t *pgda, pgd_t *pgdv, unsigned long vaddr)
{
	if (pgtable_level > 3)
		return (pud_t *)(pgd_page_paddr(*pgdv) + pud_index(vaddr) * sizeof(pud_t));
	else
		return (pud_t *)(pgda);
}

static pmd_t *
pmd_offset(pud_t *puda, pud_t *pudv, unsigned long vaddr)
{
	if (pgtable_level > 2)
		return (pmd_t *)(pud_page_paddr(*pudv) + pmd_index(vaddr) * sizeof(pmd_t));
	else
		return (pmd_t *)(puda);
}

static int calculate_plat_config(void)
{
	/* derive pgtable_level as per arch/arm64/Kconfig */
	if ((PAGESIZE() == SZ_16K && va_bits == 36) ||
			(PAGESIZE() == SZ_64K && va_bits == 42)) {
		pgtable_level = 2;
	} else if ((PAGESIZE() == SZ_64K && va_bits == 48) ||
			(PAGESIZE() == SZ_64K && va_bits == 52) ||
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
	DEBUG_MSG("pgtable_level: %d\n", pgtable_level);

	return TRUE;
}

unsigned long
get_kvbase_arm64(void)
{
	if (flipped_va)
		return PAGE_OFFSET;

	return (0xffffffffffffffffUL << va_bits);
}

int
get_phys_base_arm64(void)
{
	int i;
	unsigned long long phys_start;
	unsigned long long virt_start;

	if (NUMBER(PHYS_OFFSET) != NOT_FOUND_NUMBER) {
		info->phys_base = NUMBER(PHYS_OFFSET);
		DEBUG_MSG("phys_base    : %lx (vmcoreinfo)\n",
				info->phys_base);
		return TRUE;
	}

	if (get_num_pt_loads() && PAGE_OFFSET) {
		for (i = 0;
		    get_pt_load(i, &phys_start, NULL, &virt_start, NULL);
		    i++) {
			if (virt_start != NOT_KV_ADDR
			    && virt_start >= PAGE_OFFSET
			    && phys_start != NOT_PADDR) {
				info->phys_base = phys_start -
					(virt_start & ~PAGE_OFFSET);
				DEBUG_MSG("phys_base    : %lx (pt_load)\n",
						info->phys_base);
				return TRUE;
			}
		}
	}

	ERRMSG("Cannot determine phys_base\n");
	return FALSE;
}

ulong
get_stext_symbol(void)
{
	int found;
	FILE *fp;
	char buf[BUFSIZE];
	char *kallsyms[MAXARGS];
	ulong kallsym;

	if (!file_exists("/proc/kallsyms")) {
		ERRMSG("(%s) does not exist, will not be able to read symbols. %s\n",
		       "/proc/kallsyms", strerror(errno));
		return FALSE;
	}

	if ((fp = fopen("/proc/kallsyms", "r")) == NULL) {
		ERRMSG("Cannot open (%s) to read symbols. %s\n",
		       "/proc/kallsyms", strerror(errno));
		return FALSE;
	}

	found = FALSE;
	kallsym = 0;

	while (!found && fgets(buf, BUFSIZE, fp) &&
	      (parse_line(buf, kallsyms) == 3)) {
		if (hexadecimal(kallsyms[0], 0) &&
		    STREQ(kallsyms[2], "_stext")) {
			kallsym = htol(kallsyms[0], 0);
			found = TRUE;
			break;
		}
	}
	fclose(fp);

	return(found ? kallsym : FALSE);
}

static int
get_va_bits_from_stext_arm64(void)
{
	ulong _stext;

	_stext = get_stext_symbol();
	if (!_stext) {
		ERRMSG("Can't get the symbol of _stext.\n");
		return FALSE;
	}

	/*
	 * Derive va_bits as per arch/arm64/Kconfig. Note that this is a
	 * best case approximation at the moment, as there can be
	 * inconsistencies in this calculation (for e.g., for 52-bit
	 * kernel VA case, the 48th bit is set in * the _stext symbol).
	 */
	if ((_stext & PAGE_OFFSET_48) == PAGE_OFFSET_48) {
		va_bits = 48;
	} else if ((_stext & PAGE_OFFSET_47) == PAGE_OFFSET_47) {
		va_bits = 47;
	} else if ((_stext & PAGE_OFFSET_42) == PAGE_OFFSET_42) {
		va_bits = 42;
	} else if ((_stext & PAGE_OFFSET_39) == PAGE_OFFSET_39) {
		va_bits = 39;
	} else if ((_stext & PAGE_OFFSET_36) == PAGE_OFFSET_36) {
		va_bits = 36;
	} else {
		ERRMSG("Cannot find a proper _stext for calculating VA_BITS\n");
		return FALSE;
	}

	DEBUG_MSG("va_bits       : %d (guess from _stext)\n", va_bits);

	return TRUE;
}

static void
get_page_offset_arm64(void)
{
	ulong page_end;
	int vabits_min;

	/*
	 * See arch/arm64/include/asm/memory.h for more details of
	 * the PAGE_OFFSET calculation.
	 */
	vabits_min = (va_bits > 48) ? 48 : va_bits;
	page_end = -(1UL << (vabits_min - 1));

	if (SYMBOL(_stext) > page_end) {
		flipped_va = TRUE;
		info->page_offset = -(1UL << vabits_actual);
	} else {
		flipped_va = FALSE;
		info->page_offset = -(1UL << (vabits_actual - 1));
	}

	DEBUG_MSG("page_offset   : %lx (from page_end check)\n",
		info->page_offset);
}

int
get_machdep_info_arm64(void)
{
	/* Check if va_bits is still not initialized. If still 0, call
	 * get_versiondep_info() to initialize the same.
	 */
	if (!va_bits)
		get_versiondep_info_arm64();

	/* Determine if the PA address range is 52-bits: ARMv8.2-LPA */
	if (NUMBER(MAX_PHYSMEM_BITS) != NOT_FOUND_NUMBER) {
		info->max_physmem_bits = NUMBER(MAX_PHYSMEM_BITS);
		DEBUG_MSG("max_physmem_bits : %ld (vmcoreinfo)\n", info->max_physmem_bits);
		if (info->max_physmem_bits == 52)
			lpa_52_bit_support_available = 1;
	} else {
		if (va_bits == 52)
			info->max_physmem_bits = 52; /* just guess */
		else
			info->max_physmem_bits = 48;

		DEBUG_MSG("max_physmem_bits : %ld (guess)\n", info->max_physmem_bits);
	}

	if (!calculate_plat_config()) {
		ERRMSG("Can't determine platform config values\n");
		return FALSE;
	}

	kimage_voffset = NUMBER(kimage_voffset);
	info->section_size_bits = SECTIONS_SIZE_BITS;

	DEBUG_MSG("kimage_voffset   : %lx\n", kimage_voffset);
	DEBUG_MSG("section_size_bits: %ld\n", info->section_size_bits);

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
	if (NUMBER(VA_BITS) != NOT_FOUND_NUMBER) {
		va_bits = NUMBER(VA_BITS);
		DEBUG_MSG("va_bits      : %d (vmcoreinfo)\n", va_bits);
	} else if (get_va_bits_from_stext_arm64() == FALSE) {
		ERRMSG("Can't determine va_bits.\n");
		return FALSE;
	}

	/*
	 * See TCR_EL1, Translation Control Register (EL1) register
	 * description in the ARMv8 Architecture Reference Manual.
	 * Basically, we can use the TCR_EL1.T1SZ value to determine
	 * the virtual addressing range supported in the kernel-space
	 * (i.e. vabits_actual) since Linux 5.9.
	 */
	if (NUMBER(TCR_EL1_T1SZ) != NOT_FOUND_NUMBER) {
		vabits_actual = 64 - NUMBER(TCR_EL1_T1SZ);
		DEBUG_MSG("vabits_actual : %d (vmcoreinfo)\n", vabits_actual);
	} else if ((va_bits == 52) && (SYMBOL(mem_section) != NOT_FOUND_SYMBOL)) {
		/*
		 * Linux 5.4 through 5.10 have the following linear space:
		 *   48-bit: 0xffff000000000000 - 0xffff7fffffffffff
		 *   52-bit: 0xfff0000000000000 - 0xfff7ffffffffffff
		 * and SYMBOL(mem_section) should be in linear space if
		 * the kernel is configured with COMFIG_SPARSEMEM_EXTREME=y.
		 */
		if (SYMBOL(mem_section) & (1UL << (va_bits - 1)))
			vabits_actual = 48;
		else
			vabits_actual = 52;
		DEBUG_MSG("vabits_actual : %d (guess from mem_section)\n", vabits_actual);
	} else {
		vabits_actual = va_bits;
		DEBUG_MSG("vabits_actual : %d (same as va_bits)\n", vabits_actual);
	}

	get_page_offset_arm64();

	return TRUE;
}

/* 1GB section for Page Table level = 4 and Page Size = 4KB */
static int
is_pud_sect(pud_t pud)
{
	return ((pud_val(pud) & PUD_TYPE_MASK) == PUD_TYPE_SECT);
}

static int
is_pmd_sect(pmd_t pmd)
{
	return ((pmd_val(pmd) & PMD_TYPE_MASK) == PMD_TYPE_SECT);
}

/*
 * vaddr_to_paddr_arm64() - translate arbitrary virtual address to physical
 * @vaddr: virtual address to translate
 *
 * Function translates @vaddr into physical address using page tables. This
 * address can be any virtual address. Returns physical address of the
 * corresponding virtual address or %NOT_PADDR when there is no translation.
 */
unsigned long long
vaddr_to_paddr_arm64(unsigned long vaddr)
{
	unsigned long long paddr = NOT_PADDR;
	unsigned long long swapper_phys;
	pgd_t	*pgda, pgdv;
	pud_t	*puda, pudv;
	pmd_t	*pmda, pmdv;
	pte_t 	*ptea, ptev;

	if (SYMBOL(swapper_pg_dir) == NOT_FOUND_SYMBOL) {
		ERRMSG("Can't get the symbol of swapper_pg_dir.\n");
		return NOT_PADDR;
	}

	swapper_phys = __pa(SYMBOL(swapper_pg_dir));

	pgda = pgd_offset(swapper_phys, vaddr);
	if (!readmem(PADDR, (unsigned long long)pgda, &pgdv, sizeof(pgdv))) {
		ERRMSG("Can't read pgd\n");
		return NOT_PADDR;
	}

	puda = pud_offset(pgda, &pgdv, vaddr);
	if (!readmem(PADDR, (unsigned long long)puda, &pudv, sizeof(pudv))) {
		ERRMSG("Can't read pud\n");
		return NOT_PADDR;
	}

	if (is_pud_sect(pudv)) {
		paddr = (pud_page_paddr(pudv) & PUD_MASK) +
				(vaddr & (PUD_SIZE - 1));
		return paddr;
	}

	pmda = pmd_offset(puda, &pudv, vaddr);
	if (!readmem(PADDR, (unsigned long long)pmda, &pmdv, sizeof(pmdv))) {
		ERRMSG("Can't read pmd\n");
		return NOT_PADDR;
	}

	if (is_pmd_sect(pmdv)) {
		paddr = (pmd_page_paddr(pmdv) & PMD_MASK) +
				(vaddr & (PMD_SIZE - 1));
		return paddr;
	}

	ptea = (pte_t *)pte_offset(&pmdv, vaddr);
	if (!readmem(PADDR, (unsigned long long)ptea, &ptev, sizeof(ptev))) {
		ERRMSG("Can't read pte\n");
		return NOT_PADDR;
	}

	if (!(pte_val(ptev) & PAGE_PRESENT)) {
		ERRMSG("Can't get a valid pte.\n");
		return NOT_PADDR;
	} else {
		paddr = __pte_to_phys(ptev) +
				(vaddr & (PAGESIZE() - 1));
	}

	return paddr;
}

#endif /* __aarch64__ */
