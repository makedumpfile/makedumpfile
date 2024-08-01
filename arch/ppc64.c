/*
 * ppc64.c
 *
 * Created by: Sachin Sant (sachinp@in.ibm.com)
 * Copyright (C) IBM Corporation, 2006. All rights reserved
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

#ifdef __powerpc64__

#include "../print_info.h"
#include "../elf_info.h"
#include "../makedumpfile.h"
#include <endian.h>

/*
 * Swaps a 8 byte value
 */
static ulong swap64(ulong val, uint swap)
{
	if (swap)
		return (((val & 0x00000000000000ffULL) << 56) |
			((val & 0x000000000000ff00ULL) << 40) |
			((val & 0x0000000000ff0000ULL) << 24) |
			((val & 0x00000000ff000000ULL) <<  8) |
			((val & 0x000000ff00000000ULL) >>  8) |
			((val & 0x0000ff0000000000ULL) >> 24) |
			((val & 0x00ff000000000000ULL) >> 40) |
			((val & 0xff00000000000000ULL) >> 56));
	else
		return val;
}

/*
 * Convert physical address to kernel virtual address
 */
static inline ulong paddr_to_vaddr_ppc64(ulong paddr)
{
	return (paddr + info->kernel_start);
}

/*
 * Convert the raw pgd entry to next pgtable adress
 */
static inline ulong pgd_page_vaddr_l4(ulong pgd)
{
	ulong pgd_val;

	pgd_val = (pgd & ~info->pgd_masked_bits);
	if (info->kernel_version >= KERNEL_VERSION(4, 6, 0)) {
		/*
		 * physical address is stored starting from kernel v4.6
		 */
		pgd_val = paddr_to_vaddr_ppc64(pgd_val);
	}

	return pgd_val;
}

/*
 * Convert the raw pud entry to next pgtable adress
 */
static inline ulong pud_page_vaddr_l4(ulong pud)
{
	ulong pud_val;

	pud_val = (pud & ~info->pud_masked_bits);
	if (info->kernel_version >= KERNEL_VERSION(4, 6, 0)) {
		/*
		 * physical address is stored starting from kernel v4.6
		 */
		pud_val = paddr_to_vaddr_ppc64(pud_val);
	}

	return pud_val;
}

/*
 * Convert the raw pmd entry to next pgtable adress
 */
static inline ulong pmd_page_vaddr_l4(ulong pmd)
{
	ulong pmd_val;

	pmd_val = (pmd & ~info->pmd_masked_bits);
	if (info->kernel_version >= KERNEL_VERSION(4, 6, 0)) {
		/*
		 * physical address is stored starting from kernel v4.6
		 */
		pmd_val = paddr_to_vaddr_ppc64(pmd_val);
	}

	return pmd_val;
}

/*
 * This function traverses vmemmap list to get the count of vmemmap regions
 * and populates the regions' info in info->vmemmap_list[]
 */
static int
get_vmemmap_list_info(ulong head)
{
	int   i, cnt;
	long  backing_size, virt_addr_offset, phys_offset, list_offset;
	ulong curr, next;
	char  *vmemmap_buf = NULL;

	backing_size		= SIZE(vmemmap_backing);
	virt_addr_offset	= OFFSET(vmemmap_backing.virt_addr);
	phys_offset		= OFFSET(vmemmap_backing.phys);
	list_offset		= OFFSET(vmemmap_backing.list);
	info->vmemmap_list = NULL;

	/*
	 * Get list count by traversing the vmemmap list
	 */
	cnt = 0;
	curr = head;
	next = 0;
	do {
		if (!readmem(VADDR, (curr + list_offset), &next,
			     sizeof(next))) {
			ERRMSG("Can't get vmemmap region addresses\n");
			goto err;
		}
		curr = next;
		cnt++;
	} while ((next != 0) && (next != head));

	/*
	 * Using temporary buffer to save vmemmap region information
	 */
	vmemmap_buf = calloc(1, backing_size);
	if (vmemmap_buf == NULL) {
		ERRMSG("Can't allocate memory for vmemmap_buf. %s\n",
		       strerror(errno));
		goto err;
	}

	info->vmemmap_list = calloc(1, cnt * sizeof(struct ppc64_vmemmap));
	if (info->vmemmap_list == NULL) {
		ERRMSG("Can't allocate memory for vmemmap_list. %s\n",
		       strerror(errno));
		goto err;
	}

	curr = head;
	for (i = 0; i < cnt; i++) {
		if (!readmem(VADDR, curr, vmemmap_buf, backing_size)) {
			ERRMSG("Can't get vmemmap region info\n");
			goto err;
		}

		info->vmemmap_list[i].phys = ULONG(vmemmap_buf + phys_offset);
		info->vmemmap_list[i].virt = ULONG(vmemmap_buf +
						   virt_addr_offset);
		curr = ULONG(vmemmap_buf + list_offset);

		if (info->vmemmap_list[i].virt < info->vmemmap_start)
			info->vmemmap_start = info->vmemmap_list[i].virt;

		if ((info->vmemmap_list[i].virt + info->vmemmap_psize) >
		    info->vmemmap_end)
			info->vmemmap_end = (info->vmemmap_list[i].virt +
					     info->vmemmap_psize);
	}

	free(vmemmap_buf);
	return cnt;
err:
	free(vmemmap_buf);
	free(info->vmemmap_list);
	return 0;
}

/*
 *  Verify that the kernel has made the vmemmap list available,
 *  and if so, stash the relevant data required to make vtop
 *  translations.
 */
static int
ppc64_vmemmap_init(void)
{
	int psize, shift;
	ulong head;

	/* initialise vmemmap_list in case SYMBOL(vmemmap_list) is not found */
	info->vmemmap_list = NULL;
	info->vmemmap_cnt = 0;

	if ((SYMBOL(vmemmap_list) == NOT_FOUND_SYMBOL)
	    || (SYMBOL(mmu_psize_defs) == NOT_FOUND_SYMBOL)
	    || (SYMBOL(mmu_vmemmap_psize) == NOT_FOUND_SYMBOL)
	    || (SIZE(vmemmap_backing) == NOT_FOUND_STRUCTURE)
	    || (SIZE(mmu_psize_def) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(mmu_psize_def.shift) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(vmemmap_backing.phys) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(vmemmap_backing.virt_addr) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(vmemmap_backing.list) == NOT_FOUND_STRUCTURE))
		return FALSE;

	if (!readmem(VADDR, SYMBOL(mmu_vmemmap_psize), &psize, sizeof(int)))
		return FALSE;

	if (!readmem(VADDR, SYMBOL(mmu_psize_defs) +
		     (SIZE(mmu_psize_def) * psize) +
		     OFFSET(mmu_psize_def.shift), &shift, sizeof(int)))
		return FALSE;
	info->vmemmap_psize = 1 << shift;

	/*
	 * vmemmap_list symbol can be missing or set to 0 in the kernel.
	 * This would imply vmemmap region is mapped in the kernel pagetable.
	 *
	 * So, read vmemmap_list anyway, and use 'vmemmap_list' if it's not empty
	 * (head != NULL), or we will do a kernel pagetable walk for vmemmap address
	 * translation later
	 **/
	readmem(VADDR, SYMBOL(vmemmap_list), &head, sizeof(unsigned long));

	if (head) {
		/*
		 * Get vmemmap list count and populate vmemmap regions info
		 */
		info->vmemmap_cnt = get_vmemmap_list_info(head);
		if (info->vmemmap_cnt == 0)
			return FALSE;
	}

	info->flag_vmemmap = TRUE;
	return TRUE;
}

static int
ppc64_vmalloc_init(void)
{
	if (info->page_size == 65536) {
		/*
		 * 64K pagesize
		 */
		if (info->cur_mmu_type & MMU_TYPE_RADIX) {
			info->l1_index_size = PTE_INDEX_SIZE_RADIX_64K;
			info->l2_index_size = PMD_INDEX_SIZE_RADIX_64K;
			info->l3_index_size = PUD_INDEX_SIZE_RADIX_64K;
			info->l4_index_size = PGD_INDEX_SIZE_RADIX_64K;

		} else if (info->kernel_version >= KERNEL_VERSION(4, 6, 0)) {
			info->l1_index_size = PTE_INDEX_SIZE_L4_64K_3_10;

			if (info->kernel_version >= KERNEL_VERSION(4, 12, 0)) {
				info->l2_index_size = PMD_INDEX_SIZE_L4_64K_4_12;
				if (info->kernel_version >= KERNEL_VERSION(4, 17, 0))
					info->l3_index_size = PUD_INDEX_SIZE_L4_64K_4_17;
				else
					info->l3_index_size = PUD_INDEX_SIZE_L4_64K_4_12;
				info->l4_index_size = PGD_INDEX_SIZE_L4_64K_4_12;
			} else {
				info->l2_index_size = PMD_INDEX_SIZE_L4_64K_4_6;
				info->l3_index_size = PUD_INDEX_SIZE_L4_64K_4_6;
				info->l4_index_size = PGD_INDEX_SIZE_L4_64K_3_10;
			}
		} else if (info->kernel_version >= KERNEL_VERSION(3, 10, 0)) {
			info->l1_index_size = PTE_INDEX_SIZE_L4_64K_3_10;
			info->l2_index_size = PMD_INDEX_SIZE_L4_64K_3_10;
			info->l3_index_size = PUD_INDEX_SIZE_L4_64K;
			info->l4_index_size = PGD_INDEX_SIZE_L4_64K_3_10;
		} else {
			info->l1_index_size = PTE_INDEX_SIZE_L4_64K;
			info->l2_index_size = PMD_INDEX_SIZE_L4_64K;
			info->l3_index_size = PUD_INDEX_SIZE_L4_64K;
			info->l4_index_size = PGD_INDEX_SIZE_L4_64K;
		}

		info->pte_rpn_shift = (SYMBOL(demote_segment_4k) ?
			PTE_RPN_SHIFT_L4_64K_V2 : PTE_RPN_SHIFT_L4_64K_V1);

		if (info->kernel_version >= KERNEL_VERSION(4, 6, 0)) {
			info->pgd_masked_bits = PGD_MASKED_BITS_64K_4_6;
			info->pud_masked_bits = PUD_MASKED_BITS_64K_4_6;
			info->pmd_masked_bits = PMD_MASKED_BITS_64K_4_6;
		} else {
			info->pgd_masked_bits = PGD_MASKED_BITS_64K;
			info->pud_masked_bits = PUD_MASKED_BITS_64K;
			info->pmd_masked_bits = (info->kernel_version >= KERNEL_VERSION(3, 11, 0) ?
				PMD_MASKED_BITS_64K_3_11 : PMD_MASKED_BITS_64K);
		}
	} else {
		/*
		 * 4K pagesize
		 */
		if (info->cur_mmu_type & MMU_TYPE_RADIX) {
			info->l1_index_size = PTE_INDEX_SIZE_RADIX_4K;
			info->l2_index_size = PMD_INDEX_SIZE_RADIX_4K;
			info->l3_index_size = PUD_INDEX_SIZE_RADIX_4K;
			info->l4_index_size = PGD_INDEX_SIZE_RADIX_4K;

		} else {
			info->l1_index_size = PTE_INDEX_SIZE_L4_4K;
			info->l2_index_size = PMD_INDEX_SIZE_L4_4K;
			info->l3_index_size = (info->kernel_version >= KERNEL_VERSION(3, 7, 0) ?
				PUD_INDEX_SIZE_L4_4K_3_7 : PUD_INDEX_SIZE_L4_4K);
			info->l4_index_size = PGD_INDEX_SIZE_L4_4K;
		}

		info->pte_rpn_shift = (info->kernel_version >= KERNEL_VERSION(4, 5, 0) ?
			PTE_RPN_SHIFT_L4_4K_4_5 : PTE_RPN_SHIFT_L4_4K);

		info->pgd_masked_bits = PGD_MASKED_BITS_4K;
		info->pud_masked_bits = PUD_MASKED_BITS_4K;
		info->pmd_masked_bits = PMD_MASKED_BITS_4K;
	}

	if (info->kernel_version >= KERNEL_VERSION(4, 7, 0)) {
		info->pgd_masked_bits = PGD_MASKED_BITS_4_7;
		info->pud_masked_bits = PUD_MASKED_BITS_4_7;
		info->pmd_masked_bits = PMD_MASKED_BITS_4_7;
	}

	info->pte_rpn_mask = PTE_RPN_MASK_DEFAULT;
	if ((info->kernel_version >= KERNEL_VERSION(4, 6, 0)) &&
	    (info->kernel_version < KERNEL_VERSION(4, 11, 0))) {
		info->pte_rpn_mask = PTE_RPN_MASK_L4_4_6;
		info->pte_rpn_shift = PTE_RPN_SHIFT_L4_4_6;
	}

	if (info->kernel_version >= KERNEL_VERSION(4, 11, 0)) {
		info->pte_rpn_mask = PTE_RPN_MASK_L4_4_11;
		info->pte_rpn_shift = PTE_RPN_SHIFT_L4_4_11;
	}

	/*
	 * Compute ptrs per each level
	 */
	info->l1_shift = info->page_shift;
	info->ptrs_per_l1 = (1 << info->l1_index_size);
	info->ptrs_per_l2 = (1 << info->l2_index_size);
	info->ptrs_per_l3 = (1 << info->l3_index_size);
	info->ptrs_per_l4 = (1 << info->l4_index_size);
	info->ptrs_per_pgd = info->ptrs_per_l4;

	/*
	 * Compute shifts
	 */
	info->l2_shift = info->l1_shift + info->l1_index_size;
	info->l3_shift = info->l2_shift + info->l2_index_size;
	info->l4_shift = info->l3_shift + info->l3_index_size;

	return TRUE;
}

static unsigned long long
ppc64_vtop_level4(unsigned long vaddr)
{
	ulong *level4;
	ulong *pgdir, *page_upper;
	ulong *page_middle, *page_table;
	unsigned long long pgd_pte, pud_pte;
	unsigned long long pmd_pte, pte;
	unsigned long long paddr = NOT_PADDR;
	uint is_hugepage = 0;
	uint pdshift;
	uint swap = 0;

	if (info->page_buf == NULL) {
		/*
		 * This is the first vmalloc address translation request
		 */
		info->page_buf = (char *)calloc(1, PAGESIZE());
		if (info->page_buf == NULL) {
			ERRMSG("Can't allocate memory to read page tables. %s\n",
			       strerror(errno));
			return NOT_PADDR;
		}
	}

	if (info->kernel_version >= KERNEL_VERSION(4, 7, 0)) {
		/*
		 * Starting with kernel v4.7, page table entries are always
		 * big endian on server processors. Set this flag if
		 * kernel is not big endian.
		 */
		if (__BYTE_ORDER == __LITTLE_ENDIAN)
			swap = 1;
	}

	level4 = (ulong *)info->kernel_pgd;
	pgdir = (ulong *)((ulong *)level4 + PGD_OFFSET_L4(vaddr));
	if (!readmem(VADDR, PAGEBASE(level4), info->page_buf, PAGESIZE())) {
		ERRMSG("Can't read PGD page: 0x%llx\n", PAGEBASE(level4));
		return NOT_PADDR;
	}
	pgd_pte = swap64(ULONG((info->page_buf + PAGEOFFSET(pgdir))), swap);
	if (!pgd_pte)
		return NOT_PADDR;

	if (IS_HUGEPAGE(pgd_pte)) {
		is_hugepage = 1;
		pte = pgd_pte;
		pdshift = info->l4_shift;
		goto out;
	}

	/*
	 * Sometimes we don't have level3 pagetable entries
	 */
	if (info->l3_index_size != 0) {
		pgd_pte = pgd_page_vaddr_l4(pgd_pte);
		page_upper = (ulong *)((ulong *)pgd_pte + PUD_OFFSET_L4(vaddr));
		if (!readmem(VADDR, PAGEBASE(pgd_pte), info->page_buf, PAGESIZE())) {
			ERRMSG("Can't read PUD page: 0x%llx\n", PAGEBASE(pgd_pte));
			return NOT_PADDR;
		}
		pud_pte = swap64(ULONG((info->page_buf + PAGEOFFSET(page_upper))), swap);
		if (!pud_pte)
			return NOT_PADDR;

		if (IS_HUGEPAGE(pud_pte)) {
			is_hugepage = 1;
			pte = pud_pte;
			pdshift = info->l3_shift;
			goto out;
		}
	} else {
		pud_pte = pgd_pte;
	}

	pud_pte = pud_page_vaddr_l4(pud_pte);
	page_middle = (ulong *)((ulong *)pud_pte + PMD_OFFSET_L4(vaddr));
	if (!readmem(VADDR, PAGEBASE(pud_pte), info->page_buf, PAGESIZE())) {
		ERRMSG("Can't read PMD page: 0x%llx\n", PAGEBASE(pud_pte));
		return NOT_PADDR;
	}
	pmd_pte = swap64(ULONG((info->page_buf + PAGEOFFSET(page_middle))), swap);
	if (!(pmd_pte))
		return NOT_PADDR;

	if (IS_HUGEPAGE(pmd_pte)) {
		is_hugepage = 1;
		pte = pmd_pte;
		pdshift = info->l2_shift;
		goto out;
	}

	pmd_pte = pmd_page_vaddr_l4(pmd_pte);
	page_table = (ulong *)(pmd_pte)
			+ (BTOP(vaddr) & (info->ptrs_per_l1 - 1));
	if (!readmem(VADDR, PAGEBASE(pmd_pte), info->page_buf, PAGESIZE())) {
		ERRMSG("Can't read page table: 0x%llx\n", PAGEBASE(pmd_pte));
		return NOT_PADDR;
	}
	pte = swap64(ULONG((info->page_buf + PAGEOFFSET(page_table))), swap);
	if (!(pte & _PAGE_PRESENT)) {
		ERRMSG("Page not present!\n");
		return NOT_PADDR;
	}

	if (!pte)
		return NOT_PADDR;

out:
	if (is_hugepage) {
		paddr = PAGEBASE(PTOB((pte & info->pte_rpn_mask) >> info->pte_rpn_shift))
			+ (vaddr & ((1UL << pdshift) - 1));
	} else {
		paddr = PAGEBASE(PTOB((pte & info->pte_rpn_mask) >> info->pte_rpn_shift))
			+ PAGEOFFSET(vaddr);
	}

	return paddr;
}

/*
 *  If the vmemmap address translation information is stored in the kernel,
 *  make the translation.
 */
static unsigned long long
ppc64_vmemmap_to_phys(unsigned long vaddr)
{
	int	i;
	ulong	offset;
	unsigned long long paddr = NOT_PADDR;

	if (!info->vmemmap_list)
		return ppc64_vtop_level4(vaddr);

	for (i = 0; i < info->vmemmap_cnt; i++) {
		if ((vaddr >= info->vmemmap_list[i].virt) && (vaddr <
		    (info->vmemmap_list[i].virt + info->vmemmap_psize))) {
			offset = vaddr - info->vmemmap_list[i].virt;
			paddr = info->vmemmap_list[i].phys + offset;
			break;
		}
	}

	return paddr;
}

int
set_ppc64_max_physmem_bits(void)
{
	long array_len = ARRAY_LENGTH(mem_section);

	/* Check if we can get MAX_PHYSMEM_BITS from vmcoreinfo */
	if (NUMBER(MAX_PHYSMEM_BITS) != NOT_FOUND_NUMBER) {
		info->max_physmem_bits = NUMBER(MAX_PHYSMEM_BITS);
		return TRUE;
	}

	/*
	 * The older ppc64 kernels uses _MAX_PHYSMEM_BITS as 42 and the
	 * newer kernels 3.7 onwards uses 46 bits.
	 */

	info->max_physmem_bits  = _MAX_PHYSMEM_BITS_ORIG ;
	if ((array_len == (NR_MEM_SECTIONS() / _SECTIONS_PER_ROOT_EXTREME()))
		|| (array_len == (NR_MEM_SECTIONS() / _SECTIONS_PER_ROOT())))
		return TRUE;

	info->max_physmem_bits  = _MAX_PHYSMEM_BITS_3_7;
	if ((array_len == (NR_MEM_SECTIONS() / _SECTIONS_PER_ROOT_EXTREME()))
		|| (array_len == (NR_MEM_SECTIONS() / _SECTIONS_PER_ROOT())))
		return TRUE;

	info->max_physmem_bits  = _MAX_PHYSMEM_BITS_4_19;
	if ((array_len == (NR_MEM_SECTIONS() / _SECTIONS_PER_ROOT_EXTREME()))
		|| (array_len == (NR_MEM_SECTIONS() / _SECTIONS_PER_ROOT())))
		return TRUE;

	info->max_physmem_bits  = _MAX_PHYSMEM_BITS_4_20;
	if ((array_len == (NR_MEM_SECTIONS() / _SECTIONS_PER_ROOT_EXTREME()))
		|| (array_len == (NR_MEM_SECTIONS() / _SECTIONS_PER_ROOT())))
		return TRUE;

	return FALSE;
}

int
get_machdep_info_ppc64(void)
{
	unsigned long vmlist, vmap_area_list, vmalloc_start;

	info->section_size_bits = _SECTION_SIZE_BITS;
	if (!set_ppc64_max_physmem_bits()) {
		ERRMSG("Can't detect max_physmem_bits.\n");
		return FALSE;
	}
	info->page_offset = __PAGE_OFFSET;

	if (SYMBOL(_stext) == NOT_FOUND_SYMBOL) {
		ERRMSG("Can't get the symbol of _stext.\n");
		return FALSE;
	}
	info->kernel_start = SYMBOL(_stext);
	DEBUG_MSG("kernel_start : %lx\n", info->kernel_start);

	/*
	 * To get vmalloc_start, prefer NUMBER(vmalloc_start) if exported in
	 * vmcoreinfo, as 'vmap_area_list' and 'vmlist' in Linux 6.9 and later
	 * kernels might be empty
	 */
	if (NUMBER(vmalloc_start) != NOT_FOUND_NUMBER) {
		vmalloc_start = NUMBER(vmalloc_start);
	} else if ((SYMBOL(vmap_area_list) != NOT_FOUND_SYMBOL)
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
		 * vmlist and the offset of vm_struct.addr if they are not necessary.
		 */
		return TRUE;
	}
	info->vmalloc_start = vmalloc_start;
	DEBUG_MSG("vmalloc_start: %lx\n", vmalloc_start);

	if (SYMBOL(swapper_pg_dir) != NOT_FOUND_SYMBOL) {
		info->kernel_pgd = SYMBOL(swapper_pg_dir);
	} else if (SYMBOL(cpu_pgd) != NOT_FOUND_SYMBOL) {
		info->kernel_pgd = SYMBOL(cpu_pgd);
	} else {
		ERRMSG("No swapper_pg_dir or cpu_pgd symbols exist\n");
		return FALSE;
	}

	info->vmemmap_start = VMEMMAP_REGION_ID << REGION_SHIFT;
	if (SYMBOL(vmemmap_list) != NOT_FOUND_SYMBOL) {
		info->vmemmap_end = info->vmemmap_start;
		if (ppc64_vmemmap_init() == FALSE) {
			ERRMSG("Can't get vmemmap list info.\n");
			return FALSE;
		}
		DEBUG_MSG("vmemmap_start: %lx\n", info->vmemmap_start);
	}

	return TRUE;
}

int
get_versiondep_info_ppc64()
{
	unsigned long cur_cpu_spec;
	uint mmu_features;

	/*
	 * On PowerISA 3.0 based server processors, a kernel can run with
	 * radix MMU or standard MMU. Get the current MMU type.
	 */
	info->cur_mmu_type = MMU_TYPE_STD;

	if (NUMBER(RADIX_MMU) != NOT_FOUND_SYMBOL) {
		if (NUMBER(RADIX_MMU) == 1) {
			info->cur_mmu_type = MMU_TYPE_RADIX;
		}
	} else if ((SYMBOL(cur_cpu_spec) != NOT_FOUND_SYMBOL)
	    && (OFFSET(cpu_spec.mmu_features) != NOT_FOUND_STRUCTURE)) {
		if (readmem(VADDR, SYMBOL(cur_cpu_spec), &cur_cpu_spec,
		    sizeof(cur_cpu_spec))) {
			if (readmem(VADDR, cur_cpu_spec + OFFSET(cpu_spec.mmu_features),
			    &mmu_features, sizeof(mmu_features)))
				info->cur_mmu_type = mmu_features & MMU_TYPE_RADIX;
		}
	}

	/*
	 * Initialize Linux page table info
	 */
	if (ppc64_vmalloc_init() == FALSE) {
		ERRMSG("Can't initialize for vmalloc translation\n");
		return FALSE;
	}
	info->page_offset = __PAGE_OFFSET;

	return TRUE;
}

int
is_vmalloc_addr_ppc64(unsigned long vaddr)
{
	return (info->vmalloc_start && vaddr >= info->vmalloc_start);
}

unsigned long long
vaddr_to_paddr_ppc64(unsigned long vaddr)
{
	unsigned long long paddr;

	if ((info->flag_vmemmap)
	    && (vaddr >= info->vmemmap_start)) {
		return ppc64_vmemmap_to_phys(vaddr);
	}

	paddr = vaddr_to_paddr_general(vaddr);
	if (paddr != NOT_PADDR)
		return paddr;

	if (!is_vmalloc_addr_ppc64(vaddr))
		return (vaddr - info->kernel_start);

	if ((SYMBOL(vmap_area_list) == NOT_FOUND_SYMBOL)
	    || (OFFSET(vmap_area.va_start) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(vmap_area.list) == NOT_FOUND_STRUCTURE)) {
		/*
		 * Don't depend on vmap_area_list/vmlist if vmalloc_start is set in
		 * vmcoreinfo, in that case proceed without error
		 */
		if (NUMBER(vmalloc_start) == NOT_FOUND_NUMBER)
			if ((SYMBOL(vmlist) == NOT_FOUND_SYMBOL)
				|| (OFFSET(vm_struct.addr) == NOT_FOUND_STRUCTURE)) {
				ERRMSG("Can't get info for vmalloc translation.\n");
				return NOT_PADDR;
			}
	}

	return ppc64_vtop_level4(vaddr);
}

int arch_crashkernel_mem_size_ppc64()
{
	const char f_crashsize[] = "/proc/device-tree/chosen/linux,crashkernel-size";
	const char f_crashbase[] = "/proc/device-tree/chosen/linux,crashkernel-base";
	unsigned long crashk_sz_be, crashk_sz;
	unsigned long crashk_base_be, crashk_base;
	uint swap;
	FILE *fp, *fpb;

	fp = fopen(f_crashsize, "r");
	if (!fp) {
		ERRMSG("Cannot open %s\n", f_crashsize);
		return FALSE;
	}
	fpb = fopen(f_crashbase, "r");
	if (!fpb) {
		ERRMSG("Cannot open %s\n", f_crashbase);
		fclose(fp);
		return FALSE;
	}

	fread(&crashk_sz_be, sizeof(crashk_sz_be), 1, fp);
	fread(&crashk_base_be, sizeof(crashk_base_be), 1, fpb);
	fclose(fp);
	fclose(fpb);
	/* dev tree is always big endian */
	swap = !is_bigendian();
	crashk_sz = swap64(crashk_sz_be, swap);
	crashk_base = swap64(crashk_base_be, swap);
	crash_reserved_mem_nr = 1;
	crash_reserved_mem[0].start = crashk_base;
	crash_reserved_mem[0].end   = crashk_base + crashk_sz - 1;

	return TRUE;
}

#endif /* powerpc64 */
