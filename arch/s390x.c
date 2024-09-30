/*
 * s390x.c
 *
 * Created by: Michael Holzheu (holzheu@de.ibm.com)
 * Copyright IBM Corp. 2010
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

#ifdef __s390x__

#include "../print_info.h"
#include "../elf_info.h"
#include "../makedumpfile.h"

#define TABLE_SIZE		4096

/*
 * Bits in the virtual address
 *
 * |<-----  RX  ---------->|
 * |  RFX  |  RSX  |  RTX  |  SX  | PX |  BX  |
 * 0        11      22      33     44   52    63
 *
 * RX: Region Index
 *	RFX:	Region first index
 *	RSX:	Region second index
 *	RTX:	Region third index
 * SX: Segment index
 * PX: Page index
 * BX: Byte index
 *
 * RX part of vaddr is divided into three fields RFX, RSX and RTX each of
 * 11 bit in size
 */
#define _REGION_INDEX_SHIFT	11
#define _PAGE_INDEX_MASK	0xff000UL	/* page index (PX) mask */
#define _BYTE_INDEX_MASK	0x00fffUL	/* Byte index (BX) mask */
#define _PAGE_BYTE_INDEX_MASK	(_PAGE_INDEX_MASK | _BYTE_INDEX_MASK)

/* Region/segment table index */
#define rsg_index(x, y)	\
		(((x) >> ((_REGION_INDEX_SHIFT * y) + _SEGMENT_INDEX_SHIFT)) \
		& _REGION_OFFSET_MASK)
/* Page table index */
#define pte_index(x)	(((x) >> _PAGE_INDEX_SHIFT) & _PAGE_OFFSET_MASK)

#define rsg_offset(x, y)	(rsg_index( x, y) * sizeof(unsigned long))
#define pte_offset(x)		(pte_index(x) * sizeof(unsigned long))

#define LOWCORE_SIZE		0x2000

#define OS_INFO_VERSION_MAJOR	1
#define OS_INFO_VERSION_MINOR	1

#define OS_INFO_VMCOREINFO	0
#define OS_INFO_REIPL_BLOCK	1
#define OS_INFO_FLAGS_ENTRY	2
#define OS_INFO_RESERVED	3
#define OS_INFO_IDENTITY_BASE	4
#define OS_INFO_KASLR_OFFSET	5
#define OS_INFO_KASLR_OFF_PHYS	6
#define OS_INFO_VMEMMAP		7
#define OS_INFO_AMODE31_START	8
#define OS_INFO_AMODE31_END	9

struct os_info_entry {
	union {
		uint64_t	addr;
		uint64_t	val;
	};
	uint64_t		size;
	uint32_t		csum;
} __attribute__((packed));

struct os_info {
	uint64_t		magic;
	uint32_t		csum;
	uint16_t		version_major;
	uint16_t		version_minor;
	uint64_t		crashkernel_addr;
	uint64_t		crashkernel_size;
	struct	os_info_entry	entry[10];
	uint8_t			reserved[3864];
} __attribute__((packed));

#define S390X_LC_OS_INFO	0x0e18

struct s390_ops {
	unsigned long long	(*virt_to_phys)(unsigned long vaddr);
	unsigned long		(*phys_to_virt)(unsigned long long paddr);
};

static unsigned long long vaddr_to_paddr_s390x_legacy(unsigned long vaddr);
static unsigned long long vaddr_to_paddr_s390x_vr(unsigned long vaddr);
static unsigned long paddr_to_vaddr_s390x_legacy(unsigned long long paddr);
static unsigned long paddr_to_vaddr_s390x_vr(unsigned long long paddr);

struct s390_ops s390_ops = {
	.virt_to_phys = vaddr_to_paddr_s390x_legacy,
	.phys_to_virt = paddr_to_vaddr_s390x_legacy,
};

unsigned long long vaddr_to_paddr_s390x(unsigned long vaddr)
{
	return s390_ops.virt_to_phys(vaddr);
}

unsigned long paddr_to_vaddr_s390x(unsigned long long paddr)
{
	return s390_ops.phys_to_virt(paddr);
}

int
set_s390x_max_physmem_bits(void)
{
	long array_len = ARRAY_LENGTH(mem_section);

	/* Check if we can get MAX_PHYSMEM_BITS from vmcoreinfo */
	if (NUMBER(MAX_PHYSMEM_BITS) != NOT_FOUND_NUMBER) {
		info->max_physmem_bits = NUMBER(MAX_PHYSMEM_BITS);
		return TRUE;
	}

	/*
	 * The older s390x kernels uses _MAX_PHYSMEM_BITS as 42 and the
	 * newer kernels uses 46 bits.
	 */

	info->max_physmem_bits  = _MAX_PHYSMEM_BITS_ORIG ;
	if ((array_len == (NR_MEM_SECTIONS() / _SECTIONS_PER_ROOT_EXTREME()))
		|| (array_len == (NR_MEM_SECTIONS() / _SECTIONS_PER_ROOT())))
		return TRUE;

	info->max_physmem_bits  = _MAX_PHYSMEM_BITS_3_3;
	if ((array_len == (NR_MEM_SECTIONS() / _SECTIONS_PER_ROOT_EXTREME()))
		|| (array_len == (NR_MEM_SECTIONS() / _SECTIONS_PER_ROOT())))
		return TRUE;

	return FALSE;
}

static int s390x_init_vm(void)
{
	struct os_info os_info;
	ulong addr;

	if (!readmem(PADDR, S390X_LC_OS_INFO, &addr, sizeof(addr))) {
		ERRMSG("Can't get s390x os_info ptr.\n");
		return FALSE;
	}

	if (addr == 0)
		return TRUE;

	if (!readmem(PADDR, addr, &os_info, offsetof(struct os_info, reserved))) {
		ERRMSG("Can't get os_info header.\n");
		return FALSE;
	}

	if (!os_info.entry[OS_INFO_KASLR_OFFSET].val)
		return TRUE;

	MSG("The -vr kernel detected.\n");

	info->identity_map_base   = os_info.entry[OS_INFO_IDENTITY_BASE].val;
	info->kvbase              = os_info.entry[OS_INFO_KASLR_OFFSET].val;
	info->__kaslr_offset_phys = os_info.entry[OS_INFO_KASLR_OFF_PHYS].val;
	info->vmemmap_start       = os_info.entry[OS_INFO_VMEMMAP].val;
	info->amode31_start       = os_info.entry[OS_INFO_AMODE31_START].val;
	info->amode31_end         = os_info.entry[OS_INFO_AMODE31_END].val;

	s390_ops.virt_to_phys	= vaddr_to_paddr_s390x_vr;
	s390_ops.phys_to_virt	= paddr_to_vaddr_s390x_vr;

	return TRUE;
}


int
get_machdep_info_s390x(void)
{
	unsigned long vmalloc_start;
	char *term_str = getenv("TERM");

	if (!s390x_init_vm())
		return FALSE;

	if (term_str && strcmp(term_str, "dumb") == 0)
		/* '\r' control character is ignored on "dumb" terminal. */
		flag_ignore_r_char = 1;

	info->section_size_bits = _SECTION_SIZE_BITS;
	if (!set_s390x_max_physmem_bits()) {
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
	 * Obtain the vmalloc_start address from high_memory symbol.
	 */
	if (SYMBOL(high_memory) == NOT_FOUND_SYMBOL) {
		return TRUE;
	}
	if (!readmem(VADDR, SYMBOL(high_memory), &vmalloc_start,
			sizeof(vmalloc_start))) {
		ERRMSG("Can't get vmalloc_start.\n");
		return FALSE;
	}
	info->vmalloc_start = vmalloc_start;
	DEBUG_MSG("vmalloc_start: %lx\n", vmalloc_start);

	return TRUE;
}

static int
is_vmalloc_addr_s390x(unsigned long vaddr)
{
	return (info->vmalloc_start && vaddr >= info->vmalloc_start);
}

static int
rsg_table_entry_bad(unsigned long entry, int level)
{
	unsigned long mask = ~_REGION_ENTRY_INVALID
				& ~_REGION_ENTRY_TYPE_MASK
				& ~_REGION_ENTRY_LENGTH
				& ~_SEGMENT_ENTRY_LARGE
				& ~_SEGMENT_ENTRY_CO;

	if (level)
		mask &= ~_REGION_ENTRY_ORIGIN;
	else
		mask &= ~_SEGMENT_ENTRY_ORIGIN;

	return  (entry & mask) != 0;
}

/* Region or segment table traversal function */
static unsigned long
_kl_rsg_table_deref_s390x(unsigned long vaddr, unsigned long table,
							int len, int level)
{
	unsigned long offset, entry;

	offset = rsg_offset(vaddr, level);

	/* check if offset is over the table limit. */
	if (offset >= ((len + 1) * TABLE_SIZE)) {
		ERRMSG("offset is over the table limit.\n");
		return 0;
	}

	if (!readmem(PADDR, table + offset, &entry, sizeof(entry))) {
		if (level)
			ERRMSG("Can't read region table %d entry\n", level);
		else
			ERRMSG("Can't read segment table entry\n");
		return 0;
	}
	/*
	 * Check if the segment table entry could be read and doesn't have
	 * any of the reserved bits set.
	 */
	if (rsg_table_entry_bad(entry, level)) {
		ERRMSG("Bad region/segment table entry.\n");
		return 0;
	}
	/*
	 * Check if the region/segment table entry is with valid
	 * level and not invalid.
	 */
	if ((RSG_TABLE_LEVEL(entry) != level)
			&& (entry & _REGION_ENTRY_INVALID)) {
		ERRMSG("Invalid region/segment table level or entry.\n");
		return 0;
	}

	return entry;
}

/* Page table traversal function */
static ulong _kl_pg_table_deref_s390x(unsigned long vaddr, unsigned long table)
{
	unsigned long offset, entry;

	offset = pte_offset(vaddr);
	readmem(PADDR, table + offset, &entry, sizeof(entry));
	/*
	 * Check if the page table entry could be read and doesn't have
	 * the reserved bit set.
	 * Check if the page table entry has the invalid bit set.
	 */
	if (entry &  (_PAGE_ZERO | _PAGE_INVALID)) {
		ERRMSG("Invalid page table entry.\n");
		return 0;
	}

	return entry;
}

/* vtop_s390x() - translate virtual address to physical
 *	@vaddr: virtual address to translate
 *
 * Function converts the @vaddr into physical address using page tables.
 *
 * Return:
 *	Physical address or NOT_PADDR if translation fails.
 */
static unsigned long long
vtop_s390x(unsigned long vaddr)
{
	unsigned long long paddr = NOT_PADDR;
	unsigned long long swapper_pg_dir;
	unsigned long table, entry;
	int level, len;

	swapper_pg_dir = SYMBOL(swapper_pg_dir);
	if (swapper_pg_dir == NOT_FOUND_SYMBOL) {
		ERRMSG("Can't get the symbol of swapper_pg_dir.\n");
		return NOT_PADDR;
	}
	table = vaddr_to_paddr(swapper_pg_dir);

	/* Read the first entry to find the number of page table levels. */
	if (!readmem(PADDR, table, &entry, sizeof(entry))) {
		ERRMSG("Can't read swapper_pg_dir entry.\n");
		return NOT_PADDR;
	}
	level = TABLE_LEVEL(entry);
	len = TABLE_LENGTH(entry);

	if ((vaddr >> (_SEGMENT_PAGE_SHIFT + (_REGION_INDEX_SHIFT * level)))) {
		ERRMSG("Address too big for the number of page table " \
								"levels.\n");
		return NOT_PADDR;
	}

	/*
	 * Walk the region and segment tables.
	 */
	while (level >= 0) {
		entry = _kl_rsg_table_deref_s390x(vaddr, table, len, level);
		if (!entry) {
			return NOT_PADDR;
		}
		table = entry & _REGION_ENTRY_ORIGIN;
		if ((entry & _REGION_ENTRY_LARGE) && (level == 1)) {
			table &= ~0x7fffffffUL;
			paddr = table + (vaddr & 0x7fffffffUL);
			return paddr;
		}
		len = RSG_TABLE_LENGTH(entry);
		level--;
	}

	/*
	 * Check if this is a large page.
	 * if yes, then add the 1MB page offset (PX + BX) and return the value.
	 * if no, then get the page table entry using PX index.
	 */
	if (entry & _SEGMENT_ENTRY_LARGE) {
		table &= ~_PAGE_BYTE_INDEX_MASK;
		paddr = table + (vaddr &  _PAGE_BYTE_INDEX_MASK);
	} else {
		entry = _kl_pg_table_deref_s390x(vaddr,
					entry & _SEGMENT_ENTRY_ORIGIN);
		if (!entry)
			return NOT_PADDR;

		/*
		 * Isolate the page origin from the page table entry.
		 * Add the page offset (BX).
		 */
		paddr = (entry &  _REGION_ENTRY_ORIGIN)
			+ (vaddr & _BYTE_INDEX_MASK);
	}

	return paddr;
}

static unsigned long long
vaddr_to_paddr_s390x_legacy(unsigned long vaddr)
{
	unsigned long long paddr;

	paddr = vaddr_to_paddr_general(vaddr);
	if (paddr != NOT_PADDR)
		return paddr;

	if (SYMBOL(high_memory) == NOT_FOUND_SYMBOL) {
		ERRMSG("Can't get necessary information for vmalloc "
			"translation.\n");
		return NOT_PADDR;
	}

	if (is_vmalloc_addr_s390x(vaddr)) {
		paddr = vtop_s390x(vaddr);
	}
	else {
		paddr = vaddr - KVBASE;
	}

	return paddr;
}

static unsigned long long
vaddr_to_paddr_s390x_vr(unsigned long vaddr)
{
	if (vaddr < LOWCORE_SIZE)
		return vaddr;
	if ((vaddr < info->amode31_end) && (vaddr >= info->amode31_start))
		return vaddr;
	if (vaddr < info->vmemmap_start)
		return vaddr - info->identity_map_base;
	if (vaddr >= info->kvbase)
		return vaddr - info->kvbase + info->__kaslr_offset_phys;
	return vtop_s390x(vaddr);
}

unsigned long
paddr_to_vaddr_s390x_legacy(unsigned long long paddr)
{
	return (unsigned long)paddr_to_vaddr_general(paddr);
}

unsigned long
paddr_to_vaddr_s390x_vr(unsigned long long paddr)
{
	return info->identity_map_base + (unsigned long)paddr;
}

struct addr_check {
	unsigned long addr;
	int found;
};

static int phys_addr_callback(void *data, int nr, char *str,
			      unsigned long base, unsigned long length)
{
	struct addr_check *addr_check = data;
	unsigned long addr = addr_check->addr;

	if (addr >= base && addr < base + length) {
		addr_check->found = 1;
		return -1;
	}
	return 0;
}

int is_iomem_phys_addr_s390x(unsigned long addr)
{
	/* Implicit VtoP conversion will be performed for addr here. */
	struct addr_check addr_check = {addr, 0};

	iomem_for_each_line("System RAM\n", phys_addr_callback, &addr_check);
	return addr_check.found;
}

#endif /* __s390x__ */
