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

#ifdef __powerpc__

#include "makedumpfile.h"

int
get_machdep_info_ppc64(void)
{
	unsigned long vmlist, vmalloc_start;

	info->section_size_bits = _SECTION_SIZE_BITS;
	info->max_physmem_bits  = _MAX_PHYSMEM_BITS;
	info->page_offset = __PAGE_OFFSET;

	if (SYMBOL(_stext) == NOT_FOUND_SYMBOL) {
		ERRMSG("Can't get the symbol of _stext.\n");
		return FALSE;
	}
	info->kernel_start = SYMBOL(_stext);
	DEBUG_MSG("kernel_start : %lx\n", info->kernel_start);

	/*
	 * For the compatibility, makedumpfile should run without the symbol
	 * vmlist and the offset of vm_struct.addr if they are not necessary.
	 */
	if ((SYMBOL(vmlist) == NOT_FOUND_SYMBOL)
	    || (OFFSET(vm_struct.addr) == NOT_FOUND_STRUCTURE)) {
		return TRUE;
	}
	if (!readmem(VADDR, SYMBOL(vmlist), &vmlist, sizeof(vmlist))) {
		ERRMSG("Can't get vmlist.\n");
		return FALSE;
	}
	if (!readmem(VADDR, vmlist + OFFSET(vm_struct.addr), &vmalloc_start,
	    sizeof(vmalloc_start))) {
		ERRMSG("Can't get vmalloc_start.\n");
		return FALSE;
	}
	info->vmalloc_start = vmalloc_start;
	DEBUG_MSG("vmalloc_start: %lx\n", vmalloc_start);

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

	paddr = vaddr_to_paddr_general(vaddr);
	if (paddr != NOT_PADDR)
		return paddr;

	if ((SYMBOL(vmlist) == NOT_FOUND_SYMBOL)
	    || (OFFSET(vm_struct.addr) == NOT_FOUND_STRUCTURE)) {
		ERRMSG("Can't get necessary information for vmalloc translation.\n");
		return NOT_PADDR;
	}
	if (!is_vmalloc_addr_ppc64(vaddr))
		return (vaddr - info->kernel_start);

	/*
	 * TODO: Support vmalloc translation.
	 */
	ERRMSG("This makedumpfile does not support vmalloc translation.\n");
	return NOT_PADDR;
}

#endif /* powerpc */
