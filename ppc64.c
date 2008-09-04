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
	info->section_size_bits = _SECTION_SIZE_BITS;
	info->max_physmem_bits  = _MAX_PHYSMEM_BITS;
	info->page_offset = __PAGE_OFFSET;

	return TRUE;
}

#endif /* powerpc */
