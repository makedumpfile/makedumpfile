/* 
 * x86.c
 *
 * Copyright (C) 2006  NEC Corporation
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

#include "makedumpfile.h"

extern struct symbol_table	symbol_table;
extern struct size_table	size_table;
extern struct offset_table	offset_table;

int
get_machdep_info_x86(struct DumpInfo *info)
{
	/* PAE */
	if ((SYMBOL(pkmap_count) != NOT_FOUND_SYMBOL)
	    && (SYMBOL(pkmap_count_next) != NOT_FOUND_SYMBOL)
	    && ((SYMBOL(pkmap_count_next)-SYMBOL(pkmap_count))/sizeof(int))
	    == 512)
		info->section_size_bits = _SECTION_SIZE_BITS_PAE;
	else
		info->section_size_bits = _SECTION_SIZE_BITS;

	return TRUE;
}

#endif /* x86 */

