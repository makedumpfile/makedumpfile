/*
 * erase_info.h
 *
 * Created by: Mahesh J Salgaonkar <mahesh@linux.vnet.ibm.com>
 *
 * Copyright (C) 2011  IBM Corporation
 * Copyright (C) 2011  NEC Corporation
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
#ifndef _ERASE_INFO_H
#define _ERASE_INFO_H

#define MAX_SIZE_STR_LEN (26)

/*
 * Erase information, original symbol expressions.
 */
struct erase_info {
	char		*symbol_expr;
	int		num_sizes;
	long		*sizes;
	int		erased;		/* 1= erased, 0= Not erased */
};

extern struct erase_info	*erase_info;
extern unsigned long		num_erase_info;

int gather_filter_info(void);
void clear_filter_info(void);
void filter_data_buffer(unsigned char *buf, unsigned long long paddr, size_t size);
unsigned long get_size_eraseinfo(void);

#endif /* _ERASE_INFO_H */

