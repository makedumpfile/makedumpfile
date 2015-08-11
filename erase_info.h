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

unsigned long long get_symbol_addr_all(char *);
long get_domain_all(char *, int, unsigned long long *);
int get_die_member_all(unsigned long long die_off, int index, long *offset,
		char **name, int *nbits, int *fbits, unsigned long long *m_die);
int get_die_nfields_all(unsigned long long die_off);

struct call_back {
	long (*get_domain_all)(char *, int, unsigned long long *);
	int (*readmem)(int type_addr, unsigned long long addr, void *bufptr,
             size_t size);
	int (*get_die_attr_type)(unsigned long long die_off, int *type_flag,
            unsigned long long *die_attr_off);
	char * (*get_die_name)(unsigned long long die_off);
	unsigned long long (*get_die_offset)(char *sysname);
	int (*get_die_length)(unsigned long long die_off, int flag);
	int (*get_die_member_all)(unsigned long long die_off, int index,
		long *offset, char **name, int *nbits, int *fbits,
		unsigned long long *m_die);
	int (*get_die_nfields_all)(unsigned long long die_off);
	unsigned long long (*get_symbol_addr_all)(char *symname);
	int (*update_filter_info_raw)(unsigned long long, int, int);
};

extern struct erase_info	*erase_info;
extern unsigned long		num_erase_info;

int gather_filter_info(void);
void clear_filter_info(void);
void filter_data_buffer(unsigned char *buf, unsigned long long paddr, size_t size);
void filter_data_buffer_parallel(unsigned char *buf, unsigned long long paddr,
					size_t size, pthread_mutex_t *mutex);
unsigned long get_size_eraseinfo(void);
int update_filter_info_raw(unsigned long long, int, int);

#endif /* _ERASE_INFO_H */

