/*
 * dwarf_info.h
 *
 * Copyright (C) 2011 NEC Corporation
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
#ifndef _DWARF_INFO_H
#define _DWARF_INFO_H

#define LEN_SRCFILE			(100)

#define NOT_FOUND_LONG_VALUE		(-1)
#define FAILED_DWARFINFO		(-2)
#define INVALID_STRUCTURE_DATA		(-3)
#define FOUND_ARRAY_TYPE		(LONG_MAX - 1)

#define NOT_FOUND_SYMBOL		(0)
#define NOT_FOUND_STRUCTURE		(NOT_FOUND_LONG_VALUE)
#define NOT_FOUND_NUMBER		(NOT_FOUND_LONG_VALUE)

/* flags for dwarf_info.type_flag */
#define TYPE_BASE	0x01
#define TYPE_ARRAY	0x02
#define TYPE_PTR	0x04
#define TYPE_STRUCT	0x08
#define TYPE_LIST_HEAD	0x10

enum {
	DWARF_INFO_GET_STRUCT_SIZE,
	DWARF_INFO_GET_MEMBER_OFFSET,
	DWARF_INFO_GET_MEMBER_OFFSET_1ST_UNION,
	DWARF_INFO_GET_MEMBER_ARRAY_LENGTH,
	DWARF_INFO_GET_SYMBOL_ARRAY_LENGTH,
	DWARF_INFO_GET_TYPEDEF_SIZE,
	DWARF_INFO_GET_TYPEDEF_SRCNAME,
	DWARF_INFO_GET_ENUM_NUMBER,
	DWARF_INFO_CHECK_SYMBOL_ARRAY_TYPE,
	DWARF_INFO_GET_SYMBOL_TYPE,
	DWARF_INFO_GET_MEMBER_TYPE,
	DWARF_INFO_GET_ENUMERATION_TYPE_SIZE,
	DWARF_INFO_GET_DOMAIN_STRUCT,
	DWARF_INFO_GET_DOMAIN_TYPEDEF,
	DWARF_INFO_GET_DOMAIN_ARRAY,
	DWARF_INFO_GET_DOMAIN_UNION,
	DWARF_INFO_GET_DOMAIN_ENUM,
	DWARF_INFO_GET_DOMAIN_REF,
	DWARF_INFO_GET_DOMAIN_STRING,
	DWARF_INFO_GET_DOMAIN_BASE,
	DWARF_INFO_GET_DIE,
};

char *get_dwarf_module_name(void);
void get_fileinfo_of_debuginfo(int *fd, char **name);
unsigned long long get_symbol_addr(char *symname);
unsigned long get_next_symbol_addr(char *symname);
long get_structure_size(char *structname, int flag_typedef);
long get_pointer_size(void);
char *get_symbol_type_name(char *symname, int cmd, long *size, unsigned long *flag);
long get_member_offset(char *structname, char *membername, int cmd);
char *get_member_type_name(char *structname, char *membername, int cmd, long *size, unsigned long *flag);
long get_array_length(char *name01, char *name02, unsigned int cmd);
long get_enum_number(char *enum_name);
int get_source_filename(char *structname, char *src_name, int cmd);
long get_domain(char *symname, int cmd, unsigned long long *die);
int get_die_nfields(unsigned long long die_off);
int get_die_member(unsigned long long die_off, int index, long *offset,
	char **name, int *nbits, int *fbits, unsigned long long *m_die);
int get_die_attr_type(unsigned long long die_off, int *type_flag,
	unsigned long long *die_attr_off);
char *get_die_name(unsigned long long die_off);
unsigned long long get_die_offset(char *sysname);
int get_die_length(unsigned long long die_off, int flag);
int set_dwarf_debuginfo(char *mod_name, char *os_release, char *name_debuginfo, int fd_debuginfo);

#endif  /* DWARF_INFO_H */

