/*
 * extension_eppic.h
 *
 * Created by: Aravinda Prasad <aravinda@linux.vnet.ibm.com>
 *
 * Copyright (C) 2012, 2013  IBM Corporation
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
#ifndef _EXTENSION_EPPIC_H
#define _EXTENSION_EPPIC_H

#include "eppic_api.h"
#include "erase_info.h"

/*
 * MEMBER_S, ENUM_S, DEF_S and TYPE_S are extracts from eppic header
 * file eppic.h. The reason for not including the eppic.h header file
 * in this file is because, lot of things in eppic.h are not required
 * for makedumpfile extension.
 */

#define MAX_ARRAY_DIMENSION 16

/* member information */
typedef MEMBER_S {

	char *name;
	int offset; /* offset from top of structure */
	int size;   /* size in bytes of the member or of the bit array */
	int fbit;   /* fist bit (-1) is not a bit field */
	int nbits;  /* number of bits for this member */
	int value;  /* for a enum member, the corresponding value_t */

} member_t;

/* list to hold enum constant information */
typedef ENUM_S {
	struct enum_s *next;
	char *name;
	int value;

} enum_t;

/* list of macro symbols and there corresponding value_ts */
typedef DEF_S {
	struct def_s *next;
	char *name;
	char *val;

} def_t;


typedef TYPE_S {
	int type;   /* type_t of type_t */
	ull idx;    /* index to basetype_t or ctype_t */
	int size;   /* size of this item */
	/* ... next fields are use internally */
	int typattr;    /* base type_t qualifiers */
	int ref;    /* level of reference */
	int fct;        /* 1 if function pointer */
	int *idxlst;    /* points to list of indexes if array */
	ull rtype;  /* type_t a reference refers too */
} type_t;

#undef ERRMSG
#define ERRMSG(x...) \
do { \
		fprintf(stderr, __FUNCTION__); \
		fprintf(stderr, ": "); \
		fprintf(stderr, x); \
} while (0)


struct call_back *cb;

#define GET_DOMAIN_ALL cb->get_domain_all
#define READMEM cb->readmem
#define GET_DIE_ATTR_TYPE cb->get_die_attr_type
#define GET_DIE_NAME cb->get_die_name
#define GET_DIE_OFFSET cb->get_die_offset
#define GET_DIE_LENGTH cb->get_die_length
#define GET_DIE_MEMBER_ALL cb->get_die_member_all
#define GET_DIE_NFIELDS_ALL cb->get_die_nfields_all
#define GET_SYMBOL_ADDR_ALL cb->get_symbol_addr_all
#define UPDATE_FILTER_INFO_RAW cb->update_filter_info_raw

#endif /* _EXTENSION_EPPIC_H */
