/*
 * extension_eppic.c
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
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <dwarf.h>

#include "makedumpfile.h"
#include "extension_eppic.h"

static int apigetctype(int, char *, type_t *);

/*
 * Most of the functions included in this file performs similar
 * functionality as in the applications/crash/eppic.c file part of
 * eppic, but uses DWARF instead of gdb. Few of the functions are
 * reused directly which are acknowledged in the comment before the
 * function.
 */

/*
 * This is the call back function called when a new eppic macro is
 * loaded. This will execute the loaded eppic macro.
 *
 * "fname" is considered as the entry point of an eppic macro only if
 * the following functions are defined:
 *
 *  fname_help()
 *  fname_usage()
 *
 * These functions have no relevance in makedumpfile context as
 * makedumpfile automatically executes the eppic macro by calling the
 * entry point and user will not have any option to execute the usage
 * or help functions. However they are required to identify the entry
 * points in the eppic macro.
 */
void
reg_callback(char *name, int load)
{
	char fname[MAX_SYMNAMELEN];

	/* Nothing to process for unload request */
	if (!load)
		return;

	snprintf(fname, sizeof(fname), "%s_help", name);
	if (eppic_chkfname(fname, 0)) {
		snprintf(fname, sizeof(fname), "%s_usage", name);
		if (eppic_chkfname(fname, 0))
			eppic_cmd(name, NULL, 0);
	}
	return;
}

/*
 * This function is a copy of eppic_setupidx() function in
 * applications/crash/eppic.c file from eppic source code
 * repository.
 *
 * set idx value to actual array indexes from specified size
 */
static void
eppic_setupidx(TYPE_S *t, int ref, int nidx, int *idxlst)
{
	/* put the idxlst in index size format */
	if (nidx) {
		int i;
		for (i = 0; i < nidx - 1; i++) {
			/* kludge for array dimensions of [1] */
			if (idxlst[i + 1] == 0)
				idxlst[i + 1] = 1;
			idxlst[i] = idxlst[i] / idxlst[i + 1];
		}

		/* divide by element size for last element bound */
		if (ref)
			idxlst[i] /= eppic_defbsize();
		else
			idxlst[i] /= eppic_type_getsize(t);
		eppic_type_setidxlst(t, idxlst);
	}
}

/*
 * Call back functions for eppic to query the dump image
 */

static int
apigetmem(ull iaddr, void *p, int nbytes)
{
	return READMEM(VADDR, iaddr, p, nbytes);
}

static int
apiputmem(ull iaddr, void *p, int nbytes)
{
	return 1;
}

/*
 * Drill down the type of the member and update eppic with information
 * about the member
 */
static char *
drilldown(ull offset, type_t *t)
{
	int type_flag, len = 0, t_len = 0, nidx = 0;
	int fctflg = 0, ref = 0, *idxlst = 0;
	unsigned long long die_off = offset, t_die_off;
	char *tstr = NULL, *tstr_dup = NULL;

	while (GET_DIE_ATTR_TYPE(die_off, &type_flag, &t_die_off)) {
		switch (type_flag) {
		/* typedef inserts a level of reference to the actual type */
		case DW_TAG_pointer_type:
			ref++;
			die_off = t_die_off;
			/*
			 * This could be a void *, in which case the drill
			 * down stops here
			 */
			if (!GET_DIE_ATTR_TYPE(die_off, &type_flag,
						&t_die_off)) {
				/* make it a char* */
				eppic_parsetype("char", t, ref);
				return eppic_strdup("");
			}
			break;
		/* Handle pointer to function */
		case DW_TAG_subroutine_type:
			fctflg = 1;
			die_off = t_die_off;
			break;
		/* Handle arrays */
		case DW_TAG_array_type:
			if (!idxlst) {
				idxlst = eppic_calloc(sizeof(int) * \
					(MAX_ARRAY_DIMENSION + 1));
				if (!idxlst) {
					ERRMSG("Out of memory\n");
					return NULL;
				}
			}
			if (nidx >= MAX_ARRAY_DIMENSION) {
				ERRMSG("Too many array indexes. Max=%d\n",
						MAX_ARRAY_DIMENSION);
				return NULL;
			}

			/* handle multi-dimensional array */
			len = GET_DIE_LENGTH(die_off, FALSE);
			t_len = GET_DIE_LENGTH(t_die_off, FALSE);
			if (len > 0 && t_len > 0)
				idxlst[nidx++] = len / t_len;
			die_off = t_die_off;
			break;
		/* Handle typedef */
		case DW_TAG_typedef:
			die_off = t_die_off;
			break;
		case DW_TAG_base_type:
			eppic_parsetype(tstr = GET_DIE_NAME(t_die_off), t, 0);
			goto out;
		case DW_TAG_union_type:
			eppic_type_mkunion(t);
			goto label;
		case DW_TAG_enumeration_type:
			eppic_type_mkenum(t);
			goto label;
		case DW_TAG_structure_type:
			eppic_type_mkstruct(t);
label:
			eppic_type_setsize(t, GET_DIE_LENGTH(t_die_off, TRUE));
			eppic_type_setidx(t, (ull)t_die_off);
			tstr = GET_DIE_NAME(t_die_off);
			/* Drill down further */
			if (tstr)
				apigetctype(V_STRUCT, tstr, t);
			die_off = 0;
			break;
		/* Unknown TAG ? */
		default:
			die_off = t_die_off;
			break;
		}
	}

out:
	eppic_setupidx(t, ref, nidx, idxlst);
	if (fctflg)
		eppic_type_setfct(t, 1);
	eppic_pushref(t, ref + (nidx ? 1 : 0));
	tstr_dup = (tstr) ? eppic_strdup(tstr) : eppic_strdup("");
	/* Free the memory allocated by makedumpfile. */
	free(tstr);
	return tstr_dup;
}

/*
 * Get the type, size and position information for a member of a structure.
 */
static char *
apimember(char *mname, ull idx, type_t *tm, member_t *m, ull *last_index)
{
	int index, nfields = -1, size;
	int nbits = 0, fbits = 0;
	long offset;
	unsigned long long m_die, die_off = idx;
	char *name = NULL;

	nfields = GET_DIE_NFIELDS_ALL(die_off);
	/*
	 * GET_DIE_NFIELDS() returns < 0 if the die is not structure type
	 * or union type
	 */
	if (nfields <= 0)
		return NULL;

	/* if we're being asked the next member in a getfirst/getnext
	 * sequence
	 */
	if (mname && !mname[0] && last_index && (*last_index))
		index = *last_index;
	else
		index = 0;

	while (index < nfields) {
		size = GET_DIE_MEMBER_ALL(die_off, index, &offset, &name,
					&nbits, &fbits, &m_die);

		if (size < 0)
			return NULL;

		if (!mname || !mname[0] || !strcmp(mname, name)) {
			eppic_member_ssize(m, size);
			if (name) {
				eppic_member_sname(m, name);
				/*
				 * Free the memory allocated by makedumpfile.
				 */
				free(name);
			}
			else
				eppic_member_sname(m, "");
			eppic_member_soffset(m, offset);
			eppic_member_snbits(m, nbits);
			eppic_member_sfbit(m, fbits);
			*last_index = index + 1;
			return drilldown(m_die, tm);
		}
		index++;
	}
	return NULL;
}

static int
apigetctype(int ctype, char *name, type_t *tout)
{
	long size = 0;
	unsigned long long die = 0;

	switch (ctype) {
	case V_TYPEDEF:
		size = GET_DOMAIN_ALL(name, DWARF_INFO_GET_DOMAIN_TYPEDEF,
									&die);
		break;
	case V_STRUCT:
		size = GET_DOMAIN_ALL(name, DWARF_INFO_GET_DOMAIN_STRUCT, &die);
		break;
	case V_UNION:
		size = GET_DOMAIN_ALL(name, DWARF_INFO_GET_DOMAIN_UNION, &die);
		break;
	/* TODO
	 * Implement for all the domains
	 */
	}

	if (size <= 0 || !die)
		return 0;

	/* populate */
	eppic_type_settype(tout, ctype);
	eppic_type_setsize(tout, size);
	eppic_type_setidx(tout, (ull)(unsigned long)die);
	eppic_pushref(tout, 0);
	return 1;
}

static char *
apigetrtype(ull idx, type_t *t)
{
	return drilldown(idx, t);
}

static int
apialignment(ull idx)
{
	return 0;
}

int
apigetval(char *name, ull *val, VALUE_S *value)
{
	ull ptr = 0;

	ptr = GET_SYMBOL_ADDR_ALL(name);

	if (!ptr)
		return 0;

	*val = ptr;

	if (!value)
		return 1;

	/* Support for fully typed symbol access */
	ull type;
	TYPE_S *stype;

	type = GET_DIE_OFFSET(name);
	stype = eppic_gettype(value);

	apigetrtype(type, stype);

	eppic_pushref(stype, 1);
	eppic_setmemaddr(value, *val);
	eppic_do_deref(1, value, value);

	*val = eppic_getval(value);

	if (!eppic_typeislocal(stype) && eppic_type_getidx(stype) > 100) {
		char *tname = GET_DIE_NAME(eppic_type_getidx(stype));
		if (tname) {
			eppic_chktype(stype, tname);
			/* Free the memory allocated by makedumpfile. */
			free(tname);
		}
	}
	return 1;
}

static enum_t *
apigetenum(char *name)
{
	return 0;
}

static def_t *
apigetdefs(void)
{
	return 0;
}

static uint8_t
apigetuint8(void *ptr)
{
	uint8_t val;
	if (!READMEM(VADDR, (unsigned long)ptr, (char *)&val, sizeof(val)))
		return (uint8_t) -1;
	return val;
}

static uint16_t
apigetuint16(void *ptr)
{
	uint16_t val;
	if (!READMEM(VADDR, (unsigned long)ptr, (char *)&val, sizeof(val)))
		return (uint16_t) -1;
	return val;
}

static uint32_t
apigetuint32(void *ptr)
{
	uint32_t val;
	if (!READMEM(VADDR, (unsigned long)ptr, (char *)&val, sizeof(val)))
		return (uint32_t) -1;
	return val;
}

static uint64_t
apigetuint64(void *ptr)
{
	uint64_t val;
	if (!READMEM(VADDR, (unsigned long)ptr, (char *)&val, sizeof(val)))
		return (uint64_t) -1;
	return val;
}

static char *
apifindsym(char *p)
{
	return NULL;
}

apiops icops = {
	apigetmem,
	apiputmem,
	apimember,
	apigetctype,
	apigetrtype,
	apialignment,
	apigetval,
	apigetenum,
	apigetdefs,
	apigetuint8,
	apigetuint16,
	apigetuint32,
	apigetuint64,
	apifindsym
};

/* Extensions to built-in functions */
VALUE_S *
eppic_memset(VALUE_S *vaddr, VALUE_S *vch, VALUE_S *vlen)
{
	ull addr = eppic_getval(vaddr);
	int len = eppic_getval(vlen);
	int ch = eppic_getval(vch);

	/*
	 * Set the value at address from iaddr till iaddr + nbytes
	 * to the value specified in variable ch
	 */
	UPDATE_FILTER_INFO_RAW(addr, ch, len);
	return eppic_makebtype(1);
}


/* Initialize eppic */
int
eppic_init(void *fun_ptr)
{
	cb = (struct call_back *)fun_ptr;

	if (eppic_open() >= 0) {

		/* Register call back functions */
		eppic_apiset(&icops, 3, sizeof(long), 0);

		/* set the new function callback */
		eppic_setcallback(reg_callback);

		/* Extend built-in functions to include memset */
		eppic_builtin("int memset(char *, int, int)",
				(bf_t *)eppic_memset);

		return 0;
	}
	return 1;
}

