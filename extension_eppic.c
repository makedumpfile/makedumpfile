/*
 * extension_eppic.c
 *
 * Created by: Aravinda Prasad <aravinda@linux.vnet.ibm.com>
 *
 * Copyright (C) 2012  IBM Corporation
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

#include "makedumpfile.h"
#include "extension_eppic.h"

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
 * Call back functions for eppic to query the dump image
 */

static int
apigetmem(ull iaddr, void *p, int nbytes)
{
	return readmem(VADDR, iaddr, p, nbytes);
}

static int
apiputmem(ull iaddr, void *p, int nbytes)
{
	return 1;
}

static char *
apimember(char *mname, ull pidx, type_t *tm,
		member_t *m, ull *lidx)
{
	return 0;
}

static int
apigetctype(int ctype, char *name, type_t *tout)
{
	long size = 0;
	unsigned long long die = 0;

	switch (ctype) {
	case V_TYPEDEF:
		size = get_domain(name, DWARF_INFO_GET_DOMAIN_TYPEDEF, &die);
		break;
	case V_STRUCT:
		size = get_domain(name, DWARF_INFO_GET_DOMAIN_STRUCT, &die);
		break;
	case V_UNION:
		size = get_domain(name, DWARF_INFO_GET_DOMAIN_UNION, &die);
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
	return "";
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

	ptr = get_symbol_addr(name);
	if (!ptr)
		return 0;

	*val = ptr;
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
	if (!readmem(VADDR, (unsigned long)ptr, (char *)&val, sizeof(val)))
		return (uint8_t) -1;
	return val;
}

static uint16_t
apigetuint16(void *ptr)
{
	uint16_t val;
	if (!readmem(VADDR, (unsigned long)ptr, (char *)&val, sizeof(val)))
		return (uint16_t) -1;
	return val;
}

static uint32_t
apigetuint32(void *ptr)
{
	uint32_t val;
	if (!readmem(VADDR, (unsigned long)ptr, (char *)&val, sizeof(val)))
		return (uint32_t) -1;
	return val;
}

static uint64_t
apigetuint64(void *ptr)
{
	uint64_t val;
	if (!readmem(VADDR, (unsigned long)ptr, (char *)&val, sizeof(val)))
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


/* Initialize eppic */
int
eppic_init()
{
	if (eppic_open() >= 0) {

		/* Register call back functions */
		eppic_apiset(&icops, 3, sizeof(long), 0);

		/* set the new function callback */
		eppic_setcallback(reg_callback);

		return 0;
	}
	return 1;
}

