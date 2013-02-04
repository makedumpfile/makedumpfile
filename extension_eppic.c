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


/* Initialize eppic */
int
eppic_init()
{
	if (eppic_open() >= 0) {

		/* Register call back functions */
		eppic_apiset(NULL, 3, sizeof(long), 0);

		/* set the new function callback */
		eppic_setcallback(reg_callback);

		return 0;
	}
	return 1;
}

