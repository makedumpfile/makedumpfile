/*
 * common.h
 *
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
#ifndef _COMMON_H
#define _COMMON_H

#define TRUE		(1)
#define FALSE		(0)
#define ERROR		(-1)
#define UNUSED   	(-1)
#define RETURN_ON_ERROR  	(0x2)

#ifndef LONG_MAX
#define LONG_MAX	((long)(~0UL>>1))
#endif
#ifndef ULONG_MAX
#define ULONG_MAX	(~0UL)
#endif
#define ULONGLONG_MAX	(~0ULL)

#define MAX(a,b)	((a) > (b) ? (a) : (b))
#define MIN(a,b)	((a) < (b) ? (a) : (b))

#define divideup(x, y)	(((x) + ((y) - 1)) / (y))
#define round(x, y)	(((x) / (y)) * (y))
#define roundup(x, y)	((((x) + ((y) - 1)) / (y)) * (y))

#define NUM_HEX  (0x1)
#define NUM_DEC  (0x2)
#define NUM_EXPR (0x4)
#define NUM_ANY  (NUM_HEX|NUM_DEC|NUM_EXPR)

/*
 * Incorrect address
 */
#define NOT_MEMMAP_ADDR	(0x0)
#define NOT_KV_ADDR	(0x0)
#define NOT_PADDR	(ULONGLONG_MAX)
#define BADADDR  	((ulong)(-1))

#endif  /* COMMON_H */

