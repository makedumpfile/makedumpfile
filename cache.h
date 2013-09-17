/*
 * cache.h
 *
 * Written by: Petr Tesarik <ptesarik@suse.cz>
 *
 * Copyright (c) 2012 SUSE LINUX Products GmbH, Nuernberg, Germany.
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

#ifndef _CACHE_H
#define _CACHE_H

int cache_init(void);
void *cache_search(unsigned long long paddr);
void *cache_alloc(unsigned long long paddr);
void cache_add(unsigned long long paddr);

#endif	/* _CACHE_H */
