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

struct cache_entry {
	unsigned long long paddr;
	void *bufptr;
	unsigned long buflen;
	struct cache_entry *next, *prev;

	void (*discard)(struct cache_entry *);
};

int cache_init(void);
void *cache_search(unsigned long long paddr, unsigned long length);
struct cache_entry *cache_alloc(unsigned long long paddr);
void cache_add(struct cache_entry *entry);
void cache_free(struct cache_entry *entry);

#endif	/* _CACHE_H */
