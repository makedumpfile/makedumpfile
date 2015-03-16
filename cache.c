/*
 * cache.h
 *
 * Created by: Petr Tesarik <ptesarik@suse.cz>
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

#include "makedumpfile.h"
#include "cache.h"
#include "print_info.h"

struct cache {
	struct cache_entry *head, *tail;
};

/* 8 pages covers 4-level paging plus 4 data pages */
#define CACHE_SIZE	8
static struct cache_entry entries[CACHE_SIZE];
static struct cache_entry *pool[CACHE_SIZE];
static int avail = CACHE_SIZE;

static struct cache used, pending;

int
cache_init(void)
{
	void *bufptr;
	int i;

	for (i = 0; i < CACHE_SIZE; ++i) {
		bufptr = malloc(info->page_size);
		if (bufptr == NULL) {
			ERRMSG("Can't allocate memory for cache. %s\n",
			       strerror(errno));
			return FALSE;
		}
		entries[i].bufptr = bufptr;
		pool[i] = &entries[i];
	}

	return TRUE;
}

static void
add_entry(struct cache *cache, struct cache_entry *entry)
{
	entry->next = cache->head;
	entry->prev = NULL;
	if (cache->head)
		cache->head->prev = entry;
	cache->head = entry;
	if (!cache->tail)
		cache->tail = entry;
}

static void
remove_entry(struct cache *cache, struct cache_entry *entry)
{
	if (entry->next)
		entry->next->prev = entry->prev;
	else
		cache->tail = entry->prev;

	if (entry->prev)
		entry->prev->next = entry->next;
	else
		cache->head = entry->next;
}

void *
cache_search(unsigned long long paddr)
{
	struct cache_entry *entry;
	for (entry = used.head; entry; entry = entry->next)
		if (entry->paddr == paddr) {
			if (entry != used.head) {
				remove_entry(&used, entry);
				add_entry(&used, entry);
			}
			return entry->bufptr;
		}

	return NULL;		/* cache miss */
}

struct cache_entry *
cache_alloc(unsigned long long paddr)
{
	struct cache_entry *entry = NULL;

	if (avail) {
		entry = pool[--avail];
		add_entry(&pending, entry);
	} else if (pending.tail) {
		entry = pending.tail;
	} else if (used.tail) {
		entry = used.tail;
		remove_entry(&used, entry);
		add_entry(&pending, entry);
	} else
		return NULL;

	entry->paddr = paddr;
	return entry;
}

void
cache_add(struct cache_entry *entry)
{
	remove_entry(&pending, entry);
	add_entry(&used, entry);
}

void
cache_free(struct cache_entry *entry)
{
	remove_entry(&pending, entry);
	pool[avail++] = entry;
}
