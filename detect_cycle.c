/*
 * detect_cycle.c  --  Generic cycle detection using Brent's algorithm
 *
 * Created by: Philipp Rudo <prudo@redhat.com>
 *
 * Copyright (c) 2022 Red Hat, Inc. All rights reserved.
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

#include <stdlib.h>

#include "detect_cycle.h"

struct detect_cycle {
	/* First entry of the list */
	void *head;

	/* Variables required by Brent's algorithm */
	void *fast_p;
	void *slow_p;
	unsigned long length;
	unsigned long power;

	/* Function to get the next entry in the list */
	dc_next_t next;

	/* Private data passed to next */
	void *data;
};

struct detect_cycle *dc_init(void *head, void *data, dc_next_t next)
{
	struct detect_cycle *new;

	new = malloc(sizeof(*new));
	if (!new)
		return NULL;

	new->next = next;
	new->data = data;

	new->head = head;
	new->slow_p = head;
	new->fast_p = head;
	new->length = 0;
	new->power  = 2;

	return new;
}

int dc_next(struct detect_cycle *dc, void **next)
{

	if (dc->length == dc->power) {
		dc->length = 0;
		dc->power *= 2;
		dc->slow_p = dc->fast_p;
	}

	dc->fast_p = dc->next(dc->fast_p, dc->data);
	dc->length++;

	if (dc->slow_p == dc->fast_p)
		return 1;

	*next = dc->fast_p;
	return 0;
}

void dc_find_start(struct detect_cycle *dc, void **first, unsigned long *len)
{
	void *slow_p, *fast_p;
	unsigned long tmp;

	slow_p = fast_p = dc->head;
	tmp = dc->length;

	while (tmp) {
		fast_p = dc->next(fast_p, dc->data);
		tmp--;
	}

	while (slow_p != fast_p) {
		slow_p = dc->next(slow_p, dc->data);
		fast_p = dc->next(fast_p, dc->data);
	}

	*first = slow_p;
	*len = dc->length;
}
