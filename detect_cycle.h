/*
 * detect_cycle.h  --  Generic cycle detection using Brent's algorithm
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

struct detect_cycle;

typedef void *(*dc_next_t)(void *prev, void *data);

/*
 * Initialize cycle detection.
 * Returns a pointer to allocated struct detect_cycle. The caller is
 * responsible to free the memory after use.
 */
struct detect_cycle *dc_init(void *head, void *data, dc_next_t next);

/*
 * Get next entry in the list using dc->next.
 * Returns 1 when cycle was detected, 0 otherwise.
 */
int dc_next(struct detect_cycle *dc, void **next);

/*
 * Get the start and length of the cycle. Must only be called after cycle was
 * detected by dc_next.
 */
void dc_find_start(struct detect_cycle *dc, void **first, unsigned long *len);
