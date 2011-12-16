/*
 * sadump_info.c
 *
 * Created by: HATAYAMA, Daisuke <d.hatayama@jp.fujitsu.com>
 *
 * Copyright (C) 2011  FUJITSU LIMITED
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
#if defined(__x86__) || defined(__x86_64__)

#include "makedumpfile.h"
#include "print_info.h"

struct sadump_diskset_info {
	char *name_memory;
	int fd_memory;
	struct sadump_part_header *sph_memory;
	unsigned long data_offset;
};

struct sadump_info {
	struct sadump_part_header *sph_memory;
	struct sadump_header *sh_memory;
	struct sadump_disk_set_header *sdh_memory;
	struct sadump_media_header *smh_memory;
	struct sadump_diskset_info *diskset_info;
	int num_disks;
	unsigned long sub_hdr_offset;
	uint32_t smram_cpu_state_size;
	unsigned long data_offset;
};

static struct sadump_info sadump_info = {};
static struct sadump_info *si = &sadump_info;

int
sadump_add_diskset_info(char *name_memory)
{
	si->num_disks++;

	si->diskset_info =
		realloc(si->diskset_info,
			si->num_disks*sizeof(struct sadump_diskset_info));
	if (!si->diskset_info) {
		ERRMSG("Can't allocate memory for sadump_diskset_info. %s\n",
		       strerror(errno));
		return FALSE;
	}

	si->diskset_info[si->num_disks - 1].name_memory = name_memory;

	return TRUE;
}

char *
sadump_head_disk_name_memory(void)
{
	return si->diskset_info[0].name_memory;
}

void
free_sadump_info(void)
{
	if (si->diskset_info)
		free(si->diskset_info);
}

#endif /* defined(__x86__) && defined(__x86_64__) */
