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
#include "sadump_mod.h"

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

static char *guid_to_str(efi_guid_t *guid, char *buf, size_t buflen);
static struct tm *efi_time_t_to_tm(const efi_time_t *e);
static int verify_magic_number(uint32_t magicnum[DUMP_PART_HEADER_MAGICNUM_SIZE]);
static int read_device(void *buf, size_t bytes, ulong *offset);
static int read_device_diskset(struct sadump_diskset_info *sdi, void *buf,
			       size_t bytes, ulong *offset);
static int read_sadump_header(char *filename);
static int read_sadump_header_diskset(int diskid, struct sadump_diskset_info *sdi);

static struct sadump_info sadump_info = {};
static struct sadump_info *si = &sadump_info;

int
check_and_get_sadump_header_info(char *filename)
{
	int i;

	if (!read_sadump_header(filename))
		return FALSE;

	if (info->flag_sadump_diskset && info->flag_sadump == SADUMP_DISKSET) {

		si->diskset_info[0].fd_memory = info->fd_memory;
		si->diskset_info[0].sph_memory = si->sph_memory;
		si->diskset_info[0].data_offset = si->data_offset;

		for (i = 1; i < si->num_disks; ++i) {
			struct sadump_diskset_info *sdi =
				&si->diskset_info[i];

			if ((sdi->fd_memory =
			     open(sdi->name_memory, O_RDONLY)) < 0) {
				ERRMSG("Can't open the dump diskset "
				       "memory(%s). %s\n", sdi->name_memory,
				       strerror(errno));
				return FALSE;
			}

			if (!read_sadump_header_diskset(i, sdi))
				return FALSE;
		}
	}

	return TRUE;
}

static char *
guid_to_str(efi_guid_t *guid, char *buf, size_t buflen)
{
	snprintf(buf, buflen,
		 "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		 guid->data1, guid->data2, guid->data3,
		 guid->data4[0], guid->data4[1], guid->data4[2],
		 guid->data4[3], guid->data4[4], guid->data4[5],
		 guid->data4[6], guid->data4[7]);

	return buf;
}

static struct tm *
efi_time_t_to_tm(const efi_time_t *e)
{
	static struct tm t;
	time_t ti;

	memset(&t, 0, sizeof(t));

	t.tm_sec  = e->second;
	t.tm_min  = e->minute;
	t.tm_hour = e->hour;
	t.tm_mday = e->day;
	t.tm_mon  = e->month - 1;
	t.tm_year = e->year - 1900;

	if (e->timezone != EFI_UNSPECIFIED_TIMEZONE)
		t.tm_hour += e->timezone;

	else
		DEBUG_MSG("sadump: timezone information is missing\n");

	ti = mktime(&t);
	if (ti == (time_t)-1)
		return &t;

	return localtime_r(&ti, &t);
}

static int
verify_magic_number(uint32_t magicnum[DUMP_PART_HEADER_MAGICNUM_SIZE])
{
	int i;

	for (i = 1; i < DUMP_PART_HEADER_MAGICNUM_SIZE; ++i)
		if (magicnum[i] != (magicnum[i - 1] + 7) * 11)
			return FALSE;

	return TRUE;
}

static int
read_device(void *buf, size_t bytes, ulong *offset)
{
	if (lseek(info->fd_memory, *offset, SEEK_SET) < 0) {
		ERRMSG("Can't seek a file(%s). %s\n",
		       info->name_memory, strerror(errno));
		return FALSE;
	}
	if (read(info->fd_memory, buf, bytes) != bytes) {
		ERRMSG("Can't read a file(%s). %s\n",
		       info->name_memory, strerror(errno));
		return FALSE;
	}
	*offset += bytes;
	return TRUE;
}

static int
read_device_diskset(struct sadump_diskset_info *sdi, void *buf,
		    size_t bytes, unsigned long *offset)
{
	if (lseek(sdi->fd_memory, *offset, SEEK_SET) < 0) {
		ERRMSG("Can't seek a file(%s). %s\n",
		       sdi->name_memory, strerror(errno));
		return FALSE;
	}
	if (read(sdi->fd_memory, buf, bytes) != bytes) {
		ERRMSG("Can't read a file(%s). %s\n",
		       sdi->name_memory, strerror(errno));
		return FALSE;
	}
	*offset += bytes;
	return TRUE;
}

static int
read_sadump_header(char *filename)
{
	struct sadump_part_header *sph = NULL;
	struct sadump_header *sh = NULL;
	struct sadump_disk_set_header *sdh = NULL;
	struct sadump_media_header *smh = NULL;
	unsigned long offset = 0, sub_hdr_offset;
	unsigned long block_size = SADUMP_DEFAULT_BLOCK_SIZE;
	unsigned long bitmap_len, dumpable_bitmap_len;
	enum sadump_format_type flag_sadump;
	uint32_t smram_cpu_state_size = 0;
	char guid[33];

	if ((si->sph_memory = malloc(SADUMP_DEFAULT_BLOCK_SIZE)) == NULL) {
		ERRMSG("Can't allocate memory for partition header buffer: "
		       "%s\n", strerror(errno));
		return FALSE;
	}

	if ((si->sh_memory = malloc(SADUMP_DEFAULT_BLOCK_SIZE)) == NULL) {
		ERRMSG("Can't allocate memory for dump header buffer: "
		       "%s\n", strerror(errno));
		return FALSE;
	}

	if ((si->sdh_memory = malloc(SADUMP_DEFAULT_BLOCK_SIZE)) == NULL) {
		ERRMSG("Can't allocate memory for disk set header buffer: "
		       "%s\n", strerror(errno));
		return FALSE;
	}

	if ((si->smh_memory = malloc(SADUMP_DEFAULT_BLOCK_SIZE)) == NULL) {
		ERRMSG("Can't allocate memory for media header buffer: "
		       "%s\n", strerror(errno));
		return FALSE;
	}

	sph = si->sph_memory;
	sh = si->sh_memory;
	sdh = si->sdh_memory;
	smh = si->smh_memory;

restart:
	if (block_size < 0)
		return FALSE;

	if (!read_device(sph, block_size, &offset))
		return ERROR;

	if (sph->signature1 == SADUMP_SIGNATURE1 &&
	    sph->signature2 == SADUMP_SIGNATURE2) {

		if (sph->set_disk_set == 0) {

			flag_sadump = SADUMP_SINGLE_PARTITION;

			DEBUG_MSG("sadump: read dump device as single partition\n");

		} else {

			flag_sadump = SADUMP_DISKSET;

			DEBUG_MSG("sadump: read dump device as diskset\n");

		}

	} else {

		offset = 0;

		if (!read_device(smh, block_size, &offset))
			return ERROR;

		if (!read_device(sph, block_size, &offset))
			return ERROR;

		if (sph->signature1 != SADUMP_SIGNATURE1 ||
		    sph->signature2 != SADUMP_SIGNATURE2) {

			DEBUG_MSG("sadump: does not have partition header\n");

			flag_sadump = SADUMP_UNKNOWN;

			DEBUG_MSG("sadump: read dump device as unknown format\n");

			goto out;
		}

		flag_sadump = SADUMP_MEDIA_BACKUP;

		DEBUG_MSG("sadump: read dump device as media backup format\n");

	}

	if (!verify_magic_number(sph->magicnum)) {
		DEBUG_MSG("sadump: invalid magic number\n");
		return FALSE;
	}

	if (flag_sadump == SADUMP_DISKSET) {
		uint32_t header_blocks;
		size_t header_size;

		if (sph->set_disk_set != 1) {
			DEBUG_MSG("sadump: id of this disk is %d\n",
				  sph->set_disk_set);
			return FALSE;
		}

		if (!read_device(&header_blocks, sizeof(uint32_t),
					&offset))
			return FALSE;

		offset -= sizeof(uint32_t);
		header_size = header_blocks * block_size;

		if (header_size > block_size) {
			sdh = realloc(sdh, header_size);
			if (!sdh) {
				ERRMSG("Can't allocate memory for disk "
				       "set memory\n");
				return FALSE;
			}
		}

		if (!read_device(sdh, header_size, &offset))
			return ERROR;

		DEBUG_MSG("sadump: the diskset consists of %u disks\n",
			  sdh->disk_num);

	}

	if (!read_device(sh, block_size, &offset))
		return FALSE;

	sub_hdr_offset = offset;

	if (strncmp(sh->signature, SADUMP_SIGNATURE, 8) != 0) {
		DEBUG_MSG("sadump: does not have dump header\n");
		return FALSE;
	}

	if (flag_sadump == SADUMP_MEDIA_BACKUP) {

		if (memcmp(&sph->sadump_id, &smh->sadump_id,
			   sizeof(efi_guid_t)) != 0) {
			DEBUG_MSG("sadump: system ID mismatch\n");
			DEBUG_MSG("  partition header: %s\n",
				  guid_to_str(&sph->sadump_id, guid,
					      sizeof(guid)));
			DEBUG_MSG("  media header: %s\n",
				  guid_to_str(&smh->sadump_id, guid,
					      sizeof(guid)));
			return FALSE;
		}

		if (memcmp(&sph->disk_set_id, &smh->disk_set_id,
			   sizeof(efi_guid_t)) != 0) {
			DEBUG_MSG("sadump: disk set ID mismtch\n");
			DEBUG_MSG("  partition header: %s\n",
				  guid_to_str(&sph->disk_set_id, guid,
					      sizeof(guid)));
			DEBUG_MSG("  media header: %s\n",
				  guid_to_str(&smh->disk_set_id, guid,
					      sizeof(guid)));
			return FALSE;
		}

		if (memcmp(&sph->time_stamp, &smh->time_stamp,
			   sizeof(efi_time_t)) != 0) {
			DEBUG_MSG("sadump: time stamp mismatch\n");
			DEBUG_MSG("  partition header: %s",
				  asctime(efi_time_t_to_tm(&sph->time_stamp)));
			DEBUG_MSG("  media header: %s",
				  asctime(efi_time_t_to_tm(&smh->time_stamp)));
		}

		if (smh->sequential_num != 1) {
			DEBUG_MSG("sadump: first media file has sequential "
				  "number %d\n", smh->sequential_num);
			return FALSE;
		}

	}

	if (sh->block_size != block_size) {
		block_size = sh->block_size;
		offset = 0;
		goto restart;
	}

	if (sh->sub_hdr_size > 0) {
		if (!read_device(&smram_cpu_state_size, sizeof(uint32_t),
				 &offset)) {
			DEBUG_MSG("sadump: cannot read SMRAM CPU STATE size\n");
			return FALSE;
		}
		smram_cpu_state_size /= sh->nr_cpus;

		offset -= sizeof(uint32_t);
		offset += sh->sub_hdr_size * block_size;
	}

	if (!sh->bitmap_blocks) {
		DEBUG_MSG("sadump: bitmap_blocks is zero\n");
		return FALSE;
	}

	if (!sh->dumpable_bitmap_blocks) {
		DEBUG_MSG("sadump: dumpable_bitmap_blocks is zero\n");
		return FALSE;
	}

	bitmap_len = block_size * sh->bitmap_blocks;
	dumpable_bitmap_len = block_size * sh->dumpable_bitmap_blocks;

	si->sub_hdr_offset = sub_hdr_offset;
	si->smram_cpu_state_size = smram_cpu_state_size;
	si->data_offset = offset + bitmap_len + dumpable_bitmap_len;

out:
	switch (flag_sadump) {
	case SADUMP_SINGLE_PARTITION:
		DEBUG_MSG("sadump: single partition configuration\n");
		break;
	case SADUMP_DISKSET:
		DEBUG_MSG("sadump: diskset configuration with %d disks\n",
			  sdh->disk_num);
		break;
	case SADUMP_MEDIA_BACKUP:
		DEBUG_MSG("sadump: media backup file\n");
		break;
	case SADUMP_UNKNOWN:
		DEBUG_MSG("sadump: unknown format\n");
		break;
	}

	info->flag_sadump = flag_sadump;

	return TRUE;
}

static int
read_sadump_header_diskset(int diskid, struct sadump_diskset_info *sdi)
{
	struct sadump_part_header *sph = NULL;
	unsigned long offset = 0;
	char guid[33];

	if ((sph = malloc(si->sh_memory->block_size)) == NULL) {
		ERRMSG("Can't allocate memory for partition header buffer. "
		       "%s\n", strerror(errno));
		goto error;
	}

	if (!read_device_diskset(sdi, sph, si->sh_memory->block_size,
				 &offset))
		goto error;

	if (sph->signature1 != SADUMP_SIGNATURE1 ||
	    sph->signature2 != SADUMP_SIGNATURE2) {
		DEBUG_MSG("sadump: does not have partition header\n");
		free(sph);
		goto error;
	}

	if (memcmp(&si->sph_memory->sadump_id, &sph->sadump_id,
		   sizeof(efi_guid_t)) != 0) {
		DEBUG_MSG("sadump: system ID mismatch\n");
		DEBUG_MSG("  partition header on disk #1: %s\n",
			  guid_to_str(&si->sph_memory->sadump_id, guid,
				      sizeof(guid)));
		DEBUG_MSG("  partition header on disk #%d: %s\n", diskid,
			  guid_to_str(&sph->sadump_id, guid, sizeof(guid)));
		goto error;
	}

	if (memcmp(&si->sph_memory->disk_set_id, &sph->disk_set_id,
		   sizeof(efi_guid_t)) != 0) {
		DEBUG_MSG("sadump: disk set ID mismatch\n");
		DEBUG_MSG("  partition header on disk #1: %s\n",
			  guid_to_str(&si->sph_memory->disk_set_id, guid,
				      sizeof(guid)));
		DEBUG_MSG("  partition header on disk #%d: %s\n", diskid,
			  guid_to_str(&sph->disk_set_id, guid, sizeof(guid)));
		goto error;
	}

	if (memcmp(&si->sdh_memory->vol_info[diskid-1].id, &sph->vol_id,
		   sizeof(efi_guid_t)) != 0) {
		DEBUG_MSG("sadump: volume ID mismatch\n");
		DEBUG_MSG("  disk set header on disk #1: %s\n",
			  guid_to_str(&si->sdh_memory->vol_info[diskid-1].id,
				      guid, sizeof(guid)));
		DEBUG_MSG("  partition header on disk #%d: %s\n",
			  diskid+1,
			  guid_to_str(&sph->vol_id, guid, sizeof(guid)));
		goto error;
	}

	if (memcmp(&si->sph_memory->time_stamp, &sph->time_stamp,
		   sizeof(efi_time_t)) != 0) {
		DEBUG_MSG("sadump time stamp mismatch\n");
		DEBUG_MSG("  partition header on disk #1: %s\n",
			  asctime(efi_time_t_to_tm
				  (&si->sph_memory->time_stamp)));
		DEBUG_MSG("  partition header on disk #%d: %s\n",
			  diskid, asctime(efi_time_t_to_tm(&sph->time_stamp)));
	}

	if (diskid+1 != sph->set_disk_set) {
		DEBUG_MSG("sadump: wrong disk order; #%d expected but #%d given\n",
			  diskid+1, sph->set_disk_set);
		goto error;
	}

	sdi->sph_memory = sph;
	sdi->data_offset = si->sh_memory->block_size;

	return TRUE;

error:
	free(sph);

	return FALSE;
}

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
	if (si->sph_memory)
		free(si->sph_memory);
	if (si->sh_memory)
		free(si->sh_memory);
	if (si->sdh_memory)
		free(si->sdh_memory);
	if (si->smh_memory)
		free(si->smh_memory);
	if (si->diskset_info) {
		int i;

		for (i = 1; i < si->num_disks; ++i) {
			if (si->diskset_info[i].fd_memory)
				close(si->diskset_info[i].fd_memory);
			if (si->diskset_info[i].sph_memory)
				free(si->diskset_info[i].sph_memory);
		}
		free(si->diskset_info);
	}
}

#endif /* defined(__x86__) && defined(__x86_64__) */
