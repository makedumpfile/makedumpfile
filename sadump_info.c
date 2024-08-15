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
#include "elf_info.h"
#include "print_info.h"
#include "sadump_mod.h"

#include <arpa/inet.h> /* htonl, htons */

#define SADUMP_EFI_GUID_TEXT_REPR_LEN 36

#ifdef __x86__

#define KEXEC_NOTE_HEAD_BYTES roundup(sizeof(Elf32_Nhdr), 4)

#endif

#ifdef __x86_64__

#define MEGABYTES(x)	((x) * (1048576))

#define KEXEC_NOTE_HEAD_BYTES roundup(sizeof(Elf64_Nhdr), 4)

#endif

#define KEXEC_CORE_NOTE_DESC_BYTES roundup(sizeof(struct elf_prstatus), 4)

#define KEXEC_NOTE_BYTES ((KEXEC_NOTE_HEAD_BYTES * 2) +                \
			  roundup(KEXEC_CORE_NOTE_NAME_BYTES, 4) +     \
			  KEXEC_CORE_NOTE_DESC_BYTES )

#define for_each_online_cpu(cpu)					\
	for (cpu = 0; cpu < max_mask_cpu(); ++cpu)	\
		if (is_online_cpu(cpu))

enum {
	BITPERWORD = BITPERBYTE * sizeof(unsigned long)
};

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
	unsigned long long *block_table;
	unsigned long *__per_cpu_offset;
	unsigned long __per_cpu_load;
	FILE *file_elf_note;
	char *cpu_online_mask_buf;
	size_t cpumask_size;
/* Backup Region, First 640K of System RAM. */
#define KEXEC_BACKUP_SRC_END    0x0009ffff
	unsigned long long backup_src_start;
	unsigned long backup_src_size;
	unsigned long long backup_offset;
	int kdump_backed_up;
	mdf_pfn_t max_mapnr;
	struct dump_bitmap *ram_bitmap;
};

static char *guid_to_str(efi_guid_t *guid, char *buf, size_t buflen);
static struct tm *efi_time_t_to_tm(const efi_time_t *e);
static int verify_magic_number(uint32_t magicnum[DUMP_PART_HEADER_MAGICNUM_SIZE]);
static int read_device(void *buf, size_t bytes, ulong *offset);
static int read_device_diskset(struct sadump_diskset_info *sdi, void *buf,
			       size_t bytes, ulong *offset);
static int read_sadump_header(char *filename);
static int read_sadump_header_diskset(int diskid, struct sadump_diskset_info *sdi);
static unsigned long long pfn_to_block(mdf_pfn_t pfn);
static int lookup_diskset(unsigned long long whole_offset, int *diskid,
			  unsigned long long *disk_offset);
static int max_mask_cpu(void);
static int cpu_online_mask_init(void);
static int per_cpu_init(void);
static int get_data_from_elf_note_desc(const char *note_buf, uint32_t n_descsz,
				       char *name, uint32_t n_type, char **data);
static int alignfile(unsigned long *offset);
static int
write_elf_note_header(char *name, void *data, size_t descsz, uint32_t type,
		      unsigned long *offset, unsigned long *desc_offset);
static int is_online_cpu(int cpu);
static unsigned long legacy_per_cpu_ptr(unsigned long ptr, int cpu);
static unsigned long per_cpu_ptr(unsigned long ptr, int cpu);
static int get_prstatus_from_crash_notes(int cpu, char *prstatus_buf);
static int cpu_to_apicid(int cpu, int *apicid);
static int get_smram_cpu_state(int apicid, struct sadump_smram_cpu_state *smram);
static int copy_regs_from_prstatus(struct elf_prstatus *prstatus,
				   const char *prstatus_buf);
static int
copy_regs_from_smram_cpu_state(struct elf_prstatus *prstatus,
			       const struct sadump_smram_cpu_state *smram);
static void
debug_message_smram_cpu_state(int apicid, struct sadump_smram_cpu_state *s);
static void
debug_message_user_regs_struct(int cpu, struct elf_prstatus *prstatus);
static int get_registers(int cpu, struct elf_prstatus *prstatus);

static struct sadump_info sadump_info = {};
static struct sadump_info *si = &sadump_info;

static inline int
sadump_is_on(char *bitmap, mdf_pfn_t i)
{
	return bitmap[i >> 3] & (1 << (7 - (i & 7)));
}

static inline int
sadump_is_dumpable(struct dump_bitmap *bitmap, mdf_pfn_t pfn)
{
	off_t offset;
	ssize_t rcode;

	if (pfn == 0 || bitmap->no_block != pfn/PFN_BUFBITMAP) {
		offset = bitmap->offset + BUFSIZE_BITMAP*(pfn/PFN_BUFBITMAP);
		lseek(bitmap->fd, offset, SEEK_SET);
		rcode = read(bitmap->fd, bitmap->buf, BUFSIZE_BITMAP);
		if (rcode != BUFSIZE_BITMAP)
			ERRMSG("Can't read the bitmap(%s). %s\n",
				bitmap->file_name, strerror(errno));
		if (pfn == 0)
			bitmap->no_block = 0;
		else
			bitmap->no_block = pfn / PFN_BUFBITMAP;
	}
	return sadump_is_on(bitmap->buf, pfn % PFN_BUFBITMAP);
}

static inline int
sadump_is_ram(mdf_pfn_t pfn)
{
	return sadump_is_dumpable(si->ram_bitmap, pfn);
}

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

static void
reverse_bit(char *buf, int len)
{
	int i;
	unsigned char c;

	for (i = 0; i < len; i++) {
		c = buf[i];
		c = ((c & 0x55) << 1) | ((c & 0xaa) >> 1); /* Swap 1bit */
		c = ((c & 0x33) << 2) | ((c & 0xcc) >> 2); /* Swap 2bit */
		c = (c << 4) | (c >> 4); /* Swap 4bit */
		buf[i] = c;
	}
}

int
sadump_copy_1st_bitmap_from_memory(void)
{
	struct sadump_header *sh = si->sh_memory;
	off_t offset_page;
	unsigned long bitmap_offset, bitmap_len;
	mdf_pfn_t pfn, pfn_bitmap1;
	extern mdf_pfn_t pfn_memhole;
	size_t buf_len;
	char *buf;

	bitmap_offset =	si->sub_hdr_offset + sh->block_size*sh->sub_hdr_size;
	bitmap_len = sh->block_size * sh->bitmap_blocks;

	if (lseek(info->fd_memory, bitmap_offset, SEEK_SET) < 0) {
		ERRMSG("Can't seek %s. %s\n",
		       info->name_memory, strerror(errno));
		return FALSE;
	}
	if (lseek(info->bitmap1->fd, info->bitmap1->offset, SEEK_SET) < 0) {
		ERRMSG("Can't seek the bitmap(%s). %s\n",
		       info->bitmap1->file_name, strerror(errno));
		return FALSE;
	}

	buf_len = si->sh_memory->block_size;
	buf = malloc(buf_len);
	if (!buf) {
		ERRMSG("Can't allocate buffer. %s\n", strerror(errno));
		return FALSE;
	}
	memset(buf, 0, buf_len);

	offset_page = 0;
	while (offset_page < bitmap_len) {
		if (read(info->fd_memory, buf, buf_len) != buf_len) {
			ERRMSG("Can't read %s. %s\n",
			       info->name_memory, strerror(errno));
			free(buf);
			return FALSE;
		}
		/*
		 * sadump formats associate each bit in a bitmap with
		 * a physical page in reverse order with the
		 * kdump-compressed format. We need to change bit
		 * order to reuse bitmaps in sadump formats in the
		 * kdump-compressed format.
		 */
		reverse_bit(buf, buf_len);
		if (write(info->bitmap1->fd, buf, buf_len) != buf_len) {
			ERRMSG("Can't write the bitmap(%s). %s\n",
			       info->bitmap1->file_name, strerror(errno));
			free(buf);
			return FALSE;
		}
		offset_page += buf_len;
	}

	pfn_bitmap1 = 0;
	for (pfn = 0; pfn < info->max_mapnr; ++pfn) {
		if (sadump_is_ram(pfn))
			pfn_bitmap1++;
	}
	pfn_memhole = info->max_mapnr - pfn_bitmap1;

	/*
	 * kdump uses the first 640kB on the 2nd kernel. But both
	 * bitmaps should reflect the 1st kernel memory situation. We
	 * modify bitmap accordingly.
	 */
	if (si->kdump_backed_up) {
		unsigned long long paddr;
		mdf_pfn_t pfn, backup_src_pfn;

		for (paddr = si->backup_src_start;
		     paddr < si->backup_src_start + si->backup_src_size;
		     paddr += info->page_size) {

			pfn = paddr_to_pfn(paddr);
			backup_src_pfn = paddr_to_pfn(paddr +
						      si->backup_offset -
						      si->backup_src_start);

			if (is_dumpable(info->bitmap_memory, backup_src_pfn, NULL))
				set_bit_on_1st_bitmap(pfn, NULL);
			else
				clear_bit_on_1st_bitmap(pfn, NULL);
		}
	}

	free(buf);
	return TRUE;
}

int
sadump_generate_vmcoreinfo_from_vmlinux(size_t *vmcoreinfo_size)
{
	size_t size;

	if (!info->file_vmcoreinfo)
		return FALSE;

	if ((SYMBOL(system_utsname) == NOT_FOUND_SYMBOL) &&
	    (SYMBOL(init_uts_ns) == NOT_FOUND_SYMBOL)) {
		ERRMSG("Can't get the symbol of system_utsname.\n");
		return FALSE;
	}

	if (get_mem_type() == NOT_FOUND_MEMTYPE) {
		ERRMSG("Can't find the memory type.\n");
		return FALSE;
	}

	strncpy(info->release, info->system_utsname.release,
		STRLEN_OSRELEASE);

	write_vmcoreinfo_data();

	size = ftell(info->file_vmcoreinfo);

	*vmcoreinfo_size = size;

	return TRUE;
}

int
sadump_generate_elf_note_from_dumpfile(void)
{
	size_t size_vmcoreinfo, size_pt_note;
	int x_cpu;
	unsigned long offset, offset_vmcoreinfo;
	char *vmcoreinfo_buf = NULL;
	int retval = FALSE;

	if (!per_cpu_init())
		return FALSE;

	if (!(info->file_vmcoreinfo = tmpfile())) {
		ERRMSG("Can't create a temporary strings(%s).\n",
		       FILENAME_VMCOREINFO);
		return FALSE;
	}
	if (!sadump_generate_vmcoreinfo_from_vmlinux(&size_vmcoreinfo)) {
		ERRMSG("Can't generate vmcoreinfo data.\n");
		goto error;
	}
	if ((vmcoreinfo_buf = malloc(size_vmcoreinfo)) == NULL) {
		ERRMSG("Can't allocate vmcoreinfo buffer. %s\n",
		       strerror(errno));
		goto cleanup;
	}
	rewind(info->file_vmcoreinfo);
	if (fread(vmcoreinfo_buf, size_vmcoreinfo, 1,
		  info->file_vmcoreinfo) != 1) {
		ERRMSG("Can't read vmcoreinfo temporary file. %s\n",
		       strerror(errno));
		goto cleanup;
	}

	if (!(si->file_elf_note = tmpfile())) {
		ERRMSG("Can't create a temporary elf_note file. %s\n",
		       strerror(errno));
		goto cleanup;
	}
	if (!cpu_online_mask_init())
		goto cleanup;
	offset = 0;
	for_each_online_cpu(x_cpu) {
		struct elf_prstatus prstatus;

		memset(&prstatus, 0, sizeof(prstatus));

		if (!get_registers(x_cpu, &prstatus))
			goto cleanup;

		if (!write_elf_note_header("CORE", &prstatus, sizeof(prstatus),
					   NT_PRSTATUS, &offset, NULL))
			goto cleanup;

	}

	if (!write_elf_note_header("VMCOREINFO", vmcoreinfo_buf,
				   size_vmcoreinfo, 0, &offset,
				   &offset_vmcoreinfo))
		goto cleanup;

	size_pt_note = ftell(si->file_elf_note);
	set_pt_note(0, size_pt_note);
	set_vmcoreinfo(offset_vmcoreinfo, size_vmcoreinfo);

	retval = TRUE;

cleanup:
	free(vmcoreinfo_buf);
	if (info->file_vmcoreinfo) {
		fclose(info->file_vmcoreinfo);
		info->file_vmcoreinfo = NULL;
	}
error:
	return retval;
}

static char *
guid_to_str(efi_guid_t *guid, char *buf, size_t buflen)
{
	snprintf(buf, buflen,
		 "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		 htonl(guid->data1), htons(guid->data2), htons(guid->data3),
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
	char guid[SADUMP_EFI_GUID_TEXT_REPR_LEN+1];

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
			DEBUG_MSG("sadump: disk set ID mismatch\n");
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

	switch (sh->header_version) {
	case 0:
		si->max_mapnr = (mdf_pfn_t)(uint64_t)sh->max_mapnr;
		break;
	default:
		ERRMSG("sadump: unsupported header version: %u\n"
		       "sadump: assuming header version: 1\n",
		       sh->header_version);
	case 1:
		si->max_mapnr = (mdf_pfn_t)sh->max_mapnr_64;
		break;
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
	char guid[SADUMP_EFI_GUID_TEXT_REPR_LEN+1];

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
sadump_initialize_bitmap_memory(void)
{
	struct sadump_header *sh = si->sh_memory;
	struct dump_bitmap *bmp;
	unsigned long dumpable_bitmap_offset;
	unsigned long long section, max_section;
	mdf_pfn_t pfn;
	unsigned long long *block_table;

	dumpable_bitmap_offset =
		si->sub_hdr_offset +
		sh->block_size * (sh->sub_hdr_size + sh->bitmap_blocks);

	bmp = malloc(sizeof(struct dump_bitmap));
	if (bmp == NULL) {
		ERRMSG("Can't allocate memory for the memory-bitmap. %s\n",
		       strerror(errno));
		return FALSE;
	}

	bmp->fd = info->fd_memory;
	bmp->file_name = info->name_memory;
	bmp->no_block = -1;
	bmp->offset = dumpable_bitmap_offset;

	bmp->buf = malloc(BUFSIZE_BITMAP);
	if (!bmp->buf) {
		ERRMSG("Can't allocate memory for the memory-bitmap's buffer. %s\n",
		       strerror(errno));
		free(bmp);
		return FALSE;
	}
	memset(bmp->buf, 0, BUFSIZE_BITMAP);

	max_section = divideup(si->max_mapnr, SADUMP_PF_SECTION_NUM);

	block_table = calloc(sizeof(unsigned long long), max_section);
	if (block_table == NULL) {
		ERRMSG("Can't allocate memory for the block_table. %s\n",
		       strerror(errno));
		free(bmp->buf);
		free(bmp);
		return FALSE;
	}

	for (section = 0; section < max_section; ++section) {
		if (section > 0)
			block_table[section] = block_table[section-1];
		for (pfn = section * SADUMP_PF_SECTION_NUM;
		     pfn < (section + 1) * SADUMP_PF_SECTION_NUM;
		     ++pfn)
			if (is_dumpable(bmp, pfn, NULL))
				block_table[section]++;
	}

	info->bitmap_memory = bmp;
	si->block_table = block_table;

	bmp = malloc(sizeof(struct dump_bitmap));
	if (bmp == NULL) {
		ERRMSG("Can't allocate memory for the memory-bitmap. %s\n",
		       strerror(errno));
		return FALSE;
	}
	bmp->fd = info->fd_memory;
	bmp->file_name = info->name_memory;
	bmp->no_block = -1;
	bmp->offset = si->sub_hdr_offset + sh->block_size * sh->sub_hdr_size;

	bmp->buf = malloc(BUFSIZE_BITMAP);
	if (!bmp->buf) {
		ERRMSG("Can't allocate memory for the memory-bitmap's buffer. %s\n",
		       strerror(errno));
		free(bmp);
		return FALSE;
	}
	memset(bmp->buf, 0, BUFSIZE_BITMAP);

	si->ram_bitmap = bmp;

	/*
	 * Perform explicitly zero filtering. Without this processing
	 * crash utility faces different behaviors on reading zero
	 * pages that are filtered out on the kdump-compressed format
	 * originating from kdump ELF and from sadump formats: the
	 * former succeeds in reading zero pages but the latter fails.
	 */
	for (pfn = 0; pfn < si->max_mapnr; pfn++) {
		if (sadump_is_ram(pfn) &&
		    !sadump_is_dumpable(info->bitmap_memory, pfn)) {
			info->dump_level |= DL_EXCLUDE_ZERO;
			break;
		}
	}

	return TRUE;
}

static int
max_mask_cpu(void)
{
	return BITPERBYTE * si->cpumask_size;
}

static int
cpu_online_mask_init(void)
{
	ulong cpu_online_mask_addr;

	if (si->cpu_online_mask_buf && si->cpumask_size)
		return TRUE;

	if (SYMBOL(cpu_online_mask) == NOT_FOUND_SYMBOL ||
	    (SIZE(cpumask) == NOT_FOUND_STRUCTURE &&
	     SIZE(cpumask_t) == NOT_FOUND_STRUCTURE))
		return FALSE;

	si->cpumask_size = SIZE(cpumask) == NOT_FOUND_STRUCTURE
		? SIZE(cpumask_t)
		: SIZE(cpumask);

	if (!(si->cpu_online_mask_buf = calloc(1, si->cpumask_size))) {
		ERRMSG("Can't allocate cpu_online_mask buffer. %s\n",
		       strerror(errno));
		return FALSE;
	}

	if ((SIZE(cpumask) == NOT_FOUND_STRUCTURE) ||
	    (SYMBOL(__cpu_online_mask) != NOT_FOUND_SYMBOL))
		cpu_online_mask_addr = SYMBOL(cpu_online_mask);

	else {
		if (!readmem(VADDR, SYMBOL(cpu_online_mask),
			     &cpu_online_mask_addr, sizeof(unsigned long))) {
			ERRMSG("Can't read cpu_online_mask pointer.\n");
			return FALSE;
		}

	}

	if (!readmem(VADDR, cpu_online_mask_addr, si->cpu_online_mask_buf,
		     si->cpumask_size)) {
		ERRMSG("Can't read cpu_online_mask memory.\n");
		return FALSE;
	}

	return TRUE;
}

int
sadump_num_online_cpus(void)
{
	int cpu, count = 0;

	if (!cpu_online_mask_init())
		return FALSE;

	DEBUG_MSG("sadump: online cpus:");

	for_each_online_cpu(cpu) {
		count++;
		DEBUG_MSG(" %d", cpu);
	}

	DEBUG_MSG("\nsadump: nr_cpus: %d\n", count);

	return count;
}

int
sadump_set_timestamp(struct timeval *ts)
{
	static struct tm t;
	efi_time_t *e = &si->sph_memory->time_stamp;
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
		return FALSE;

	ts->tv_sec = ti;
	ts->tv_usec = 0;

	return TRUE;
}

mdf_pfn_t
sadump_get_max_mapnr(void)
{
	return si->max_mapnr;
}

#ifdef __x86_64__

/*
 * Get address of vector0 interrupt handler (Devide Error) form Interrupt
 * Descriptor Table.
 */
static unsigned long
get_vec0_addr(ulong idtr)
{
	struct gate_struct64 {
		uint16_t offset_low;
		uint16_t segment;
		uint32_t ist : 3, zero0 : 5, type : 5, dpl : 2, p : 1;
		uint16_t offset_middle;
		uint32_t offset_high;
		uint32_t zero1;
	} __attribute__((packed)) gate;

	readmem(PADDR, idtr, &gate, sizeof(gate));

	return ((ulong)gate.offset_high << 32)
		+ ((ulong)gate.offset_middle << 16)
		+ gate.offset_low;
}

/*
 * Find "elfcorehdr=" in the boot parameter of kernel and return the address
 * of elfcorehdr.
 */
static ulong
get_elfcorehdr(ulong cr3)
{
	char cmdline[BUFSIZE], *ptr;
	ulong cmdline_vaddr;
	ulong cmdline_paddr;
	ulong buf_vaddr, buf_paddr;
	char *end;
	ulong elfcorehdr_addr = 0, elfcorehdr_size = 0;

	if (SYMBOL(saved_command_line) == NOT_FOUND_SYMBOL) {
		ERRMSG("Can't get the symbol of saved_command_line.\n");
		return 0;
	}
	cmdline_vaddr = SYMBOL(saved_command_line);
	if ((cmdline_paddr = vtop4_x86_64_pagetable(cmdline_vaddr, cr3)) == NOT_PADDR)
		return 0;

	DEBUG_MSG("sadump: cmdline vaddr: %lx\n", cmdline_vaddr);
	DEBUG_MSG("sadump: cmdline paddr: %lx\n", cmdline_paddr);

	if (!readmem(PADDR, cmdline_paddr, &buf_vaddr, sizeof(ulong)))
		return 0;

	if ((buf_paddr = vtop4_x86_64_pagetable(buf_vaddr, cr3)) == NOT_PADDR)
		return 0;

	DEBUG_MSG("sadump: cmdline buf vaddr: %lx\n", buf_vaddr);
	DEBUG_MSG("sadump: cmdline buf paddr: %lx\n", buf_paddr);

	memset(cmdline, 0, BUFSIZE);
	if (!readmem(PADDR, buf_paddr, cmdline, BUFSIZE))
		return 0;

	ptr = strstr(cmdline, "elfcorehdr=");
	if (!ptr)
		return 0;

	DEBUG_MSG("sadump: 2nd kernel detected.\n");

	ptr += strlen("elfcorehdr=");
	elfcorehdr_addr = memparse(ptr, &end);
	if (*end == '@') {
		elfcorehdr_size = elfcorehdr_addr;
		elfcorehdr_addr = memparse(end + 1, &end);
	}

	DEBUG_MSG("sadump: elfcorehdr_addr: %lx\n", elfcorehdr_addr);
	DEBUG_MSG("sadump: elfcorehdr_size: %lx\n", elfcorehdr_size);

	return elfcorehdr_addr;
}

/*
 * Get vmcoreinfo from elfcorehdr.
 * Some codes are imported from Linux kernel(fs/proc/vmcore.c)
 */
static int
get_vmcoreinfo_in_kdump_kernel(ulong elfcorehdr, ulong *addr, int *len)
{
	unsigned char e_ident[EI_NIDENT];
	Elf64_Ehdr ehdr;
	Elf64_Phdr phdr;
	Elf64_Nhdr nhdr;
	ulong ptr;
	ulong nhdr_offset = 0;
	int i;

	if (!readmem(PADDR, elfcorehdr, e_ident, EI_NIDENT))
		return FALSE;

	if (e_ident[EI_CLASS] != ELFCLASS64) {
		ERRMSG("Only ELFCLASS64 is supportd\n");
		return FALSE;
	}

	if (!readmem(PADDR, elfcorehdr, &ehdr, sizeof(ehdr)))
		return FALSE;

	/* Sanity Check */
	if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
		(ehdr.e_type != ET_CORE) ||
		ehdr.e_ident[EI_CLASS] != ELFCLASS64 ||
		ehdr.e_ident[EI_VERSION] != EV_CURRENT ||
		ehdr.e_version != EV_CURRENT ||
		ehdr.e_ehsize != sizeof(Elf64_Ehdr) ||
		ehdr.e_phentsize != sizeof(Elf64_Phdr) ||
		ehdr.e_phnum == 0) {
		ERRMSG("Invalid elf header\n");
		return FALSE;
	}

	ptr = elfcorehdr + ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		ulong offset;
		char name[16];

		if (!readmem(PADDR, ptr, &phdr, sizeof(phdr)))
			return FALSE;

		ptr += sizeof(phdr);
		if (phdr.p_type != PT_NOTE)
			continue;

		offset = phdr.p_offset;
		if (!readmem(PADDR, offset, &nhdr, sizeof(nhdr)))
			return FALSE;

		offset += divideup(sizeof(Elf64_Nhdr), sizeof(Elf64_Word))*
			  sizeof(Elf64_Word);
		memset(name, 0, sizeof(name));
		if (!readmem(PADDR, offset, name, sizeof(name)))
			return FALSE;

		if(!strcmp(name, "VMCOREINFO")) {
			nhdr_offset = offset;
			break;
		}
	}

	if (!nhdr_offset)
		return FALSE;

	*addr = nhdr_offset +
		divideup(nhdr.n_namesz, sizeof(Elf64_Word))*
		sizeof(Elf64_Word);
	*len = nhdr.n_descsz;

	DEBUG_MSG("sadump: vmcoreinfo addr: %lx\n", *addr);
	DEBUG_MSG("sadump: vmcoreinfo len:  %d\n", *len);

	return TRUE;
}

/*
 * Check if current kaslr_offset/phys_base is for 1st kernel or 2nd kernel.
 * If we are in 2nd kernel, get kaslr_offset/phys_base from vmcoreinfo.
 *
 * 1. Get command line and try to retrieve "elfcorehdr=" boot parameter
 * 2. If "elfcorehdr=" is not found in command line, we are in 1st kernel.
 *    There is nothing to do.
 * 3. If "elfcorehdr=" is found, we are in 2nd kernel. Find vmcoreinfo
 *    using "elfcorehdr=" and retrieve kaslr_offset/phys_base from vmcoreinfo.
 */
int
get_kaslr_offset_from_vmcoreinfo(ulong cr3, ulong *kaslr_offset,
				 ulong *phys_base)
{
	ulong elfcorehdr_addr = 0;
	ulong vmcoreinfo_addr;
	int vmcoreinfo_len;
	char *buf, *pos;
	int ret = FALSE;

	elfcorehdr_addr = get_elfcorehdr(cr3);
	if (!elfcorehdr_addr)
		return FALSE;

	if (!get_vmcoreinfo_in_kdump_kernel(elfcorehdr_addr, &vmcoreinfo_addr,
					    &vmcoreinfo_len))
		return FALSE;

	if (!vmcoreinfo_len)
		return FALSE;

	DEBUG_MSG("sadump: Find vmcoreinfo in kdump memory\n");

	if (!(buf = malloc(vmcoreinfo_len))) {
		ERRMSG("Can't allocate vmcoreinfo buffer.\n");
		return FALSE;
	}

	if (!readmem(PADDR, vmcoreinfo_addr, buf, vmcoreinfo_len))
		goto finish;

	pos = strstr(buf, STR_NUMBER("phys_base"));
	if (!pos)
		goto finish;
	*phys_base  = strtoull(pos + strlen(STR_NUMBER("phys_base")), NULL, 0);

	pos = strstr(buf, STR_KERNELOFFSET);
	if (!pos)
		goto finish;
	*kaslr_offset = strtoull(pos + strlen(STR_KERNELOFFSET), NULL, 16);
	ret = TRUE;

finish:
	free(buf);
	return ret;
}

static int linux_banner_sanity_check(ulong cr3)
{
	unsigned long linux_banner_paddr;
	char buf[sizeof("Linux version")];

	linux_banner_paddr = vtop4_x86_64_pagetable(SYMBOL(linux_banner), cr3);
	if (linux_banner_paddr == NOT_PADDR) {
		DEBUG_MSG("sadump: linux_banner address translation failed\n");
		return FALSE;
	}

	if (!readmem(PADDR, linux_banner_paddr, &buf, sizeof(buf))) {
		DEBUG_MSG("sadump: reading linux_banner failed\n");
		return FALSE;
	}

	if (!STRNEQ(buf, "Linux version")) {
		DEBUG_MSG("sadump: linux_banner sanity check failed\n");
		return FALSE;
	}

	return TRUE;
}

/*
 * Calculate kaslr_offset and phys_base
 *
 * kaslr_offset:
 *   The difference between original address in vmlinux and actual address
 *   placed randomly by kaslr feature. To be more accurate,
 *   kaslr_offset = actual address  - original address
 *
 * phys_base:
 *   Physical address where the kerenel is placed. In other words, it's a
 *   physical address of __START_KERNEL_map. This is also decided randomly by
 *   kaslr.
 *
 * kaslr offset and phys_base are calculated as follows:
 *
 * kaslr_offset:
 * 1) Get IDTR and CR3 value from the dump header.
 * 2) Get a virtual address of IDT from IDTR value
 *    --- (A)
 * 3) Translate (A) to physical address using CR3, which points a top of
 *    page table.
 *    --- (B)
 * 4) Get an address of vector0 (Devide Error) interrupt handler from
 *    IDT, which are pointed by (B).
 *    --- (C)
 * 5) Get an address of symbol "divide_error" form vmlinux
 *    --- (D)
 *
 * Now we have two addresses:
 * (C)-> Actual address of "divide_error"
 * (D)-> Original address of "divide_error" in the vmlinux
 *
 * kaslr_offset can be calculated by the difference between these two
 * value.
 *
 * phys_base;
 * 1) Get IDT virtual address from vmlinux
 *    --- (E)
 *
 * So phys_base can be calculated using relationship of directly mapped
 * address.
 *
 * phys_base =
 *   Physical address(B) -
 *   (Virtual address(E) + kaslr_offset - __START_KERNEL_map)
 *
 * Note that the address (A) cannot be used instead of (E) because (A) is
 * not direct map address, it's a fixed map address.
 *
 * This solution works in most every case, but does not work in the
 * following case.
 *
 * 1) If the dump is captured on early stage of kernel boot, IDTR points
 *    early IDT table(early_idts) instead of normal IDT(idt_table).
 * 2) If the dump is captured whle kdump is working, IDTR points
 *    IDT table of 2nd kernel, not 1st kernel.
 *
 * Current implementation does not support the case 1), need
 * enhancement in the future. For the case 2), get kaslr_offset and
 * phys_base as follows.
 *
 * 1) Get kaslr_offset and phys_base using the above solution.
 * 2) Get kernel boot parameter from "saved_command_line"
 * 3) If "elfcorehdr=" is not included in boot parameter, we are in the
 *    first kernel, nothing to do any more.
 * 4) If "elfcorehdr=" is included in boot parameter, we are in the 2nd
 *    kernel. Retrieve vmcoreinfo from address of "elfcorehdr=" and
 *    get kaslr_offset and phys_base from vmcoreinfo.
 */
#define PTI_USER_PGTABLE_BIT		(info->page_shift)
#define PTI_USER_PGTABLE_MASK		(1 << PTI_USER_PGTABLE_BIT)
#define CR3_PCID_MASK			0xFFFull
#define CR4_LA57			(1 << 12)
int
calc_kaslr_offset(void)
{
	struct sadump_header *sh = si->sh_memory;
	uint64_t idtr = 0, cr3 = 0, idtr_paddr;
	struct sadump_smram_cpu_state smram;
	int apicid;
	unsigned long divide_error_vmcore, divide_error_vmlinux;
	unsigned long kaslr_offset, phys_base;
	unsigned long kaslr_offset_kdump, phys_base_kdump;
	int sanity_check_passed = FALSE;

	for (apicid = 0; apicid < sh->nr_cpus; ++apicid) {

		DEBUG_MSG("sadump: apicid: %d\n", apicid);

		if (!get_smram_cpu_state(apicid, &smram)) {
			ERRMSG("get_smram_cpu_state error\n");
			return FALSE;
		}

		idtr = ((uint64_t)smram.IdtUpper)<<32|(uint64_t)smram.IdtLower;

		if (!smram.Cr3 || !idtr) {
			DEBUG_MSG("sadump: cr3: %lx idt: %lx, skipped\n",
				  smram.Cr3, idtr);
			continue;
		}

		if ((SYMBOL(pti_init) != NOT_FOUND_SYMBOL) ||
		    (SYMBOL(kaiser_init) != NOT_FOUND_SYMBOL))
			cr3 = smram.Cr3 & ~(CR3_PCID_MASK|PTI_USER_PGTABLE_MASK);
		else
			cr3 = smram.Cr3 & ~CR3_PCID_MASK;

		NUMBER(pgtable_l5_enabled) = !!(smram.Cr4 & CR4_LA57);

		/* Convert virtual address of IDT table to physical address */
		idtr_paddr = vtop4_x86_64_pagetable(idtr, cr3);
		if (idtr_paddr == NOT_PADDR) {
			DEBUG_MSG("sadump: converting IDT physical address "
				  "failed.\n");
			continue;
		}

		/* Now we can calculate kaslr_offset and phys_base */
		divide_error_vmlinux = SYMBOL(divide_error);
		divide_error_vmcore = get_vec0_addr(idtr_paddr);
		kaslr_offset = divide_error_vmcore - divide_error_vmlinux;
		phys_base = idtr_paddr -
			(SYMBOL(idt_table)+kaslr_offset-__START_KERNEL_map);

		info->kaslr_offset = kaslr_offset;
		info->phys_base = phys_base;

		DEBUG_MSG("sadump: idtr=%" PRIx64 "\n", idtr);
		DEBUG_MSG("sadump: cr3=%" PRIx64 "\n", cr3);
		DEBUG_MSG("sadump: cr4=%" PRIx32 "\n", smram.Cr4);
		DEBUG_MSG("sadump: idtr(phys)=%" PRIx64 "\n", idtr_paddr);
		DEBUG_MSG("sadump: devide_error(vmlinux)=%lx\n",
			  divide_error_vmlinux);
		DEBUG_MSG("sadump: devide_error(vmcore)=%lx\n",
			  divide_error_vmcore);

		/* Reload symbol */
		if (!get_symbol_info()) {
			ERRMSG("Reading symbol table failed\n");
			return FALSE;
		}

		/* Sanity check */
		if (linux_banner_sanity_check(cr3)) {
			sanity_check_passed = TRUE;
			break;
		}

		info->kaslr_offset = 0;
		info->phys_base = 0;
	}

	if (!sanity_check_passed) {
		ERRMSG("failed to calculate kaslr_offset and phys_base; "
		       "default to 0\n");
		info->kaslr_offset = 0;
		info->phys_base = 0;
		return TRUE;
	}

	/*
	 * Check if current kaslr_offset/phys_base is for 1st kernel or 2nd
	 * kernel. If we are in 2nd kernel, get kaslr_offset/phys_base
	 * from vmcoreinfo
	 */
	if (get_kaslr_offset_from_vmcoreinfo(cr3, &kaslr_offset_kdump,
					     &phys_base_kdump)) {
		info->kaslr_offset = kaslr_offset_kdump;
		info->phys_base = phys_base_kdump;

		/* Reload symbol */
		if (!get_symbol_info()) {
			ERRMSG("Reading symbol table failed\n");
			return FALSE;
		}
	}

	DEBUG_MSG("sadump: kaslr_offset=%lx\n", info->kaslr_offset);
	DEBUG_MSG("sadump: phys_base=%lx\n", info->phys_base);

	return TRUE;
}

int
sadump_virt_phys_base(void)
{
	char buf[BUFSIZE];
	unsigned long phys, linux_banner_phys;

	if (SYMBOL(linux_banner) == NOT_FOUND_SYMBOL) {
		DEBUG_MSG("sadump: symbol linux_banner is not found\n");
		goto failed;
	}

	linux_banner_phys = SYMBOL(linux_banner) - __START_KERNEL_map;

	if (readmem(PADDR, linux_banner_phys + info->phys_base, buf,
		    strlen("Linux version")) && STRNEQ(buf, "Linux version"))
                return TRUE;

	for (phys = (-MEGABYTES(16)); phys != MEGABYTES(16+1);
             phys += MEGABYTES(1)) {
		if (readmem(PADDR, linux_banner_phys + phys, buf,
			    strlen("Linux version")) &&
		    STRNEQ(buf, "Linux version")) {
			DEBUG_MSG("sadump: phys_base: %lx %s\n", phys,
				  info->phys_base != phys ? "override" : "");
			info->phys_base = phys;
			return TRUE;
		}
	}

failed:
	if (calc_kaslr_offset())
		return TRUE;

	info->phys_base = 0;

	DEBUG_MSG("sadump: failed to calculate phys_base; default to 0\n");

	return FALSE;
}

#endif /* __x86_64__ */

int
readpage_sadump(unsigned long long paddr, void *bufptr)
{
	mdf_pfn_t pfn;
	unsigned long long block, whole_offset, perdisk_offset;
	int fd_memory;

	if (si->kdump_backed_up &&
	    paddr >= si->backup_src_start &&
	    paddr < si->backup_src_start + si->backup_src_size)
		paddr += si->backup_offset - si->backup_src_start;

	pfn = paddr_to_pfn(paddr);

	if (pfn >= si->max_mapnr)
		return FALSE;

	if (!sadump_is_ram(pfn)) {
		ERRMSG("pfn(%llx) is not ram.\n", pfn);
		return FALSE;
	}

	if (!sadump_is_dumpable(info->bitmap_memory, pfn)) {
		memset(bufptr, 0, info->page_size);
		return TRUE;
	}

	block = pfn_to_block(pfn);
	whole_offset = block * si->sh_memory->block_size;

	if (info->flag_sadump == SADUMP_DISKSET) {
		int diskid;

		if (!lookup_diskset(whole_offset, &diskid, &perdisk_offset))
			return FALSE;

		fd_memory = si->diskset_info[diskid].fd_memory;
		perdisk_offset += si->diskset_info[diskid].data_offset;

	} else {
		fd_memory = info->fd_memory;
		perdisk_offset = whole_offset + si->data_offset;

	}

	if (lseek(fd_memory, perdisk_offset, SEEK_SET) < 0)
		return FALSE;

	if (read(fd_memory, bufptr, info->page_size) != info->page_size)
		return FALSE;

	return TRUE;
}

int
sadump_check_debug_info(void)
{
	if (SYMBOL(linux_banner) == NOT_FOUND_SYMBOL)
		return FALSE;
	if (SYMBOL(bios_cpu_apicid) == NOT_FOUND_SYMBOL &&
	    SYMBOL(x86_bios_cpu_apicid) == NOT_FOUND_SYMBOL)
		return FALSE;
	if (SYMBOL(x86_bios_cpu_apicid) != NOT_FOUND_SYMBOL &&
	    (SYMBOL(x86_bios_cpu_apicid_early_ptr) == NOT_FOUND_SYMBOL ||
	     SYMBOL(x86_bios_cpu_apicid_early_map) == NOT_FOUND_SYMBOL))
		return FALSE;
	if (SYMBOL(crash_notes) == NOT_FOUND_SYMBOL)
		return FALSE;
	if (SIZE(percpu_data) == NOT_FOUND_STRUCTURE &&
	    SYMBOL(__per_cpu_load) == NOT_FOUND_SYMBOL)
		return FALSE;
	if (SYMBOL(__per_cpu_load) != NOT_FOUND_SYMBOL &&
	    (SYMBOL(__per_cpu_offset) == NOT_FOUND_SYMBOL &&
	     ARRAY_LENGTH(__per_cpu_offset) == NOT_FOUND_STRUCTURE))
		return FALSE;
	if (SIZE(elf_prstatus) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(elf_prstatus.pr_reg) == NOT_FOUND_STRUCTURE)
		return FALSE;
#ifdef __x86__
	if (OFFSET(user_regs_struct.bx) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(user_regs_struct.cx) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(user_regs_struct.dx) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(user_regs_struct.si) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(user_regs_struct.di) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(user_regs_struct.bp) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(user_regs_struct.ax) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(user_regs_struct.ds) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(user_regs_struct.es) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(user_regs_struct.fs) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(user_regs_struct.gs) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(user_regs_struct.orig_ax) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(user_regs_struct.ip) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(user_regs_struct.cs) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(user_regs_struct.flags) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(user_regs_struct.sp) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(user_regs_struct.ss) == NOT_FOUND_STRUCTURE)
		return FALSE;
#elif defined(__x86_64__)
	if (OFFSET(user_regs_struct.r15) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(user_regs_struct.r14) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(user_regs_struct.r13) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(user_regs_struct.r12) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(user_regs_struct.bp) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(user_regs_struct.bx) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(user_regs_struct.r11) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(user_regs_struct.r10) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(user_regs_struct.r9) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(user_regs_struct.r8) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(user_regs_struct.ax) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(user_regs_struct.cx) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(user_regs_struct.dx) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(user_regs_struct.si) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(user_regs_struct.di) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(user_regs_struct.orig_ax) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(user_regs_struct.ip) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(user_regs_struct.cs) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(user_regs_struct.flags) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(user_regs_struct.sp) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(user_regs_struct.ss) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(user_regs_struct.fs_base) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(user_regs_struct.gs_base) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(user_regs_struct.ds) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(user_regs_struct.es) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(user_regs_struct.fs) == NOT_FOUND_STRUCTURE)
		return FALSE;
	if (OFFSET(user_regs_struct.gs) == NOT_FOUND_STRUCTURE)
		return FALSE;
#endif /* __x86_64__ */
	return TRUE;
}

static unsigned long long
pfn_to_block(mdf_pfn_t pfn)
{
	unsigned long long block, section, p;

	section = pfn / SADUMP_PF_SECTION_NUM;

	if (section)
		block = si->block_table[section - 1];
	else
		block = 0;

	for (p = section * SADUMP_PF_SECTION_NUM; p < pfn; ++p)
		if (sadump_is_dumpable(info->bitmap_memory, p))
			block++;

	return block;
}

static int
lookup_diskset(unsigned long long whole_offset, int *diskid,
	       unsigned long long *disk_offset)
{
	unsigned long long offset = whole_offset;
	int i;

	for (i = 0; i < si->num_disks; ++i) {
		struct sadump_diskset_info *sdi = &si->diskset_info[i];
		unsigned long long used_device_i, data_offset_i, ram_size;

		used_device_i = sdi->sph_memory->used_device;
		data_offset_i = sdi->data_offset;

		ram_size = used_device_i - data_offset_i;

		if (offset < ram_size)
			break;
		offset -= ram_size;
	}

	if (i == si->num_disks)
		return FALSE;

	*diskid = i;
	*disk_offset = offset;

	return TRUE;
}

static int
per_cpu_init(void)
{
	size_t __per_cpu_offset_size;
	int i;

	if (SIZE(percpu_data) != NOT_FOUND_STRUCTURE)
		return TRUE;

	__per_cpu_offset_size =
		ARRAY_LENGTH(__per_cpu_offset) * sizeof(unsigned long);

	if (!(si->__per_cpu_offset = malloc(__per_cpu_offset_size))) {
		ERRMSG("Can't allocate __per_cpu_offset buffer.\n");
		return FALSE;
	}

	if (!readmem(VADDR, SYMBOL(__per_cpu_offset), si->__per_cpu_offset,
		     __per_cpu_offset_size)) {
		ERRMSG("Can't read __per_cpu_offset memory.\n");
		return FALSE;
	}

	if (SYMBOL(__per_cpu_load) == NOT_FOUND_SYMBOL) {
		ERRMSG("Can't find __per_cpu_load symbol.\n");
		return FALSE;
	}
	si->__per_cpu_load = SYMBOL(__per_cpu_load);

	DEBUG_MSG("sadump: __per_cpu_load: %#lx\n", si->__per_cpu_load);
	DEBUG_MSG("sadump: __per_cpu_offset: LENGTH: %ld\n",
		  ARRAY_LENGTH(__per_cpu_offset));

	for (i = 0; i < ARRAY_LENGTH(__per_cpu_offset); ++i) {
		DEBUG_MSG("sadump: __per_cpu_offset[%d]: %#lx\n", i,
			  si->__per_cpu_offset[i]);
	}

	return TRUE;
}

static int
get_data_from_elf_note_desc(const char *note_buf, uint32_t n_descsz,
			    char *name, uint32_t n_type, char **data)
{
	Elf32_Nhdr *note32;
	char *note_name;

	note32 = (Elf32_Nhdr *)note_buf;
	note_name = (char *)(note32 + 1);

	if (note32->n_type != n_type ||
	    note32->n_namesz != strlen(name) + 1 ||
	    note32->n_descsz != n_descsz ||
	    strncmp(note_name, name, note32->n_namesz))
		return FALSE;

	*data = (char *)note_buf +
		roundup(sizeof(Elf32_Nhdr) + note32->n_namesz, 4);

	return TRUE;
}

static int
alignfile(unsigned long *offset)
{
	char nullbyte = '\0';
	unsigned int len;

	len = roundup(*offset, 4) - *offset;
	if (fwrite(&nullbyte, 1, len, si->file_elf_note) != len) {
		ERRMSG("Can't write elf_note file. %s\n", strerror(errno));
		return FALSE;
	}
	*offset += len;
	return TRUE;
}

static int
write_elf_note_header(char *name, void *data, size_t descsz, uint32_t type,
		      unsigned long *offset, unsigned long *desc_offset)
{
	Elf32_Nhdr nhdr;

	nhdr.n_namesz = strlen(name) + 1;
	nhdr.n_descsz = descsz;
	nhdr.n_type = type;

	if (fwrite(&nhdr, sizeof(nhdr), 1, si->file_elf_note) != 1) {
		ERRMSG("Can't write elf_note file. %s\n", strerror(errno));
		return FALSE;
	}
	*offset += sizeof(nhdr);

	if (fwrite(name, nhdr.n_namesz, 1, si->file_elf_note) != 1) {
		ERRMSG("Can't write elf_note file. %s\n", strerror(errno));
		return FALSE;
	}
	*offset += nhdr.n_namesz;
	if (!alignfile(offset))
		return FALSE;

	if (desc_offset)
		*desc_offset = *offset;

	if (fwrite(data, nhdr.n_descsz, 1, si->file_elf_note) != 1) {
		ERRMSG("Can't write elf_note file. %s\n", strerror(errno));
		return FALSE;
	}
	*offset += nhdr.n_descsz;
	if (!alignfile(offset))
		return FALSE;

	return TRUE;
}

static int
is_online_cpu(int cpu)
{
	unsigned long mask;

	if (cpu < 0 || cpu >= max_mask_cpu())
		return FALSE;

	mask = ULONG(si->cpu_online_mask_buf +
		     (cpu / BITPERWORD) * sizeof(unsigned long));

	return (mask & (1UL << (cpu % BITPERWORD))) ? TRUE : FALSE;
}

static unsigned long
legacy_per_cpu_ptr(unsigned long ptr, int cpu)
{
	unsigned long addr;

	if (!is_online_cpu(cpu))
		return 0UL;

	if (!readmem(VADDR, ~ptr + cpu*sizeof(unsigned long), &addr,
		     sizeof(addr)))
		return 0UL;

	return addr;
}

static unsigned long
per_cpu_ptr(unsigned long ptr, int cpu)
{
	if (!is_online_cpu(cpu))
		return 0UL;

	if (si->__per_cpu_offset[cpu] == si->__per_cpu_load)
		return 0UL;

	return ptr + si->__per_cpu_offset[cpu];
}

static int
get_prstatus_from_crash_notes(int cpu, char *prstatus_buf)
{
	unsigned long crash_notes_vaddr, percpu_addr;
	char note_buf[KEXEC_NOTE_BYTES], zero_buf[KEXEC_NOTE_BYTES];
	char *prstatus_ptr;

	if (!is_online_cpu(cpu))
		return FALSE;

	if (SYMBOL(crash_notes) == NOT_FOUND_SYMBOL)
		return FALSE;

	if (!readmem(VADDR, SYMBOL(crash_notes), &crash_notes_vaddr,
		     sizeof(crash_notes_vaddr)))
		return FALSE;

	if (!crash_notes_vaddr) {
		DEBUG_MSG("sadump: crash_notes %d is NULL\n", cpu);
		return FALSE;
	}

	memset(zero_buf, 0, KEXEC_NOTE_BYTES);

	percpu_addr = SIZE(percpu_data) != NOT_FOUND_STRUCTURE
		? legacy_per_cpu_ptr(crash_notes_vaddr, cpu)
		: per_cpu_ptr(crash_notes_vaddr, cpu);

	if (!readmem(VADDR, percpu_addr, note_buf, KEXEC_NOTE_BYTES))
		return FALSE;

	if (memcmp(note_buf, zero_buf, KEXEC_NOTE_BYTES) == 0)
		return FALSE;

	if (!get_data_from_elf_note_desc(note_buf, SIZE(elf_prstatus), "CORE",
					 NT_PRSTATUS, (void *)&prstatus_ptr))
		return FALSE;

	memcpy(prstatus_buf, prstatus_ptr, SIZE(elf_prstatus));

	return TRUE;
}

static int
cpu_to_apicid(int cpu, int *apicid)
{
	if (SYMBOL(bios_cpu_apicid) != NOT_FOUND_SYMBOL) {
		uint8_t apicid_u8;

		if (!readmem(VADDR, SYMBOL(bios_cpu_apicid)+cpu*sizeof(uint8_t),
			     &apicid_u8, sizeof(uint8_t)))
			return FALSE;

		*apicid = (int)apicid_u8;

		DEBUG_MSG("sadump: apicid %u for cpu %d from "
			  "bios_cpu_apicid\n", apicid_u8, cpu);

	} else if (SYMBOL(x86_bios_cpu_apicid) != NOT_FOUND_SYMBOL) {
		uint16_t apicid_u16;
		unsigned long early_ptr, apicid_addr;

		if (!readmem(VADDR, SYMBOL(x86_bios_cpu_apicid_early_ptr),
			     &early_ptr, sizeof(early_ptr)))
			return FALSE;
		/*
		 * Note: SYMBOL(name) value is adjusted by info->kaslr_offset,
		 * but per_cpu symbol does not need to be adjusted becasue it
		 * is not affected by kaslr.
		 */
		apicid_addr = early_ptr
			? SYMBOL(x86_bios_cpu_apicid_early_map)+cpu*sizeof(uint16_t)
			: per_cpu_ptr(SYMBOL(x86_bios_cpu_apicid) - info->kaslr_offset, cpu);

		if (!readmem(VADDR, apicid_addr, &apicid_u16, sizeof(uint16_t)))
			return FALSE;

		*apicid = (int)apicid_u16;

		DEBUG_MSG("sadump: apicid %u for cpu %d from "
			  "x86_bios_cpu_apicid\n", apicid_u16, cpu);

	} else {

		ERRMSG("sadump: no symbols for access to acpidid\n");

		return FALSE;
	}

	return TRUE;
}

static int
get_smram_cpu_state(int apicid, struct sadump_smram_cpu_state *smram)
{
	unsigned long offset;

	if (!si->sub_hdr_offset || !si->smram_cpu_state_size ||
	    apicid >= si->sh_memory->nr_cpus)
		return FALSE;

	offset = si->sub_hdr_offset + sizeof(uint32_t) +
		si->sh_memory->nr_cpus * sizeof(struct sadump_apic_state);

	if (lseek(info->fd_memory, offset+apicid*si->smram_cpu_state_size,
		  SEEK_SET) < 0)
		DEBUG_MSG("sadump: cannot lseek smram cpu state in dump sub "
			  "header\n");

	if (read(info->fd_memory, smram, si->smram_cpu_state_size) !=
	    si->smram_cpu_state_size)
		DEBUG_MSG("sadump: cannot read smram cpu state in dump sub "
			  "header\n");

	return TRUE;
}

#ifdef __x86__

static int
copy_regs_from_prstatus(struct elf_prstatus *prstatus,
			const char *prstatus_buf)
{
	struct user_regs_struct *r = &prstatus->pr_reg;
	const char *pr_reg_buf = prstatus_buf + OFFSET(elf_prstatus.pr_reg);

	r->bx = ULONG(pr_reg_buf + OFFSET(user_regs_struct.bx));
	r->cx = ULONG(pr_reg_buf + OFFSET(user_regs_struct.cx));
	r->dx = ULONG(pr_reg_buf + OFFSET(user_regs_struct.dx));
	r->si = ULONG(pr_reg_buf + OFFSET(user_regs_struct.si));
	r->di = ULONG(pr_reg_buf + OFFSET(user_regs_struct.di));
	r->bp = ULONG(pr_reg_buf + OFFSET(user_regs_struct.bp));
	r->ax = ULONG(pr_reg_buf + OFFSET(user_regs_struct.ax));
	r->ds = ULONG(pr_reg_buf + OFFSET(user_regs_struct.ds));
	r->es = ULONG(pr_reg_buf + OFFSET(user_regs_struct.es));
	r->fs = ULONG(pr_reg_buf + OFFSET(user_regs_struct.fs));
	r->gs = ULONG(pr_reg_buf + OFFSET(user_regs_struct.gs));
	r->orig_ax = ULONG(pr_reg_buf + OFFSET(user_regs_struct.orig_ax));
	r->ip = ULONG(pr_reg_buf + OFFSET(user_regs_struct.ip));
	r->cs = ULONG(pr_reg_buf + OFFSET(user_regs_struct.cs));
	r->flags = ULONG(pr_reg_buf + OFFSET(user_regs_struct.flags));
	r->sp = ULONG(pr_reg_buf + OFFSET(user_regs_struct.sp));
	r->ss = ULONG(pr_reg_buf + OFFSET(user_regs_struct.ss));

	return TRUE;
}

static int
copy_regs_from_smram_cpu_state(struct elf_prstatus *prstatus,
			       const struct sadump_smram_cpu_state *smram)
{
	struct user_regs_struct *regs = &prstatus->pr_reg;

	regs->bx = smram->RbxLower;
	regs->cx = smram->RcxLower;
	regs->dx = smram->RdxLower;
	regs->si = smram->RsiLower;
	regs->di = smram->RdiLower;
	regs->bp = smram->RbpLower;
	regs->ax = smram->RaxLower;
	regs->ds = smram->Ds & 0xffff;
	regs->es = smram->Es & 0xffff;
	regs->fs = smram->Fs & 0xffff;
	regs->gs = smram->Gs & 0xffff;
	regs->orig_ax = smram->RaxLower;
	regs->ip = (uint32_t)smram->Rip;
	regs->cs = smram->Cs & 0xffff;
	regs->flags = (uint32_t)smram->Rflags;
	regs->sp = smram->RspLower;
	regs->ss = smram->Ss & 0xffff;

	return TRUE;
}

static void
debug_message_user_regs_struct(int cpu, struct elf_prstatus *prstatus)
{
	struct user_regs_struct *r = &prstatus->pr_reg;

	DEBUG_MSG(
		"sadump: CPU: %d\n"
		"    BX: %08lx CX: %08lx DX: %08lx SI: %08lx\n"
		"    DI: %08lx BP: %08lx AX: %08lx ORIG_AX: %08lx\n"
		"    DS: %04lx ES: %04lx FS: %04lx GS: %04lx CS: %04lx SS: %04lx\n"
		"    IP: %08lx FLAGS: %04lx SP: %08lx\n",
		cpu,
		r->bx, r->cx, r->dx, r->si,
		r->di, r->bp, r->ax, r->orig_ax,
		r->ds, r->es, r->fs, r->gs, r->cs, r->ss,
		r->ip, r->flags, r->sp);
}

#elif defined(__x86_64__)

static int
copy_regs_from_prstatus(struct elf_prstatus *prstatus,
			const char *prstatus_buf)
{
	struct user_regs_struct *r = &prstatus->pr_reg;
	const char *pr_reg_buf = prstatus_buf + OFFSET(elf_prstatus.pr_reg);

	r->r15 = ULONG(pr_reg_buf + OFFSET(user_regs_struct.r15));
	r->r14 = ULONG(pr_reg_buf + OFFSET(user_regs_struct.r14));
	r->r13 = ULONG(pr_reg_buf + OFFSET(user_regs_struct.r13));
	r->bp = ULONG(pr_reg_buf + OFFSET(user_regs_struct.bp));
	r->bx = ULONG(pr_reg_buf + OFFSET(user_regs_struct.bx));
	r->r11 = ULONG(pr_reg_buf + OFFSET(user_regs_struct.r11));
	r->r10 = ULONG(pr_reg_buf + OFFSET(user_regs_struct.r10));
	r->r9 = ULONG(pr_reg_buf + OFFSET(user_regs_struct.r9));
	r->r8 = ULONG(pr_reg_buf + OFFSET(user_regs_struct.r8));
	r->ax = ULONG(pr_reg_buf + OFFSET(user_regs_struct.ax));
	r->cx = ULONG(pr_reg_buf + OFFSET(user_regs_struct.cx));
	r->dx = ULONG(pr_reg_buf + OFFSET(user_regs_struct.dx));
	r->si = ULONG(pr_reg_buf + OFFSET(user_regs_struct.si));
	r->di = ULONG(pr_reg_buf + OFFSET(user_regs_struct.di));
	r->orig_ax = ULONG(pr_reg_buf + OFFSET(user_regs_struct.orig_ax));
	r->ip = ULONG(pr_reg_buf + OFFSET(user_regs_struct.ip));
	r->cs = ULONG(pr_reg_buf + OFFSET(user_regs_struct.cs));
	r->flags = ULONG(pr_reg_buf + OFFSET(user_regs_struct.flags));
	r->sp = ULONG(pr_reg_buf + OFFSET(user_regs_struct.sp));
	r->ss = ULONG(pr_reg_buf + OFFSET(user_regs_struct.ss));
	r->fs_base = ULONG(pr_reg_buf + OFFSET(user_regs_struct.fs_base));
	r->gs_base = ULONG(pr_reg_buf + OFFSET(user_regs_struct.gs_base));
	r->ds = ULONG(pr_reg_buf + OFFSET(user_regs_struct.ds));
	r->es = ULONG(pr_reg_buf + OFFSET(user_regs_struct.es));
	r->fs = ULONG(pr_reg_buf + OFFSET(user_regs_struct.fs));
	r->gs = ULONG(pr_reg_buf + OFFSET(user_regs_struct.gs));

	return TRUE;
}

static int
copy_regs_from_smram_cpu_state(struct elf_prstatus *prstatus,
			       const struct sadump_smram_cpu_state *smram)
{
	struct user_regs_struct *regs = &prstatus->pr_reg;

	regs->r15 = ((uint64_t)smram->R15Upper<<32)+smram->R15Lower;
	regs->r14 = ((uint64_t)smram->R14Upper<<32)+smram->R14Lower;
	regs->r13 = ((uint64_t)smram->R13Upper<<32)+smram->R13Lower;
	regs->r12 = ((uint64_t)smram->R12Upper<<32)+smram->R12Lower;
	regs->bp = ((uint64_t)smram->RbpUpper<<32)+smram->RbpLower;
	regs->bx = ((uint64_t)smram->RbxUpper<<32)+smram->RbxLower;
	regs->r11 = ((uint64_t)smram->R11Upper<<32)+smram->R11Lower;
	regs->r10 = ((uint64_t)smram->R10Upper<<32)+smram->R10Lower;
	regs->r9 = ((uint64_t)smram->R9Upper<<32)+smram->R9Lower;
	regs->r8 = ((uint64_t)smram->R8Upper<<32)+smram->R8Lower;
	regs->ax = ((uint64_t)smram->RaxUpper<<32)+smram->RaxLower;
	regs->cx = ((uint64_t)smram->RcxUpper<<32)+smram->RcxLower;
	regs->dx = ((uint64_t)smram->RdxUpper<<32)+smram->RdxLower;
	regs->si = ((uint64_t)smram->RsiUpper<<32)+smram->RsiLower;
	regs->di = ((uint64_t)smram->RdiUpper<<32)+smram->RdiLower;
	regs->orig_ax = ((uint64_t)smram->RaxUpper<<32)+smram->RaxLower;
	regs->ip = smram->Rip;
	regs->cs = smram->Cs;
	regs->flags = smram->Rflags;
	regs->sp = ((uint64_t)smram->RspUpper<<32)+smram->RspLower;
	regs->ss = smram->Ss;
	regs->fs_base = 0;
	regs->gs_base = 0;
	regs->ds = smram->Ds;
	regs->es = smram->Es;
	regs->fs = smram->Fs;
	regs->gs = smram->Gs;

	return TRUE;
}

static void
debug_message_user_regs_struct(int cpu, struct elf_prstatus *prstatus)
{
	struct user_regs_struct *r = &prstatus->pr_reg;

	DEBUG_MSG(
		"sadump: CPU: %d\n"
		"    R15: %016llx R14: %016llx R13: %016llx\n"
		"    R12: %016llx RBP: %016llx RBX: %016llx\n"
		"    R11: %016llx R10: %016llx R9: %016llx\n"
		"    R8: %016llx RAX: %016llx RCX: %016llx\n"
		"    RDX: %016llx RSI: %016llx RDI: %016llx\n"
		"    ORIG_RAX: %016llx RIP: %016llx\n"
		"    CS: %04lx FLAGS: %08llx RSP: %016llx\n"
		"    SS: %04lx FS_BASE: %04lx GS_BASE: %04lx\n"
		"    DS: %04lx ES: %04lx FS: %04lx GS: %04lx\n",
		cpu,
		(unsigned long long)r->r15, (unsigned long long)r->r14,
		(unsigned long long)r->r13, (unsigned long long)r->r12,
		(unsigned long long)r->bp, (unsigned long long)r->bx,
		(unsigned long long)r->r11, (unsigned long long)r->r10,
		(unsigned long long)r->r9, (unsigned long long)r->r8,
		(unsigned long long)r->ax, (unsigned long long)r->cx,
		(unsigned long long)r->dx, (unsigned long long)r->si,
		(unsigned long long)r->di,
		(unsigned long long)r->orig_ax,
		(unsigned long long)r->ip, r->cs,
		(unsigned long long)r->flags, (unsigned long long)r->sp,
		r->ss, r->fs_base, r->gs_base, r->ds, r->es, r->fs,
		r->gs);
}

#endif /* __x86_64__ */

static void
debug_message_smram_cpu_state(int apicid, struct sadump_smram_cpu_state *s)
{
	DEBUG_MSG(
		"sadump: APIC ID: %d\n"
		"    RIP: %016llx RSP: %08x%08x RBP: %08x%08x\n"
		"    RAX: %08x%08x RBX: %08x%08x RCX: %08x%08x\n"
		"    RDX: %08x%08x RSI: %08x%08x RDI: %08x%08x\n"
		"    R08: %08x%08x R09: %08x%08x R10: %08x%08x\n"
		"    R11: %08x%08x R12: %08x%08x R13: %08x%08x\n"
		"    R14: %08x%08x R15: %08x%08x\n"
		"    SMM REV: %08x SMM BASE %08x\n"
		"    CS : %08x DS: %08x SS: %08x ES: %08x FS: %08x\n"
		"    GS : %08x\n"
		"    CR0: %016llx CR3: %016llx CR4: %08x\n"
		"    GDT: %08x%08x LDT: %08x%08x IDT: %08x%08x\n"
		"    GDTlim: %08x LDTlim: %08x IDTlim: %08x\n"
		"    LDTR: %08x TR: %08x RFLAGS: %016llx\n"
		"    EPTP: %016llx EPTP_SETTING: %08x\n"
		"    DR6: %016llx DR7: %016llx\n"
		"    Ia32Efer: %016llx\n"
		"    IoMemAddr: %08x%08x IoEip: %016llx\n"
		"    IoMisc: %08x LdtInfo: %08x\n"
		"    IoInstructionRestart: %04x AutoHaltRestart: %04x\n",
		apicid,
		(unsigned long long)s->Rip, s->RspUpper, s->RspLower, s->RbpUpper, s->RbpLower,
		s->RaxUpper, s->RaxLower, s->RbxUpper, s->RbxLower, s->RcxUpper, s->RcxLower,
		s->RdxUpper, s->RdxLower, s->RsiUpper, s->RsiLower, s->RdiUpper, s->RdiLower,
		s->R8Upper, s->R8Lower, s->R9Upper, s->R9Lower, s->R10Upper, s->R10Lower,
		s->R11Upper, s->R11Lower, s->R12Upper, s->R12Lower, s->R13Upper, s->R13Lower,
		s->R14Upper, s->R14Lower, s->R15Upper, s->R15Lower,
		s->SmmRevisionId, s->Smbase,
		s->Cs, s->Ds, s->Ss, s->Es, s->Fs, s->Gs,
		(unsigned long long)s->Cr0, (unsigned long long)s->Cr3, s->Cr4,
		s->GdtUpper, s->GdtLower, s->LdtUpper, s->LdtLower, s->IdtUpper, s->IdtLower,
		s->GdtLimit, s->LdtLimit, s->IdtLimit,
		s->Ldtr, s->Tr, (unsigned long long)s->Rflags,
		(unsigned long long)s->Eptp, s->EptpSetting,
		(unsigned long long)s->Dr6, (unsigned long long)s->Dr7,
		(unsigned long long)s->Ia32Efer,
		s->IoMemAddrUpper, s->IoMemAddrLower, (unsigned long long)s->IoEip,
		s->IoMisc, s->LdtInfo,
		s->IoInstructionRestart,
		s->AutoHaltRestart);
}

static int
get_registers(int cpu, struct elf_prstatus *prstatus)
{
	struct sadump_smram_cpu_state smram;
	char *prstatus_buf = NULL;
	int retval = FALSE, apicid = 0;

	if (!(prstatus_buf = malloc(SIZE(elf_prstatus)))) {
		ERRMSG("Can't allocate elf_prstatus buffer. %s\n",
		       strerror(errno));
		goto error;
	}

	if (get_prstatus_from_crash_notes(cpu, prstatus_buf)) {

		if (!copy_regs_from_prstatus(prstatus, prstatus_buf))
			goto cleanup;

		DEBUG_MSG("sadump: cpu #%d registers from crash_notes\n", cpu);

		debug_message_user_regs_struct(cpu, prstatus);

	} else {

		if (!cpu_to_apicid(cpu, &apicid))
			goto cleanup;

		if (!get_smram_cpu_state(apicid, &smram))
			goto cleanup;

		copy_regs_from_smram_cpu_state(prstatus, &smram);

		DEBUG_MSG("sadump: cpu #%d registers from SMRAM\n", cpu);

		debug_message_smram_cpu_state(apicid, &smram);
		debug_message_user_regs_struct(cpu, prstatus);

	}

	retval = TRUE;
cleanup:
	free(prstatus_buf);
error:
	return retval;
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
	si->diskset_info[si->num_disks - 1].fd_memory = -1;

	return TRUE;
}

int
sadump_read_elf_note(char *buf, size_t size_note)
{
	if (!si->file_elf_note)
		return FALSE;

	rewind(si->file_elf_note);

	if (fread(buf, size_note, 1, si->file_elf_note) != 1) {
		ERRMSG("Can't read elf note file. %s\n",
		       strerror(errno));
		return FALSE;
	}

	return TRUE;
}

long
sadump_page_size(void)
{
	return si->sh_memory->block_size;
}

char *
sadump_head_disk_name_memory(void)
{
	return si->diskset_info[0].name_memory;
}

char *
sadump_format_type_name(void)
{
	switch (info->flag_sadump) {
	case SADUMP_SINGLE_PARTITION:
		return "single partition";
	case SADUMP_DISKSET:
		return "diskset";
	case SADUMP_MEDIA_BACKUP:
		return "media backup";
	case SADUMP_UNKNOWN:
		return "unknown";
	}
	return "";
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
			if (si->diskset_info[i].fd_memory >= 0)
				close(si->diskset_info[i].fd_memory);
			if (si->diskset_info[i].sph_memory)
				free(si->diskset_info[i].sph_memory);
		}
		free(si->diskset_info);
	}
	if (si->__per_cpu_offset)
		free(si->__per_cpu_offset);
	if (si->block_table)
		free(si->block_table);
	if (si->file_elf_note)
		fclose(si->file_elf_note);
	if (si->cpu_online_mask_buf)
		free(si->cpu_online_mask_buf);
	if (si->ram_bitmap) {
		if (si->ram_bitmap->buf)
			free(si->ram_bitmap->buf);
		free(si->ram_bitmap);
	}
}

void
sadump_kdump_backup_region_init(void)
{
	unsigned char buf[BUFSIZE];
	unsigned long i, total, kexec_crash_image_p, elfcorehdr_p;
	Elf64_Off e_phoff;
	uint16_t e_phnum, e_phentsize;
	unsigned long long backup_offset;
	unsigned long backup_src_start, backup_src_size;
	size_t bufsize;
	
	if (!readmem(VADDR, SYMBOL(kexec_crash_image), &kexec_crash_image_p,
		     sizeof(unsigned long))) {
		ERRMSG("Can't read kexec_crash_image pointer. %s\n",
		       strerror(errno));
		return;
	}

	if (!kexec_crash_image_p) {
		DEBUG_MSG("sadump: kexec crash image was not loaded\n");
		return;
	}

	if (!readmem(VADDR, kexec_crash_image_p+OFFSET(kimage.segment),
		     buf, SIZE(kexec_segment)*ARRAY_LENGTH(kimage.segment))) {
		ERRMSG("Can't read kexec_crash_image->segment. %s\n",
		       strerror(errno));
		return;
	}

	elfcorehdr_p = 0;
	for (i = 0; i < ARRAY_LENGTH(kimage.segment); ++i) {
		char e_ident[EI_NIDENT];
		unsigned long mem;

		mem=ULONG(buf+i*SIZE(kexec_segment)+OFFSET(kexec_segment.mem));
		if (!mem)
			continue;

		if (!readmem(PADDR, mem, e_ident, SELFMAG)) {
			DEBUG_MSG("sadump: failed to read elfcorehdr buffer\n");
			return;
		}

		if (strncmp(ELFMAG, e_ident, SELFMAG) == 0) {
			elfcorehdr_p = mem;
			break;
		}
	}
	if (!elfcorehdr_p) {
		DEBUG_MSG("sadump: kexec_crash_image contains no elfcorehdr "
			  "segment\n");
		return;
	}

	if (!readmem(PADDR, elfcorehdr_p, buf, SIZE(elf64_hdr))) {
		ERRMSG("Can't read elfcorehdr ELF header. %s\n",
		       strerror(errno));
		return;
	}

	e_phnum = USHORT(buf + OFFSET(elf64_hdr.e_phnum));
	e_phentsize = USHORT(buf + OFFSET(elf64_hdr.e_phentsize));
	e_phoff = ULONG(buf + OFFSET(elf64_hdr.e_phoff));

	backup_src_start = backup_src_size = backup_offset = 0;
	for (i = 0; i < e_phnum; ++i) {
		unsigned long p_type, p_offset, p_paddr, p_memsz;

		if (!readmem(PADDR, elfcorehdr_p+e_phoff+i*e_phentsize, buf,
			     e_phentsize)) {
			ERRMSG("Can't read elfcorehdr program header. %s\n",
			       strerror(errno));
			return;
		}

		p_type = UINT(buf + OFFSET(elf64_phdr.p_type));
		p_offset = ULONG(buf + OFFSET(elf64_phdr.p_offset));
		p_paddr = ULONG(buf + OFFSET(elf64_phdr.p_paddr));
		p_memsz = ULONG(buf + OFFSET(elf64_phdr.p_memsz));

		if (p_type == PT_LOAD &&
		    p_paddr <= KEXEC_BACKUP_SRC_END &&
		    p_paddr + p_memsz <= p_offset) {

			backup_src_start = p_paddr;
			backup_src_size = p_memsz;
			backup_offset = p_offset;

DEBUG_MSG("sadump: SRC_START: %#016lx SRC_SIZE: %#016lx SRC_OFFSET: %#016llx\n",
	  backup_src_start, backup_src_size, backup_offset);

			break;
		}
	}
	if (i == e_phnum) {
DEBUG_MSG("sadump: No PT_LOAD in elfcorehdr for backup area\n");
		return;
	}

	bufsize = BUFSIZE;
	for (total = 0; total < backup_src_size; total += bufsize) {

		if (backup_src_size - total < BUFSIZE)
			bufsize = backup_src_size - total;

		if (!readmem(PADDR, backup_offset + total, buf, bufsize)) {
			ERRMSG("Can't read backup region. %s\n",
			       strerror(errno));
			return;
		}

		/*
		 * We're assuming that the backup region is full of 0
		 * before kdump saves the first 640kB memory of the
		 * 1st kernel in the region.
		 */
		if (!is_zero_page(buf, bufsize)) {

			si->kdump_backed_up = TRUE;
			si->backup_src_start = backup_src_start;
			si->backup_src_size = backup_src_size;
			si->backup_offset = backup_offset;

			DEBUG_MSG("sadump: kdump backup region used\n");

			return;
		}
	}

	DEBUG_MSG("sadump: kdump backup region unused\n");
}

#endif /* defined(__x86__) || defined(__x86_64__) */
