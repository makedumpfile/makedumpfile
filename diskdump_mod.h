/*
 * diskdump.h
 *
 * Copyright (C) 2004, 2005 David Anderson
 * Copyright (C) 2004, 2005 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2005  FUJITSU LIMITED
 * Copyright (C) 2005  NEC Corporation
 *
 * This software may be freely redistributed under the terms of the
 * GNU General Public License.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <elf.h>

#define divideup(x, y)	(((x) + ((y) - 1)) / (y))
#define round(x, y)	(((x) / (y)) * (y))
#define roundup(x, y)	((((x) + ((y) - 1)) / (y)) * (y))

#define DUMP_PARTITION_SIGNATURE	"diskdump"
#define DISK_DUMP_SIGNATURE		"DISKDUMP"
#define KDUMP_SIGNATURE			"KDUMP   "
#define SIG_LEN (sizeof(DUMP_PARTITION_SIGNATURE) - 1)
#define DISKDUMP_HDADER_BLOCKS		(1)
#define KDUMP_SUB_HEADER_BLOCKS		(1)

#define DUMP_HEADER_COMPLETED	0
#define DUMP_HEADER_INCOMPLETED 1
#define DUMP_HEADER_COMPRESSED  8

struct new_utsname {
        char sysname[65];
        char nodename[65];
        char release[65];
        char version[65];
        char machine[65];
        char domainname[65];
};

struct disk_dump_header {
	char			signature[SIG_LEN];	/* = "KDUMP   " */
	int			header_version; /* Dump header version */
	struct new_utsname	utsname;	/* copy of system_utsname */
	struct timeval		timestamp;	/* Time stamp */
	unsigned int		status; 	/* Above flags */
	int			block_size;	/* Size of a block in byte */
	int			sub_hdr_size;	/* Size of arch dependent
						   header in blocks */
	unsigned int		bitmap_blocks;	/* Size of Memory bitmap in
						   block */
	unsigned int		max_mapnr;	/* = max_mapnr */
	unsigned int		total_ram_blocks;/* Number of blocks should be
						   written */
	unsigned int		device_blocks;	/* Number of total blocks in
						 * the dump device */
	unsigned int		written_blocks; /* Number of written blocks */
	unsigned int		current_cpu;	/* CPU# which handles dump */
	int			nr_cpus;	/* Number of CPUs */
	struct task_struct	*tasks[0];
};

/*
 * Sub header for KDUMP
 * But Common header of KDUMP is disk_dump_header of diskdump.
 */
struct kdump_sub_header {
	unsigned long	phys_base;
	int		dump_level;	/* header_version 1 and later */
	int		split;		/* header_version 2 and later */
	unsigned long	start_pfn;	/* header_version 2 and later */
	unsigned long	end_pfn;	/* header_version 2 and later */
};

/* page flags */
#define DUMP_DH_COMPRESSED	0x1	/* page is compressed               */

/* descriptor of each page for vmcore */
typedef struct page_desc {
	off_t			offset;		/* the offset of the page data*/
	unsigned int		size;		/* the size of this dump page */
	unsigned int		flags;		/* flags */
	unsigned long long	page_flags;	/* page flags */
} page_desc_t;

#define DISKDUMP_CACHED_PAGES	(16)
#define PAGE_VALID		(0x1)	/* flags */
#define DISKDUMP_VALID_PAGE(flags)	((flags) & PAGE_VALID)

