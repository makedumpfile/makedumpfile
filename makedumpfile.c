/*
 * makedumpfile.c
 *
 * Copyright (C) 2006, 2007, 2008, 2009  NEC Corporation
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

struct symbol_table	symbol_table;
struct size_table	size_table;
struct offset_table	offset_table;
struct array_table	array_table;
struct number_table	number_table;
struct srcfile_table	srcfile_table;

struct dwarf_info	dwarf_info;
struct vm_table		vt = { 0 };
struct DumpInfo		*info = NULL;

char filename_stdout[] = FILENAME_STDOUT;
int message_level;

/*
 * Forward declarations
 */
void print_progress(const char 		*msg,
		    unsigned long 	current,
		    unsigned long 	end);

/*
 * Message texts
 */
#define PROGRESS_COPY   	"Copying data"
#define PROGRESS_HOLES		"Checking for memory holes"
#define PROGRESS_UNN_PAGES 	"Excluding unnecessary pages"
#define PROGRESS_FREE_PAGES 	"Excluding free pages"
#define PROGRESS_ZERO_PAGES 	"Excluding zero pages"
#define PROGRESS_XEN_DOMAIN 	"Excluding xen user domain"
#define PROGRESS_MAXLEN		"35"

/*
 * The numbers of the excluded pages
 */
unsigned long long pfn_zero;
unsigned long long pfn_memhole;
unsigned long long pfn_cache;
unsigned long long pfn_cache_private;
unsigned long long pfn_user;
unsigned long long pfn_free;

int retcd = FAILED;	/* return code */

void
show_version(void)
{
	MSG("makedumpfile: version " VERSION " (released on " RELEASE_DATE ")\n");
	MSG("\n");
}

#define INITIALIZE_LONG_TABLE(table, value) \
do { \
	size_member = sizeof(long); \
	num_member  = sizeof(table) / size_member; \
	ptr_long_table = (long *)&table; \
	for (i = 0; i < num_member; i++, ptr_long_table++) \
		*ptr_long_table = value; \
} while (0)

void
initialize_tables(void)
{
	int i, size_member, num_member;
	unsigned long long *ptr_symtable;
	long *ptr_long_table;

	/*
	 * Initialize the symbol table.
	 */
	size_member = sizeof(symbol_table.mem_map);
	num_member  = sizeof(symbol_table) / size_member;

	ptr_symtable = (unsigned long long *)&symbol_table;

	for (i = 0; i < num_member; i++, ptr_symtable++)
		*ptr_symtable = NOT_FOUND_SYMBOL;

	INITIALIZE_LONG_TABLE(size_table, NOT_FOUND_STRUCTURE);
	INITIALIZE_LONG_TABLE(offset_table, NOT_FOUND_STRUCTURE);
	INITIALIZE_LONG_TABLE(array_table, NOT_FOUND_STRUCTURE);
	INITIALIZE_LONG_TABLE(number_table, NOT_FOUND_NUMBER);
}

/*
 * Convert Physical Address to File Offset.
 *  If this function returns 0x0, File Offset isn't found.
 *  The File Offset 0x0 is in the ELF header.
 *  It is not in the memory image.
 */
off_t
paddr_to_offset(unsigned long long paddr)
{
	int i;
	off_t offset;
	struct pt_load_segment *pls;

	for (i = offset = 0; i < info->num_load_memory; i++) {
		pls = &info->pt_load_segments[i];
		if ((paddr >= pls->phys_start)
		    && (paddr < pls->phys_end)) {
			offset = (off_t)(paddr - pls->phys_start) +
				pls->file_offset;
				break;
		}
	}
	return offset;
}

unsigned long long
vaddr_to_paddr_general(unsigned long long vaddr)
{
	int i;
	unsigned long long paddr = NOT_PADDR;
	struct pt_load_segment *pls;

	for (i = 0; i < info->num_load_memory; i++) {
		pls = &info->pt_load_segments[i];
		if ((vaddr >= pls->virt_start)
		    && (vaddr < pls->virt_end)) {
			paddr = (off_t)(vaddr - pls->virt_start) +
				pls->phys_start;
				break;
		}
	}
	return paddr;
}

/*
 * This function is slow because it doesn't use the memory.
 * It is useful at few calls like get_str_osrelease_from_vmlinux().
 */
off_t
vaddr_to_offset_slow(int fd, char *filename, unsigned long long vaddr)
{
	off_t offset = 0;
	int i, phnum, num_load, flag_elf64, elf_format;
	Elf64_Phdr load64;
	Elf32_Phdr load32;

	elf_format = check_elf_format(fd, filename, &phnum, &num_load);

	if (elf_format == ELF64)
		flag_elf64 = TRUE;
	else if (elf_format == ELF32)
		flag_elf64 = FALSE;
	else
		return 0;

	for (i = 0; i < phnum; i++) {
		if (flag_elf64) { /* ELF64 */
			if (!get_elf64_phdr(fd, filename, i, &load64)) {
				ERRMSG("Can't find Phdr %d.\n", i);
				return 0;
			}
			if (load64.p_type != PT_LOAD)
				continue;

			if ((vaddr < load64.p_vaddr)
			    || (load64.p_vaddr + load64.p_filesz <= vaddr))
				continue;

			offset = load64.p_offset + (vaddr - load64.p_vaddr);
			break;
		} else {         /* ELF32 */
			if (!get_elf32_phdr(fd, filename, i, &load32)) {
				ERRMSG("Can't find Phdr %d.\n", i);
				return 0;
			}
			if (load32.p_type != PT_LOAD)
				continue;

			if ((vaddr < load32.p_vaddr)
			    || (load32.p_vaddr + load32.p_filesz <= vaddr))
				continue;

			offset = load32.p_offset + (vaddr - load32.p_vaddr);
			break;
		}
	}

	return offset;
}

/*
 * Get the number of the page descriptors from the ELF info.
 */
int
get_max_mapnr(void)
{
	int i;
	unsigned long long max_paddr;
	struct pt_load_segment *pls;

	for (i = 0, max_paddr = 0; i < info->num_load_memory; i++) {
		pls = &info->pt_load_segments[i];
		if (max_paddr < pls->phys_end)
			max_paddr = pls->phys_end;
	}
	info->max_mapnr = max_paddr / info->page_size;

	DEBUG_MSG("\n");
	DEBUG_MSG("max_mapnr    : %llx\n", info->max_mapnr);

	return TRUE;
}

int
is_in_same_page(unsigned long vaddr1, unsigned long vaddr2)
{
	if (round(vaddr1, info->page_size) == round(vaddr2, info->page_size))
		return TRUE;

	return FALSE;
}

int
readmem(int type_addr, unsigned long long addr, void *bufptr, size_t size)
{
	size_t read_size, next_size;
	off_t offset = 0;
	unsigned long long next_addr;
	unsigned long long paddr;
	char *next_ptr;
	const off_t failed = (off_t)-1;

	switch (type_addr) {
	case VADDR:
		if ((paddr = vaddr_to_paddr(addr)) == NOT_PADDR) {
			ERRMSG("Can't convert a virtual address(%llx) to physical address.\n",
			    addr);
			goto error;
		}
		break;
	case PADDR:
		paddr = addr;
		break;
	case VADDR_XEN:
		if ((paddr = kvtop_xen(addr)) == NOT_PADDR) {
			ERRMSG("Can't convert a virtual address(%llx) to machine address.\n",
			    addr);
			goto error;
		}
		break;
	case MADDR_XEN:
		paddr = addr;
  		break;
	default:
		ERRMSG("Invalid address type (%d).\n", type_addr);
		goto error;
	}

	read_size = size;

	/*
	 * Read each page, because pages are not necessarily continuous.
	 * Ex) pages in vmalloc area
	 */
	if (!is_in_same_page(addr, addr + size - 1)) {
		read_size = info->page_size - (addr % info->page_size);
		next_addr = roundup(addr + 1, info->page_size);
		next_size = size - read_size;
		next_ptr  = (char *)bufptr + read_size;

		if (!readmem(type_addr, next_addr, next_ptr, next_size))
			goto error;
	}

	if (!(offset = paddr_to_offset(paddr))) {
		ERRMSG("Can't convert a physical address(%llx) to offset.\n",
		    paddr);
		goto error;
	}

	if (lseek(info->fd_memory, offset, SEEK_SET) == failed) {
		ERRMSG("Can't seek the dump memory(%s). %s\n",
		    info->name_memory, strerror(errno));
		goto error;
	}

	if (read(info->fd_memory, bufptr, read_size) != read_size) {
		ERRMSG("Can't read the dump memory(%s). %s\n",
		    info->name_memory, strerror(errno));
		goto error;
	}

	return size;
error:
	ERRMSG("type_addr: %d, addr:%llx, size:%zd\n", type_addr, addr, size);
	return FALSE;
}

int32_t
get_kernel_version(char *release)
{
	int32_t version;
	long maj, min, rel;
	char *start, *end;

	/*
	 * This method checks that vmlinux and vmcore are same kernel version.
	 */
	start = release;
	maj = strtol(start, &end, 10);
	if (maj == LONG_MAX)
		return FALSE;

	start = end + 1;
	min = strtol(start, &end, 10);
	if (min == LONG_MAX)
		return FALSE;

	start = end + 1;
	rel = strtol(start, &end, 10);
	if (rel == LONG_MAX)
  		return FALSE;

	version = KERNEL_VERSION(maj, min, rel);

	if ((version < OLDEST_VERSION) || (LATEST_VERSION < version)) {
		MSG("The kernel version is not supported.\n");
		MSG("The created dumpfile may be incomplete.\n");
	}
	return version;
}

int
is_page_size(long page_size)
{
	/*
	 * Page size is restricted to a hamming weight of 1.
	 */
	if (page_size > 0 && !(page_size & (page_size - 1)))
		return TRUE;

	return FALSE;
}

int
set_page_size(long page_size)
{
	if (!is_page_size(page_size)) {
		ERRMSG("Invalid page_size: %ld", page_size);
		return FALSE;
	}
	info->page_size = page_size;
	info->page_shift = ffs(info->page_size) - 1;
	DEBUG_MSG("page_size    : %ld\n", info->page_size);

	return TRUE;
}

int
fallback_to_current_page_size(void)
{

	if (!set_page_size(sysconf(_SC_PAGE_SIZE)))
		return FALSE;

	DEBUG_MSG("WARNING: Cannot determine page size (no vmcoreinfo).\n");
	DEBUG_MSG("Using the dump kernel page size: %ld\n",
	    info->page_size);

	return TRUE;
}

int
check_release(void)
{
	struct utsname system_utsname;
	unsigned long utsname;

	/*
	 * Get the kernel version.
	 */
	if (SYMBOL(system_utsname) != NOT_FOUND_SYMBOL) {
		utsname = SYMBOL(system_utsname);
	} else if (SYMBOL(init_uts_ns) != NOT_FOUND_SYMBOL) {
		utsname = SYMBOL(init_uts_ns) + sizeof(int);
	} else {
		ERRMSG("Can't get the symbol of system_utsname.\n");
		return FALSE;
	}
	if (!readmem(VADDR, utsname, &system_utsname, sizeof(struct utsname))){
		ERRMSG("Can't get the address of system_utsname.\n");
		return FALSE;
	}

	if (info->flag_read_vmcoreinfo) {
		if (strcmp(system_utsname.release, info->release)) {
			ERRMSG("%s and %s don't match.\n",
			    info->name_vmcoreinfo, info->name_memory);
			retcd = WRONG_RELEASE;
			return FALSE;
		}
	}

	info->kernel_version = get_kernel_version(system_utsname.release);
	if (info->kernel_version == FALSE) {
		if (!info->flag_read_vmcoreinfo)
			ERRMSG("Or %s and %s don't match.\n",
			    info->name_vmlinux, info->name_memory);
		return FALSE;
	}

	return TRUE;
}

void
print_usage(void)
{
	MSG("\n");
	MSG("Usage:\n");
	MSG("  Creating DUMPFILE:\n");
	MSG("  # makedumpfile    [-c|-E] [-d DL] [-x VMLINUX|-i VMCOREINFO] VMCORE DUMPFILE\n");
	MSG("\n");
	MSG("  Outputting the dump data in the flattened format to the standard output:\n");
	MSG("  # makedumpfile -F [-c|-E] [-d DL] [-x VMLINUX|-i VMCOREINFO] VMCORE\n");
	MSG("\n");
	MSG("  Rearranging the dump data in the flattened format to a readable DUMPFILE:\n");
	MSG("  # makedumpfile -R DUMPFILE\n");
	MSG("\n");
	MSG("  Generating VMCOREINFO:\n");
	MSG("  # makedumpfile -g VMCOREINFO -x VMLINUX\n");
	MSG("\n");
	MSG("\n");
	MSG("  Creating DUMPFILE of Xen:\n");
	MSG("  # makedumpfile -E [--xen-syms XEN-SYMS|--xen-vmcoreinfo VMCOREINFO] VMCORE DUMPFILE\n");
	MSG("\n");
	MSG("  Generating VMCOREINFO of Xen:\n");
	MSG("  # makedumpfile -g VMCOREINFO --xen-syms XEN-SYMS\n");
	MSG("\n");
	MSG("\n");
	MSG("Available options:\n");
	MSG("  [-c]:\n");
	MSG("      Compress dump data by each page.\n");
	MSG("      A user cannot specify this option with -E option, because the ELF format\n");
	MSG("      does not support compressed data.\n");
	MSG("      THIS IS ONLY FOR THE CRASH UTILITY.\n");
	MSG("\n");
	MSG("  [-d DL]:\n");
	MSG("      Specify the type of unnecessary page for analysis.\n");
	MSG("      Pages of the specified type are not copied to DUMPFILE. The page type\n");
	MSG("      marked in the following table is excluded. A user can specify multiple\n");
	MSG("      page types by setting the sum of each page type for Dump_Level (DL).\n");
	MSG("      The maximum of Dump_Level is 31.\n");
	MSG("      Note that Dump_Level for Xen dump filtering is 0 or 1.\n");
	MSG("\n");
	MSG("      Dump  |  zero   cache   cache    user    free\n");
	MSG("      Level |  page   page    private  data    page\n");
	MSG("     -------+---------------------------------------\n");
	MSG("         0  |\n");
	MSG("         1  |  X\n");
	MSG("         2  |         X\n");
	MSG("         4  |         X       X\n");
	MSG("         8  |                          X\n");
	MSG("        16  |                                  X\n");
	MSG("        31  |  X      X       X        X       X\n");
	MSG("\n");
	MSG("  [-E]:\n");
	MSG("      Create DUMPFILE in the ELF format.\n");
	MSG("      This option cannot be specified with -c option, because the ELF\n");
	MSG("      format does not support compressed data.\n");
	MSG("\n");
	MSG("  [-x VMLINUX]:\n");
	MSG("      Specify the first kernel's VMLINUX to analyze the first kernel's\n");
	MSG("      memory usage.\n");
	MSG("      The page size of the first kernel and the second kernel should match.\n");
	MSG("\n");
	MSG("  [-i VMCOREINFO]:\n");
	MSG("      Specify VMCOREINFO instead of VMLINUX for analyzing the first kernel's\n");
	MSG("      memory usage.\n");
	MSG("      VMCOREINFO should be made beforehand by makedumpfile with -g option,\n");
	MSG("      and it contains the first kernel's information. If Dump_Level is 2 or\n");
	MSG("      more and [-x VMLINUX] is not specified, this option is necessary.\n");
	MSG("\n");
	MSG("  [-g VMCOREINFO]:\n");
	MSG("      Generate VMCOREINFO from the first kernel's VMLINUX.\n");
	MSG("      VMCOREINFO must be generated on the system that is running the first\n");
	MSG("      kernel. With -i option, a user can specify VMCOREINFO generated on the\n");
	MSG("      other system that is running the same first kernel. [-x VMLINUX] must\n");
	MSG("      be specified.\n");
	MSG("\n");
	MSG("  [-F]:\n");
	MSG("      Output the dump data in the flattened format to the standard output\n");
	MSG("      for transporting the dump data by SSH.\n");
	MSG("      Analysis tools cannot read the flattened format directly. For analysis,\n");
	MSG("      the dump data in the flattened format should be rearranged to a readable\n");
	MSG("      DUMPFILE by -R option.\n");
	MSG("\n");
	MSG("  [-R]:\n");
	MSG("      Rearrange the dump data in the flattened format from the standard input\n");
	MSG("      to a readable DUMPFILE.\n");
	MSG("\n");
	MSG("  [--xen-syms XEN-SYMS]:\n");
	MSG("      Specify the XEN-SYMS to analyze Xen's memory usage.\n");
	MSG("\n");
	MSG("  [--xen-vmcoreinfo VMCOREINFO]:\n");
	MSG("      Specify the VMCOREINFO of Xen to analyze Xen's memory usage.\n");
	MSG("\n");
	MSG("  [--xen_phys_start XEN_PHYS_START_ADDRESS]:\n");
	MSG("      This option is only for x86_64.\n");
	MSG("      Specify the XEN_PHYS_START_ADDRESS, if the xen code/data is relocatable\n");
	MSG("      and VMCORE does not contain XEN_PHYS_START_ADDRESS in the CRASHINFO.\n");
	MSG("\n");
	MSG("  [-X]:\n");
	MSG("      Exclude all the user domain pages from Xen kdump's VMCORE, and extract\n");
	MSG("      the part of Xen and domain-0.\n");
	MSG("\n");
	MSG("  [--message-level ML]:\n");
	MSG("      Specify the message types.\n");
	MSG("      Users can restrict output printed by specifying Message_Level (ML) with\n");
	MSG("      this option. The message type marked with an X in the following table is\n");
	MSG("      printed. For example, according to the table, specifying 7 as ML means\n");
	MSG("      progress indicator, common message, and error message are printed, and\n");
	MSG("      this is a default value.\n");
	MSG("      Note that the maximum value of message_level is 31.\n");
	MSG("\n");
	MSG("      Message | progress    common    error     debug     report\n");
	MSG("      Level   | indicator   message   message   message   message\n");
	MSG("     ---------+------------------------------------------------------\n");
	MSG("            0 |\n");
	MSG("            1 |     X\n");
	MSG("            2 |                X\n");
	MSG("            4 |                          X\n");
	MSG("          * 7 |     X          X         X\n");
	MSG("            8 |                                    X\n");
	MSG("           16 |                                              X\n");
	MSG("           31 |     X          X         X         X         X\n");
	MSG("\n");
	MSG("  [--vtop VIRTUAL_ADDRESS]:\n");
	MSG("      This option is useful, when user debugs the translation problem\n");
	MSG("      of virtual address. If specifing the VIRTUAL_ADDRESS, its physical\n");
	MSG("      address is printed.\n");
	MSG("\n");
	MSG("  [-D]:\n");
	MSG("      Print debugging message.\n");
	MSG("\n");
	MSG("  [-f]:\n");
	MSG("      Overwrite DUMPFILE even if it already exists.\n");
	MSG("\n");
	MSG("  [-h]:\n");
	MSG("      Show help message.\n");
	MSG("\n");
	MSG("  [-v]:\n");
	MSG("      Show the version of makedumpfile.\n");
	MSG("\n");
	MSG("  VMLINUX:\n");
	MSG("      This is a pathname to the first kernel's vmlinux.\n");
	MSG("      This file must have the debug information of the first kernel to analyze\n");
	MSG("      the first kernel's memory usage.\n");
	MSG("\n");
	MSG("  VMCORE:\n");
	MSG("      This is a pathname to the first kernel's memory core image.\n");
	MSG("      This argument is generally /proc/vmcore.\n");
	MSG("\n");
	MSG("  DUMPFILE:\n");
	MSG("      This is a pathname to a file created by this command.\n");
	MSG("\n");
	MSG("  XEN-SYMS:\n");
	MSG("      This is a pathname to the xen-syms.\n");
	MSG("      This file must have the debug information of Xen to analyze\n");
	MSG("      Xen's memory usage.\n");
	MSG("\n");
}

int
open_vmcoreinfo(char *mode)
{
	FILE *file_vmcoreinfo;

	if ((file_vmcoreinfo = fopen(info->name_vmcoreinfo, mode)) == NULL) {
		ERRMSG("Can't open the vmcoreinfo file(%s). %s\n",
		    info->name_vmcoreinfo, strerror(errno));
		return FALSE;
	}
	info->file_vmcoreinfo = file_vmcoreinfo;
	return TRUE;
}

int
open_kernel_file(void)
{
	int fd;

	if (info->name_vmlinux) {
		if ((fd = open(info->name_vmlinux, O_RDONLY)) < 0) {
			ERRMSG("Can't open the kernel file(%s). %s\n",
			    info->name_vmlinux, strerror(errno));
			return FALSE;
		}
		info->fd_vmlinux = fd;
	}
	if (info->name_xen_syms) {
		if ((fd = open(info->name_xen_syms, O_RDONLY)) < 0) {
			ERRMSG("Can't open the kernel file(%s). %s\n",
			    info->name_xen_syms, strerror(errno));
			return FALSE;
		}
		info->fd_xen_syms = fd;
	}
	return TRUE;
}

int
open_dump_memory(void)
{
	int fd;

	if ((fd = open(info->name_memory, O_RDONLY)) < 0) {
		ERRMSG("Can't open the dump memory(%s). %s\n",
		    info->name_memory, strerror(errno));
		return FALSE;
	}
	info->fd_memory = fd;
	return TRUE;
}

int
open_dump_file(void)
{
	int fd;
	int open_flags = O_RDWR|O_CREAT|O_TRUNC;

	if (!info->flag_force)
		open_flags |= O_EXCL;

	if (info->flag_flatten) {
		fd = STDOUT_FILENO;
		info->name_dumpfile = filename_stdout;
	} else if ((fd = open(info->name_dumpfile, open_flags,
	    S_IRUSR|S_IWUSR)) < 0) {
		ERRMSG("Can't open the dump file(%s). %s\n",
		    info->name_dumpfile, strerror(errno));
		return FALSE;
	}
	info->fd_dumpfile = fd;
	return TRUE;
}

int
open_dump_bitmap(void)
{
	int i, fd;

	if ((info->name_bitmap
	    = (char *)malloc(sizeof(FILENAME_BITMAP))) == NULL) {
		ERRMSG("Can't allocate memory for the filename. %s\n",
		    strerror(errno));
		return FALSE;
	}
	strcpy(info->name_bitmap, FILENAME_BITMAP);
	if ((fd = mkstemp(info->name_bitmap)) < 0) {
		ERRMSG("Can't open the bitmap file(%s). %s\n",
		    info->name_bitmap, strerror(errno));
		return FALSE;
	}
	info->fd_bitmap = fd;

	if (info->flag_split) {
		/*
		 * Reserve file descriptors of bitmap for creating split
		 * dumpfiles by multiple processes, because a bitmap file will
		 * be unlinked just after this and it is not possible to open
		 * a bitmap file later.
		 */
		for (i = 0; i < info->num_dumpfile; i++) {
			if ((fd = open(info->name_bitmap, O_RDONLY)) < 0) {
				ERRMSG("Can't open the bitmap file(%s). %s\n",
				    info->name_bitmap, strerror(errno));
				return FALSE;
			}
			SPLITTING_FD_BITMAP(i) = fd;
		}
	}
	unlink(info->name_bitmap);

	return TRUE;
}

/*
 * Open the following files when it generates the vmcoreinfo file.
 * - vmlinux
 * - vmcoreinfo file
 */
int
open_files_for_generating_vmcoreinfo(void)
{
	if (!open_kernel_file())
		return FALSE;

	if (!open_vmcoreinfo("w"))
		return FALSE;

	return TRUE;
}

/*
 * Open the following file when it rearranges the dump data.
 * - dump file
 */
int
open_files_for_rearranging_dumpdata(void)
{
	if (!open_dump_file())
		return FALSE;

	return TRUE;
}

/*
 * Open the following files when it creates the dump file.
 * - dump mem
 * - dump file
 * - bit map
 * if it reads the vmcoreinfo file
 *   - vmcoreinfo file
 * else
 *   - vmlinux
 */
int
open_files_for_creating_dumpfile(void)
{
	if (info->flag_read_vmcoreinfo) {
		if (!open_vmcoreinfo("r"))
			return FALSE;
	} else {
		if (!open_kernel_file())
			return FALSE;
	}
	if (!open_dump_memory())
		return FALSE;

	if (!open_dump_bitmap())
		return FALSE;

	return TRUE;
}

int
dump_Elf_load(Elf64_Phdr *prog, int num_load)
{
	struct pt_load_segment *pls;

	if (prog->p_type != PT_LOAD) {
		ERRMSG("%s isn't the dump memory.\n", info->name_memory);
		return FALSE;
	}

	pls = &info->pt_load_segments[num_load];
	pls->phys_start  = prog->p_paddr;
	pls->phys_end    = pls->phys_start + prog->p_filesz;
	pls->virt_start  = prog->p_vaddr;
	pls->virt_end    = pls->virt_start + prog->p_filesz;
	pls->file_offset = prog->p_offset;

	DEBUG_MSG("LOAD (%d)\n", num_load);
	DEBUG_MSG("  phys_start : %llx\n", pls->phys_start);
	DEBUG_MSG("  phys_end   : %llx\n", pls->phys_end);
	DEBUG_MSG("  virt_start : %llx\n", pls->virt_start);
	DEBUG_MSG("  virt_end   : %llx\n", pls->virt_end);

	return TRUE;
}

int
get_elf64_ehdr(Elf64_Ehdr *ehdr)
{
	const off_t failed = (off_t)-1;

	if (lseek(info->fd_memory, 0, SEEK_SET) == failed) {
		ERRMSG("Can't seek the dump memory(%s). %s\n",
		    info->name_memory, strerror(errno));
		return FALSE;
	}
	if (read(info->fd_memory, ehdr, sizeof(Elf64_Ehdr))
	    != sizeof(Elf64_Ehdr)) {
		ERRMSG("Can't read the dump memory(%s). %s\n",
		    info->name_memory, strerror(errno));
		return FALSE;
	}
	if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
		ERRMSG("Can't get valid e_ident.\n");
		return FALSE;
	}
	return TRUE;
}

int
get_elf64_phdr(int fd, char *filename, int index, Elf64_Phdr *phdr)
{
	off_t offset;
	const off_t failed = (off_t)-1;

	offset = sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr) * index;

	if (lseek(fd, offset, SEEK_SET) == failed) {
		ERRMSG("Can't seek %s. %s\n", filename, strerror(errno));
		return FALSE;
	}
	if (read(fd, phdr, sizeof(Elf64_Phdr)) != sizeof(Elf64_Phdr)) {
		ERRMSG("Can't read %s. %s\n", filename, strerror(errno));
		return FALSE;
	}
	return TRUE;
}

int
get_elf32_ehdr(Elf32_Ehdr *ehdr)
{
	const off_t failed = (off_t)-1;

	if (lseek(info->fd_memory, 0, SEEK_SET) == failed) {
		ERRMSG("Can't seek the dump memory(%s). %s\n",
		    info->name_memory, strerror(errno));
		return FALSE;
	}
	if (read(info->fd_memory, ehdr, sizeof(Elf32_Ehdr))
	    != sizeof(Elf32_Ehdr)) {
		ERRMSG("Can't read the dump memory(%s). %s\n",
		    info->name_memory, strerror(errno));
		return FALSE;
	}
	if (ehdr->e_ident[EI_CLASS] != ELFCLASS32) {
		ERRMSG("Can't get valid e_ident.\n");
		return FALSE;
	}
	return TRUE;
}

int
get_elf32_phdr(int fd, char *filename, int index, Elf32_Phdr *phdr)
{
	off_t offset;
	const off_t failed = (off_t)-1;

	offset = sizeof(Elf32_Ehdr) + sizeof(Elf32_Phdr) * index;

	if (lseek(fd, offset, SEEK_SET) == failed) {
		ERRMSG("Can't seek %s. %s\n", filename, strerror(errno));
		return FALSE;
	}
	if (read(fd, phdr, sizeof(Elf32_Phdr)) != sizeof(Elf32_Phdr)) {
		ERRMSG("Can't read %s. %s\n", filename, strerror(errno));
		return FALSE;
	}
	return TRUE;
}

int
get_elf_phdr_memory(int index, Elf64_Phdr *phdr)
{
	Elf32_Phdr phdr32;

	if (info->flag_elf64_memory) { /* ELF64 */
		if (!get_elf64_phdr(info->fd_memory, info->name_memory,
		    index, phdr)) {
			ERRMSG("Can't find Phdr %d.\n", index);
			return FALSE;
		}
	} else {
		if (!get_elf32_phdr(info->fd_memory, info->name_memory,
		    index, &phdr32)) {
			ERRMSG("Can't find Phdr %d.\n", index);
			return FALSE;
		}
		memset(phdr, 0, sizeof(Elf64_Phdr));
		phdr->p_type   = phdr32.p_type;
		phdr->p_flags  = phdr32.p_flags;
		phdr->p_offset = phdr32.p_offset;
		phdr->p_vaddr  = phdr32.p_vaddr;
		phdr->p_paddr  = phdr32.p_paddr;
		phdr->p_filesz = phdr32.p_filesz;
		phdr->p_memsz  = phdr32.p_memsz;
		phdr->p_align  = phdr32.p_align;
	}
	return TRUE;
}

int
check_elf_format(int fd, char *filename, int *phnum, int *num_load)
{
	int i;
	Elf64_Ehdr ehdr64;
	Elf64_Phdr load64;
	Elf32_Ehdr ehdr32;
	Elf32_Phdr load32;
	const off_t failed = (off_t)-1;

	if (lseek(fd, 0, SEEK_SET) == failed) {
		ERRMSG("Can't seek %s. %s\n", filename, strerror(errno));
		return FALSE;
	}
	if (read(fd, &ehdr64, sizeof(Elf64_Ehdr)) != sizeof(Elf64_Ehdr)) {
		ERRMSG("Can't read %s. %s\n", filename, strerror(errno));
		return FALSE;
	}
	if (lseek(fd, 0, SEEK_SET) == failed) {
		ERRMSG("Can't seek %s. %s\n", filename, strerror(errno));
		return FALSE;
	}
	if (read(fd, &ehdr32, sizeof(Elf32_Ehdr)) != sizeof(Elf32_Ehdr)) {
		ERRMSG("Can't read %s. %s\n", filename, strerror(errno));
		return FALSE;
	}
	(*num_load) = 0;
	if ((ehdr64.e_ident[EI_CLASS] == ELFCLASS64)
	    && (ehdr32.e_ident[EI_CLASS] != ELFCLASS32)) {
		(*phnum) = ehdr64.e_phnum;
		for (i = 0; i < ehdr64.e_phnum; i++) {
			if (!get_elf64_phdr(fd, filename, i, &load64)) {
				ERRMSG("Can't find Phdr %d.\n", i);
				return FALSE;
			}
			if (load64.p_type == PT_LOAD)
				(*num_load)++;
		}
		return ELF64;

	} else if ((ehdr64.e_ident[EI_CLASS] != ELFCLASS64)
	    && (ehdr32.e_ident[EI_CLASS] == ELFCLASS32)) {
		(*phnum) = ehdr32.e_phnum;
		for (i = 0; i < ehdr32.e_phnum; i++) {
			if (!get_elf32_phdr(fd, filename, i, &load32)) {
				ERRMSG("Can't find Phdr %d.\n", i);
				return FALSE;
			}
			if (load32.p_type == PT_LOAD)
				(*num_load)++;
		}
		return ELF32;
	}
	ERRMSG("Can't get valid ehdr.\n");
	return FALSE;
}

int
get_elf_info(void)
{
	int i, j, phnum, num_load, elf_format;
	off_t offset_note;
	unsigned long size_note;
	Elf64_Phdr phdr;

	/*
	 * Check ELF64 or ELF32.
	 */
	elf_format = check_elf_format(info->fd_memory, info->name_memory,
	    &phnum, &num_load);

	if (elf_format == ELF64)
		info->flag_elf64_memory = TRUE;
	else if (elf_format == ELF32)
		info->flag_elf64_memory = FALSE;
	else
		return FALSE;

	info->num_load_memory = num_load;

	if (!info->num_load_memory) {
		ERRMSG("Can't get the number of PT_LOAD.\n");
		return FALSE;
	}
	if ((info->pt_load_segments = (struct pt_load_segment *)
	    calloc(1, sizeof(struct pt_load_segment) *
	    info->num_load_memory)) == NULL) {
		ERRMSG("Can't allocate memory for the PT_LOAD. %s\n",
		    strerror(errno));
		return FALSE;
	}
	offset_note = 0;
	size_note   = 0;
	for (i = 0, j = 0; i < phnum; i++) {
		if (!get_elf_phdr_memory(i, &phdr))
			return FALSE;

		if (phdr.p_type == PT_NOTE) {
			offset_note = phdr.p_offset;
			size_note   = phdr.p_filesz;
		}
		if (phdr.p_type != PT_LOAD)
			continue;

		if (j == 0) {
			info->offset_load_memory = phdr.p_offset;
			if (!info->offset_load_memory) {
				ERRMSG("Can't get the offset of page data.\n");
				return FALSE;
			}
		}
		if (j >= info->num_load_memory)
			return FALSE;
		if(!dump_Elf_load(&phdr, j))
			return FALSE;
		j++;
	}
	if (offset_note == 0 || size_note == 0) {
		ERRMSG("Can't find PT_NOTE Phdr.\n");
		return FALSE;
	}
	if (!get_pt_note_info(offset_note, size_note)) {
		ERRMSG("Can't get PT_NOTE information.\n");
		return FALSE;
	}

	return TRUE;
}

unsigned long long
get_symbol_addr(char *symname)
{
	int i;
	unsigned long long symbol = NOT_FOUND_SYMBOL;
	Elf *elfd = NULL;
	GElf_Shdr shdr;
	GElf_Sym sym;
	Elf_Data *data = NULL;
	Elf_Scn *scn = NULL;
	char *sym_name = NULL;
	const off_t failed = (off_t)-1;

	if (lseek(dwarf_info.fd_debuginfo, 0, SEEK_SET) == failed) {
		ERRMSG("Can't seek the kernel file(%s). %s\n",
		    dwarf_info.name_debuginfo, strerror(errno));
		return NOT_FOUND_SYMBOL;
	}
	if (!(elfd = elf_begin(dwarf_info.fd_debuginfo, ELF_C_READ, NULL))) {
		ERRMSG("Can't get first elf header of %s.\n",
		    dwarf_info.name_debuginfo);
		return NOT_FOUND_SYMBOL;
	}
	while ((scn = elf_nextscn(elfd, scn)) != NULL) {
		if (gelf_getshdr(scn, &shdr) == NULL) {
			ERRMSG("Can't get section header.\n");
			goto out;
		}
		if (shdr.sh_type == SHT_SYMTAB)
			break;
	}
	if (!scn) {
		ERRMSG("Can't find symbol table.\n");
		goto out;
	}

	data = elf_getdata(scn, data);

	if ((!data) || (data->d_size == 0)) {
		ERRMSG("No data in symbol table.\n");
		goto out;
	}

	for (i = 0; i < (shdr.sh_size/shdr.sh_entsize); i++) {
		if (gelf_getsym(data, i, &sym) == NULL) {
			ERRMSG("Can't get symbol at index %d.\n", i);
			goto out;
		}
		sym_name = elf_strptr(elfd, shdr.sh_link, sym.st_name);

		if (sym_name == NULL)
			continue;

		if (!strcmp(sym_name, symname)) {
			symbol = sym.st_value;
			break;
		}
	}
out:
	if (elfd != NULL)
		elf_end(elfd);

	return symbol;
}

unsigned long
get_next_symbol_addr(char *symname)
{
	int i;
	unsigned long symbol = NOT_FOUND_SYMBOL;
	unsigned long next_symbol = NOT_FOUND_SYMBOL;
	Elf *elfd = NULL;
	GElf_Shdr shdr;
	GElf_Sym sym;
	Elf_Data *data = NULL;
	Elf_Scn *scn = NULL;
	char *sym_name = NULL;
	const off_t failed = (off_t)-1;

	if (lseek(dwarf_info.fd_debuginfo, 0, SEEK_SET) == failed) {
		ERRMSG("Can't seek the kernel file(%s). %s\n",
		    dwarf_info.name_debuginfo, strerror(errno));
		return NOT_FOUND_SYMBOL;
	}
	if (!(elfd = elf_begin(dwarf_info.fd_debuginfo, ELF_C_READ, NULL))) {
		ERRMSG("Can't get first elf header of %s.\n",
		    dwarf_info.name_debuginfo);
		return NOT_FOUND_SYMBOL;
	}
	while ((scn = elf_nextscn(elfd, scn)) != NULL) {
		if (gelf_getshdr(scn, &shdr) == NULL) {
			ERRMSG("Can't get section header.\n");
			goto out;
		}
		if (shdr.sh_type == SHT_SYMTAB)
			break;
	}
	if (!scn) {
		ERRMSG("Can't find symbol table.\n");
		goto out;
	}

	data = elf_getdata(scn, data);

	if ((!data) || (data->d_size == 0)) {
		ERRMSG("No data in symbol table.\n");
		goto out;
	}

	for (i = 0; i < (shdr.sh_size/shdr.sh_entsize); i++) {
		if (gelf_getsym(data, i, &sym) == NULL) {
			ERRMSG("Can't get symbol at index %d.\n", i);
			goto out;
		}
		sym_name = elf_strptr(elfd, shdr.sh_link, sym.st_name);

		if (sym_name == NULL)
			continue;

		if (!strcmp(sym_name, symname)) {
			symbol = sym.st_value;
			break;
		}
	}

	if (symbol == NOT_FOUND_SYMBOL)
		goto out;

	/*
	 * Search for next symbol.
	 */
	for (i = 0; i < (shdr.sh_size/shdr.sh_entsize); i++) {
		if (gelf_getsym(data, i, &sym) == NULL) {
			ERRMSG("Can't get symbol at index %d.\n", i);
			goto out;
		}
		sym_name = elf_strptr(elfd, shdr.sh_link, sym.st_name);

		if (sym_name == NULL)
			continue;

		if (symbol < sym.st_value) {
			if (next_symbol == NOT_FOUND_SYMBOL)
				next_symbol = sym.st_value;

			else if (sym.st_value < next_symbol)
				next_symbol = sym.st_value;
		}
	}
out:
	if (elfd != NULL)
		elf_end(elfd);

	return next_symbol;
}

int
is_kvaddr(unsigned long long addr)
{
	return (addr >= (unsigned long long)(KVBASE));
}

static int
get_data_member_location(Dwarf_Die *die, long *offset)
{
	size_t expcnt;
	Dwarf_Attribute attr;
	Dwarf_Op *expr;

	if (dwarf_attr(die, DW_AT_data_member_location, &attr) == NULL)
		return FALSE;

	if (dwarf_getlocation(&attr, &expr, &expcnt) < 0)
		return FALSE;

	(*offset) = expr[0].number;

	return TRUE;
}

static int
get_die_type(Dwarf *dwarfd, Dwarf_Die *die, Dwarf_Die *die_type)
{
	Dwarf_Attribute attr;
	Dwarf_Off offset_type, offset_cu;

	offset_cu = dwarf_dieoffset(die) - dwarf_cuoffset(die);

	/*
	 * Get the offset of DW_AT_type.
	 */
	if (dwarf_attr(die, DW_AT_type, &attr) == NULL)
		return FALSE;

	if (dwarf_formref(&attr, &offset_type) < 0)
		return FALSE;

	if (dwarf_offdie(dwarfd, offset_type + offset_cu, die_type) == NULL) {
		ERRMSG("Can't get CU die.\n");
		return FALSE;
	}
	return TRUE;
}

static int
get_data_array_length(Dwarf *dwarfd, Dwarf_Die *die)
{
	int tag;
	Dwarf_Attribute attr;
	Dwarf_Die die_type;
	Dwarf_Word upper_bound;

	if (!get_die_type(dwarfd, die, &die_type)) {
		ERRMSG("Can't get CU die of DW_AT_type.\n");
		return FALSE;
	}
	tag = dwarf_tag(&die_type);
	if (tag != DW_TAG_array_type) {
		/*
		 * This kernel doesn't have the member of array.
		 */
		return TRUE;
	}

	/*
	 * Get the demanded array length.
	 */
	dwarf_child(&die_type, &die_type);
	do {
		tag  = dwarf_tag(&die_type);
		if (tag == DW_TAG_subrange_type)
			break;
	} while (dwarf_siblingof(&die_type, &die_type));

	if (tag != DW_TAG_subrange_type)
		return FALSE;

	if (dwarf_attr(&die_type, DW_AT_upper_bound, &attr) == NULL)
		return FALSE;

	if (dwarf_formudata(&attr, &upper_bound) < 0)
		return FALSE;

	if (upper_bound < 0)
		return FALSE;

	dwarf_info.array_length = upper_bound + 1;

	return TRUE;
}

static int
check_array_type(Dwarf *dwarfd, Dwarf_Die *die)
{
	int tag;
	Dwarf_Die die_type;

	if (!get_die_type(dwarfd, die, &die_type)) {
		ERRMSG("Can't get CU die of DW_AT_type.\n");
		return FALSE;
	}
	tag = dwarf_tag(&die_type);
	if (tag == DW_TAG_array_type)
		dwarf_info.array_length = FOUND_ARRAY_TYPE;

	return TRUE;
}

/*
 * Function for searching struct page.union.struct.mapping.
 */
int
__search_mapping(Dwarf *dwarfd, Dwarf_Die *die, long *offset)
{
	int tag;
	const char *name;
	Dwarf_Die child, *walker;

	if (dwarf_child(die, &child) != 0)
		return FALSE;

	walker = &child;
	do {
		tag  = dwarf_tag(walker);
		name = dwarf_diename(walker);

		if (tag != DW_TAG_member)
			continue;
		if ((!name) || strcmp(name, dwarf_info.member_name))
			continue;
		if (!get_data_member_location(walker, offset))
			continue;
		return TRUE;

	} while (!dwarf_siblingof(walker, walker));

	return FALSE;
}

/*
 * Function for searching struct page.union.struct.
 */
int
search_mapping(Dwarf *dwarfd, Dwarf_Die *die, long *offset)
{
	Dwarf_Die child, *walker;
	Dwarf_Die die_struct;

	if (dwarf_child(die, &child) != 0)
		return FALSE;

	walker = &child;

	do {
		if (dwarf_tag(walker) != DW_TAG_member)
			continue;
		if (!get_die_type(dwarfd, walker, &die_struct))
			continue;
		if (dwarf_tag(&die_struct) != DW_TAG_structure_type)
			continue;
		if (__search_mapping(dwarfd, &die_struct, offset))
			return TRUE;
	} while (!dwarf_siblingof(walker, walker));

	return FALSE;
}

static void
search_member(Dwarf *dwarfd, Dwarf_Die *die)
{
	int tag;
	long offset, offset_union;
	const char *name;
	Dwarf_Die child, *walker, die_union;

	if (dwarf_child(die, &child) != 0)
		return;

	walker = &child;

	do {
		tag  = dwarf_tag(walker);
		name = dwarf_diename(walker);

		if (tag != DW_TAG_member)
			continue;

		switch (dwarf_info.cmd) {
		case DWARF_INFO_GET_MEMBER_OFFSET:
			if ((!name) || strcmp(name, dwarf_info.member_name))
				continue;
			/*
			 * Get the member offset.
			 */
			if (!get_data_member_location(walker, &offset))
				continue;
			dwarf_info.member_offset = offset;
			return;
		case DWARF_INFO_GET_MEMBER_OFFSET_IN_UNION:
			if (!get_die_type(dwarfd, walker, &die_union))
				continue;
			if (dwarf_tag(&die_union) != DW_TAG_union_type)
				continue;
			/*
			 * Search page.mapping in union.
			 */
			if (!search_mapping(dwarfd, &die_union, &offset_union))
				continue;
			/*
			 * Get the member offset.
			 */
			if (!get_data_member_location(walker, &offset))
 				continue;
			dwarf_info.member_offset = offset + offset_union;
 			return;
		case DWARF_INFO_GET_MEMBER_OFFSET_1ST_UNION:
			if (!get_die_type(dwarfd, walker, &die_union))
				continue;
			if (dwarf_tag(&die_union) != DW_TAG_union_type)
				continue;
			/*
			 * Get the member offset.
			 */
			if (!get_data_member_location(walker, &offset))
				continue;
			dwarf_info.member_offset = offset;
			return;
		case DWARF_INFO_GET_MEMBER_ARRAY_LENGTH:
			if ((!name) || strcmp(name, dwarf_info.member_name))
				continue;
			/*
			 * Get the member length.
			 */
			if (!get_data_array_length(dwarfd, walker))
				continue;
			return;
		}
	} while (!dwarf_siblingof(walker, walker));

	/*
	 * Return even if not found.
	 */
	return;
}

int
is_search_structure(int cmd)
{
	if ((cmd == DWARF_INFO_GET_STRUCT_SIZE)
	    || (cmd == DWARF_INFO_GET_MEMBER_OFFSET)
	    || (cmd == DWARF_INFO_GET_MEMBER_OFFSET_IN_UNION)
	    || (cmd == DWARF_INFO_GET_MEMBER_OFFSET_1ST_UNION)
	    || (cmd == DWARF_INFO_GET_MEMBER_ARRAY_LENGTH))
		return TRUE;
	else
		return FALSE;
}

int
is_search_number(int cmd)
{
	if (cmd == DWARF_INFO_GET_ENUM_NUMBER)
		return TRUE;
	else
		return FALSE;
}

int
is_search_symbol(int cmd)
{
	if ((cmd == DWARF_INFO_GET_SYMBOL_ARRAY_LENGTH)
	    || (cmd == DWARF_INFO_CHECK_SYMBOL_ARRAY_TYPE))
		return TRUE;
	else
		return FALSE;
}

int
is_search_typedef(int cmd)
{
	if ((cmd == DWARF_INFO_GET_TYPEDEF_SIZE)
	    || (cmd == DWARF_INFO_GET_TYPEDEF_SRCNAME))
		return TRUE;
	else
		return FALSE;
}

static void
search_structure(Dwarf *dwarfd, Dwarf_Die *die, int *found)
{
	int tag;
	const char *name;

	/*
	 * If we get to here then we don't have any more
	 * children, check to see if this is a relevant tag
	 */
	do {
		tag  = dwarf_tag(die);
		name = dwarf_diename(die);
		if ((tag != DW_TAG_structure_type) || (!name)
		    || strcmp(name, dwarf_info.struct_name))
			continue;
		/*
		 * Skip if DW_AT_byte_size is not included.
		 */
		dwarf_info.struct_size = dwarf_bytesize(die);

		if (dwarf_info.struct_size > 0)
			break;

	} while (!dwarf_siblingof(die, die));

	if (dwarf_info.struct_size <= 0) {
		/*
		 * Not found the demanded structure.
		 */
		return;
	}

	/*
	 * Found the demanded structure.
	 */
	*found = TRUE;
	switch (dwarf_info.cmd) {
	case DWARF_INFO_GET_STRUCT_SIZE:
		break;
	case DWARF_INFO_GET_MEMBER_OFFSET:
	case DWARF_INFO_GET_MEMBER_OFFSET_IN_UNION:
	case DWARF_INFO_GET_MEMBER_OFFSET_1ST_UNION:
	case DWARF_INFO_GET_MEMBER_ARRAY_LENGTH:
		search_member(dwarfd, die);
		break;
	}
}

static void
search_number(Dwarf *dwarfd, Dwarf_Die *die, int *found)
{
	int tag;
	Dwarf_Word const_value;
	Dwarf_Attribute attr;
	Dwarf_Die child, *walker;
	const char *name;

	do {
		tag  = dwarf_tag(die);
		if (tag != DW_TAG_enumeration_type)
			continue;

		if (dwarf_child(die, &child) != 0)
			continue;

		walker = &child;

		do {
			tag  = dwarf_tag(walker);
			name = dwarf_diename(walker);

			if ((tag != DW_TAG_enumerator) || (!name)
			    || strcmp(name, dwarf_info.enum_name))
				continue;

			if (!dwarf_attr(walker, DW_AT_const_value, &attr))
				continue;

			if (dwarf_formudata(&attr, &const_value) < 0)
				continue;

			*found = TRUE;
			dwarf_info.enum_number = (long)const_value;

		} while (!dwarf_siblingof(walker, walker));

	} while (!dwarf_siblingof(die, die));
}

static void
search_typedef(Dwarf *dwarfd, Dwarf_Die *die, int *found)
{
	int tag = 0;
	char *src_name = NULL;
	const char *name;
	Dwarf_Die die_type;

	/*
	 * If we get to here then we don't have any more
	 * children, check to see if this is a relevant tag
	 */
	do {
		tag  = dwarf_tag(die);
		name = dwarf_diename(die);

		if ((tag != DW_TAG_typedef) || (!name)
		    || strcmp(name, dwarf_info.struct_name))
			continue;

		if (dwarf_info.cmd == DWARF_INFO_GET_TYPEDEF_SIZE) {
			if (!get_die_type(dwarfd, die, &die_type)) {
				ERRMSG("Can't get CU die of DW_AT_type.\n");
				break;
			}
			dwarf_info.struct_size = dwarf_bytesize(&die_type);
			if (dwarf_info.struct_size <= 0)
				continue;

			*found = TRUE;
			break;
		} else if (dwarf_info.cmd == DWARF_INFO_GET_TYPEDEF_SRCNAME) {
			src_name = (char *)dwarf_decl_file(die);
			if (!src_name)
				continue;

			*found = TRUE;
			strncpy(dwarf_info.src_name, src_name, LEN_SRCFILE);
			break;
		}
	} while (!dwarf_siblingof(die, die));
}

static void
search_symbol(Dwarf *dwarfd, Dwarf_Die *die, int *found)
{
	int tag;
	const char *name;

	/*
	 * If we get to here then we don't have any more
	 * children, check to see if this is a relevant tag
	 */
	do {
		tag  = dwarf_tag(die);
		name = dwarf_diename(die);

		if ((tag == DW_TAG_variable) && (name)
		    && !strcmp(name, dwarf_info.symbol_name))
			break;

	} while (!dwarf_siblingof(die, die));

	if ((tag != DW_TAG_variable) || (!name)
	    || strcmp(name, dwarf_info.symbol_name)) {
		/*
		 * Not found the demanded symbol.
		 */
		return;
	}

	/*
	 * Found the demanded symbol.
	 */
	*found = TRUE;
	switch (dwarf_info.cmd) {
	case DWARF_INFO_GET_SYMBOL_ARRAY_LENGTH:
		get_data_array_length(dwarfd, die);
		break;
	case DWARF_INFO_CHECK_SYMBOL_ARRAY_TYPE:
		check_array_type(dwarfd, die);
		break;
	}
}

static void
search_die_tree(Dwarf *dwarfd, Dwarf_Die *die, int *found)
{
	Dwarf_Die child;

	/*
	 * start by looking at the children
	 */
	if (dwarf_child(die, &child) == 0)
		search_die_tree(dwarfd, &child, found);

	if (*found)
		return;

	if (is_search_structure(dwarf_info.cmd))
		search_structure(dwarfd, die, found);

	else if (is_search_number(dwarf_info.cmd))
		search_number(dwarfd, die, found);

	else if (is_search_symbol(dwarf_info.cmd))
		search_symbol(dwarfd, die, found);

	else if (is_search_typedef(dwarf_info.cmd))
		search_typedef(dwarfd, die, found);
}

int
get_debug_info(void)
{
	int found = FALSE;
	char *name = NULL;
	size_t shstrndx, header_size;
	uint8_t address_size, offset_size;
	Dwarf *dwarfd = NULL;
	Elf *elfd = NULL;
	Dwarf_Off off = 0, next_off = 0, abbrev_offset = 0;
	Elf_Scn *scn = NULL;
	GElf_Shdr scnhdr_mem, *scnhdr = NULL;
	Dwarf_Die cu_die;
	const off_t failed = (off_t)-1;

	int ret = FALSE;

	if (lseek(dwarf_info.fd_debuginfo, 0, SEEK_SET) == failed) {
		ERRMSG("Can't seek the kernel file(%s). %s\n",
		    dwarf_info.name_debuginfo, strerror(errno));
		return FALSE;
	}
	if (!(elfd = elf_begin(dwarf_info.fd_debuginfo, ELF_C_READ_MMAP, NULL))) {
		ERRMSG("Can't get first elf header of %s.\n",
		    dwarf_info.name_debuginfo);
		return FALSE;
	}
	if (!(dwarfd = dwarf_begin_elf(elfd, DWARF_C_READ, NULL))) {
		ERRMSG("Can't create a handle for a new debug session.\n");
		goto out;
	}
	if (elf_getshstrndx(elfd, &shstrndx) < 0) {
		ERRMSG("Can't get the section index of the string table.\n");
		goto out;
	}

	/*
	 * Search for ".debug_info" section.
	 */
	while ((scn = elf_nextscn(elfd, scn)) != NULL) {
		scnhdr = gelf_getshdr(scn, &scnhdr_mem);
		name = elf_strptr(elfd, shstrndx, scnhdr->sh_name);
		if (!strcmp(name, ".debug_info"))
			break;
	}
	if (strcmp(name, ".debug_info")) {
		ERRMSG("Can't get .debug_info section.\n");
		goto out;
	}

	/*
	 * Search by each CompileUnit.
	 */
	while (dwarf_nextcu(dwarfd, off, &next_off, &header_size,
	    &abbrev_offset, &address_size, &offset_size) == 0) {
		off += header_size;
		if (dwarf_offdie(dwarfd, off, &cu_die) == NULL) {
			ERRMSG("Can't get CU die.\n");
			goto out;
		}
		search_die_tree(dwarfd, &cu_die, &found);
		if (found)
			break;
		off = next_off;
	}
	ret = TRUE;
out:
	if (dwarfd != NULL)
		dwarf_end(dwarfd);
	if (elfd != NULL)
		elf_end(elfd);

	return ret;
}

/*
 * Get the size of structure.
 */
long
get_structure_size(char *structname, int flag_typedef)
{
	if (flag_typedef)
		dwarf_info.cmd = DWARF_INFO_GET_TYPEDEF_SIZE;
	else
		dwarf_info.cmd = DWARF_INFO_GET_STRUCT_SIZE;

	dwarf_info.struct_name = structname;
	dwarf_info.struct_size = NOT_FOUND_STRUCTURE;

	if (!get_debug_info())
		return FAILED_DWARFINFO;

	return dwarf_info.struct_size;
}

/*
 * Get the offset of member.
 */
long
get_member_offset(char *structname, char *membername, int cmd)
{
	dwarf_info.cmd = cmd;
	dwarf_info.struct_name = structname;
	dwarf_info.struct_size = NOT_FOUND_STRUCTURE;
	dwarf_info.member_name = membername;
	dwarf_info.member_offset = NOT_FOUND_STRUCTURE;

	if (!get_debug_info())
		return FAILED_DWARFINFO;

	return dwarf_info.member_offset;
}

/*
 * Get the length of array.
 */
long
get_array_length(char *name01, char *name02, unsigned int cmd)
{
	switch (cmd) {
	case DWARF_INFO_GET_SYMBOL_ARRAY_LENGTH:
		dwarf_info.symbol_name = name01;
		break;
	case DWARF_INFO_CHECK_SYMBOL_ARRAY_TYPE:
		dwarf_info.symbol_name = name01;
		break;
	case DWARF_INFO_GET_MEMBER_ARRAY_LENGTH:
		dwarf_info.struct_name = name01;
		dwarf_info.member_name = name02;
		break;
	}
	dwarf_info.cmd           = cmd;
	dwarf_info.struct_size   = NOT_FOUND_STRUCTURE;
	dwarf_info.member_offset = NOT_FOUND_STRUCTURE;
	dwarf_info.array_length  = NOT_FOUND_STRUCTURE;

	if (!get_debug_info())
		return FAILED_DWARFINFO;

	return dwarf_info.array_length;
}

long
get_enum_number(char *enum_name) {

	dwarf_info.cmd         = DWARF_INFO_GET_ENUM_NUMBER;
	dwarf_info.enum_name   = enum_name;
	dwarf_info.enum_number = NOT_FOUND_NUMBER;

	if (!get_debug_info())
		return FAILED_DWARFINFO;

	return dwarf_info.enum_number;
}

/*
 * Get the source filename.
 */
int
get_source_filename(char *structname, char *src_name, int cmd)
{
	dwarf_info.cmd = cmd;
	dwarf_info.struct_name = structname;

	if (!get_debug_info())
		return FALSE;

	strncpy(src_name, dwarf_info.src_name, LEN_SRCFILE);

	return TRUE;
}

int
get_symbol_info(void)
{
	/*
	 * Get symbol info.
	 */
	SYMBOL_INIT(mem_map, "mem_map");
	SYMBOL_INIT(vmem_map, "vmem_map");
	SYMBOL_INIT(mem_section, "mem_section");
	SYMBOL_INIT(pkmap_count, "pkmap_count");
	SYMBOL_INIT_NEXT(pkmap_count_next, "pkmap_count");
	SYMBOL_INIT(system_utsname, "system_utsname");
	SYMBOL_INIT(init_uts_ns, "init_uts_ns");
	SYMBOL_INIT(_stext, "_stext");
	SYMBOL_INIT(swapper_pg_dir, "swapper_pg_dir");
	SYMBOL_INIT(init_level4_pgt, "init_level4_pgt");
	SYMBOL_INIT(vmlist, "vmlist");
	SYMBOL_INIT(phys_base, "phys_base");
	SYMBOL_INIT(node_online_map, "node_online_map");
	SYMBOL_INIT(node_states, "node_states");
	SYMBOL_INIT(node_memblk, "node_memblk");
	SYMBOL_INIT(node_data, "node_data");
	SYMBOL_INIT(pgdat_list, "pgdat_list");
	SYMBOL_INIT(contig_page_data, "contig_page_data");
	SYMBOL_INIT(log_buf, "log_buf");
	SYMBOL_INIT(log_buf_len, "log_buf_len");
	SYMBOL_INIT(log_end, "log_end");

	if (SYMBOL(node_data) != NOT_FOUND_SYMBOL)
		SYMBOL_ARRAY_TYPE_INIT(node_data, "node_data");
	if (SYMBOL(pgdat_list) != NOT_FOUND_SYMBOL)
		SYMBOL_ARRAY_LENGTH_INIT(pgdat_list, "pgdat_list");
	if (SYMBOL(mem_section) != NOT_FOUND_SYMBOL)
		SYMBOL_ARRAY_LENGTH_INIT(mem_section, "mem_section");
	if (SYMBOL(node_memblk) != NOT_FOUND_SYMBOL)
		SYMBOL_ARRAY_LENGTH_INIT(node_memblk, "node_memblk");

	return TRUE;
}

int
get_structure_info(void)
{
	/*
	 * Get offsets of the page_discriptor's members.
	 */
	SIZE_INIT(page, "page");
	OFFSET_INIT(page.flags, "page", "flags");
	OFFSET_INIT(page._count, "page", "_count");

	OFFSET_INIT(page.mapping, "page", "mapping");

	/*
	 * On linux-2.6.16 or later, page.mapping is defined
	 * in anonymous union.
	 */
	if (OFFSET(page.mapping) == NOT_FOUND_STRUCTURE)
		OFFSET_IN_UNION_INIT(page.mapping, "page", "mapping");

	/*
	 * Some vmlinux(s) don't have debugging information about
	 * page.mapping. Then, makedumpfile assumes that there is
	 * "mapping" next to "private(unsigned long)" in the first
	 * union.
	 */
	if (OFFSET(page.mapping) == NOT_FOUND_STRUCTURE) {
		OFFSET(page.mapping) = get_member_offset("page", NULL,
		    DWARF_INFO_GET_MEMBER_OFFSET_1ST_UNION);
		if (OFFSET(page.mapping) == FAILED_DWARFINFO)
			return FALSE;
		if (OFFSET(page.mapping) != NOT_FOUND_STRUCTURE)
			OFFSET(page.mapping) += sizeof(unsigned long);
	}

	OFFSET_INIT(page.lru, "page", "lru");

	/*
	 * Get offsets of the mem_section's members.
	 */
	SIZE_INIT(mem_section, "mem_section");
	OFFSET_INIT(mem_section.section_mem_map, "mem_section",
	    "section_mem_map");

	/*
	 * Get offsets of the pglist_data's members.
	 */
	SIZE_INIT(pglist_data, "pglist_data");
	OFFSET_INIT(pglist_data.node_zones, "pglist_data", "node_zones");
	OFFSET_INIT(pglist_data.nr_zones, "pglist_data", "nr_zones");
	OFFSET_INIT(pglist_data.node_mem_map, "pglist_data", "node_mem_map");
	OFFSET_INIT(pglist_data.node_start_pfn, "pglist_data","node_start_pfn");
	OFFSET_INIT(pglist_data.node_spanned_pages, "pglist_data",
	    "node_spanned_pages");
	OFFSET_INIT(pglist_data.pgdat_next, "pglist_data", "pgdat_next");

	/*
	 * Get offsets of the zone's members.
	 */
	SIZE_INIT(zone, "zone");
	OFFSET_INIT(zone.free_pages, "zone", "free_pages");
	OFFSET_INIT(zone.free_area, "zone", "free_area");
	OFFSET_INIT(zone.vm_stat, "zone", "vm_stat");
	OFFSET_INIT(zone.spanned_pages, "zone", "spanned_pages");
	MEMBER_ARRAY_LENGTH_INIT(zone.free_area, "zone", "free_area");

	/*
	 * Get offsets of the free_area's members.
	 */
	SIZE_INIT(free_area, "free_area");
	OFFSET_INIT(free_area.free_list, "free_area", "free_list");
	MEMBER_ARRAY_LENGTH_INIT(free_area.free_list, "free_area", "free_list");

	/*
	 * Get offsets of the list_head's members.
	 */
	SIZE_INIT(list_head, "list_head");
	OFFSET_INIT(list_head.next, "list_head", "next");
	OFFSET_INIT(list_head.prev, "list_head", "prev");

	/*
	 * Get offsets of the node_memblk_s's members.
	 */
	SIZE_INIT(node_memblk_s, "node_memblk_s");
	OFFSET_INIT(node_memblk_s.start_paddr, "node_memblk_s", "start_paddr");
	OFFSET_INIT(node_memblk_s.size, "node_memblk_s", "size");
	OFFSET_INIT(node_memblk_s.nid, "node_memblk_s", "nid");

	OFFSET_INIT(vm_struct.addr, "vm_struct", "addr");

	ENUM_NUMBER_INIT(NR_FREE_PAGES, "NR_FREE_PAGES");
	ENUM_NUMBER_INIT(N_ONLINE, "N_ONLINE");

	ENUM_NUMBER_INIT(PG_lru, "PG_lru");
	ENUM_NUMBER_INIT(PG_private, "PG_private");
	ENUM_NUMBER_INIT(PG_swapcache, "PG_swapcache");

	TYPEDEF_SIZE_INIT(nodemask_t, "nodemask_t");

	return TRUE;
}

int
get_srcfile_info(void)
{
	TYPEDEF_SRCFILE_INIT(pud_t, "pud_t");

	return TRUE;
}

int
get_value_for_old_linux(void)
{
	if (NUMBER(PG_lru) == NOT_FOUND_NUMBER)
		NUMBER(PG_lru) = PG_lru_ORIGINAL;
	if (NUMBER(PG_private) == NOT_FOUND_NUMBER)
		NUMBER(PG_private) = PG_private_ORIGINAL;
	if (NUMBER(PG_swapcache) == NOT_FOUND_NUMBER)
		NUMBER(PG_swapcache) = PG_swapcache_ORIGINAL;
	return TRUE;
}

int
get_str_osrelease_from_vmlinux(void)
{
	struct utsname system_utsname;
	unsigned long long utsname;
	off_t offset;
	const off_t failed = (off_t)-1;

	/*
	 * Get the kernel version.
	 */
	if (SYMBOL(system_utsname) != NOT_FOUND_SYMBOL) {
		utsname = SYMBOL(system_utsname);
	} else if (SYMBOL(init_uts_ns) != NOT_FOUND_SYMBOL) {
		utsname = SYMBOL(init_uts_ns) + sizeof(int);
	} else {
		ERRMSG("Can't get the symbol of system_utsname.\n");
		return FALSE;
	}
	offset = vaddr_to_offset_slow(dwarf_info.fd_debuginfo,
	    dwarf_info.name_debuginfo, utsname);

	if (!offset) {
		ERRMSG("Can't convert vaddr (%llx) of utsname to an offset.\n",
		    utsname);
		return FALSE;
	}
	if (lseek(dwarf_info.fd_debuginfo, offset, SEEK_SET) == failed) {
		ERRMSG("Can't seek %s. %s\n", dwarf_info.name_debuginfo,
		    strerror(errno));
		return FALSE;
	}
	if (read(dwarf_info.fd_debuginfo, &system_utsname, sizeof system_utsname)
	    != sizeof system_utsname) {
		ERRMSG("Can't read %s. %s\n", dwarf_info.name_debuginfo,
		    strerror(errno));
		return FALSE;
	}
	if (!strncpy(info->release, system_utsname.release, STRLEN_OSRELEASE)){
		ERRMSG("Can't do strncpy for osrelease.");
		return FALSE;
	}
	return TRUE;
}

int
is_sparsemem_extreme(void)
{
	if (ARRAY_LENGTH(mem_section)
	     == (NR_MEM_SECTIONS() / _SECTIONS_PER_ROOT_EXTREME()))
		return TRUE;
	else
		return FALSE;
}

int
get_mem_type(void)
{
	int ret;

	if ((SIZE(page) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(page.flags) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(page._count) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(page.mapping) == NOT_FOUND_STRUCTURE)) {
		ret = NOT_FOUND_MEMTYPE;
	} else if ((((SYMBOL(node_data) != NOT_FOUND_SYMBOL)
	        && (ARRAY_LENGTH(node_data) != NOT_FOUND_STRUCTURE))
	    || ((SYMBOL(pgdat_list) != NOT_FOUND_SYMBOL)
	        && (OFFSET(pglist_data.pgdat_next) != NOT_FOUND_STRUCTURE))
	    || ((SYMBOL(pgdat_list) != NOT_FOUND_SYMBOL)
	        && (ARRAY_LENGTH(pgdat_list) != NOT_FOUND_STRUCTURE)))
	    && (SIZE(pglist_data) != NOT_FOUND_STRUCTURE)
	    && (OFFSET(pglist_data.node_mem_map) != NOT_FOUND_STRUCTURE)
	    && (OFFSET(pglist_data.node_start_pfn) != NOT_FOUND_STRUCTURE)
	    && (OFFSET(pglist_data.node_spanned_pages) !=NOT_FOUND_STRUCTURE)){
		ret = DISCONTIGMEM;
	} else if ((SYMBOL(mem_section) != NOT_FOUND_SYMBOL)
	    && (SIZE(mem_section) != NOT_FOUND_STRUCTURE)
	    && (OFFSET(mem_section.section_mem_map) != NOT_FOUND_STRUCTURE)
	    && (ARRAY_LENGTH(mem_section) != NOT_FOUND_STRUCTURE)) {
		if (is_sparsemem_extreme())
			ret = SPARSEMEM_EX;
		else
			ret = SPARSEMEM;
	} else if (SYMBOL(mem_map) != NOT_FOUND_SYMBOL) {
		ret = FLATMEM;
	} else {
		ret = NOT_FOUND_MEMTYPE;
	}

	return ret;
}

int
generate_vmcoreinfo(void)
{
	if (!set_page_size(sysconf(_SC_PAGE_SIZE)))
		return FALSE;

	dwarf_info.fd_debuginfo   = info->fd_vmlinux;
	dwarf_info.name_debuginfo = info->name_vmlinux;

	if (!get_symbol_info())
		return FALSE;

	if (!get_structure_info())
		return FALSE;

	if (!get_srcfile_info())
		return FALSE;

	if ((SYMBOL(system_utsname) == NOT_FOUND_SYMBOL)
	    && (SYMBOL(init_uts_ns) == NOT_FOUND_SYMBOL)) {
		ERRMSG("Can't get the symbol of system_utsname.\n");
		return FALSE;
	}
	if (!get_str_osrelease_from_vmlinux())
		return FALSE;

	if (!(info->kernel_version = get_kernel_version(info->release)))
		return FALSE;

	if (get_mem_type() == NOT_FOUND_MEMTYPE) {
		ERRMSG("Can't find the memory type.\n");
		return FALSE;
	}

	/*
	 * write 1st kernel's OSRELEASE
	 */
	fprintf(info->file_vmcoreinfo, "%s%s\n", STR_OSRELEASE,
	    info->release);

	/*
	 * write 1st kernel's PAGESIZE
	 */
	fprintf(info->file_vmcoreinfo, "%s%ld\n", STR_PAGESIZE,
	    info->page_size);

	/*
	 * write the symbol of 1st kernel
	 */
	WRITE_SYMBOL("mem_map", mem_map);
	WRITE_SYMBOL("vmem_map", vmem_map);
	WRITE_SYMBOL("mem_section", mem_section);
	WRITE_SYMBOL("pkmap_count", pkmap_count);
	WRITE_SYMBOL("pkmap_count_next", pkmap_count_next);
	WRITE_SYMBOL("system_utsname", system_utsname);
	WRITE_SYMBOL("init_uts_ns", init_uts_ns);
	WRITE_SYMBOL("_stext", _stext);
	WRITE_SYMBOL("swapper_pg_dir", swapper_pg_dir);
	WRITE_SYMBOL("init_level4_pgt", init_level4_pgt);
	WRITE_SYMBOL("vmlist", vmlist);
	WRITE_SYMBOL("phys_base", phys_base);
	WRITE_SYMBOL("node_online_map", node_online_map);
	WRITE_SYMBOL("node_states", node_states);
	WRITE_SYMBOL("node_data", node_data);
	WRITE_SYMBOL("pgdat_list", pgdat_list);
	WRITE_SYMBOL("contig_page_data", contig_page_data);
	WRITE_SYMBOL("log_buf", log_buf);
	WRITE_SYMBOL("log_buf_len", log_buf_len);
	WRITE_SYMBOL("log_end", log_end);

	/*
	 * write the structure size of 1st kernel
	 */
	WRITE_STRUCTURE_SIZE("page", page);
	WRITE_STRUCTURE_SIZE("mem_section", mem_section);
	WRITE_STRUCTURE_SIZE("pglist_data", pglist_data);
	WRITE_STRUCTURE_SIZE("zone", zone);
	WRITE_STRUCTURE_SIZE("free_area", free_area);
	WRITE_STRUCTURE_SIZE("list_head", list_head);
	WRITE_STRUCTURE_SIZE("node_memblk_s", node_memblk_s);
	WRITE_STRUCTURE_SIZE("nodemask_t", nodemask_t);

	/*
	 * write the member offset of 1st kernel
	 */
	WRITE_MEMBER_OFFSET("page.flags", page.flags);
	WRITE_MEMBER_OFFSET("page._count", page._count);
	WRITE_MEMBER_OFFSET("page.mapping", page.mapping);
	WRITE_MEMBER_OFFSET("page.lru", page.lru);
	WRITE_MEMBER_OFFSET("mem_section.section_mem_map",
	    mem_section.section_mem_map);
	WRITE_MEMBER_OFFSET("pglist_data.node_zones", pglist_data.node_zones);
	WRITE_MEMBER_OFFSET("pglist_data.nr_zones", pglist_data.nr_zones);
	WRITE_MEMBER_OFFSET("pglist_data.node_mem_map",
	    pglist_data.node_mem_map);
	WRITE_MEMBER_OFFSET("pglist_data.node_start_pfn",
	    pglist_data.node_start_pfn);
	WRITE_MEMBER_OFFSET("pglist_data.node_spanned_pages",
	    pglist_data.node_spanned_pages);
	WRITE_MEMBER_OFFSET("pglist_data.pgdat_next", pglist_data.pgdat_next);
	WRITE_MEMBER_OFFSET("zone.free_pages", zone.free_pages);
	WRITE_MEMBER_OFFSET("zone.free_area", zone.free_area);
	WRITE_MEMBER_OFFSET("zone.vm_stat", zone.vm_stat);
	WRITE_MEMBER_OFFSET("zone.spanned_pages", zone.spanned_pages);
	WRITE_MEMBER_OFFSET("free_area.free_list", free_area.free_list);
	WRITE_MEMBER_OFFSET("list_head.next", list_head.next);
	WRITE_MEMBER_OFFSET("list_head.prev", list_head.prev);
	WRITE_MEMBER_OFFSET("node_memblk_s.start_paddr", node_memblk_s.start_paddr);
	WRITE_MEMBER_OFFSET("node_memblk_s.size", node_memblk_s.size);
	WRITE_MEMBER_OFFSET("node_memblk_s.nid", node_memblk_s.nid);
	WRITE_MEMBER_OFFSET("vm_struct.addr", vm_struct.addr);

	if (SYMBOL(node_data) != NOT_FOUND_SYMBOL)
		WRITE_ARRAY_LENGTH("node_data", node_data);
	if (SYMBOL(pgdat_list) != NOT_FOUND_SYMBOL)
		WRITE_ARRAY_LENGTH("pgdat_list", pgdat_list);
	if (SYMBOL(mem_section) != NOT_FOUND_SYMBOL)
		WRITE_ARRAY_LENGTH("mem_section", mem_section);
	if (SYMBOL(node_memblk) != NOT_FOUND_SYMBOL)
		WRITE_ARRAY_LENGTH("node_memblk", node_memblk);

	WRITE_ARRAY_LENGTH("zone.free_area", zone.free_area);
	WRITE_ARRAY_LENGTH("free_area.free_list", free_area.free_list);

	WRITE_NUMBER("NR_FREE_PAGES", NR_FREE_PAGES);
	WRITE_NUMBER("N_ONLINE", N_ONLINE);

	WRITE_NUMBER("PG_lru", PG_lru);
	WRITE_NUMBER("PG_private", PG_private);
	WRITE_NUMBER("PG_swapcache", PG_swapcache);

	/*
	 * write the source file of 1st kernel
	 */
	WRITE_SRCFILE("pud_t", pud_t);

	return TRUE;
}

int
read_vmcoreinfo_basic_info(void)
{
	time_t tv_sec = 0;
	long page_size = FALSE;
	char buf[BUFSIZE_FGETS], *endp;
	unsigned int get_release = FALSE, i;

	if (fseek(info->file_vmcoreinfo, 0, SEEK_SET) < 0) {
		ERRMSG("Can't seek the vmcoreinfo file(%s). %s\n",
		    info->name_vmcoreinfo, strerror(errno));
		return FALSE;
	}

	while (fgets(buf, BUFSIZE_FGETS, info->file_vmcoreinfo)) {
		i = strlen(buf);
		if (!i)
			break;
		if (buf[i - 1] == '\n')
			buf[i - 1] = '\0';
		if (strncmp(buf, STR_OSRELEASE, strlen(STR_OSRELEASE)) == 0) {
			get_release = TRUE;
			/* if the release have been stored, skip this time. */
			if (strlen(info->release))
				continue;
			strcpy(info->release, buf + strlen(STR_OSRELEASE));
		}
		if (strncmp(buf, STR_PAGESIZE, strlen(STR_PAGESIZE)) == 0) {
			page_size = strtol(buf+strlen(STR_PAGESIZE),&endp,10);
			if ((!page_size || page_size == LONG_MAX)
			    || strlen(endp) != 0) {
				ERRMSG("Invalid data in %s: %s",
				    info->name_vmcoreinfo, buf);
				return FALSE;
			}
			if (!set_page_size(page_size)) {
				ERRMSG("Invalid data in %s: %s",
				    info->name_vmcoreinfo, buf);
				return FALSE;
			}
		}
		if (strncmp(buf, STR_CRASHTIME, strlen(STR_CRASHTIME)) == 0) {
			tv_sec = strtol(buf+strlen(STR_CRASHTIME),&endp,10);
			if ((!tv_sec || tv_sec == LONG_MAX)
			    || strlen(endp) != 0) {
				ERRMSG("Invalid data in %s: %s",
				    info->name_vmcoreinfo, buf);
				return FALSE;
			}
			info->timestamp.tv_sec = tv_sec;
		}
		if (strncmp(buf, STR_CONFIG_X86_PAE,
		    strlen(STR_CONFIG_X86_PAE)) == 0)
			vt.mem_flags |= MEMORY_X86_PAE;

		if (strncmp(buf, STR_CONFIG_PGTABLE_3,
		    strlen(STR_CONFIG_PGTABLE_3)) == 0)
			vt.mem_flags |= MEMORY_PAGETABLE_3L;

		if (strncmp(buf, STR_CONFIG_PGTABLE_4,
		    strlen(STR_CONFIG_PGTABLE_4)) == 0)
			vt.mem_flags |= MEMORY_PAGETABLE_4L;
	}
	if (!get_release || !info->page_size) {
		ERRMSG("Invalid format in %s", info->name_vmcoreinfo);
		return FALSE;
	}
	return TRUE;
}

unsigned long
read_vmcoreinfo_symbol(char *str_symbol)
{
	unsigned long symbol = NOT_FOUND_SYMBOL;
	char buf[BUFSIZE_FGETS], *endp;
	unsigned int i;

	if (fseek(info->file_vmcoreinfo, 0, SEEK_SET) < 0) {
		ERRMSG("Can't seek the vmcoreinfo file(%s). %s\n",
		    info->name_vmcoreinfo, strerror(errno));
		return INVALID_SYMBOL_DATA;
	}

	while (fgets(buf, BUFSIZE_FGETS, info->file_vmcoreinfo)) {
		i = strlen(buf);
		if (!i)
			break;
		if (buf[i - 1] == '\n')
			buf[i - 1] = '\0';
		if (strncmp(buf, str_symbol, strlen(str_symbol)) == 0) {
			symbol = strtoul(buf + strlen(str_symbol), &endp, 16);
			if ((!symbol || symbol == ULONG_MAX)
			    || strlen(endp) != 0) {
				ERRMSG("Invalid data in %s: %s",
				    info->name_vmcoreinfo, buf);
				return INVALID_SYMBOL_DATA;
			}
			break;
		}
	}
	return symbol;
}

long
read_vmcoreinfo_long(char *str_structure)
{
	long data = NOT_FOUND_LONG_VALUE;
	char buf[BUFSIZE_FGETS], *endp;
	unsigned int i;

	if (fseek(info->file_vmcoreinfo, 0, SEEK_SET) < 0) {
		ERRMSG("Can't seek the vmcoreinfo file(%s). %s\n",
		    info->name_vmcoreinfo, strerror(errno));
		return INVALID_STRUCTURE_DATA;
	}

	while (fgets(buf, BUFSIZE_FGETS, info->file_vmcoreinfo)) {
		i = strlen(buf);
		if (!i)
			break;
		if (buf[i - 1] == '\n')
			buf[i - 1] = '\0';
		if (strncmp(buf, str_structure, strlen(str_structure)) == 0) {
			data = strtol(buf + strlen(str_structure), &endp, 10);
			if ((data == LONG_MAX) || strlen(endp) != 0) {
				ERRMSG("Invalid data in %s: %s",
				    info->name_vmcoreinfo, buf);
				return INVALID_STRUCTURE_DATA;
			}
			break;
		}
	}
	return data;
}

int
read_vmcoreinfo_string(char *str_in, char *str_out)
{
	char buf[BUFSIZE_FGETS];
	unsigned int i;

	if (fseek(info->file_vmcoreinfo, 0, SEEK_SET) < 0) {
		ERRMSG("Can't seek the vmcoreinfo file(%s). %s\n",
		    info->name_vmcoreinfo, strerror(errno));
		return FALSE;
	}

	while (fgets(buf, BUFSIZE_FGETS, info->file_vmcoreinfo)) {
		i = strlen(buf);
		if (!i)
			break;
		if (buf[i - 1] == '\n')
			buf[i - 1] = '\0';
		if (strncmp(buf, str_in, strlen(str_in)) == 0) {
			strncpy(str_out, buf + strlen(str_in), LEN_SRCFILE - strlen(str_in));
			break;
		}
	}
	return TRUE;
}

int
read_vmcoreinfo(void)
{
	if (!read_vmcoreinfo_basic_info())
		return FALSE;

	READ_SYMBOL("mem_map", mem_map);
	READ_SYMBOL("vmem_map", vmem_map);
	READ_SYMBOL("mem_section", mem_section);
	READ_SYMBOL("pkmap_count", pkmap_count);
	READ_SYMBOL("pkmap_count_next", pkmap_count_next);
	READ_SYMBOL("system_utsname", system_utsname);
	READ_SYMBOL("init_uts_ns", init_uts_ns);
	READ_SYMBOL("_stext", _stext);
	READ_SYMBOL("swapper_pg_dir", swapper_pg_dir);
	READ_SYMBOL("init_level4_pgt", init_level4_pgt);
	READ_SYMBOL("vmlist", vmlist);
	READ_SYMBOL("phys_base", phys_base);
	READ_SYMBOL("node_online_map", node_online_map);
	READ_SYMBOL("node_states", node_states);
	READ_SYMBOL("node_data", node_data);
	READ_SYMBOL("pgdat_list", pgdat_list);
	READ_SYMBOL("contig_page_data", contig_page_data);
	READ_SYMBOL("log_buf", log_buf);
	READ_SYMBOL("log_buf_len", log_buf_len);
	READ_SYMBOL("log_end", log_end);

	READ_STRUCTURE_SIZE("page", page);
	READ_STRUCTURE_SIZE("mem_section", mem_section);
	READ_STRUCTURE_SIZE("pglist_data", pglist_data);
	READ_STRUCTURE_SIZE("zone", zone);
	READ_STRUCTURE_SIZE("free_area", free_area);
	READ_STRUCTURE_SIZE("list_head", list_head);
	READ_STRUCTURE_SIZE("node_memblk_s", node_memblk_s);
	READ_STRUCTURE_SIZE("nodemask_t", nodemask_t);

	READ_MEMBER_OFFSET("page.flags", page.flags);
	READ_MEMBER_OFFSET("page._count", page._count);
	READ_MEMBER_OFFSET("page.mapping", page.mapping);
	READ_MEMBER_OFFSET("page.lru", page.lru);
	READ_MEMBER_OFFSET("mem_section.section_mem_map",
	    mem_section.section_mem_map);
	READ_MEMBER_OFFSET("pglist_data.node_zones", pglist_data.node_zones);
	READ_MEMBER_OFFSET("pglist_data.nr_zones", pglist_data.nr_zones);
	READ_MEMBER_OFFSET("pglist_data.node_mem_map",pglist_data.node_mem_map);
	READ_MEMBER_OFFSET("pglist_data.node_start_pfn",
	    pglist_data.node_start_pfn);
	READ_MEMBER_OFFSET("pglist_data.node_spanned_pages",
	    pglist_data.node_spanned_pages);
	READ_MEMBER_OFFSET("pglist_data.pgdat_next", pglist_data.pgdat_next);
	READ_MEMBER_OFFSET("zone.free_pages", zone.free_pages);
	READ_MEMBER_OFFSET("zone.free_area", zone.free_area);
	READ_MEMBER_OFFSET("zone.vm_stat", zone.vm_stat);
	READ_MEMBER_OFFSET("zone.spanned_pages", zone.spanned_pages);
	READ_MEMBER_OFFSET("free_area.free_list", free_area.free_list);
	READ_MEMBER_OFFSET("list_head.next", list_head.next);
	READ_MEMBER_OFFSET("list_head.prev", list_head.prev);
	READ_MEMBER_OFFSET("node_memblk_s.start_paddr", node_memblk_s.start_paddr);
	READ_MEMBER_OFFSET("node_memblk_s.size", node_memblk_s.size);
	READ_MEMBER_OFFSET("node_memblk_s.nid", node_memblk_s.nid);
	READ_MEMBER_OFFSET("vm_struct.addr", vm_struct.addr);

	READ_ARRAY_LENGTH("node_data", node_data);
	READ_ARRAY_LENGTH("pgdat_list", pgdat_list);
	READ_ARRAY_LENGTH("mem_section", mem_section);
	READ_ARRAY_LENGTH("node_memblk", node_memblk);
	READ_ARRAY_LENGTH("zone.free_area", zone.free_area);
	READ_ARRAY_LENGTH("free_area.free_list", free_area.free_list);

	READ_NUMBER("NR_FREE_PAGES", NR_FREE_PAGES);
	READ_NUMBER("N_ONLINE", N_ONLINE);

	READ_NUMBER("PG_lru", PG_lru);
	READ_NUMBER("PG_private", PG_private);
	READ_NUMBER("PG_swapcache", PG_swapcache);

	READ_SRCFILE("pud_t", pud_t);

	return TRUE;
}

int
get_pt_note_info(off_t off_note, unsigned long sz_note)
{
	int n_type;
	off_t offset;
	char buf[VMCOREINFO_XEN_NOTE_NAME_BYTES];
	Elf64_Nhdr note64;
	Elf32_Nhdr note32;

	const off_t failed = (off_t)-1;

	offset = off_note;
	n_type = 0;
	while (offset < off_note + sz_note) {
		if (lseek(info->fd_memory, offset, SEEK_SET) == failed) {
			ERRMSG("Can't seek the dump memory(%s). %s\n",
			    info->name_memory, strerror(errno));
			return FALSE;
		}
		if (info->flag_elf64_memory) {
			if (read(info->fd_memory, &note64, sizeof(note64))
			    != sizeof(note64)) {
				ERRMSG("Can't read the dump memory(%s). %s\n",
				    info->name_memory, strerror(errno));
				return FALSE;
			}
			n_type = note64.n_type;
		} else {
			if (read(info->fd_memory, &note32, sizeof(note32))
			    != sizeof(note32)) {
				ERRMSG("Can't read the dump memory(%s). %s\n",
				    info->name_memory, strerror(errno));
				return FALSE;
			}
			n_type = note32.n_type;
		}
		if (read(info->fd_memory, &buf, sizeof(buf)) != sizeof(buf)) {
			ERRMSG("Can't read the dump memory(%s). %s\n",
			    info->name_memory, strerror(errno));
			return FALSE;
		}
		/*
		 * Check whether /proc/vmcore contains vmcoreinfo,
		 * and get both the offset and the size.
		 *
		 * NOTE: The owner name of xen should be checked at first,
		 *       because its name is "VMCOREINFO_XEN" and the one
		 *       of linux is "VMCOREINFO".
		 */
		if (!strncmp(VMCOREINFO_XEN_NOTE_NAME, buf,
		    VMCOREINFO_XEN_NOTE_NAME_BYTES)) {
			if (info->flag_elf64_memory) {
				info->offset_vmcoreinfo_xen = offset
				    + (sizeof(note64)
				    + ((note64.n_namesz + 3) & ~3));
				info->size_vmcoreinfo_xen = note64.n_descsz;
			} else {
				info->offset_vmcoreinfo_xen = offset
				    + (sizeof(note32)
				    + ((note32.n_namesz + 3) & ~3));
				info->size_vmcoreinfo_xen = note32.n_descsz;
			}
		} else if (!strncmp(VMCOREINFO_NOTE_NAME, buf,
		    VMCOREINFO_NOTE_NAME_BYTES)) {
			if (info->flag_elf64_memory) {
				info->offset_vmcoreinfo = offset
				    + (sizeof(note64)
				    + ((note64.n_namesz + 3) & ~3));
				info->size_vmcoreinfo = note64.n_descsz;
			} else {
				info->offset_vmcoreinfo = offset
				    + (sizeof(note32)
				    + ((note32.n_namesz + 3) & ~3));
				info->size_vmcoreinfo = note32.n_descsz;
			}
		/*
		 * Check whether /proc/vmcore contains xen's note.
		 */
		} else if (n_type == XEN_ELFNOTE_CRASH_INFO) {
			vt.mem_flags |= MEMORY_XEN;
			if (info->flag_elf64_memory) {
				info->offset_xen_crash_info = offset
				    + (sizeof(note64)
				    + ((note64.n_namesz + 3) & ~3));
				info->size_xen_crash_info = note64.n_descsz;
			} else {
				info->offset_xen_crash_info = offset
				    + (sizeof(note32)
				    + ((note32.n_namesz + 3) & ~3));
				info->size_xen_crash_info = note32.n_descsz;
			}
		}

		if (info->flag_elf64_memory) {
			offset += sizeof(Elf64_Nhdr)
			    + ((note64.n_namesz + 3) & ~3)
			    + ((note64.n_descsz + 3) & ~3);
		} else {
			offset += sizeof(Elf32_Nhdr)
			    + ((note32.n_namesz + 3) & ~3)
			    + ((note32.n_descsz + 3) & ~3);
		}
	}
	if (vt.mem_flags & MEMORY_XEN)
		DEBUG_MSG("Xen kdump\n");
	else
		DEBUG_MSG("Linux kdump\n");

	return TRUE;
}

/*
 * Extract vmcoreinfo from /proc/vmcore and output it to /tmp/vmcoreinfo.tmp.
 */
int
copy_vmcoreinfo(off_t offset, unsigned long size)
{
	int fd;
	char buf[VMCOREINFO_BYTES];
	const off_t failed = (off_t)-1;

	if (!offset || !size)
		return FALSE;

	if ((fd = mkstemp(info->name_vmcoreinfo)) < 0) {
		ERRMSG("Can't open the vmcoreinfo file(%s). %s\n",
		    info->name_vmcoreinfo, strerror(errno));
		return FALSE;
	}
	if (lseek(info->fd_memory, offset, SEEK_SET) == failed) {
		ERRMSG("Can't seek the dump memory(%s). %s\n",
		    info->name_memory, strerror(errno));
		return FALSE;
	}
	if (read(info->fd_memory, &buf, size) != size) {
		ERRMSG("Can't read the dump memory(%s). %s\n",
		    info->name_memory, strerror(errno));
		return FALSE;
	}
	if (write(fd, &buf, size) != size) {
		ERRMSG("Can't write the vmcoreinfo file(%s). %s\n",
		    info->name_vmcoreinfo, strerror(errno));
		return FALSE;
	}
	if (close(fd) < 0) {
		ERRMSG("Can't close the vmcoreinfo file(%s). %s\n",
		    info->name_vmcoreinfo, strerror(errno));
		return FALSE;
	}
	return TRUE;
}

int
read_vmcoreinfo_from_vmcore(off_t offset, unsigned long size, int flag_xen_hv)
{
	int ret = FALSE;

	/*
	 * Copy vmcoreinfo to /tmp/vmcoreinfoXXXXXX.
	 */
	if (!(info->name_vmcoreinfo = strdup(FILENAME_VMCOREINFO))) {
		MSG("Can't duplicate strings(%s).\n", FILENAME_VMCOREINFO);
		return FALSE;
	}
	if (!copy_vmcoreinfo(offset, size))
		goto out;

	/*
	 * Read vmcoreinfo from /tmp/vmcoreinfoXXXXXX.
	 */
	if (!open_vmcoreinfo("r"))
		goto out;

	unlink(info->name_vmcoreinfo);

	if (flag_xen_hv) {
		if (!read_vmcoreinfo_xen())
			goto out;
	} else {
		if (!read_vmcoreinfo())
			goto out;
	}
	close_vmcoreinfo();

	ret = TRUE;
out:
	free(info->name_vmcoreinfo);
	info->name_vmcoreinfo = NULL;

	return ret;
}

/*
 * Get the number of online nodes.
 */
int
get_nodes_online(void)
{
	int len, i, j, online;
	unsigned long node_online_map = 0, bitbuf, *maskptr;

	if ((SYMBOL(node_online_map) == NOT_FOUND_SYMBOL)
	    && (SYMBOL(node_states) == NOT_FOUND_SYMBOL))
		return 0;

	if (SIZE(nodemask_t) == NOT_FOUND_STRUCTURE) {
		ERRMSG("Can't get the size of nodemask_t.\n");
		return 0;
	}

	len = SIZE(nodemask_t);
	vt.node_online_map_len = len/sizeof(unsigned long);
	if (!(vt.node_online_map = (unsigned long *)malloc(len))) {
		ERRMSG("Can't allocate memory for the node online map. %s\n",
		    strerror(errno));
		return 0;
	}
	if (SYMBOL(node_online_map) != NOT_FOUND_SYMBOL) {
		node_online_map = SYMBOL(node_online_map);
	} else if (SYMBOL(node_states) != NOT_FOUND_SYMBOL) {
		/*
		 * For linux-2.6.23-rc4-mm1
		 */
		node_online_map = SYMBOL(node_states)
		     + (SIZE(nodemask_t) * NUMBER(N_ONLINE));
	}
	if (!readmem(VADDR, node_online_map, vt.node_online_map, len)){
		ERRMSG("Can't get the node online map.\n");
		return 0;
	}
	online = 0;
	maskptr = (unsigned long *)vt.node_online_map;
	for (i = 0; i < vt.node_online_map_len; i++, maskptr++) {
		bitbuf = *maskptr;
		for (j = 0; j < sizeof(bitbuf) * 8; j++) {
			online += bitbuf & 1;
			bitbuf = bitbuf >> 1;
		}
	}
	return online;
}

int
get_numnodes(void)
{
	if (!(vt.numnodes = get_nodes_online())) {
		vt.numnodes = 1;
	}
	DEBUG_MSG("\n");
	DEBUG_MSG("num of NODEs : %d\n", vt.numnodes);
	DEBUG_MSG("\n");

	return TRUE;
}

int
next_online_node(int first)
{
	int i, j, node;
	unsigned long mask, *maskptr;

	/* It cannot occur */
	if ((first/(sizeof(unsigned long) * 8)) >= vt.node_online_map_len) {
		ERRMSG("next_online_node: %d is too large!\n", first);
		return -1;
	}

	maskptr = (unsigned long *)vt.node_online_map;
	for (i = node = 0; i <  vt.node_online_map_len; i++, maskptr++) {
		mask = *maskptr;
		for (j = 0; j < (sizeof(unsigned long) * 8); j++, node++) {
			if (mask & 1) {
				if (node >= first)
					return node;
			}
			mask >>= 1;
		}
	}
	return -1;
}

unsigned long
next_online_pgdat(int node)
{
	int i;
	unsigned long pgdat;

	/*
	 * Get the pglist_data structure from symbol "node_data".
	 *     The array number of symbol "node_data" cannot be gotten
	 *     from vmlinux. Instead, check it is DW_TAG_array_type.
	 */
	if ((SYMBOL(node_data) == NOT_FOUND_SYMBOL)
	    || (ARRAY_LENGTH(node_data) == NOT_FOUND_STRUCTURE))
		goto pgdat2;

	if (!readmem(VADDR, SYMBOL(node_data) + (node * sizeof(void *)),
	    &pgdat, sizeof pgdat))
		goto pgdat2;

	if (!is_kvaddr(pgdat))
		goto pgdat2;

	return pgdat;

pgdat2:
	/*
	 * Get the pglist_data structure from symbol "pgdat_list".
	 */
	if (SYMBOL(pgdat_list) == NOT_FOUND_SYMBOL)
		goto pgdat3;

	else if ((0 < node)
	    && (ARRAY_LENGTH(pgdat_list) == NOT_FOUND_STRUCTURE))
		goto pgdat3;

	else if ((ARRAY_LENGTH(pgdat_list) != NOT_FOUND_STRUCTURE)
	    && (ARRAY_LENGTH(pgdat_list) < node))
		goto pgdat3;

	if (!readmem(VADDR, SYMBOL(pgdat_list) + (node * sizeof(void *)),
	    &pgdat, sizeof pgdat))
		goto pgdat3;

	if (!is_kvaddr(pgdat))
		goto pgdat3;

	return pgdat;

pgdat3:
	/*
	 * linux-2.6.16 or former
	 */
	if ((SYMBOL(pgdat_list) == NOT_FOUND_SYMBOL)
	    || (OFFSET(pglist_data.pgdat_next) == NOT_FOUND_STRUCTURE))
		goto pgdat4;

	if (!readmem(VADDR, SYMBOL(pgdat_list), &pgdat, sizeof pgdat))
		goto pgdat4;

	if (!is_kvaddr(pgdat))
		goto pgdat4;

	if (node == 0)
		return pgdat;

	for (i = 1; i <= node; i++) {
		if (!readmem(VADDR, pgdat+OFFSET(pglist_data.pgdat_next),
		    &pgdat, sizeof pgdat))
			goto pgdat4;

		if (!is_kvaddr(pgdat))
			goto pgdat4;
	}
	return pgdat;

pgdat4:
	/*
	 * Get the pglist_data structure from symbol "contig_page_data".
	 */
	if (SYMBOL(contig_page_data) == NOT_FOUND_SYMBOL)
		return FALSE;

	if (node != 0)
		return FALSE;

	return SYMBOL(contig_page_data);
}

void
dump_mem_map(unsigned long long pfn_start,
    unsigned long long pfn_end, unsigned long mem_map, int num_mm)
{
	struct mem_map_data *mmd;

	mmd = &info->mem_map_data[num_mm];
	mmd->pfn_start = pfn_start;
	mmd->pfn_end   = pfn_end;
	mmd->mem_map   = mem_map;

	DEBUG_MSG("mem_map (%d)\n", num_mm);
	DEBUG_MSG("  mem_map    : %lx\n", mem_map);
	DEBUG_MSG("  pfn_start  : %llx\n", pfn_start);
	DEBUG_MSG("  pfn_end    : %llx\n", pfn_end);

	return;
}

int
get_mm_flatmem(void)
{
	unsigned long mem_map;

	/*
	 * Get the address of the symbol "mem_map".
	 */
	if (!readmem(VADDR, SYMBOL(mem_map), &mem_map, sizeof mem_map)
	    || !mem_map) {
		ERRMSG("Can't get the address of mem_map.\n");
		return FALSE;
	}
	info->num_mem_map = 1;
	if ((info->mem_map_data = (struct mem_map_data *)
	    malloc(sizeof(struct mem_map_data)*info->num_mem_map)) == NULL) {
		ERRMSG("Can't allocate memory for the mem_map_data. %s\n",
		    strerror(errno));
		return FALSE;
	}
	dump_mem_map(0, info->max_mapnr, mem_map, 0);

	return TRUE;
}

int
get_node_memblk(int num_memblk,
    unsigned long *start_paddr, unsigned long *size, int *nid)
{
	unsigned long node_memblk;

	if (ARRAY_LENGTH(node_memblk) <= num_memblk) {
		ERRMSG("Invalid num_memblk.\n");
		return FALSE;
	}
	node_memblk = SYMBOL(node_memblk) + SIZE(node_memblk_s) * num_memblk;
	if (!readmem(VADDR, node_memblk+OFFSET(node_memblk_s.start_paddr),
	    start_paddr, sizeof(unsigned long))) {
		ERRMSG("Can't get node_memblk_s.start_paddr.\n");
		return FALSE;
	}
	if (!readmem(VADDR, node_memblk + OFFSET(node_memblk_s.size),
	    size, sizeof(unsigned long))) {
		ERRMSG("Can't get node_memblk_s.size.\n");
		return FALSE;
	}
	if (!readmem(VADDR, node_memblk + OFFSET(node_memblk_s.nid),
	    nid, sizeof(int))) {
		ERRMSG("Can't get node_memblk_s.nid.\n");
		return FALSE;
	}
	return TRUE;
}

int
get_num_mm_discontigmem(void)
{
	int i, nid;
	unsigned long start_paddr, size;

	if ((SYMBOL(node_memblk) == NOT_FOUND_SYMBOL)
	    || (ARRAY_LENGTH(node_memblk) == NOT_FOUND_STRUCTURE)
	    || (SIZE(node_memblk_s) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(node_memblk_s.start_paddr) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(node_memblk_s.size) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(node_memblk_s.nid) == NOT_FOUND_STRUCTURE)) {
		return vt.numnodes;
	} else {
		for (i = 0; i < ARRAY_LENGTH(node_memblk); i++) {
			if (!get_node_memblk(i, &start_paddr, &size, &nid)) {
				ERRMSG("Can't get the node_memblk (%d)\n", i);
				return 0;
			}
			if (!start_paddr && !size &&!nid)
				break;

			DEBUG_MSG("nid : %d\n", nid);
			DEBUG_MSG("  start_paddr: %lx\n", start_paddr);
			DEBUG_MSG("  size       : %lx\n", size);
		}
		if (i == 0) {
			/*
			 * On non-NUMA systems, node_memblk_s is not set.
			 */
			return vt.numnodes;
		} else {
			return i;
		}
	}
}

int
separate_mem_map(struct mem_map_data *mmd, int *id_mm, int nid_pgdat,
    unsigned long mem_map_pgdat, unsigned long pfn_start_pgdat)
{
	int i, nid;
	unsigned long start_paddr, size, pfn_start, pfn_end, mem_map;

	for (i = 0; i < ARRAY_LENGTH(node_memblk); i++) {
		if (!get_node_memblk(i, &start_paddr, &size, &nid)) {
			ERRMSG("Can't get the node_memblk (%d)\n", i);
			return FALSE;
		}
		if (!start_paddr && !size && !nid)
			break;

		/*
		 * Check pglist_data.node_id and node_memblk_s.nid match.
		 */
		if (nid_pgdat != nid)
			continue;

		pfn_start = start_paddr / info->page_size;
		pfn_end   = pfn_start + (size / info->page_size);

		if (pfn_start < pfn_start_pgdat) {
			ERRMSG("node_memblk_s.start_paddr of node (%d) is invalid.\n", nid);
			return FALSE;
		}
		if (info->max_mapnr < pfn_end) {
			DEBUG_MSG("pfn_end of node (%d) is over max_mapnr.\n",
			    nid);
			DEBUG_MSG("  pfn_start: %lx\n", pfn_start);
			DEBUG_MSG("  pfn_end  : %lx\n", pfn_end);
			DEBUG_MSG("  max_mapnr: %llx\n", info->max_mapnr);

			pfn_end = info->max_mapnr;
		}

		mem_map = mem_map_pgdat+SIZE(page)*(pfn_start-pfn_start_pgdat);

		mmd->pfn_start = pfn_start;
		mmd->pfn_end   = pfn_end;
		mmd->mem_map   = mem_map;

		mmd++;
		(*id_mm)++;
	}
	return TRUE;
}

int
get_mm_discontigmem(void)
{
	int i, j, id_mm, node, num_mem_map, separate_mm = FALSE;
	unsigned long pgdat, mem_map, pfn_start, pfn_end, node_spanned_pages;
	unsigned long vmem_map;
	struct mem_map_data temp_mmd;

	num_mem_map = get_num_mm_discontigmem();
	if (num_mem_map < vt.numnodes) {
		ERRMSG("Can't get the number of mem_map.\n");
		return FALSE;
	}
	struct mem_map_data mmd[num_mem_map];
	if (vt.numnodes < num_mem_map) {
		separate_mm = TRUE;
	}

	/*
	 * Note:
	 *  This note is only for ia64 discontigmem kernel.
	 *  It is better to take mem_map information from a symbol vmem_map
	 *  instead of pglist_data.node_mem_map, because some node_mem_map
	 *  sometimes does not have mem_map information corresponding to its
	 *  node_start_pfn.
	 */
	if (SYMBOL(vmem_map) != NOT_FOUND_SYMBOL) {
		if (!readmem(VADDR, SYMBOL(vmem_map), &vmem_map, sizeof vmem_map)) {
			ERRMSG("Can't get vmem_map.\n");
			return FALSE;
		}
	}

	/*
	 * Get the first node_id.
	 */
	if ((node = next_online_node(0)) < 0) {
		ERRMSG("Can't get next online node.\n");
		return FALSE;
	}
	if (!(pgdat = next_online_pgdat(node))) {
		ERRMSG("Can't get pgdat list.\n");
		return FALSE;
	}
	id_mm = 0;
	for (i = 0; i < vt.numnodes; i++) {
		if (!readmem(VADDR, pgdat + OFFSET(pglist_data.node_start_pfn),
		    &pfn_start, sizeof pfn_start)) {
			ERRMSG("Can't get node_start_pfn.\n");
			return FALSE;
		}
		if (!readmem(VADDR,pgdat+OFFSET(pglist_data.node_spanned_pages),
		    &node_spanned_pages, sizeof node_spanned_pages)) {
			ERRMSG("Can't get node_spanned_pages.\n");
			return FALSE;
		}
		pfn_end = pfn_start + node_spanned_pages;

		if (SYMBOL(vmem_map) == NOT_FOUND_SYMBOL) {
			if (!readmem(VADDR, pgdat + OFFSET(pglist_data.node_mem_map),
			    &mem_map, sizeof mem_map)) {
				ERRMSG("Can't get mem_map.\n");
				return FALSE;
			}
		} else
			mem_map = vmem_map + (SIZE(page) * pfn_start);

		if (separate_mm) {
			/*
			 * For some ia64 NUMA systems.
			 * On some systems, a node has the separated memory.
			 * And pglist_data(s) have the duplicated memory range
			 * like following:
			 *
			 * Nid:      Physical address
			 *  0 : 0x1000000000 - 0x2000000000
			 *  1 : 0x2000000000 - 0x3000000000
			 *  2 : 0x0000000000 - 0x6020000000 <- Overlapping
			 *  3 : 0x3000000000 - 0x4000000000
			 *  4 : 0x4000000000 - 0x5000000000
			 *  5 : 0x5000000000 - 0x6000000000
			 *
			 * Then, mem_map(s) should be separated by
			 * node_memblk_s info.
			 */
			if (!separate_mem_map(&mmd[id_mm], &id_mm, node,
			    mem_map, pfn_start)) {
				ERRMSG("Can't separate mem_map.\n");
				return FALSE;
			}
		} else {
			if (info->max_mapnr < pfn_end) {
				DEBUG_MSG("pfn_end of node (%d) is over max_mapnr.\n",
				    node);
				DEBUG_MSG("  pfn_start: %lx\n", pfn_start);
				DEBUG_MSG("  pfn_end  : %lx\n", pfn_end);
				DEBUG_MSG("  max_mapnr: %llx\n", info->max_mapnr);

				pfn_end = info->max_mapnr;
			}

			/*
			 * The number of mem_map is the same as the number
			 * of nodes.
			 */
			mmd[id_mm].pfn_start = pfn_start;
			mmd[id_mm].pfn_end   = pfn_end;
			mmd[id_mm].mem_map   = mem_map;
			id_mm++;
		}

		/*
		 * Get pglist_data of the next node.
		 */
		if (i < (vt.numnodes - 1)) {
			if ((node = next_online_node(node + 1)) < 0) {
				ERRMSG("Can't get next online node.\n");
				return FALSE;
			} else if (!(pgdat = next_online_pgdat(node))) {
				ERRMSG("Can't determine pgdat list (node %d).\n",
				    node);
				return FALSE;
			}
		}
	}

	/*
	 * Sort mem_map by pfn_start.
	 */
	for (i = 0; i < (num_mem_map - 1); i++) {
		for (j = i + 1; j < num_mem_map; j++) {
			if (mmd[j].pfn_start < mmd[i].pfn_start) {
				temp_mmd = mmd[j];
				mmd[j] = mmd[i];
				mmd[i] = temp_mmd;
			}
		}
	}

	/*
	 * Calculate the number of mem_map.
	 */
	info->num_mem_map = num_mem_map;
	if (mmd[0].pfn_start != 0)
		info->num_mem_map++;

	for (i = 0; i < num_mem_map - 1; i++) {
		if (mmd[i].pfn_end > mmd[i + 1].pfn_start) {
			ERRMSG("The mem_map is overlapped with the next one.\n");
			ERRMSG("mmd[%d].pfn_end   = %llx\n", i, mmd[i].pfn_end);
			ERRMSG("mmd[%d].pfn_start = %llx\n", i + 1, mmd[i + 1].pfn_start);
			return FALSE;
		} else if (mmd[i].pfn_end == mmd[i + 1].pfn_start)
			/*
			 * Continuous mem_map
			 */
			continue;

		/*
		 * Discontinuous mem_map
		 */
		info->num_mem_map++;
	}
	if (mmd[num_mem_map - 1].pfn_end < info->max_mapnr)
		info->num_mem_map++;

	if ((info->mem_map_data = (struct mem_map_data *)
	    malloc(sizeof(struct mem_map_data)*info->num_mem_map)) == NULL) {
		ERRMSG("Can't allocate memory for the mem_map_data. %s\n",
		    strerror(errno));
		return FALSE;
	}

	/*
	 * Create mem_map data.
	 */
	id_mm = 0;
	if (mmd[0].pfn_start != 0) {
		dump_mem_map(0, mmd[0].pfn_start, NOT_MEMMAP_ADDR, id_mm);
		id_mm++;
	}
	for (i = 0; i < num_mem_map; i++) {
		dump_mem_map(mmd[i].pfn_start, mmd[i].pfn_end,
		    mmd[i].mem_map, id_mm);
		id_mm++;
		if ((i < num_mem_map - 1)
		    && (mmd[i].pfn_end != mmd[i + 1].pfn_start)) {
			dump_mem_map(mmd[i].pfn_end, mmd[i +1].pfn_start,
			    NOT_MEMMAP_ADDR, id_mm);
			id_mm++;
		}
	}
	i = num_mem_map - 1;
	if (mmd[i].pfn_end < info->max_mapnr)
		dump_mem_map(mmd[i].pfn_end, info->max_mapnr,
		    NOT_MEMMAP_ADDR, id_mm);

	return TRUE;
}

unsigned long
nr_to_section(unsigned long nr, unsigned long *mem_sec)
{
	unsigned long addr;

	if (!is_kvaddr(mem_sec[SECTION_NR_TO_ROOT(nr)]))
		return NOT_KV_ADDR;

	if (is_sparsemem_extreme())
		addr = mem_sec[SECTION_NR_TO_ROOT(nr)] +
		    (nr & SECTION_ROOT_MASK()) * SIZE(mem_section);
	else
		addr = SYMBOL(mem_section) + (nr * SIZE(mem_section));

	if (!is_kvaddr(addr))
		return NOT_KV_ADDR;

	return addr;
}

unsigned long
section_mem_map_addr(unsigned long addr)
{
	char *mem_section;
	unsigned long map;

	if (!is_kvaddr(addr))
		return NOT_KV_ADDR;

	if ((mem_section = malloc(SIZE(mem_section))) == NULL) {
		ERRMSG("Can't allocate memory for a struct mem_section. %s\n",
		    strerror(errno));
		return NOT_KV_ADDR;
	}
	if (!readmem(VADDR, addr, mem_section, SIZE(mem_section))) {
		ERRMSG("Can't get a struct mem_section(%lx).\n", addr);
		free(mem_section);
		return NOT_KV_ADDR;
	}
	map = ULONG(mem_section + OFFSET(mem_section.section_mem_map));
	map &= SECTION_MAP_MASK;
	free(mem_section);

	return map;
}

unsigned long
sparse_decode_mem_map(unsigned long coded_mem_map, unsigned long section_nr)
{
	if (!is_kvaddr(coded_mem_map))
		return NOT_KV_ADDR;

	return coded_mem_map +
	    (SECTION_NR_TO_PFN(section_nr) * SIZE(page));
}

int
get_mm_sparsemem(void)
{
	unsigned int section_nr, mem_section_size, num_section;
	unsigned long long pfn_start, pfn_end;
	unsigned long section, mem_map;
	unsigned long *mem_sec = NULL;

	int ret = FALSE;

	/*
	 * Get the address of the symbol "mem_section".
	 */
	num_section = divideup(info->max_mapnr, PAGES_PER_SECTION());
	if (is_sparsemem_extreme()) {
		info->sections_per_root = _SECTIONS_PER_ROOT_EXTREME();
		mem_section_size = sizeof(void *) * NR_SECTION_ROOTS();
	} else {
		info->sections_per_root = _SECTIONS_PER_ROOT();
		mem_section_size = SIZE(mem_section) * NR_SECTION_ROOTS();
	}
	if ((mem_sec = malloc(mem_section_size)) == NULL) {
		ERRMSG("Can't allocate memory for the mem_section. %s\n",
		    strerror(errno));
		return FALSE;
	}
	if (!readmem(VADDR, SYMBOL(mem_section), mem_sec,
	    mem_section_size)) {
		ERRMSG("Can't get the address of mem_section.\n");
		goto out;
	}
	info->num_mem_map = num_section;
	if ((info->mem_map_data = (struct mem_map_data *)
	    malloc(sizeof(struct mem_map_data)*info->num_mem_map)) == NULL) {
		ERRMSG("Can't allocate memory for the mem_map_data. %s\n",
		    strerror(errno));
		goto out;
	}
	for (section_nr = 0; section_nr < num_section; section_nr++) {
		section = nr_to_section(section_nr, mem_sec);
		mem_map = section_mem_map_addr(section);
		mem_map = sparse_decode_mem_map(mem_map, section_nr);
		if (!is_kvaddr(mem_map))
			mem_map = NOT_MEMMAP_ADDR;
		pfn_start = section_nr * PAGES_PER_SECTION();
		pfn_end   = pfn_start + PAGES_PER_SECTION();
		if (info->max_mapnr < pfn_end)
			pfn_end = info->max_mapnr;
		dump_mem_map(pfn_start, pfn_end, mem_map, section_nr);
	}
	ret = TRUE;
out:
	if (mem_sec != NULL)
		free(mem_sec);

	return ret;
}

int
get_mem_map_without_mm(void)
{
	info->num_mem_map = 1;
	if ((info->mem_map_data = (struct mem_map_data *)
	    malloc(sizeof(struct mem_map_data)*info->num_mem_map)) == NULL) {
		ERRMSG("Can't allocate memory for the mem_map_data. %s\n",
		    strerror(errno));
		return FALSE;
	}
	dump_mem_map(0, info->max_mapnr, NOT_MEMMAP_ADDR, 0);

	return TRUE;
}

int
get_mem_map(void)
{
	int ret;

	switch (get_mem_type()) {
	case SPARSEMEM:
		DEBUG_MSG("\n");
		DEBUG_MSG("Memory type  : SPARSEMEM\n");
		DEBUG_MSG("\n");
		ret = get_mm_sparsemem();
		break;
	case SPARSEMEM_EX:
		DEBUG_MSG("\n");
		DEBUG_MSG("Memory type  : SPARSEMEM_EX\n");
		DEBUG_MSG("\n");
		ret = get_mm_sparsemem();
		break;
	case DISCONTIGMEM:
		DEBUG_MSG("\n");
		DEBUG_MSG("Memory type  : DISCONTIGMEM\n");
		DEBUG_MSG("\n");
		ret = get_mm_discontigmem();
		break;
	case FLATMEM:
		DEBUG_MSG("\n");
		DEBUG_MSG("Memory type  : FLATMEM\n");
		DEBUG_MSG("\n");
		ret = get_mm_flatmem();
		break;
	default:
		ERRMSG("Can't distinguish the memory type.\n");
		ret = FALSE;
		break;
	}
	return ret;
}

int
initial(void)
{
	int flag_need_debuginfo;

	if (!(vt.mem_flags & MEMORY_XEN) && info->flag_exclude_xen_dom) {
		MSG("'-X' option is disable,");
		MSG("because %s is not Xen's memory core image.\n", info->name_memory);
		MSG("Commandline parameter is invalid.\n");
		MSG("Try `makedumpfile --help' for more information.\n");
		return FALSE;
	}

	if (!get_phys_base())
		return FALSE;

	/*
	 * Get the debug information for analysis from the vmcoreinfo file
	 */
	if (info->flag_read_vmcoreinfo) {
		if (!read_vmcoreinfo())
			return FALSE;
		close_vmcoreinfo();
	/*
	 * Get the debug information for analysis from the kernel file
	 */
	} else if (info->name_vmlinux) {
		dwarf_info.fd_debuginfo   = info->fd_vmlinux;
		dwarf_info.name_debuginfo = info->name_vmlinux;

		if (!get_symbol_info())
			return FALSE;

		if (!get_structure_info())
			return FALSE;

		if (!get_srcfile_info())
			return FALSE;
	} else {
		/*
		 * Check whether /proc/vmcore contains vmcoreinfo,
		 * and get both the offset and the size.
		 */
		if (!info->offset_vmcoreinfo || !info->size_vmcoreinfo) {
			if (info->max_dump_level <= DL_EXCLUDE_ZERO)
				goto out;

			MSG("%s doesn't contain vmcoreinfo.\n",
			    info->name_memory);
			MSG("Specify '-x' option or '-i' option.\n");
			MSG("Commandline parameter is invalid.\n");
			MSG("Try `makedumpfile --help' for more information.\n");
			return FALSE;
		}
	}

	/*
	 * Get the debug information from /proc/vmcore
	 */
	if (info->offset_vmcoreinfo && info->size_vmcoreinfo) {
		if (!read_vmcoreinfo_from_vmcore(info->offset_vmcoreinfo,
		    info->size_vmcoreinfo, FALSE))
			return FALSE;
	}

	if (!get_value_for_old_linux())
		return FALSE;
out:
	if (!info->page_size) {
		/*
		 * If we cannot get page_size from a vmcoreinfo file,
		 * fall back to the current kernel page size.
		 */
		if (!fallback_to_current_page_size())
			return FALSE;
	}
	if (!get_max_mapnr())
		return FALSE;

	if ((info->max_dump_level <= DL_EXCLUDE_ZERO) && !info->flag_dmesg)
		flag_need_debuginfo = FALSE;
	else 
		flag_need_debuginfo = TRUE;

	if (!flag_need_debuginfo) {
		if (!get_mem_map_without_mm())
			return FALSE;
		else
			return TRUE;
	}

	if (!get_machdep_info())
		return FALSE;

	if (!check_release())
		return FALSE;

	if (!get_versiondep_info())
		return FALSE;

	if (!get_numnodes())
		return FALSE;

	if (!get_mem_map())
		return FALSE;

	return TRUE;
}

void
initialize_bitmap(struct dump_bitmap *bitmap)
{
	bitmap->fd        = info->fd_bitmap;
	bitmap->file_name = info->name_bitmap;
	bitmap->no_block  = -1;
	memset(bitmap->buf, 0, BUFSIZE_BITMAP);
}

void
initialize_1st_bitmap(struct dump_bitmap *bitmap)
{
	initialize_bitmap(bitmap);
	bitmap->offset = 0;
}

void
initialize_2nd_bitmap(struct dump_bitmap *bitmap)
{
	initialize_bitmap(bitmap);
	bitmap->offset = info->len_bitmap / 2;
}

int
set_bitmap(struct dump_bitmap *bitmap, unsigned long long pfn,
    int val)
{
	int byte, bit;
	off_t old_offset, new_offset;
	old_offset = bitmap->offset + BUFSIZE_BITMAP * bitmap->no_block;
	new_offset = bitmap->offset + BUFSIZE_BITMAP * (pfn / PFN_BUFBITMAP);

	if (0 <= bitmap->no_block && old_offset != new_offset) {
		if (lseek(bitmap->fd, old_offset, SEEK_SET) < 0 ) {
			ERRMSG("Can't seek the bitmap(%s). %s\n",
			    bitmap->file_name, strerror(errno));
			return FALSE;
		}
		if (write(bitmap->fd, bitmap->buf, BUFSIZE_BITMAP)
		    != BUFSIZE_BITMAP) {
			ERRMSG("Can't write the bitmap(%s). %s\n",
			    bitmap->file_name, strerror(errno));
			return FALSE;
		}
	}
	if (old_offset != new_offset) {
		if (lseek(bitmap->fd, new_offset, SEEK_SET) < 0 ) {
			ERRMSG("Can't seek the bitmap(%s). %s\n",
			    bitmap->file_name, strerror(errno));
			return FALSE;
		}
		if (read(bitmap->fd, bitmap->buf, BUFSIZE_BITMAP)
		    != BUFSIZE_BITMAP) {
			ERRMSG("Can't read the bitmap(%s). %s\n",
			    bitmap->file_name, strerror(errno));
			return FALSE;
		}
		bitmap->no_block = pfn / PFN_BUFBITMAP;
	}
	/*
	 * If val is 0, clear bit on the bitmap.
	 */
	byte = (pfn%PFN_BUFBITMAP)>>3;
	bit  = (pfn%PFN_BUFBITMAP) & 7;
	if (val)
		bitmap->buf[byte] |= 1<<bit;
	else
		bitmap->buf[byte] &= ~(1<<bit);

	return TRUE;
}

int
sync_bitmap(struct dump_bitmap *bitmap)
{
	off_t offset;
	offset = bitmap->offset + BUFSIZE_BITMAP * bitmap->no_block;

	/*
	 * The bitmap buffer is not dirty, and it is not necessary
	 * to write out it.
	 */
	if (bitmap->no_block < 0)
		return TRUE;

	if (lseek(bitmap->fd, offset, SEEK_SET) < 0 ) {
		ERRMSG("Can't seek the bitmap(%s). %s\n",
		    bitmap->file_name, strerror(errno));
		return FALSE;
	}
	if (write(bitmap->fd, bitmap->buf, BUFSIZE_BITMAP)
	    != BUFSIZE_BITMAP) {
		ERRMSG("Can't write the bitmap(%s). %s\n",
		    bitmap->file_name, strerror(errno));
		return FALSE;
	}
	return TRUE;
}

int
sync_1st_bitmap(void)
{
	return sync_bitmap(info->bitmap1);
}

int
sync_2nd_bitmap(void)
{
	return sync_bitmap(info->bitmap2);
}

int
set_bit_on_1st_bitmap(unsigned long long pfn)
{
	return set_bitmap(info->bitmap1, pfn, 1);
}

int
clear_bit_on_2nd_bitmap(unsigned long long pfn)
{
	return set_bitmap(info->bitmap2, pfn, 0);
}

static inline int
is_on(char *bitmap, int i)
{
	return bitmap[i>>3] & (1 << (i & 7));
}

static inline int
is_dumpable(struct dump_bitmap *bitmap, unsigned long long pfn)
{
	off_t offset;
	if (pfn == 0 || bitmap->no_block != pfn/PFN_BUFBITMAP) {
		offset = bitmap->offset + BUFSIZE_BITMAP*(pfn/PFN_BUFBITMAP);
		lseek(bitmap->fd, offset, SEEK_SET);
		read(bitmap->fd, bitmap->buf, BUFSIZE_BITMAP);
		if (pfn == 0)
			bitmap->no_block = 0;
		else
			bitmap->no_block = pfn/PFN_BUFBITMAP;
	}
	return is_on(bitmap->buf, pfn%PFN_BUFBITMAP);
}

static inline int
is_in_segs(unsigned long long paddr)
{
	if (paddr_to_offset(paddr))
		return TRUE;
	else
		return FALSE;
}

static inline int
is_zero_page(unsigned char *buf, long page_size)
{
	size_t i;

	for (i = 0; i < page_size; i++)
		if (buf[i])
			return FALSE;
	return TRUE;
}

int
read_cache(struct cache_data *cd)
{
	const off_t failed = (off_t)-1;

	if (lseek(cd->fd, cd->offset, SEEK_SET) == failed) {
		ERRMSG("Can't seek the dump file(%s). %s\n",
		    cd->file_name, strerror(errno));
		return FALSE;
	}
	if (read(cd->fd, cd->buf, cd->cache_size) != cd->cache_size) {
		ERRMSG("Can't read the dump file(%s). %s\n",
		    cd->file_name, strerror(errno));
		return FALSE;
	}
	cd->offset += cd->cache_size;
	return TRUE;
}

int
is_bigendian(void)
{
	int i = 0x12345678;

	if (*(char *)&i == 0x12)
		return TRUE;
	else
		return FALSE;
}

int
write_and_check_space(int fd, void *buf, size_t buf_size, char *file_name)
{
	int status, written_size = 0;

	while (written_size < buf_size) {
		status = write(fd, buf + written_size,
				   buf_size - written_size);
		if (0 < status) {
			written_size += status;
			continue;
		}
		if (errno == ENOSPC)
			info->flag_nospace = TRUE;
		MSG("\nCan't write the dump file(%s). %s\n",
		    file_name, strerror(errno));
		return FALSE;
	}
	return TRUE;
}

int
write_buffer(int fd, off_t offset, void *buf, size_t buf_size, char *file_name)
{
	struct makedumpfile_data_header fdh;
	const off_t failed = (off_t)-1;

	if (fd == STDOUT_FILENO) {
		/*
		 * Output a header of flattened format instead of
		 * lseek(). For sending dump data to a different
		 * architecture, change the values to big endian.
		 */
		if (is_bigendian()){
			fdh.offset   = offset;
			fdh.buf_size = buf_size;
		} else {
			fdh.offset   = bswap_64(offset);
			fdh.buf_size = bswap_64(buf_size);
		}
		if (!write_and_check_space(fd, &fdh, sizeof(fdh), file_name))
			return FALSE;
	} else {
		if (lseek(fd, offset, SEEK_SET) == failed) {
			ERRMSG("Can't seek the dump file(%s). %s\n",
			    file_name, strerror(errno));
			return FALSE;
		}
	}
	if (!write_and_check_space(fd, buf, buf_size, file_name))
		return FALSE;

	return TRUE;
}

int
write_cache(struct cache_data *cd, void *buf, size_t size)
{
	memcpy(cd->buf + cd->buf_size, buf, size);
	cd->buf_size += size;

	if (cd->buf_size < cd->cache_size)
		return TRUE;

	if (!write_buffer(cd->fd, cd->offset, cd->buf, cd->cache_size,
	    cd->file_name))
		return FALSE;

	cd->buf_size -= cd->cache_size;
	memcpy(cd->buf, cd->buf + cd->cache_size, cd->buf_size);
	cd->offset += cd->cache_size;
	return TRUE;
}

int
write_cache_bufsz(struct cache_data *cd)
{
	if (!cd->buf_size)
		return TRUE;

	if (!write_buffer(cd->fd, cd->offset, cd->buf, cd->buf_size,
	    cd->file_name))
		return FALSE;

	cd->offset  += cd->buf_size;
	cd->buf_size = 0;
	return TRUE;
}

int
read_buf_from_stdin(void *buf, int buf_size)
{
	int read_size = 0, tmp_read_size = 0;
	time_t last_time, tm;

	last_time = time(NULL);

	while (read_size != buf_size) {

		tmp_read_size = read(STDIN_FILENO, buf + read_size,
		    buf_size - read_size);

		if (tmp_read_size < 0) {
			ERRMSG("Can't read STDIN. %s\n", strerror(errno));
			return FALSE;

		} else if (0 == tmp_read_size) {
			/*
			 * If it cannot get any data from a standard input
			 * for a long time, break this loop.
			 */
			tm = time(NULL);
			if (TIMEOUT_STDIN < (tm - last_time)) {
				ERRMSG("Can't get any data from STDIN.\n");
				return FALSE;
			}
		} else {
			read_size += tmp_read_size;
			last_time = time(NULL);
		}
	}
	return TRUE;
}

int
read_start_flat_header(void)
{
	char buf[MAX_SIZE_MDF_HEADER];
	struct makedumpfile_header fh;

	/*
	 * Get flat header.
	 */
	if (!read_buf_from_stdin(buf, MAX_SIZE_MDF_HEADER)) {
		ERRMSG("Can't get header of flattened format.\n");
		return FALSE;
	}
	memcpy(&fh, buf, sizeof(fh));

	if (!is_bigendian()){
		fh.type    = bswap_64(fh.type);
		fh.version = bswap_64(fh.version);
	}

	/*
	 * Check flat header.
	 */
	if (strcmp(fh.signature, MAKEDUMPFILE_SIGNATURE)) {
		ERRMSG("Can't get signature of flattened format.\n");
		return FALSE;
	}
	if (fh.type != TYPE_FLAT_HEADER) {
		ERRMSG("Can't get type of flattened format.\n");
		return FALSE;
	}

	return TRUE;
}

int
read_flat_data_header(struct makedumpfile_data_header *fdh)
{
	if (!read_buf_from_stdin(fdh,
	    sizeof(struct makedumpfile_data_header))) {
		ERRMSG("Can't get header of flattened format.\n");
		return FALSE;
	}
	if (!is_bigendian()){
		fdh->offset   = bswap_64(fdh->offset);
		fdh->buf_size = bswap_64(fdh->buf_size);
	}
	return TRUE;
}

int
rearrange_dumpdata(void)
{
	int read_size, tmp_read_size;
	char buf[SIZE_BUF_STDIN];
	struct makedumpfile_data_header fdh;

	/*
	 * Get flat header.
	 */
	if (!read_start_flat_header()) {
		ERRMSG("Can't get header of flattened format.\n");
		return FALSE;
	}

	/*
	 * Read the first data header.
	 */
	if (!read_flat_data_header(&fdh)) {
		ERRMSG("Can't get header of flattened format.\n");
		return FALSE;
	}

	do {
		read_size = 0;
		while (read_size < fdh.buf_size) {
			if (sizeof(buf) < (fdh.buf_size - read_size))
				tmp_read_size = sizeof(buf);
			else
				tmp_read_size = fdh.buf_size - read_size;

			if (!read_buf_from_stdin(buf, tmp_read_size)) {
				ERRMSG("Can't get data of flattened format.\n");
				return FALSE;
			}
			if (!write_buffer(info->fd_dumpfile,
			    fdh.offset + read_size, buf, tmp_read_size,
			    info->name_dumpfile))
				return FALSE;

			read_size += tmp_read_size;
		}
		/*
		 * Read the next header.
		 */
		if (!read_flat_data_header(&fdh)) {
			ERRMSG("Can't get data header of flattened format.\n");
			return FALSE;
		}

	} while ((0 <= fdh.offset) && (0 < fdh.buf_size));

	if ((fdh.offset != END_FLAG_FLAT_HEADER)
	    || (fdh.buf_size != END_FLAG_FLAT_HEADER)) {
		ERRMSG("Can't get valid end header of flattened format.\n");
		return FALSE;
	}

	return TRUE;
}

/*
 * Same as paddr_to_offset() but makes sure that the specified offset (hint)
 * in the segment.
 */
off_t
paddr_to_offset2(unsigned long long paddr, off_t hint)
{
	int i;
	off_t offset;
	unsigned long long len;
	struct pt_load_segment *pls;

	for (i = offset = 0; i < info->num_load_memory; i++) {
		pls = &info->pt_load_segments[i];
		len = pls->phys_end - pls->phys_start;
		if ((paddr >= pls->phys_start)
		    && (paddr < pls->phys_end)
		    && (hint >= pls->file_offset)
		    && (hint < pls->file_offset + len)) {
			offset = (off_t)(paddr - pls->phys_start) +
				pls->file_offset;
				break;
		}
	}
	return offset;
}

unsigned long long
page_to_pfn(unsigned long page)
{
	unsigned int num;
	unsigned long long pfn = 0, index = 0;
	struct mem_map_data *mmd;

	mmd = info->mem_map_data;
	for (num = 0; num < info->num_mem_map; num++, mmd++) {
		if (mmd->mem_map == NOT_MEMMAP_ADDR)
			continue;
		if (page < mmd->mem_map)
			continue;
		index = (page - mmd->mem_map) / SIZE(page);
		if (index > mmd->pfn_end - mmd->pfn_start)
			continue;
		pfn = mmd->pfn_start + index;
		break;
	}
	if (!pfn) {
		ERRMSG("Can't convert the address of page descriptor (%lx) to pfn.\n", page);
		return ULONGLONG_MAX;
	}
	return pfn;
}

int
reset_bitmap_of_free_pages(unsigned long node_zones)
{

	int order, i, migrate_type, migrate_types;
	unsigned long curr, previous, head, curr_page, curr_prev;
	unsigned long addr_free_pages, free_pages = 0, found_free_pages = 0;
	unsigned long long pfn, start_pfn;

	/*
	 * On linux-2.6.24 or later, free_list is divided into the array.
	 */
	migrate_types = ARRAY_LENGTH(free_area.free_list);
	if (migrate_types == NOT_FOUND_STRUCTURE)
		migrate_types = 1;

	for (order = (ARRAY_LENGTH(zone.free_area) - 1); order >= 0; --order) {
		for (migrate_type = 0; migrate_type < migrate_types;
		     migrate_type++) {
			head = node_zones + OFFSET(zone.free_area)
				+ SIZE(free_area) * order
				+ OFFSET(free_area.free_list)
				+ SIZE(list_head) * migrate_type;
			previous = head;
			if (!readmem(VADDR, head + OFFSET(list_head.next),
				     &curr, sizeof curr)) {
				ERRMSG("Can't get next list_head.\n");
				return FALSE;
			}
			for (;curr != head;) {
				curr_page = curr - OFFSET(page.lru);
				start_pfn = page_to_pfn(curr_page);
				if (start_pfn == ULONGLONG_MAX)
					return FALSE;

				if (!readmem(VADDR, curr+OFFSET(list_head.prev),
					     &curr_prev, sizeof curr_prev)) {
					ERRMSG("Can't get prev list_head.\n");
					return FALSE;
				}
				if (previous != curr_prev) {
					ERRMSG("The free list is broken.\n");
					retcd = ANALYSIS_FAILED;
					return FALSE;
				}
				for (i = 0; i < (1<<order); i++) {
					pfn = start_pfn + i;
					clear_bit_on_2nd_bitmap(pfn);
				}
				found_free_pages += i;

				previous = curr;
				if (!readmem(VADDR, curr+OFFSET(list_head.next),
					     &curr, sizeof curr)) {
					ERRMSG("Can't get next list_head.\n");
					return FALSE;
				}
			}
		}
	}

	/*
	 * Check the number of free pages.
	 */
	if (OFFSET(zone.free_pages) != NOT_FOUND_STRUCTURE) {
		addr_free_pages = node_zones + OFFSET(zone.free_pages);

	} else if (OFFSET(zone.vm_stat) != NOT_FOUND_STRUCTURE) {
		/*
		 * On linux-2.6.21 or later, the number of free_pages is
		 * in vm_stat[NR_FREE_PAGES].
		 */
		addr_free_pages = node_zones + OFFSET(zone.vm_stat)
		    + sizeof(long) * NUMBER(NR_FREE_PAGES);

	} else {
		ERRMSG("Can't get addr_free_pages.\n");
		return FALSE;
	}
	if (!readmem(VADDR, addr_free_pages, &free_pages, sizeof free_pages)) {
		ERRMSG("Can't get free_pages.\n");
		return FALSE;
	}
	if (free_pages != found_free_pages) {
		/*
		 * On linux-2.6.21 or later, the number of free_pages is
		 * sometimes different from the one of the list "free_area",
		 * because the former is flushed asynchronously.
		 */
		DEBUG_MSG("The number of free_pages is invalid.\n");
		DEBUG_MSG("  free_pages       = %ld\n", free_pages);
		DEBUG_MSG("  found_free_pages = %ld\n", found_free_pages);
	}
	pfn_free += found_free_pages;

	return TRUE;
}

int
dump_dmesg()
{
	int log_buf_len, length_log, length_oldlog, ret = FALSE;
	unsigned long log_buf, log_end, index;
	char *log_buffer = NULL;

	if (!open_files_for_creating_dumpfile())
		return FALSE;

	if (!get_elf_info())
		return FALSE;

	if (!initial())
		return FALSE;

	if ((SYMBOL(log_buf) == NOT_FOUND_SYMBOL)
	    || (SYMBOL(log_buf_len) == NOT_FOUND_SYMBOL)
	    || (SYMBOL(log_end) == NOT_FOUND_SYMBOL)) {
		ERRMSG("Can't find some symbols for log_buf.\n");
		return FALSE;
	}
	if (!readmem(VADDR, SYMBOL(log_buf), &log_buf, sizeof(log_buf))) {
		ERRMSG("Can't get log_buf.\n");
		return FALSE;
	}
	if (!readmem(VADDR, SYMBOL(log_end), &log_end, sizeof(log_end))) {
		ERRMSG("Can't to get log_end.\n");
		return FALSE;
	}
	if (!readmem(VADDR, SYMBOL(log_buf_len), &log_buf_len,
	    sizeof(log_buf_len))) {
		ERRMSG("Can't get log_buf_len.\n");
		return FALSE;
	}
	DEBUG_MSG("\n");
	DEBUG_MSG("log_buf      : %lx\n", log_buf);
	DEBUG_MSG("log_end      : %lx\n", log_end);
	DEBUG_MSG("log_buf_len  : %d\n", log_buf_len);

	if ((log_buffer = malloc(log_buf_len)) == NULL) {
		ERRMSG("Can't allocate memory for log_buf. %s\n",
		    strerror(errno));
		return FALSE;
	}

	if (log_end < log_buf_len) {
		length_log = log_end;
		if(!readmem(VADDR, log_buf, log_buffer, length_log)) {
			ERRMSG("Can't read dmesg log.\n");
			goto out;
		}
	} else {
		index = log_end & (log_buf_len - 1);
		DEBUG_MSG("index        : %lx\n", index);
		length_log = log_buf_len;
		length_oldlog = log_buf_len - index;
		if(!readmem(VADDR, log_buf + index, log_buffer, length_oldlog)) {
			ERRMSG("Can't read old dmesg log.\n");
			goto out;
		}
		if(!readmem(VADDR, log_buf, log_buffer + length_oldlog, index)) {
			ERRMSG("Can't read new dmesg log.\n");
			goto out;
		}
	}
	DEBUG_MSG("length_log   : %d\n", length_log);

	if (!open_dump_file()) {
		ERRMSG("Can't open output file.\n");
		goto out;
	}
	if (write(info->fd_dumpfile, log_buffer, length_log) < 0)
		goto out;

	if (!close_files_for_creating_dumpfile())
		goto out;

	ret = TRUE;
out:
	if (log_buffer)
		free(log_buffer);

	return ret;
}


int
_exclude_free_page(void)
{
	int i, nr_zones, num_nodes, node;
	unsigned long node_zones, zone, spanned_pages, pgdat;

	if ((node = next_online_node(0)) < 0) {
		ERRMSG("Can't get next online node.\n");
		return FALSE;
	}
	if (!(pgdat = next_online_pgdat(node))) {
		ERRMSG("Can't get pgdat list.\n");
		return FALSE;
	}
	for (num_nodes = 1; num_nodes <= vt.numnodes; num_nodes++) {

		print_progress(PROGRESS_FREE_PAGES, num_nodes - 1, vt.numnodes);

		node_zones = pgdat + OFFSET(pglist_data.node_zones);

		if (!readmem(VADDR, pgdat + OFFSET(pglist_data.nr_zones),
		    &nr_zones, sizeof(nr_zones))) {
			ERRMSG("Can't get nr_zones.\n");
			return FALSE;
		}

		for (i = 0; i < nr_zones; i++) {

			print_progress(PROGRESS_FREE_PAGES, i + nr_zones * (num_nodes - 1),
					nr_zones * vt.numnodes);

			zone = node_zones + (i * SIZE(zone));
			if (!readmem(VADDR, zone + OFFSET(zone.spanned_pages),
			    &spanned_pages, sizeof spanned_pages)) {
				ERRMSG("Can't get spanned_pages.\n");
				return FALSE;
			}
			if (!spanned_pages)
				continue;
			if (!reset_bitmap_of_free_pages(zone))
				return FALSE;
		}
		if (num_nodes < vt.numnodes) {
			if ((node = next_online_node(node + 1)) < 0) {
				ERRMSG("Can't get next online node.\n");
				return FALSE;
			} else if (!(pgdat = next_online_pgdat(node))) {
				ERRMSG("Can't determine pgdat list (node %d).\n",
				    node);
				return FALSE;
			}
		}
	}

	/*
	 * print [100 %]
	 */
	print_progress(PROGRESS_FREE_PAGES, vt.numnodes, vt.numnodes);

	return TRUE;
}

int
exclude_free_page(void)
{
	/*
	 * Check having necessary information.
	 */
	if ((SYMBOL(node_data) == NOT_FOUND_SYMBOL)
	    && (SYMBOL(pgdat_list) == NOT_FOUND_SYMBOL)
	    && (SYMBOL(contig_page_data) == NOT_FOUND_SYMBOL)) {
		ERRMSG("Can't get necessary symbols for excluding free pages.\n");
		return FALSE;
	}
	if ((SIZE(zone) == NOT_FOUND_STRUCTURE)
	    || ((OFFSET(zone.free_pages) == NOT_FOUND_STRUCTURE)
	        && (OFFSET(zone.vm_stat) == NOT_FOUND_STRUCTURE))
	    || (OFFSET(zone.free_area) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(zone.spanned_pages) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(pglist_data.node_zones) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(pglist_data.nr_zones) == NOT_FOUND_STRUCTURE)
	    || (SIZE(free_area) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(free_area.free_list) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(list_head.next) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(list_head.prev) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(page.lru) == NOT_FOUND_STRUCTURE)
	    || (ARRAY_LENGTH(zone.free_area) == NOT_FOUND_STRUCTURE)) {
		ERRMSG("Can't get necessary structures for excluding free pages.\n");
		return FALSE;
	}

	/*
	 * Detect free pages and update 2nd-bitmap.
	 */
	if (!_exclude_free_page())
		return FALSE;

	return TRUE;
}

int
create_1st_bitmap(void)
{
	int i;
 	char buf[info->page_size];
	unsigned long long pfn, pfn_start, pfn_end, pfn_bitmap1;
	struct pt_load_segment *pls;
	off_t offset_page;

	/*
	 * At first, clear all the bits on the 1st-bitmap.
	 */
	memset(buf, 0, sizeof(buf));

	if (lseek(info->bitmap1->fd, info->bitmap1->offset, SEEK_SET) < 0) {
		ERRMSG("Can't seek the bitmap(%s). %s\n",
		    info->bitmap1->file_name, strerror(errno));
		return FALSE;
	}
	offset_page = 0;
	while (offset_page < (info->len_bitmap / 2)) {
		if (write(info->bitmap1->fd, buf, info->page_size)
		    != info->page_size) {
			ERRMSG("Can't write the bitmap(%s). %s\n",
			    info->bitmap1->file_name, strerror(errno));
			return FALSE;
		}
		offset_page += info->page_size;
	}

	/*
	 * If page is on memory hole, set bit on the 1st-bitmap.
	 */
	for (i = pfn_bitmap1 = 0; i < info->num_load_memory; i++) {

		print_progress(PROGRESS_HOLES, i, info->num_load_memory);

		pls = &info->pt_load_segments[i];
		pfn_start = pls->phys_start >> PAGESHIFT();
		pfn_end   = pls->phys_end >> PAGESHIFT();
		if (!is_in_segs(pfn_start << PAGESHIFT()))
			pfn_start++;
		for (pfn = pfn_start; pfn < pfn_end; pfn++) {
			set_bit_on_1st_bitmap(pfn);
			pfn_bitmap1++;
		}
	}
	pfn_memhole = info->max_mapnr - pfn_bitmap1;

	/*
	 * print 100 %
	 */
	print_progress(PROGRESS_HOLES, info->max_mapnr, info->max_mapnr);

	if (!sync_1st_bitmap())
		return FALSE;

	return TRUE;
}

/*
 * Exclude the page filled with zero in case of creating an elf dumpfile.
 */
int
exclude_zero_pages(void)
{
	unsigned long long pfn, paddr;
	struct dump_bitmap bitmap2;
	unsigned char buf[info->page_size];

	initialize_2nd_bitmap(&bitmap2);

	for (pfn = paddr = 0; pfn < info->max_mapnr;
	    pfn++, paddr += info->page_size) {

		print_progress(PROGRESS_ZERO_PAGES, pfn, info->max_mapnr);

		if (!is_in_segs(paddr))
			continue;

		if (!is_dumpable(&bitmap2, pfn))
			continue;

		if (vt.mem_flags & MEMORY_XEN) {
			if (!readmem(MADDR_XEN, paddr, buf, info->page_size)) {
				ERRMSG("Can't get the page data(pfn:%llx, max_mapnr:%llx).\n",
				    pfn, info->max_mapnr);
				return FALSE;
			}
		} else {
			if (!readmem(PADDR, paddr, buf, info->page_size)) {
				ERRMSG("Can't get the page data(pfn:%llx, max_mapnr:%llx).\n",
				    pfn, info->max_mapnr);
				return FALSE;
			}
		}
		if (is_zero_page(buf, info->page_size)) {
			clear_bit_on_2nd_bitmap(pfn);
			pfn_zero++;
		}
	}

	/*
	 * print [100 %]
	 */
	print_progress(PROGRESS_ZERO_PAGES, info->max_mapnr, info->max_mapnr);

	return TRUE;
}

int
exclude_unnecessary_pages(void)
{
	unsigned int mm;
	unsigned long mem_map;
	unsigned long long pfn, paddr, pfn_mm;
	unsigned long long pfn_read_start, pfn_read_end, index_pg;
	unsigned char *page_cache = NULL, *pcache;
	unsigned int _count;
	unsigned long flags, mapping;
	struct mem_map_data *mmd;

	int ret = FALSE;

	if ((page_cache = malloc(SIZE(page)*PGMM_CACHED)) == NULL) {
		ERRMSG("Can't allocate memory for the pagedesc cache. %s\n",
		    strerror(errno));
		goto out;
	}
	for (mm = 0; mm < info->num_mem_map; mm++) {
		print_progress(PROGRESS_UNN_PAGES, mm, info->num_mem_map);

		mmd = &info->mem_map_data[mm];
		pfn   = mmd->pfn_start;
		paddr = pfn*info->page_size;
		mem_map = mmd->mem_map;

		if (mem_map == NOT_MEMMAP_ADDR)
			continue;

		/*
		 * Refresh the buffer of struct page, when changing mem_map.
		 */
		pfn_read_start = ULONGLONG_MAX;
		pfn_read_end   = 0;

		for (; pfn < mmd->pfn_end;
		    pfn++, mem_map += SIZE(page),
		    paddr += info->page_size) {

			/*
			 * Exclude the memory hole.
			 */
			if (!is_in_segs(paddr))
				continue;

			index_pg = pfn % PGMM_CACHED;
			if (pfn < pfn_read_start || pfn_read_end < pfn) {
				if (roundup(pfn + 1, PGMM_CACHED) < mmd->pfn_end)
					pfn_mm = PGMM_CACHED - index_pg;
				else
					pfn_mm = mmd->pfn_end - pfn;

				if (!readmem(VADDR, mem_map,
				    page_cache + (index_pg * SIZE(page)),
				    SIZE(page) * pfn_mm)) {
					ERRMSG("Can't read the buffer of struct page.\n");
					goto out;
				}
				pfn_read_start = pfn;
				pfn_read_end   = pfn + pfn_mm - 1;
			}
			pcache  = page_cache + (index_pg * SIZE(page));

			flags   = ULONG(pcache + OFFSET(page.flags));
			_count  = UINT(pcache + OFFSET(page._count));
			mapping = ULONG(pcache + OFFSET(page.mapping));

			/*
			 * Exclude the cache page without the private page.
			 */
			if ((info->dump_level & DL_EXCLUDE_CACHE)
			    && (isLRU(flags) || isSwapCache(flags))
			    && !isPrivate(flags) && !isAnon(mapping)) {
				clear_bit_on_2nd_bitmap(pfn);
				pfn_cache++;
			}
			/*
			 * Exclude the cache page with the private page.
			 */
			else if ((info->dump_level & DL_EXCLUDE_CACHE_PRI)
			    && (isLRU(flags) || isSwapCache(flags))
			    && !isAnon(mapping)) {
				clear_bit_on_2nd_bitmap(pfn);
				pfn_cache_private++;
			}
			/*
			 * Exclude the data page of the user process.
			 */
			else if ((info->dump_level & DL_EXCLUDE_USER_DATA)
			    && isAnon(mapping)) {
				clear_bit_on_2nd_bitmap(pfn);
				pfn_user++;
			}
		}
	}

	/*
	 * print [100 %]
	 */
	print_progress(PROGRESS_UNN_PAGES, info->num_mem_map, info->num_mem_map);

	if (info->dump_level & DL_EXCLUDE_FREE)
		if (!exclude_free_page())
			goto out;

	ret = TRUE;
out:
	if (page_cache != NULL)
		free(page_cache);

	return ret;
}

int
copy_bitmap(void)
{
	off_t offset;
	unsigned char buf[info->page_size];
 	const off_t failed = (off_t)-1;

	offset = 0;
	while (offset < (info->len_bitmap / 2)) {
		if (lseek(info->bitmap1->fd, info->bitmap1->offset + offset,
		    SEEK_SET) == failed) {
			ERRMSG("Can't seek the bitmap(%s). %s\n",
			    info->name_bitmap, strerror(errno));
			return FALSE;
		}
		if (read(info->bitmap1->fd, buf, sizeof(buf)) != sizeof(buf)) {
			ERRMSG("Can't read the dump memory(%s). %s\n",
			    info->name_memory, strerror(errno));
			return FALSE;
		}
		if (lseek(info->bitmap2->fd, info->bitmap2->offset + offset,
		    SEEK_SET) == failed) {
			ERRMSG("Can't seek the bitmap(%s). %s\n",
			    info->name_bitmap, strerror(errno));
			return FALSE;
		}
		if (write(info->bitmap2->fd, buf, sizeof(buf)) != sizeof(buf)) {
			ERRMSG("Can't write the bitmap(%s). %s\n",
		    	info->name_bitmap, strerror(errno));
			return FALSE;
		}
		offset += sizeof(buf);
	}

	return TRUE;
}

int
create_2nd_bitmap(void)
{
	/*
	 * Copy 1st-bitmap to 2nd-bitmap.
	 */
	if (!copy_bitmap()) {
		ERRMSG("Can't copy 1st-bitmap to 2nd-bitmap.\n");
		return FALSE;
	}

	/*
	 * Exclude unnecessary pages (free pages, cache pages, etc.)
	 */
	if (DL_EXCLUDE_ZERO < info->dump_level) {
		if (!exclude_unnecessary_pages()) {
			ERRMSG("Can't exclude unnecessary pages.\n");
			return FALSE;
		}
	}

	/*
	 * Exclude Xen user domain.
	 */
	if (info->flag_exclude_xen_dom) {
		if (!exclude_xen_user_domain()) {
			ERRMSG("Can't exclude xen user domain.\n");
			return FALSE;
		}
	}

	/*
	 * Exclude pages filled with zero for creating an ELF dumpfile.
	 *
	 * Note: If creating a kdump-compressed dumpfile, makedumpfile
	 *	 checks zero-pages while copying dumpable pages to a
	 *	 dumpfile from /proc/vmcore. That is valuable for the
	 *	 speed, because each page is read one time only.
	 *	 Otherwise (if creating an ELF dumpfile), makedumpfile
	 *	 should check zero-pages at this time because 2nd-bitmap
	 *	 should be fixed for creating an ELF header. That is slow
	 *	 due to reading each page two times, but it is necessary.
	 */
	if ((info->dump_level & DL_EXCLUDE_ZERO) && info->flag_elf_dumpfile) {
		/*
		 * 2nd-bitmap should be flushed at this time, because
		 * exclude_zero_pages() checks 2nd-bitmap.
		 */
		if (!sync_2nd_bitmap())
			return FALSE;

		if (!exclude_zero_pages()) {
			ERRMSG("Can't exclude pages filled with zero for creating an ELF dumpfile.\n");
			return FALSE;
		}
	}

	if (!sync_2nd_bitmap())
		return FALSE;

	return TRUE;
}

int
prepare_bitmap_buffer(void)
{
	unsigned long tmp;

	/*
	 * Create 2 bitmaps (1st-bitmap & 2nd-bitmap) on block_size boundary.
	 * The crash utility requires both of them to be aligned to block_size
	 * boundary.
	 */
	tmp = divideup(divideup(info->max_mapnr, BITPERBYTE), info->page_size);
	info->len_bitmap = tmp*info->page_size*2;

	/*
	 * Prepare bitmap buffers for creating dump bitmap.
	 */
	if ((info->bitmap1 = malloc(sizeof(struct dump_bitmap))) == NULL) {
		ERRMSG("Can't allocate memory for the 1st-bitmap. %s\n",
		    strerror(errno));
		return FALSE;
	}
	if ((info->bitmap2 = malloc(sizeof(struct dump_bitmap))) == NULL) {
		ERRMSG("Can't allocate memory for the 2nd-bitmap. %s\n",
		    strerror(errno));
		return FALSE;
	}
	initialize_1st_bitmap(info->bitmap1);
	initialize_2nd_bitmap(info->bitmap2);

	return TRUE;
}

void
free_bitmap_buffer(void)
{
	free(info->bitmap1);
	free(info->bitmap2);

	info->bitmap1 = NULL;
	info->bitmap2 = NULL;
}

int
create_dump_bitmap(void)
{
	int ret = FALSE;

	if (!prepare_bitmap_buffer())
		return FALSE;

	if (!create_1st_bitmap())
		goto out;

	if (!create_2nd_bitmap())
		goto out;

	ret = TRUE;
out:
	free_bitmap_buffer();

	return ret;
}

int
get_phnum_memory(void)
{
	int phnum;
	Elf64_Ehdr ehdr64;
	Elf32_Ehdr ehdr32;

	if (info->flag_elf64_memory) { /* ELF64 */
		if (!get_elf64_ehdr(&ehdr64)) {
			ERRMSG("Can't get ehdr64.\n");
			return FALSE;
		}
		phnum = ehdr64.e_phnum;
	} else {                /* ELF32 */
		if (!get_elf32_ehdr(&ehdr32)) {
			ERRMSG("Can't get ehdr32.\n");
			return FALSE;
		}
		phnum = ehdr32.e_phnum;
	}

	return phnum;
}

int
get_loads_dumpfile(void)
{
	int i, phnum, num_new_load = 0;
	long page_size = info->page_size;
	unsigned long long pfn, pfn_start, pfn_end, num_excluded;
	unsigned long frac_head, frac_tail;
	Elf64_Phdr load;
	struct dump_bitmap bitmap2;

	initialize_2nd_bitmap(&bitmap2);

	if (!(phnum = get_phnum_memory()))
		return FALSE;

	for (i = 0; i < phnum; i++) {
		if (!get_elf_phdr_memory(i, &load))
			return FALSE;
		if (load.p_type != PT_LOAD)
			continue;

		pfn_start = load.p_paddr / page_size;
		pfn_end   = (load.p_paddr + load.p_memsz)/page_size;
		frac_head = page_size - (load.p_paddr % page_size);
		frac_tail = (load.p_paddr + load.p_memsz) % page_size;

		num_new_load++;
		num_excluded = 0;

		if (frac_head && (frac_head != page_size))
			pfn_start++;
		if (frac_tail)
			pfn_end++;

		for (pfn = pfn_start; pfn < pfn_end; pfn++) {
			if (!is_dumpable(&bitmap2, pfn)) {
				num_excluded++;
				continue;
			}

			/*
			 * If the number of the contiguous pages to be excluded
			 * is 256 or more, those pages are excluded really.
			 * And a new PT_LOAD segment is created.
			 */
			if (num_excluded >= PFN_EXCLUDED) {
				num_new_load++;
			}
			num_excluded = 0;
		}
	}
	return num_new_load;
}

int
prepare_cache_data(struct cache_data *cd)
{
	cd->fd         = info->fd_dumpfile;
	cd->file_name  = info->name_dumpfile;
	cd->cache_size = info->page_size << info->block_order;
	cd->buf_size   = 0;
	cd->buf        = NULL;

	if ((cd->buf = malloc(cd->cache_size + info->page_size)) == NULL) {
		ERRMSG("Can't allocate memory for the data buffer. %s\n",
		    strerror(errno));
		return FALSE;
	}
	return TRUE;
}

void
free_cache_data(struct cache_data *cd)
{
	free(cd->buf);
	cd->buf = NULL;
}

int
write_start_flat_header()
{
	char buf[MAX_SIZE_MDF_HEADER];
	struct makedumpfile_header fh;

	if (!info->flag_flatten)
		return FALSE;

	strcpy(fh.signature, MAKEDUMPFILE_SIGNATURE);

	/*
	 * For sending dump data to a different architecture, change the values
	 * to big endian.
	 */
	if (is_bigendian()){
		fh.type    = TYPE_FLAT_HEADER;
		fh.version = VERSION_FLAT_HEADER;
	} else {
		fh.type    = bswap_64(TYPE_FLAT_HEADER);
		fh.version = bswap_64(VERSION_FLAT_HEADER);
	}

	memset(buf, 0, sizeof(buf));
	memcpy(buf, &fh, sizeof(fh));

	if (!write_and_check_space(info->fd_dumpfile, buf, MAX_SIZE_MDF_HEADER,
	    info->name_dumpfile))
		return FALSE;

	return TRUE;
}

int
write_end_flat_header(void)
{
	struct makedumpfile_data_header fdh;

	if (!info->flag_flatten)
		return FALSE;

	fdh.offset   = END_FLAG_FLAT_HEADER;
	fdh.buf_size = END_FLAG_FLAT_HEADER;

	if (!write_and_check_space(info->fd_dumpfile, &fdh, sizeof(fdh),
	    info->name_dumpfile))
		return FALSE;

	return TRUE;
}

int
write_elf_phdr(struct cache_data *cd_hdr, Elf64_Phdr *load)
{
	Elf32_Phdr load32;

	if (info->flag_elf64_memory) { /* ELF64 */
		if (!write_cache(cd_hdr, load, sizeof(Elf64_Phdr)))
			return FALSE;

	} else {
		memset(&load32, 0, sizeof(Elf32_Phdr));
		load32.p_type   = load->p_type;
		load32.p_flags  = load->p_flags;
		load32.p_offset = load->p_offset;
		load32.p_vaddr  = load->p_vaddr;
		load32.p_paddr  = load->p_paddr;
		load32.p_filesz = load->p_filesz;
		load32.p_memsz  = load->p_memsz;
		load32.p_align  = load->p_align;

		if (!write_cache(cd_hdr, &load32, sizeof(Elf32_Phdr)))
			return FALSE;
	}
	return TRUE;
}

int
write_elf_header(struct cache_data *cd_header)
{
	int i, num_loads_dumpfile, phnum;
	off_t offset_note_memory, offset_note_dumpfile;
	size_t size_note;
	Elf64_Ehdr ehdr64;
	Elf32_Ehdr ehdr32;
	Elf64_Phdr note;

	char *buf = NULL;
	const off_t failed = (off_t)-1;

	int ret = FALSE;

	if (!info->flag_elf_dumpfile)
		return FALSE;

	/*
	 * Get the PT_LOAD number of the dumpfile.
	 */
	if (!(num_loads_dumpfile = get_loads_dumpfile())) {
		ERRMSG("Can't get a number of PT_LOAD.\n");
		goto out;
	}

	if (info->flag_elf64_memory) { /* ELF64 */
		if (!get_elf64_ehdr(&ehdr64)) {
			ERRMSG("Can't get ehdr64.\n");
			goto out;
		}
		/*
		 * PT_NOTE(1) + PT_LOAD(1+)
		 */
		ehdr64.e_phnum = 1 + num_loads_dumpfile;
	} else {                /* ELF32 */
		if (!get_elf32_ehdr(&ehdr32)) {
			ERRMSG("Can't get ehdr32.\n");
			goto out;
		}
		/*
		 * PT_NOTE(1) + PT_LOAD(1+)
		 */
		ehdr32.e_phnum = 1 + num_loads_dumpfile;
	}

	/*
	 * Write an ELF header.
	 */
	if (info->flag_elf64_memory) { /* ELF64 */
		if (!write_buffer(info->fd_dumpfile, 0, &ehdr64, sizeof(ehdr64),
		    info->name_dumpfile))
			goto out;

	} else {                /* ELF32 */
		if (!write_buffer(info->fd_dumpfile, 0, &ehdr32, sizeof(ehdr32),
		    info->name_dumpfile))
			goto out;
	}

	/*
	 * Write a PT_NOTE header.
	 */
	if (!(phnum = get_phnum_memory()))
		goto out;

	for (i = 0; i < phnum; i++) {
		if (!get_elf_phdr_memory(i, &note))
			return FALSE;
		if (note.p_type == PT_NOTE)
			break;
	}
	if (note.p_type != PT_NOTE) {
		ERRMSG("Can't get a PT_NOTE header.\n");
		goto out;
	}

	if (info->flag_elf64_memory) { /* ELF64 */
		cd_header->offset    = sizeof(ehdr64);
		offset_note_dumpfile = sizeof(ehdr64)
		    + sizeof(Elf64_Phdr) * ehdr64.e_phnum;
	} else {
		cd_header->offset    = sizeof(ehdr32);
		offset_note_dumpfile = sizeof(ehdr32)
		    + sizeof(Elf32_Phdr) * ehdr32.e_phnum;
	}
	offset_note_memory = note.p_offset;
	note.p_offset      = offset_note_dumpfile;
	size_note          = note.p_filesz;

	if (!write_elf_phdr(cd_header, &note))
		goto out;

	/*
	 * Write a PT_NOTE segment.
	 * PT_LOAD header will be written later.
	 */
	if ((buf = malloc(size_note)) == NULL) {
		ERRMSG("Can't allocate memory for PT_NOTE segment. %s\n",
		    strerror(errno));
		goto out;
	}
	if (lseek(info->fd_memory, offset_note_memory, SEEK_SET) == failed) {
		ERRMSG("Can't seek the dump memory(%s). %s\n",
		    info->name_memory, strerror(errno));
		goto out;
	}
	if (read(info->fd_memory, buf, size_note) != size_note) {
		ERRMSG("Can't read the dump memory(%s). %s\n",
		    info->name_memory, strerror(errno));
		goto out;
	}
	if (!write_buffer(info->fd_dumpfile, offset_note_dumpfile, buf,
	    size_note, info->name_dumpfile))
		goto out;

	/*
	 * Set an offset of PT_LOAD segment.
	 */
	info->offset_load_dumpfile = offset_note_dumpfile + size_note;

	ret = TRUE;
out:
	if (buf != NULL)
		free(buf);

	return ret;
}

int
write_kdump_header(void)
{
	size_t size;
	struct disk_dump_header *dh = info->dump_header;
	struct kdump_sub_header sub_dump_header;

	if (info->flag_elf_dumpfile)
		return FALSE;

	/*
	 * Write common header
	 */
	strcpy(dh->signature, KDUMP_SIGNATURE);
	dh->header_version = 2;
	dh->block_size   = info->page_size;
	dh->sub_hdr_size = 1;
	dh->max_mapnr    = info->max_mapnr;
	dh->nr_cpus      = 1;
	dh->bitmap_blocks
	    = divideup(info->len_bitmap, dh->block_size);
	memcpy(&dh->timestamp, &info->timestamp, sizeof(dh->timestamp));

	size = sizeof(struct disk_dump_header);
	if (!write_buffer(info->fd_dumpfile, 0, dh, size, info->name_dumpfile))
		return FALSE;

	/*
	 * Write sub header
	 */
	size = sizeof(struct kdump_sub_header);
	memset(&sub_dump_header, 0, size);
	sub_dump_header.phys_base  = info->phys_base;
	sub_dump_header.dump_level = info->dump_level;
	if (info->flag_split) {
		sub_dump_header.split = 1;
		sub_dump_header.start_pfn = info->split_start_pfn;
		sub_dump_header.end_pfn   = info->split_end_pfn;
	}
	if (!write_buffer(info->fd_dumpfile, dh->block_size, &sub_dump_header,
	    size, info->name_dumpfile))
		return FALSE;

	info->offset_bitmap1
	    = (1 + dh->sub_hdr_size) * dh->block_size;

	return TRUE;
}

void
print_progress(const char *msg, unsigned long current, unsigned long end)
{
	int progress;
	time_t tm;
	static time_t last_time = 0;

	if (current < end) {
		tm = time(NULL);
		if (tm - last_time < 1)
			return;
		last_time = tm;
		progress = current * 100 / end;
	} else
		progress = 100;

	PROGRESS_MSG("\r");
	PROGRESS_MSG("%-" PROGRESS_MAXLEN "s: [%3d %%] ", msg, progress);
}

unsigned long long
get_num_dumpable(void)
{
	unsigned long long pfn, num_dumpable;
	struct dump_bitmap bitmap2;

	initialize_2nd_bitmap(&bitmap2);

	for (pfn = 0, num_dumpable = 0; pfn < info->max_mapnr; pfn++) {
		if (is_dumpable(&bitmap2, pfn))
			num_dumpable++;
	}
	return num_dumpable;
}

int
write_elf_load_segment(struct cache_data *cd_page, unsigned long long paddr,
		       off_t off_memory, long long size)
{
	long page_size = info->page_size;
	long long bufsz_write;
	char buf[info->page_size];

	off_memory = paddr_to_offset2(paddr, off_memory);
	if (!off_memory) {
		ERRMSG("Can't convert physaddr(%llx) to an offset.\n",
		    paddr);
		return FALSE;
	}
	if (lseek(info->fd_memory, off_memory, SEEK_SET) < 0) {
		ERRMSG("Can't seek the dump memory(%s). %s\n",
		    info->name_memory, strerror(errno));
		return FALSE;
	}

	while (size > 0) {
		if (size >= page_size)
			bufsz_write = page_size;
		else
			bufsz_write = size;

		if (read(info->fd_memory, buf, bufsz_write) != bufsz_write) {
			ERRMSG("Can't read the dump memory(%s). %s\n",
			    info->name_memory, strerror(errno));
			return FALSE;
		}
		if (!write_cache(cd_page, buf, bufsz_write))
			return FALSE;

		size -= page_size;
	}
	return TRUE;
}

int
write_elf_pages(struct cache_data *cd_header, struct cache_data *cd_page)
{
	int i, phnum;
	long page_size = info->page_size;
	unsigned long long pfn, pfn_start, pfn_end, paddr, num_excluded;
	unsigned long long num_dumpable, num_dumped = 0, per;
	unsigned long long memsz, filesz;
	unsigned long frac_head, frac_tail;
	off_t off_seg_load, off_memory;
	Elf64_Phdr load;
	struct dump_bitmap bitmap2;

	if (!info->flag_elf_dumpfile)
		return FALSE;

	initialize_2nd_bitmap(&bitmap2);

	num_dumpable = get_num_dumpable();
	per = num_dumpable / 100;

	off_seg_load    = info->offset_load_dumpfile;
	cd_page->offset = info->offset_load_dumpfile;

	if (!(phnum = get_phnum_memory()))
		return FALSE;

	for (i = 0; i < phnum; i++) {
		if (!get_elf_phdr_memory(i, &load))
			return FALSE;

		if (load.p_type != PT_LOAD)
			continue;

		off_memory= load.p_offset;
		paddr     = load.p_paddr;
		pfn_start = load.p_paddr / page_size;
		pfn_end   = (load.p_paddr + load.p_memsz) / page_size;
		frac_head = page_size - (load.p_paddr % page_size);
		frac_tail = (load.p_paddr + load.p_memsz)%page_size;

		num_excluded = 0;
		memsz  = 0;
		filesz = 0;
		if (frac_head && (frac_head != page_size)) {
			memsz  = frac_head;
			filesz = frac_head;
			pfn_start++;
		}

		if (frac_tail)
			pfn_end++;

		for (pfn = pfn_start; pfn < pfn_end; pfn++) {
			if (!is_dumpable(&bitmap2, pfn)) {
				num_excluded++;
				if ((pfn == pfn_end - 1) && frac_tail)
					memsz += frac_tail;
				else
					memsz += page_size;
				continue;
			}

			if ((num_dumped % per) == 0)
				print_progress(PROGRESS_COPY, num_dumped, num_dumpable);

			num_dumped++;

			/*
			 * The dumpable pages are continuous.
			 */
			if (!num_excluded) {
				if ((pfn == pfn_end - 1) && frac_tail) {
					memsz  += frac_tail;
					filesz += frac_tail;
				} else {
					memsz  += page_size;
					filesz += page_size;
				}
				continue;
			/*
			 * If the number of the contiguous pages to be excluded
			 * is 255 or less, those pages are not excluded.
			 */
			} else if (num_excluded < PFN_EXCLUDED) {
				if ((pfn == pfn_end - 1) && frac_tail) {
					memsz  += frac_tail;
					filesz += (page_size*num_excluded
					    + frac_tail);
				}else {
					memsz  += page_size;
					filesz += (page_size*num_excluded
					    + page_size);
				}
				num_excluded = 0;
				continue;
			}

			/*
			 * If the number of the contiguous pages to be excluded
			 * is 256 or more, those pages are excluded really.
			 * And a new PT_LOAD segment is created.
			 */
			load.p_memsz  = memsz;
			load.p_filesz = filesz;
			load.p_offset = off_seg_load;

			/*
			 * Write a PT_LOAD header.
			 */
			if (!write_elf_phdr(cd_header, &load))
				return FALSE;

			/*
			 * Write a PT_LOAD segment.
			 */
			if (!write_elf_load_segment(cd_page, paddr, off_memory,
			    load.p_filesz))
				return FALSE;

			load.p_paddr += load.p_memsz;
#ifdef __x86__
			/*
			 * FIXME:
			 *  (x86) Fill PT_LOAD headers with appropriate
			 *        virtual addresses.
			 */
			if (load.p_paddr < MAXMEM)
				load.p_vaddr += load.p_memsz;
#else
			load.p_vaddr += load.p_memsz;
#endif /* x86 */
			paddr  = load.p_paddr;
			off_seg_load += load.p_filesz;

			num_excluded = 0;
			memsz  = page_size;
			filesz = page_size;
		}
		/*
		 * Write the last PT_LOAD.
		 */
		load.p_memsz  = memsz;
		load.p_filesz = filesz;
		load.p_offset = off_seg_load;

		/*
		 * Write a PT_LOAD header.
		 */
		if (!write_elf_phdr(cd_header, &load))
			return FALSE;

		/*
		 * Write a PT_LOAD segment.
		 */
		if (!write_elf_load_segment(cd_page, paddr, off_memory, load.p_filesz))
			return FALSE;

		off_seg_load += load.p_filesz;
	}
	if (!write_cache_bufsz(cd_header))
		return FALSE;
	if (!write_cache_bufsz(cd_page))
		return FALSE;

	/*
	 * print [100 %]
	 */
	print_progress(PROGRESS_COPY, num_dumpable, num_dumpable);
	PROGRESS_MSG("\n");

	return TRUE;
}

/*
 * This function is specific for reading page.
 *
 * If reading the separated page on different PT_LOAD segments,
 * this function gets the page data from both segments. This is
 * worthy of ia64 /proc/vmcore. In ia64 /proc/vmcore, region 5
 * segment is overlapping to region 7 segment. The following is
 * example (page_size is 16KBytes):
 *
 *  region |       paddr        |       memsz
 * --------+--------------------+--------------------
 *     5   | 0x0000000004000000 | 0x0000000000638ce0
 *     7   | 0x0000000004000000 | 0x0000000000db3000
 *
 * In the above example, the last page of region 5 is 0x4638000
 * and the segment does not contain complete data of this page.
 * Then this function gets the data of 0x4638000 - 0x4638ce0
 * from region 5, and gets the remaining data from region 7.
 */
int
read_pfn(unsigned long long pfn, unsigned char *buf)
{
	unsigned long long paddr;
	off_t offset1, offset2;
	size_t size1, size2;

	paddr = info->page_size * pfn;
	offset1 = paddr_to_offset(paddr);
	offset2 = paddr_to_offset(paddr + info->page_size);

	/*
	 * Check the separated page on different PT_LOAD segments.
	 */
	if (offset1 + info->page_size == offset2) {
		size1 = info->page_size;
	} else {
		for (size1 = 1; size1 < info->page_size; size1++) {
			offset2 = paddr_to_offset(paddr + size1);
			if (offset1 + size1 != offset2)
				break;
		}
	}
	if (!readmem(PADDR, paddr, buf, size1)) {
		ERRMSG("Can't get the page data.\n");
		return FALSE;
	}
	if (size1 != info->page_size) {
		size2 = info->page_size - size1;
		if (!offset2) {
			memset(buf + size1, 0, size2);
		} else {
			if (!readmem(PADDR, paddr + size1, buf + size1, size2)) {
				ERRMSG("Can't get the page data.\n");
				return FALSE;
			}
		}
	}
	return TRUE;
}

int
write_kdump_pages(struct cache_data *cd_header, struct cache_data *cd_page)
{
 	unsigned long long pfn, per, num_dumpable, num_dumped = 0;
	unsigned long long start_pfn, end_pfn;
	unsigned long size_out;
	struct page_desc pd, pd_zero;
	off_t offset_data = 0;
	struct disk_dump_header *dh = info->dump_header;
	unsigned char buf[info->page_size], *buf_out = NULL;
	unsigned long len_buf_out;
	struct dump_bitmap bitmap2;
	const off_t failed = (off_t)-1;

	int ret = FALSE;

	if (info->flag_elf_dumpfile)
		return FALSE;

	initialize_2nd_bitmap(&bitmap2);

	len_buf_out = compressBound(info->page_size);
	if ((buf_out = malloc(len_buf_out)) == NULL) {
		ERRMSG("Can't allocate memory for the compression buffer. %s\n",
		    strerror(errno));
		goto out;
	}

	num_dumpable = get_num_dumpable();
	per = num_dumpable / 100;

	/*
	 * Calculate the offset of the page data.
	 */
	cd_header->offset
	    = (1 + dh->sub_hdr_size + dh->bitmap_blocks)*dh->block_size;
	cd_page->offset = cd_header->offset + sizeof(page_desc_t)*num_dumpable;
	offset_data  = cd_page->offset;

	/*
	 * Set a fileoffset of Physical Address 0x0.
	 */
	if (lseek(info->fd_memory, info->offset_load_memory, SEEK_SET)
	    == failed) {
		ERRMSG("Can't seek the dump memory(%s). %s\n",
		    info->name_memory, strerror(errno));
		goto out;
	}

	/*
	 * Write the data of zero-filled page.
	 */
	if (info->dump_level & DL_EXCLUDE_ZERO) {
		pd_zero.size = info->page_size;
		pd_zero.flags = 0;
		pd_zero.offset = offset_data;
		pd_zero.page_flags = 0;
		memset(buf, 0, pd_zero.size);
		if (!write_cache(cd_page, buf, pd_zero.size))
			goto out;
		offset_data  += pd_zero.size;
	}
	if (info->flag_split) {
		start_pfn = info->split_start_pfn;
		end_pfn   = info->split_end_pfn;
	}
	else {
		start_pfn = 0;
		end_pfn   = info->max_mapnr;
	}
	for (pfn = start_pfn; pfn < end_pfn; pfn++) {

		if ((num_dumped % per) == 0)
			print_progress(PROGRESS_COPY, num_dumped, num_dumpable);

		/*
		 * Check the excluded page.
		 */
		if (!is_dumpable(&bitmap2, pfn))
			continue;

		num_dumped++;

		if (!read_pfn(pfn, buf))
			goto out;

		/*
		 * Exclude the page filled with zeros.
		 */
		if ((info->dump_level & DL_EXCLUDE_ZERO)
		    && is_zero_page(buf, info->page_size)) {
			if (!write_cache(cd_header, &pd_zero, sizeof(page_desc_t)))
				goto out;
			pfn_zero++;
			continue;
		}
		/*
		 * Compress the page data.
		 */
		size_out = len_buf_out;
		if (info->flag_compress
		    && (compress2(buf_out, &size_out, buf,
		    info->page_size, Z_BEST_SPEED) == Z_OK)
		    && (size_out < info->page_size)) {
			pd.flags = 1;
			pd.size  = size_out;
			memcpy(buf, buf_out, pd.size);
		} else {
			pd.flags = 0;
			pd.size  = info->page_size;
		}
		pd.page_flags = 0;
		pd.offset     = offset_data;
		offset_data  += pd.size;

		/*
		 * Write the page header.
		 */
		if (!write_cache(cd_header, &pd, sizeof(page_desc_t)))
			goto out;

		/*
		 * Write the page data.
		 */
		if (!write_cache(cd_page, buf, pd.size))
			goto out;
	}

	/*
	 * Write the remainder.
	 */
	if (!write_cache_bufsz(cd_page))
		goto out;
	if (!write_cache_bufsz(cd_header))
		goto out;

	/*
	 * print [100 %]
	 */
	print_progress(PROGRESS_COPY, num_dumpable, num_dumpable);
	PROGRESS_MSG("\n");

	ret = TRUE;
out:
	if (buf_out != NULL)
		free(buf_out);

	return ret;
}

int
write_kdump_bitmap(void)
{
	struct cache_data bm;
	long buf_size;
	off_t offset;

	int ret = FALSE;

	if (info->flag_elf_dumpfile)
		return FALSE;

	bm.fd        = info->fd_bitmap;
	bm.file_name = info->name_bitmap;
	bm.offset    = 0;
	bm.buf       = NULL;

	if ((bm.buf = calloc(1, BUFSIZE_BITMAP)) == NULL) {
		ERRMSG("Can't allocate memory for dump bitmap buffer. %s\n",
		    strerror(errno));
		goto out;
	}
	offset = info->offset_bitmap1;
	buf_size = info->len_bitmap;

	while (buf_size > 0) {
		if (buf_size >= BUFSIZE_BITMAP)
			bm.cache_size = BUFSIZE_BITMAP;
		else
			bm.cache_size = buf_size;

		if(!read_cache(&bm))
			goto out;

		if (!write_buffer(info->fd_dumpfile, offset,
		    bm.buf, bm.cache_size, info->name_dumpfile))
			goto out;

		offset += bm.cache_size;
		buf_size -= BUFSIZE_BITMAP;
	}
	ret = TRUE;
out:
	if (bm.buf != NULL)
		free(bm.buf);

	return ret;
}

void
close_vmcoreinfo(void)
{
	if(fclose(info->file_vmcoreinfo) < 0)
		ERRMSG("Can't close the vmcoreinfo file(%s). %s\n",
		    info->name_vmcoreinfo, strerror(errno));
}

void
close_dump_memory(void)
{
	if ((info->fd_memory = close(info->fd_memory)) < 0)
		ERRMSG("Can't close the dump memory(%s). %s\n",
		    info->name_memory, strerror(errno));
}

void
close_dump_file(void)
{
	if (info->flag_flatten)
		return;

	if ((info->fd_dumpfile = close(info->fd_dumpfile)) < 0)
		ERRMSG("Can't close the dump file(%s). %s\n",
		    info->name_dumpfile, strerror(errno));
}

void
close_dump_bitmap(void)
{
	if ((info->fd_bitmap = close(info->fd_bitmap)) < 0)
		ERRMSG("Can't close the bitmap file(%s). %s\n",
		    info->name_bitmap, strerror(errno));
	free(info->name_bitmap);
}

void
close_kernel_file(void)
{
	if (info->name_vmlinux) {
		if ((info->fd_vmlinux = close(info->fd_vmlinux)) < 0) {
			ERRMSG("Can't close the kernel file(%s). %s\n",
			    info->name_vmlinux, strerror(errno));
		}
	}
	if (info->name_xen_syms) {
		if ((info->fd_xen_syms = close(info->fd_xen_syms)) < 0) {
			ERRMSG("Can't close the kernel file(%s). %s\n",
			    info->name_xen_syms, strerror(errno));
		}
	}
}

/*
 * Close the following files when it generates the vmcoreinfo file.
 * - vmlinux
 * - vmcoreinfo file
 */
int
close_files_for_generating_vmcoreinfo(void)
{
	close_kernel_file();

	close_vmcoreinfo();

	return TRUE;
}

/*
 * Close the following file when it rearranges the dump data.
 * - dump file
 */
int
close_files_for_rearranging_dumpdata(void)
{
	close_dump_file();

	return TRUE;
}

/*
 * Close the following files when it creates the dump file.
 * - dump mem
 * - dump file
 * - bit map
 * if it reads the vmcoreinfo file
 *   - vmcoreinfo file
 * else
 *   - vmlinux
 */
int
close_files_for_creating_dumpfile(void)
{
	if (info->max_dump_level > DL_EXCLUDE_ZERO)
		close_kernel_file();

	/* free name for vmcoreinfo */
	if (info->offset_vmcoreinfo && info->size_vmcoreinfo) {
		free(info->name_vmcoreinfo);
		info->name_vmcoreinfo = NULL;
	}
	close_dump_memory();

	close_dump_bitmap();

	return TRUE;
}

/*
 * for Xen extraction
 */
int
get_symbol_info_xen(void)
{
	/*
	 * Common symbol
	 */
	SYMBOL_INIT(dom_xen, "dom_xen");
	SYMBOL_INIT(dom_io, "dom_io");
	SYMBOL_INIT(domain_list, "domain_list");
	SYMBOL_INIT(frame_table, "frame_table");
	SYMBOL_INIT(alloc_bitmap, "alloc_bitmap");
	SYMBOL_INIT(max_page, "max_page");
	SYMBOL_INIT(xenheap_phys_end, "xenheap_phys_end");

	/*
	 * Architecture specific
	 */
	SYMBOL_INIT(pgd_l2, "idle_pg_table_l2");	/* x86 */
	SYMBOL_INIT(pgd_l3, "idle_pg_table_l3");	/* x86-PAE */
	if (SYMBOL(pgd_l3) == NOT_FOUND_SYMBOL)
		SYMBOL_INIT(pgd_l3, "idle_pg_table");	/* x86-PAE */
	SYMBOL_INIT(pgd_l4, "idle_pg_table_4");		/* x86_64 */
	if (SYMBOL(pgd_l4) == NOT_FOUND_SYMBOL)
		SYMBOL_INIT(pgd_l4, "idle_pg_table");		/* x86_64 */

	SYMBOL_INIT(xen_heap_start, "xen_heap_start");	/* ia64 */
	SYMBOL_INIT(xen_pstart, "xen_pstart");		/* ia64 */
	SYMBOL_INIT(frametable_pg_dir, "frametable_pg_dir");	/* ia64 */

	return TRUE;
}

int
get_structure_info_xen(void)
{
	SIZE_INIT(page_info, "page_info");
	OFFSET_INIT(page_info.count_info, "page_info", "count_info");
	/*
	 * _domain is the first member of union u
	 */
	OFFSET_INIT(page_info._domain, "page_info", "u");

	SIZE_INIT(domain, "domain");
	OFFSET_INIT(domain.domain_id, "domain", "domain_id");
	OFFSET_INIT(domain.next_in_list, "domain", "next_in_list");

	return TRUE;
}

int
get_xen_phys_start(void)
{
	off_t offset;
	unsigned long xen_phys_start;
	const off_t failed = (off_t)-1;

	if (info->xen_phys_start)
		return TRUE;

	if (info->size_xen_crash_info >= SIZE_XEN_CRASH_INFO_V2) {
		offset = info->offset_xen_crash_info + info->size_xen_crash_info
			 - sizeof(unsigned long) * 2;
		if (lseek(info->fd_memory, offset, SEEK_SET) == failed) {
			ERRMSG("Can't seek the dump memory(%s). %s\n",
			    info->name_memory, strerror(errno));
			return FALSE;
		}
		if (read(info->fd_memory, &xen_phys_start, sizeof(unsigned long))
		    != sizeof(unsigned long)) {
			ERRMSG("Can't read the dump memory(%s). %s\n",
			    info->name_memory, strerror(errno));
			return FALSE;
		}
		info->xen_phys_start = xen_phys_start;
	}

	return TRUE;
}

int
get_xen_info(void)
{
	unsigned long domain;
	unsigned int domain_id;
	int num_domain;

	if (SYMBOL(alloc_bitmap) == NOT_FOUND_SYMBOL) {
		ERRMSG("Can't get the symbol of alloc_bitmap.\n");
		return FALSE;
	}
	if (!readmem(VADDR_XEN, SYMBOL(alloc_bitmap), &info->alloc_bitmap,
	      sizeof(info->alloc_bitmap))) {
		ERRMSG("Can't get the value of alloc_bitmap.\n");
		return FALSE;
	}
	if (SYMBOL(max_page) == NOT_FOUND_SYMBOL) {
		ERRMSG("Can't get the symbol of max_page.\n");
		return FALSE;
	}
	if (!readmem(VADDR_XEN, SYMBOL(max_page), &info->max_page,
	    sizeof(info->max_page))) {
		ERRMSG("Can't get the value of max_page.\n");
		return FALSE;
	}

	/*
	 * Walk through domain_list
	 */
	if (SYMBOL(domain_list) == NOT_FOUND_SYMBOL) {
		ERRMSG("Can't get the symbol of domain_list.\n");
		return FALSE;
	}
	if (!readmem(VADDR_XEN, SYMBOL(domain_list), &domain, sizeof(domain))){
		ERRMSG("Can't get the value of domain_list.\n");
		return FALSE;
	}

	/*
	 * Get numbers of domain first
	 */
	num_domain = 0;
	while (domain) {
		num_domain++;
		if (!readmem(VADDR_XEN, domain + OFFSET(domain.next_in_list),
		    &domain, sizeof(domain))) {
			ERRMSG("Can't get through the domain_list.\n");
			return FALSE;
		}
	}

	if ((info->domain_list = (struct domain_list *)
	      malloc(sizeof(struct domain_list) * (num_domain + 2))) == NULL) {
		ERRMSG("Can't allcate memory for domain_list.\n");
		return FALSE;
	}

	info->num_domain = num_domain + 2;

	if (!readmem(VADDR_XEN, SYMBOL(domain_list), &domain, sizeof(domain))) {
		ERRMSG("Can't get the value of domain_list.\n");
		return FALSE;
	}
	num_domain = 0;
	while (domain) {
		if (!readmem(VADDR_XEN, domain + OFFSET(domain.domain_id),
		      &domain_id, sizeof(domain_id))) {
			ERRMSG("Can't get the domain_id.\n");
			return FALSE;
		}
		info->domain_list[num_domain].domain_addr = domain;
		info->domain_list[num_domain].domain_id = domain_id;
		/*
		 * pickled_id is set by architecture specific
		 */
		num_domain++;

		if (!readmem(VADDR_XEN, domain + OFFSET(domain.next_in_list),
		     &domain, sizeof(domain))) {
			ERRMSG("Can't get through the domain_list.\n");
			return FALSE;
		}
	}

	/*
	 * special domains
	 */
	if (SYMBOL(dom_xen) == NOT_FOUND_SYMBOL) {
		ERRMSG("Can't get the symbol of dom_xen.\n");
		return FALSE;
	}
	if (!readmem(VADDR_XEN, SYMBOL(dom_xen), &domain, sizeof(domain))) {
		ERRMSG("Can't get the value of dom_xen.\n");
		return FALSE;
	}
	if (!readmem(VADDR_XEN, domain + OFFSET(domain.domain_id), &domain_id,
	    sizeof(domain_id))) {
		ERRMSG( "Can't get the value of dom_xen domain_id.\n");
		return FALSE;
	}
	info->domain_list[num_domain].domain_addr = domain;
	info->domain_list[num_domain].domain_id = domain_id;
	num_domain++;

	if (SYMBOL(dom_io) == NOT_FOUND_SYMBOL) {
		ERRMSG("Can't get the symbol of dom_io.\n");
		return FALSE;
	}
	if (!readmem(VADDR_XEN, SYMBOL(dom_io), &domain, sizeof(domain))) {
		ERRMSG("Can't get the value of dom_io.\n");
		return FALSE;
	}
	if (!readmem(VADDR_XEN, domain + OFFSET(domain.domain_id), &domain_id,
	    sizeof(domain_id))) {
		ERRMSG( "Can't get the value of dom_io domain_id.\n");
		return FALSE;
	}
	info->domain_list[num_domain].domain_addr = domain;
	info->domain_list[num_domain].domain_id = domain_id;

	/*
	 * Get architecture specific data
	 */
	if (!get_xen_info_arch())
		return FALSE;

	return TRUE;
}

void
show_data_xen(void)
{
	int i;

	/*
	 * Show data for debug
	 */
	MSG("\n");
	MSG("SYMBOL(dom_xen): %llx\n", SYMBOL(dom_xen));
	MSG("SYMBOL(dom_io): %llx\n", SYMBOL(dom_io));
	MSG("SYMBOL(domain_list): %llx\n", SYMBOL(domain_list));
	MSG("SYMBOL(xen_heap_start): %llx\n", SYMBOL(xen_heap_start));
	MSG("SYMBOL(frame_table): %llx\n", SYMBOL(frame_table));
	MSG("SYMBOL(alloc_bitmap): %llx\n", SYMBOL(alloc_bitmap));
	MSG("SYMBOL(max_page): %llx\n", SYMBOL(max_page));
	MSG("SYMBOL(pgd_l2): %llx\n", SYMBOL(pgd_l2));
	MSG("SYMBOL(pgd_l3): %llx\n", SYMBOL(pgd_l3));
	MSG("SYMBOL(pgd_l4): %llx\n", SYMBOL(pgd_l4));
	MSG("SYMBOL(xenheap_phys_end): %llx\n", SYMBOL(xenheap_phys_end));
	MSG("SYMBOL(xen_pstart): %llx\n", SYMBOL(xen_pstart));
	MSG("SYMBOL(frametable_pg_dir): %llx\n", SYMBOL(frametable_pg_dir));

	MSG("SIZE(page_info): %ld\n", SIZE(page_info));
	MSG("OFFSET(page_info.count_info): %ld\n", OFFSET(page_info.count_info));
	MSG("OFFSET(page_info._domain): %ld\n", OFFSET(page_info._domain));
	MSG("SIZE(domain): %ld\n", SIZE(domain));
	MSG("OFFSET(domain.domain_id): %ld\n", OFFSET(domain.domain_id));
	MSG("OFFSET(domain.next_in_list): %ld\n", OFFSET(domain.next_in_list));

	MSG("\n");
	MSG("xen_phys_start: %lx\n", info->xen_phys_start);
	MSG("frame_table_vaddr: %lx\n", info->frame_table_vaddr);
	MSG("xen_heap_start: %lx\n", info->xen_heap_start);
	MSG("xen_heap_end:%lx\n", info->xen_heap_end);
	MSG("alloc_bitmap: %lx\n", info->alloc_bitmap);
	MSG("max_page: %lx\n", info->max_page);
	MSG("num_domain: %d\n", info->num_domain);
	for (i = 0; i < info->num_domain; i++) {
		MSG(" %u: %x: %lx\n", info->domain_list[i].domain_id,
			info->domain_list[i].pickled_id,
			info->domain_list[i].domain_addr);
	}
}

int
generate_vmcoreinfo_xen(void)
{
	if ((info->page_size = sysconf(_SC_PAGE_SIZE)) <= 0) {
		ERRMSG("Can't get the size of page.\n");
		return FALSE;
	}
	dwarf_info.fd_debuginfo   = info->fd_xen_syms;
	dwarf_info.name_debuginfo = info->name_xen_syms;

	if (!get_symbol_info_xen())
		return FALSE;

	if (!get_structure_info_xen())
		return FALSE;

	/*
	 * write 1st kernel's PAGESIZE
	 */
	fprintf(info->file_vmcoreinfo, "%s%ld\n", STR_PAGESIZE,
	    info->page_size);

	/*
	 * write the symbol of 1st kernel
	 */
	WRITE_SYMBOL("dom_xen", dom_xen);
	WRITE_SYMBOL("dom_io", dom_io);
	WRITE_SYMBOL("domain_list", domain_list);
	WRITE_SYMBOL("xen_heap_start", xen_heap_start);
	WRITE_SYMBOL("frame_table", frame_table);
	WRITE_SYMBOL("alloc_bitmap", alloc_bitmap);
	WRITE_SYMBOL("max_page", max_page);
	WRITE_SYMBOL("pgd_l2", pgd_l2);
	WRITE_SYMBOL("pgd_l3", pgd_l3);
	WRITE_SYMBOL("pgd_l4", pgd_l4);
	WRITE_SYMBOL("xenheap_phys_end", xenheap_phys_end);
	WRITE_SYMBOL("xen_pstart", xen_pstart);
	WRITE_SYMBOL("frametable_pg_dir", frametable_pg_dir);

	/*
	 * write the structure size of 1st kernel
	 */
	WRITE_STRUCTURE_SIZE("page_info", page_info);
	WRITE_STRUCTURE_SIZE("domain", domain);

	/*
	 * write the member offset of 1st kernel
	 */
	WRITE_MEMBER_OFFSET("page_info.count_info", page_info.count_info);
	WRITE_MEMBER_OFFSET("page_info._domain", page_info._domain);
	WRITE_MEMBER_OFFSET("domain.domain_id", domain.domain_id);
	WRITE_MEMBER_OFFSET("domain.next_in_list", domain.next_in_list);

	return TRUE;
}

int
read_vmcoreinfo_basic_info_xen(void)
{
	long page_size = FALSE;
	char buf[BUFSIZE_FGETS], *endp;
	unsigned int i;

	if (fseek(info->file_vmcoreinfo, 0, SEEK_SET) < 0) {
		ERRMSG("Can't seek the vmcoreinfo file(%s). %s\n",
		    info->name_vmcoreinfo, strerror(errno));
		return FALSE;
	}

	while (fgets(buf, BUFSIZE_FGETS, info->file_vmcoreinfo)) {
		i = strlen(buf);
		if (!i)
			break;
		if (buf[i - 1] == '\n')
			buf[i - 1] = '\0';
		if (strncmp(buf, STR_PAGESIZE, strlen(STR_PAGESIZE)) == 0) {
			page_size = strtol(buf+strlen(STR_PAGESIZE),&endp,10);
			if ((!page_size || page_size == LONG_MAX)
			    || strlen(endp) != 0) {
				ERRMSG("Invalid data in %s: %s",
				    info->name_vmcoreinfo, buf);
				return FALSE;
			}
			if (!set_page_size(page_size)) {
				ERRMSG("Invalid data in %s: %s",
				    info->name_vmcoreinfo, buf);
				return FALSE;
			}
			break;
		}
	}
	if (!info->page_size) {
		ERRMSG("Invalid format in %s", info->name_vmcoreinfo);
		return FALSE;
	}
	return TRUE;
}

int
read_vmcoreinfo_xen(void)
{
	if (!read_vmcoreinfo_basic_info_xen())
		return FALSE;

	READ_SYMBOL("dom_xen", dom_xen);
	READ_SYMBOL("dom_io", dom_io);
	READ_SYMBOL("domain_list", domain_list);
	READ_SYMBOL("xen_heap_start", xen_heap_start);
	READ_SYMBOL("frame_table", frame_table);
	READ_SYMBOL("alloc_bitmap", alloc_bitmap);
	READ_SYMBOL("max_page", max_page);
	READ_SYMBOL("pgd_l2", pgd_l2);
	READ_SYMBOL("pgd_l3", pgd_l3);
	READ_SYMBOL("pgd_l4", pgd_l4);
	READ_SYMBOL("xenheap_phys_end", xenheap_phys_end);
	READ_SYMBOL("xen_pstart", xen_pstart);
	READ_SYMBOL("frametable_pg_dir", frametable_pg_dir);

	READ_STRUCTURE_SIZE("page_info", page_info);
	READ_STRUCTURE_SIZE("domain", domain);

	READ_MEMBER_OFFSET("page_info.count_info", page_info.count_info);
	READ_MEMBER_OFFSET("page_info._domain", page_info._domain);
	READ_MEMBER_OFFSET("domain.domain_id", domain.domain_id);
	READ_MEMBER_OFFSET("domain.next_in_list", domain.next_in_list);

	return TRUE;
}

int
allocated_in_map(unsigned long long pfn)
{
	static unsigned long long cur_idx = -1;
	static unsigned long cur_word;
	unsigned long long idx;

	idx = pfn / PAGES_PER_MAPWORD;
	if (idx != cur_idx) {
		if (!readmem(VADDR_XEN,
		    info->alloc_bitmap + idx * sizeof(unsigned long),
		    &cur_word, sizeof(cur_word))) {
			ERRMSG("Can't access alloc_bitmap.\n");
			return 0;
		}
		cur_idx = idx;
	}

	return !!(cur_word & (1UL << (pfn & (PAGES_PER_MAPWORD - 1))));
}

int
is_select_domain(unsigned int id)
{
	int i;

	/* selected domain is fix to dom0 only now !!
	   (yes... domain_list is not necessary right now,
		   it can get from "dom0" directly) */

	for (i = 0; i < info->num_domain; i++) {
		if (info->domain_list[i].domain_id == 0 &&
		    info->domain_list[i].pickled_id == id)
			return TRUE;
	}

	return FALSE;
}

int
exclude_xen_user_domain(void)
{
	int i;
	unsigned int count_info, _domain;
	unsigned long page_info_addr;
	unsigned long long pfn, pfn_end;
	unsigned long long j, size;
	struct pt_load_segment *pls;

	/*
	 * NOTE: the first half of bitmap is not used for Xen extraction
	 */
	for (i = 0; i < info->num_load_memory; i++) {

		print_progress(PROGRESS_XEN_DOMAIN, i, info->num_load_memory);

		pls = &info->pt_load_segments[i];
		pfn     = pls->phys_start >> PAGESHIFT();
		pfn_end = pls->phys_end >> PAGESHIFT();
		size    = pfn_end - pfn;

		for (j = 0; pfn < pfn_end; pfn++, j++) {
			print_progress(PROGRESS_XEN_DOMAIN, j + (size * i),
					size * info->num_load_memory);

			if (!allocated_in_map(pfn)) {
				clear_bit_on_2nd_bitmap(pfn);
				continue;
			}

			page_info_addr = info->frame_table_vaddr + pfn * SIZE(page_info);
			if (!readmem(VADDR_XEN,
			      page_info_addr + OFFSET(page_info.count_info),
		 	      &count_info, sizeof(count_info))) {
				clear_bit_on_2nd_bitmap(pfn);
				continue;	/* page_info may not exist */
			}
			if (!readmem(VADDR_XEN,
			      page_info_addr + OFFSET(page_info._domain),
			      &_domain, sizeof(_domain))) {
				ERRMSG("Can't get page_info._domain.\n");
				return FALSE;
			}
			/*
			 * select:
			 *  - anonymous (_domain == 0), or
			 *  - xen heap area, or
			 *  - selected domain page
			 */
			if (_domain == 0)
				continue;
			if (info->xen_heap_start <= pfn && pfn < info->xen_heap_end)
				continue;
			if ((count_info & 0xffff) && is_select_domain(_domain))
				continue;
			clear_bit_on_2nd_bitmap(pfn);
		}
	}

	/*
	 * print [100 %]
	 */
	print_progress(PROGRESS_XEN_DOMAIN, info->num_load_memory, info->num_load_memory);

	return TRUE;
}

int
initial_xen(void)
{
#ifdef __powerpc__
	MSG("\n");
	MSG("ppc64 xen is not supported.\n");
	return FALSE;
#else
	if(!info->flag_elf_dumpfile) {
		MSG("Specify '-E' option for Xen.\n");
		MSG("Commandline parameter is invalid.\n");
		MSG("Try `makedumpfile --help' for more information.\n");
		return FALSE;
	}
	if (DL_EXCLUDE_ZERO < info->max_dump_level) {
		MSG("Dump_level is invalid. It should be 0 or 1.\n");
		MSG("Commandline parameter is invalid.\n");
		MSG("Try `makedumpfile --help' for more information.\n");
		return FALSE;
	}

	if (!fallback_to_current_page_size())
		return FALSE;
	/*
	 * Get the debug information for analysis from the vmcoreinfo file
	 */
	if (info->flag_read_vmcoreinfo) {
		if (!read_vmcoreinfo_xen())
			return FALSE;
		close_vmcoreinfo();
	/*
	 * Get the debug information for analysis from the xen-syms file
	 */
	} else if (info->name_xen_syms) {
		dwarf_info.fd_debuginfo   = info->fd_xen_syms;
		dwarf_info.name_debuginfo = info->name_xen_syms;

		if (!get_symbol_info_xen())
			return FALSE;
		if (!get_structure_info_xen())
			return FALSE;
	/*
	 * Get the debug information for analysis from /proc/vmcore
	 */
	} else {
		/*
		 * Check whether /proc/vmcore contains vmcoreinfo,
		 * and get both the offset and the size.
		 */
		if (!info->offset_vmcoreinfo_xen || !info->size_vmcoreinfo_xen){
			if (!info->flag_exclude_xen_dom)
				goto out;

			MSG("%s doesn't contain a vmcoreinfo for Xen.\n",
			    info->name_memory);
			MSG("Specify '--xen-syms' option or '--xen-vmcoreinfo' option.\n");
			MSG("Commandline parameter is invalid.\n");
			MSG("Try `makedumpfile --help' for more information.\n");
			return FALSE;
		}
		/*
		 * Get the debug information from /proc/vmcore
		 */
		if (!read_vmcoreinfo_from_vmcore(info->offset_vmcoreinfo_xen,
		    info->size_vmcoreinfo_xen, TRUE))
			return FALSE;
	}
	if (!get_xen_phys_start())
		return FALSE;
	if (!get_xen_info())
		return FALSE;

	if (message_level & ML_PRINT_DEBUG_MSG)
		show_data_xen();
out:
	if (!get_max_mapnr())
		return FALSE;

	return TRUE;
#endif
}

void
print_vtop(void)
{
	unsigned long long paddr;

	if (!info->vaddr_for_vtop)
		return;

	MSG("\n");
	MSG("Translating virtual address %lx to physical address.\n", info->vaddr_for_vtop);

	paddr = vaddr_to_paddr(info->vaddr_for_vtop);

	MSG("VIRTUAL           PHYSICAL\n");
	MSG("%16lx  %llx\n", info->vaddr_for_vtop, paddr);
	MSG("\n");

	info->vaddr_for_vtop = 0;

	return;
}

void
print_report(void)
{
	unsigned long long pfn_original, pfn_excluded, shrinking;

	/*
	 * /proc/vmcore doesn't contain the memory hole area.
	 */
	pfn_original = info->max_mapnr - pfn_memhole;

	pfn_excluded = pfn_zero + pfn_cache + pfn_cache_private
	    + pfn_user + pfn_free;
	shrinking = (pfn_original - pfn_excluded) * 100;
	shrinking = shrinking / pfn_original;

	REPORT_MSG("Original pages  : 0x%016llx\n", pfn_original);
	REPORT_MSG("  Excluded pages   : 0x%016llx\n", pfn_excluded);
	REPORT_MSG("    Pages filled with zero  : 0x%016llx\n", pfn_zero);
	REPORT_MSG("    Cache pages             : 0x%016llx\n", pfn_cache);
	REPORT_MSG("    Cache pages + private   : 0x%016llx\n",
	    pfn_cache_private);
	REPORT_MSG("    User process data pages : 0x%016llx\n", pfn_user);
	REPORT_MSG("    Free pages              : 0x%016llx\n", pfn_free);
	REPORT_MSG("  Remaining pages  : 0x%016llx\n",
	    pfn_original - pfn_excluded);
	REPORT_MSG("  (The number of pages is reduced to %lld%%.)\n",
	    shrinking);
	REPORT_MSG("Memory Hole     : 0x%016llx\n", pfn_memhole);
	REPORT_MSG("--------------------------------------------------\n");
	REPORT_MSG("Total pages     : 0x%016llx\n", info->max_mapnr);
	REPORT_MSG("\n");
}

int
writeout_dumpfile(void)
{
	int ret = FALSE;
	struct cache_data cd_header, cd_page;

	info->flag_nospace = FALSE;

	if (!open_dump_file())
		return FALSE;

	if (info->flag_flatten) {
		if (!write_start_flat_header())
			return FALSE;
	}
	if (!prepare_cache_data(&cd_header))
		return FALSE;

	if (!prepare_cache_data(&cd_page)) {
		free_cache_data(&cd_header);
		return FALSE;
	}
	if (info->flag_elf_dumpfile) {
		if (!write_elf_header(&cd_header))
			goto out;
		if (!write_elf_pages(&cd_header, &cd_page))
			goto out;
	} else {
		if (!write_kdump_header())
			goto out;
		if (!write_kdump_pages(&cd_header, &cd_page))
			goto out;
		if (!write_kdump_bitmap())
			goto out;
	}
	if (info->flag_flatten) {
		if (!write_end_flat_header())
			goto out;
	}

	ret = TRUE;
out:
	free_cache_data(&cd_header);
	free_cache_data(&cd_page);

	close_dump_file();

	if ((ret == FALSE) && info->flag_nospace)
		return NOSPACE;
	else
		return ret;
}

int
setup_splitting(void)
{
	int i;
	unsigned long long j, pfn_per_dumpfile;
	unsigned long long start_pfn, end_pfn;
	unsigned long long num_dumpable = get_num_dumpable();
	struct dump_bitmap bitmap2;

	if (info->num_dumpfile <= 1)
		return FALSE;

	initialize_2nd_bitmap(&bitmap2);

	pfn_per_dumpfile = num_dumpable / info->num_dumpfile;
	start_pfn = end_pfn = 0;
	for (i = 0; i < info->num_dumpfile; i++) {
		start_pfn = end_pfn;
		if (i == (info->num_dumpfile - 1)) {
			end_pfn  = info->max_mapnr;
		} else {
			for (j = 0; j < pfn_per_dumpfile; end_pfn++) {
				if (is_dumpable(&bitmap2, end_pfn))
					j++;
			}
		}
		SPLITTING_START_PFN(i) = start_pfn;
		SPLITTING_END_PFN(i)   = end_pfn;
	}

	return TRUE;
}

/*
 * This function is for creating split dumpfiles by multiple
 * processes. Each child process should re-open a /proc/vmcore
 * file, because it prevents each other from affectting the file
 * offset due to read(2) call.
 */
int
reopen_dump_memory()
{
	close_dump_memory();

	if ((info->fd_memory = open(info->name_memory, O_RDONLY)) < 0) {
		ERRMSG("Can't open the dump memory(%s). %s\n",
		    info->name_memory, strerror(errno));
		return FALSE;
	}
	return TRUE;
}

int
get_next_dump_level(int index)
{
	if (info->num_dump_level <= index)
		return -1;

	return info->array_dump_level[index];
}

int
delete_dumpfile(void)
{
	int i;

	if (info->flag_flatten)
		return TRUE;

	if (info->flag_split) {
		for (i = 0; i < info->num_dumpfile; i++)
			unlink(SPLITTING_DUMPFILE(i));
	} else {
		unlink(info->name_dumpfile);
	}
	return TRUE;
}

int
writeout_multiple_dumpfiles(void)
{
	int i, status, ret = TRUE;
	pid_t pid;
	pid_t array_pid[info->num_dumpfile];

	if (!setup_splitting())
		return FALSE;

	for (i = 0; i < info->num_dumpfile; i++) {
		if ((pid = fork()) < 0) {
			return FALSE;

		} else if (pid == 0) { /* Child */
			info->name_dumpfile   = SPLITTING_DUMPFILE(i);
			info->fd_bitmap       = SPLITTING_FD_BITMAP(i);
			info->split_start_pfn = SPLITTING_START_PFN(i);
			info->split_end_pfn   = SPLITTING_END_PFN(i);

			if (!reopen_dump_memory())
				exit(1);
			if ((status = writeout_dumpfile()) == FALSE)
				exit(1);
			else if (status == NOSPACE)
				exit(2);
			exit(0);
		}
		array_pid[i] = pid;
	}
	for (i = 0; i < info->num_dumpfile; i++) {
		waitpid(array_pid[i], &status, WUNTRACED);
		if (!WIFEXITED(status) || WEXITSTATUS(status) == 1) {
			ERRMSG("Child process(%d) finished imcompletely.(%d)\n",
			    array_pid[i], status);
			ret = FALSE;
		} else if ((ret == TRUE) && (WEXITSTATUS(status) == 2))
			ret = NOSPACE;
	}
	return ret;
}

int
create_dumpfile(void)
{
	int num_retry, status;

	if (!open_files_for_creating_dumpfile())
		return FALSE;

	if (!get_elf_info())
		return FALSE;

	if (vt.mem_flags & MEMORY_XEN) {
		if (!initial_xen())
			return FALSE;
	} else {
		if (!initial())
			return FALSE;
	}
	print_vtop();

	num_retry = 0;
retry:
	if (!create_dump_bitmap())
		return FALSE;

	if (info->flag_split) {
		if ((status = writeout_multiple_dumpfiles()) == FALSE)
			return FALSE;
	} else {
		if ((status = writeout_dumpfile()) == FALSE)
			return FALSE;
	}
	if (status == NOSPACE) {
		/*
		 * If specifying the other dump_level, makedumpfile tries
		 * to create a dumpfile with it again.
		 */
		num_retry++;
		if ((info->dump_level = get_next_dump_level(num_retry)) < 0)
 			return FALSE;
		MSG("Retry to create a dumpfile by dump_level(%d).\n",
		    info->dump_level);
		if (!delete_dumpfile())
 			return FALSE;
		goto retry;
	}
	print_report();

	if (!close_files_for_creating_dumpfile())
		return FALSE;

	return TRUE;
}

int
read_disk_dump_header(struct disk_dump_header *dh, char *filename)
{
	int fd, ret = FALSE;

	if ((fd = open(filename, O_RDONLY)) < 0) {
		ERRMSG("Can't open a file(%s). %s\n",
		    filename, strerror(errno));
		return FALSE;
	}
	if (lseek(fd, 0x0, SEEK_SET) < 0) {
		ERRMSG("Can't seek a file(%s). %s\n",
		    filename, strerror(errno));
		goto out;
	}
	if (read(fd, dh, sizeof(struct disk_dump_header))
	    != sizeof(struct disk_dump_header)) {
		ERRMSG("Can't read a file(%s). %s\n",
		    filename, strerror(errno));
		goto out;
	}
	if (strncmp(dh->signature, KDUMP_SIGNATURE, strlen(KDUMP_SIGNATURE))) {
		ERRMSG("%s is not the kdump-compressed format.\n",
		    filename);
		goto out;
	}
	ret = TRUE;
out:
	close(fd);

	return ret;
}

int
read_kdump_sub_header(struct kdump_sub_header *ksh, char *filename)
{
	int fd, ret = FALSE;

	if (!info->page_size)
		return FALSE;

	if ((fd = open(filename, O_RDONLY)) < 0) {
		ERRMSG("Can't open a file(%s). %s\n",
		    filename, strerror(errno));
		return FALSE;
	}
	if (lseek(fd, info->page_size, SEEK_SET) < 0) {
		ERRMSG("Can't seek a file(%s). %s\n",
		    filename, strerror(errno));
		goto out;
	}
	if (read(fd, ksh, sizeof(struct kdump_sub_header))
	     != sizeof(struct kdump_sub_header)) {
		ERRMSG("Can't read a file(%s). %s\n",
		    filename, strerror(errno));
		goto out;
	}
	ret = TRUE;
out:
	close(fd);

	return ret;
}

int
store_splitting_info(void)
{
	int i;
	struct disk_dump_header dh, tmp_dh;
	struct kdump_sub_header ksh;

	for (i = 0; i < info->num_dumpfile; i++) {
		if (!read_disk_dump_header(&tmp_dh, SPLITTING_DUMPFILE(i)))
			return FALSE;

		if (i == 0) {
			memcpy(&dh, &tmp_dh, sizeof(tmp_dh));
			info->max_mapnr = dh.max_mapnr;
			if (!set_page_size(dh.block_size))
				return FALSE;
			DEBUG_MSG("max_mapnr    : %llx\n", info->max_mapnr);
			DEBUG_MSG("page_size    : %ld\n", info->page_size);
		}

		/*
		 * Check whether multiple dumpfiles are parts of
		 * the same /proc/vmcore.
		 */
		if (memcmp(&dh, &tmp_dh, sizeof(tmp_dh))) {
			ERRMSG("Invalid dumpfile(%s).\n",
			    SPLITTING_DUMPFILE(i));
			return FALSE;
		}
		if (!read_kdump_sub_header(&ksh, SPLITTING_DUMPFILE(i)))
			return FALSE;

		if (i == 0) {
			info->dump_level = ksh.dump_level;
			DEBUG_MSG("dump_level   : %d\n", info->dump_level);
		}
		SPLITTING_START_PFN(i) = ksh.start_pfn;
		SPLITTING_END_PFN(i)   = ksh.end_pfn;
	}
	return TRUE;
}

void
sort_splitting_info(void)
{
	int i, j;
	unsigned long long start_pfn, end_pfn;
	char *name_dumpfile;

	/*
	 * Sort splitting_info by start_pfn.
	 */
	for (i = 0; i < (info->num_dumpfile - 1); i++) {
		for (j = i; j < info->num_dumpfile; j++) {
			if (SPLITTING_START_PFN(i) < SPLITTING_START_PFN(j))
				continue;
			start_pfn     = SPLITTING_START_PFN(i);
			end_pfn       = SPLITTING_END_PFN(i);
			name_dumpfile = SPLITTING_DUMPFILE(i);

			SPLITTING_START_PFN(i) = SPLITTING_START_PFN(j);
			SPLITTING_END_PFN(i)   = SPLITTING_END_PFN(j);
			SPLITTING_DUMPFILE(i)  = SPLITTING_DUMPFILE(j);

			SPLITTING_START_PFN(j) = start_pfn;
			SPLITTING_END_PFN(j)   = end_pfn;
			SPLITTING_DUMPFILE(j)  = name_dumpfile;
		}
	}

	DEBUG_MSG("num_dumpfile : %d\n", info->num_dumpfile);
	for (i = 0; i < info->num_dumpfile; i++) {
		DEBUG_MSG("dumpfile (%s)\n", SPLITTING_DUMPFILE(i));
		DEBUG_MSG("  start_pfn  : %llx\n", SPLITTING_START_PFN(i));
		DEBUG_MSG("  end_pfn    : %llx\n", SPLITTING_END_PFN(i));
	}
}

int
check_splitting_info(void)
{
	int i;
	unsigned long long end_pfn;

	/*
	 * Check whether there are not lack of /proc/vmcore.
	 */
	if (SPLITTING_START_PFN(0) != 0) {
		ERRMSG("There is not dumpfile corresponding to pfn 0x%x - 0x%llx.\n",
		    0x0, SPLITTING_START_PFN(0));
		return FALSE;
	}
	end_pfn = SPLITTING_END_PFN(0);

	for (i = 1; i < info->num_dumpfile; i++) {
		if (end_pfn != SPLITTING_START_PFN(i)) {
			ERRMSG("There is not dumpfile corresponding to pfn 0x%llx - 0x%llx.\n",
			    end_pfn, SPLITTING_START_PFN(i));
			return FALSE;
		}
		end_pfn = SPLITTING_END_PFN(i);
	}
	if (end_pfn != info->max_mapnr) {
		ERRMSG("There is not dumpfile corresponding to pfn 0x%llx - 0x%llx.\n",
		    end_pfn, info->max_mapnr);
		return FALSE;
	}

	return TRUE;
}

int
get_splitting_info(void)
{
	if (!store_splitting_info())
		return FALSE;

	sort_splitting_info();

	if (!check_splitting_info())
		return FALSE;

	return TRUE;
}

int
reassemble_kdump_header(void)
{
	int fd, ret = FALSE;
	off_t offset_bitmap;
	struct disk_dump_header dh;
	struct kdump_sub_header ksh;
	char *buf_bitmap;

	/*
	 * Write common header.
	 */
	if (!read_disk_dump_header(&dh, SPLITTING_DUMPFILE(0)))
		return FALSE;

	if (lseek(info->fd_dumpfile, 0x0, SEEK_SET) < 0) {
		ERRMSG("Can't seek a file(%s). %s\n",
		    info->name_dumpfile, strerror(errno));
		return FALSE;
	}
	if (write(info->fd_dumpfile, &dh, sizeof(dh)) != sizeof(dh)) {
		ERRMSG("Can't write a file(%s). %s\n",
		    info->name_dumpfile, strerror(errno));
		return FALSE;
	}

	/*
	 * Write sub header.
	 */
	if (!read_kdump_sub_header(&ksh, SPLITTING_DUMPFILE(0)))
		return FALSE;

	ksh.split = 0;
	ksh.start_pfn = 0;
	ksh.end_pfn   = 0;

	if (lseek(info->fd_dumpfile, info->page_size, SEEK_SET) < 0) {
		ERRMSG("Can't seek a file(%s). %s\n",
		    info->name_dumpfile, strerror(errno));
		return FALSE;
	}
	if (write(info->fd_dumpfile, &ksh, sizeof(ksh)) != sizeof(ksh)) {
		ERRMSG("Can't write a file(%s). %s\n",
		    info->name_dumpfile, strerror(errno));
		return FALSE;
	}

	/*
	 * Write dump bitmap to both a dumpfile and a bitmap file.
	 */
	offset_bitmap    = info->page_size * (1 + dh.sub_hdr_size);
	info->len_bitmap = info->page_size * dh.bitmap_blocks;
	if ((buf_bitmap = malloc(info->len_bitmap)) == NULL) {
		ERRMSG("Can't allcate memory for bitmap.\n");
		return FALSE;
	}

	if ((fd = open(SPLITTING_DUMPFILE(0), O_RDONLY)) < 0) {
		ERRMSG("Can't open a file(%s). %s\n",
		    SPLITTING_DUMPFILE(0), strerror(errno));
		return FALSE;
	}
	if (lseek(fd, offset_bitmap, SEEK_SET) < 0) {
		ERRMSG("Can't seek a file(%s). %s\n",
		    SPLITTING_DUMPFILE(0), strerror(errno));
		goto out;
	}
	if (read(fd, buf_bitmap, info->len_bitmap) != info->len_bitmap) {
		ERRMSG("Can't read a file(%s). %s\n",
		    SPLITTING_DUMPFILE(0), strerror(errno));
		goto out;
	}

	if (lseek(info->fd_dumpfile, offset_bitmap, SEEK_SET) < 0) {
		ERRMSG("Can't seek a file(%s). %s\n",
		    info->name_dumpfile, strerror(errno));
		goto out;
	}
	if (write(info->fd_dumpfile, buf_bitmap, info->len_bitmap)
	    != info->len_bitmap) {
		ERRMSG("Can't write a file(%s). %s\n",
		    info->name_dumpfile, strerror(errno));
		goto out;
	}

	if (lseek(info->fd_bitmap, 0x0, SEEK_SET) < 0) {
		ERRMSG("Can't seek a file(%s). %s\n",
		    info->name_bitmap, strerror(errno));
		goto out;
	}
	if (write(info->fd_bitmap, buf_bitmap, info->len_bitmap)
	    != info->len_bitmap) {
		ERRMSG("Can't write a file(%s). %s\n",
		    info->name_bitmap, strerror(errno));
		goto out;
	}

	ret = TRUE;
out:
	close(fd);

	return ret;
}

int
reassemble_kdump_pages(void)
{
	int i, fd = 0, ret = FALSE;
	off_t offset_first_ph, offset_ph_org;
	off_t offset_data_new, offset_zero_page = 0;
	unsigned long long pfn, start_pfn, end_pfn;
	unsigned long long num_dumpable, num_dumped;
	struct dump_bitmap bitmap2;
	struct disk_dump_header dh;
	struct page_desc pd, pd_zero;
	struct cache_data cd_pd, cd_data;
	char *data = NULL;

	initialize_2nd_bitmap(&bitmap2);

	if (!read_disk_dump_header(&dh, SPLITTING_DUMPFILE(0)))
		return FALSE;

	if (!prepare_cache_data(&cd_pd))
		return FALSE;

	if (!prepare_cache_data(&cd_data)) {
		free_cache_data(&cd_pd);
		return FALSE;
	}
	if ((data = malloc(info->page_size)) == NULL) {
		ERRMSG("Can't allcate memory for page data.\n");
		free_cache_data(&cd_pd);
		free_cache_data(&cd_data);
		return FALSE;
	}
	num_dumpable = get_num_dumpable();
	num_dumped = 0;

	offset_first_ph = (1 + dh.sub_hdr_size + dh.bitmap_blocks)
	     * dh.block_size;
	cd_pd.offset    = offset_first_ph;
	offset_data_new = offset_first_ph + sizeof(page_desc_t) * num_dumpable;
	cd_data.offset  = offset_data_new;

	/*
	 * Write page header of zero-filled page.
	 */
	if (info->dump_level & DL_EXCLUDE_ZERO) {
		/*
		 * makedumpfile outputs the data of zero-filled page at first
		 * if excluding zero-filled page, so the offset of first data
		 * is for zero-filled page in all dumpfiles.
		 */
		offset_zero_page = offset_data_new;

		pd_zero.size = info->page_size;
		pd_zero.flags = 0;
		pd_zero.offset = offset_data_new;
		pd_zero.page_flags = 0;
		memset(data, 0, pd_zero.size);
		if (!write_cache(&cd_data, data, pd_zero.size))
			goto out;
		offset_data_new  += pd_zero.size;
	}
	for (i = 0; i < info->num_dumpfile; i++) {
		if ((fd = open(SPLITTING_DUMPFILE(i), O_RDONLY)) < 0) {
			ERRMSG("Can't open a file(%s). %s\n",
			    SPLITTING_DUMPFILE(i), strerror(errno));
			goto out;
		}
		start_pfn = SPLITTING_START_PFN(i);
		end_pfn   = SPLITTING_END_PFN(i);

		offset_ph_org = offset_first_ph;
		for (pfn = start_pfn; pfn < end_pfn; pfn++) {
			if (!is_dumpable(&bitmap2, pfn))
				continue;

			num_dumped++;

			print_progress(PROGRESS_COPY, num_dumped, num_dumpable);

			if (lseek(fd, offset_ph_org, SEEK_SET) < 0) {
				ERRMSG("Can't seek a file(%s). %s\n",
				    SPLITTING_DUMPFILE(i), strerror(errno));
				goto out;
			}
			if (read(fd, &pd, sizeof(pd)) != sizeof(pd)) {
				ERRMSG("Can't read a file(%s). %s\n",
				    SPLITTING_DUMPFILE(i), strerror(errno));
				goto out;
			}
			if (lseek(fd, pd.offset, SEEK_SET) < 0) {
				ERRMSG("Can't seek a file(%s). %s\n",
				    SPLITTING_DUMPFILE(i), strerror(errno));
				goto out;
			}
			if (read(fd, data, pd.size) != pd.size) {
				ERRMSG("Can't read a file(%s). %s\n",
				    SPLITTING_DUMPFILE(i), strerror(errno));
				goto out;
			}
			if ((info->dump_level & DL_EXCLUDE_ZERO)
			    && (pd.offset == offset_zero_page)) {
				/*
			 	 * Handle the data of zero-filled page.
				 */
				if (!write_cache(&cd_pd, &pd_zero,
				    sizeof(pd_zero)))
					goto out;
				offset_ph_org += sizeof(pd);
				continue;
			}
			pd.offset = offset_data_new;
			if (!write_cache(&cd_pd, &pd, sizeof(pd)))
				goto out;
			offset_ph_org += sizeof(pd);

			if (!write_cache(&cd_data, data, pd.size))
				goto out;

			offset_data_new += pd.size;
		}
		close(fd);
		fd = 0;
	}
	if (!write_cache_bufsz(&cd_pd))
		goto out;
	if (!write_cache_bufsz(&cd_data))
		goto out;

	print_progress(PROGRESS_COPY, num_dumpable, num_dumpable);
	ret = TRUE;
out:
	free_cache_data(&cd_pd);
	free_cache_data(&cd_data);

	if (data)
		free(data);
	if (fd > 0)
		close(fd);

	return ret;
}

int
reassemble_dumpfile(void)
{
	if (!get_splitting_info())
		return FALSE;

	if (!open_dump_bitmap())
		return FALSE;

	if (!open_dump_file())
		return FALSE;

	if (!reassemble_kdump_header())
		return FALSE;

	if (!reassemble_kdump_pages())
		return FALSE;

	close_dump_file();
	close_dump_bitmap();

	return TRUE;
}

int
check_param_for_generating_vmcoreinfo(int argc, char *argv[])
{
	if (argc != optind)
		return FALSE;

	if (info->flag_compress        || info->dump_level
	    || info->flag_elf_dumpfile || info->flag_read_vmcoreinfo
	    || info->flag_flatten      || info->flag_rearrange
	    || info->flag_exclude_xen_dom
	    || (!info->name_vmlinux && !info->name_xen_syms))

		return FALSE;

	return TRUE;
}

/*
 * Parameters for creating dumpfile from the dump data
 * of flattened format by rearranging the dump data.
 */
int
check_param_for_rearranging_dumpdata(int argc, char *argv[])
{
	if (argc != optind + 1)
		return FALSE;

	if (info->flag_compress        || info->dump_level
	    || info->flag_elf_dumpfile || info->flag_read_vmcoreinfo
	    || info->name_vmlinux      || info->name_xen_syms
	    || info->flag_flatten      || info->flag_generate_vmcoreinfo
	    || info->flag_exclude_xen_dom)
		return FALSE;

	info->name_dumpfile = argv[optind];
	return TRUE;
}

/*
 * Parameters for reassembling multiple dumpfiles into one dumpfile.
 */
int
check_param_for_reassembling_dumpfile(int argc, char *argv[])
{
	int i;

	info->num_dumpfile  = argc - optind - 1;
	info->name_dumpfile = argv[argc - 1];

	DEBUG_MSG("num_dumpfile : %d\n", info->num_dumpfile);

	if (info->flag_compress        || info->dump_level
	    || info->flag_elf_dumpfile || info->flag_read_vmcoreinfo
	    || info->name_vmlinux      || info->name_xen_syms
	    || info->flag_flatten      || info->flag_generate_vmcoreinfo
	    || info->flag_exclude_xen_dom || info->flag_split)
		return FALSE;

	if ((info->splitting_info
	    = malloc(sizeof(splitting_info_t) * info->num_dumpfile))
	    == NULL) {
		MSG("Can't allocate memory for splitting_info.\n");
		return FALSE;
	}
	for (i = 0; i < info->num_dumpfile; i++)
		SPLITTING_DUMPFILE(i) = argv[optind + i];

	return TRUE;
}

/*
 * Check parameters to create the dump file.
 */
int
check_param_for_creating_dumpfile(int argc, char *argv[])
{
	int i;

	if (info->flag_generate_vmcoreinfo || info->flag_rearrange)
		return FALSE;

	if ((message_level < MIN_MSG_LEVEL)
	    || (MAX_MSG_LEVEL < message_level)) {
		message_level = DEFAULT_MSG_LEVEL;
		MSG("Message_level is invalid.\n");
		return FALSE;
	}
	if ((info->flag_compress && info->flag_elf_dumpfile)
	    || (info->flag_read_vmcoreinfo && info->name_vmlinux)
	    || (info->flag_read_vmcoreinfo && info->name_xen_syms))
		return FALSE;

	if (info->flag_flatten && info->flag_split)
		return FALSE;

	if ((argc == optind + 2) && !info->flag_flatten
				 && !info->flag_split) {
		/*
		 * Parameters for creating the dumpfile from vmcore.
		 */
		info->name_memory   = argv[optind];
		info->name_dumpfile = argv[optind+1];

	} else if ((argc > optind + 2) && info->flag_split) {
		/*
		 * Parameters for creating multiple dumpfiles from vmcore.
		 */
		info->num_dumpfile = argc - optind - 1;
		info->name_memory  = argv[optind];

		if (info->flag_elf_dumpfile) {
			MSG("Options for splitting dumpfile cannot be used with Elf format.\n");
			return FALSE;
		}
		if ((info->splitting_info
		    = malloc(sizeof(splitting_info_t) * info->num_dumpfile))
		    == NULL) {
			MSG("Can't allocate memory for splitting_info.\n");
			return FALSE;
		}
		for (i = 0; i < info->num_dumpfile; i++)
			SPLITTING_DUMPFILE(i) = argv[optind + 1 + i];

	} else if ((argc == optind + 1) && info->flag_flatten) {
		/*
		 * Parameters for outputting the dump data of the
		 * flattened format to STDOUT.
		 */
		info->name_memory   = argv[optind];

	} else
		return FALSE;

	return TRUE;
}

int
parse_dump_level(char *str_dump_level)
{
	int i, ret = FALSE;
	char *buf, *ptr;

	if (!(buf = strdup(str_dump_level))) {
		MSG("Can't duplicate strings(%s).\n", str_dump_level);
		return FALSE;
	}
	info->max_dump_level = 0;
	info->num_dump_level = 0;
	ptr = buf;
	while(TRUE) {
		ptr = strtok(ptr, ",");
		if (!ptr)
			break;

		i = atoi(ptr);
		if ((i < MIN_DUMP_LEVEL) || (MAX_DUMP_LEVEL < i)) {
			MSG("Dump_level(%d) is invalid.\n", i);
			goto out;
		}
		if (NUM_ARRAY_DUMP_LEVEL <= info->num_dump_level) {
			MSG("Dump_level is invalid.\n");
			goto out;
		}
		if (info->max_dump_level < i)
			info->max_dump_level = i;
		if (info->num_dump_level == 0)
			info->dump_level = i;
		info->array_dump_level[info->num_dump_level] = i;
		info->num_dump_level++;
		ptr = NULL;
	}
	ret = TRUE;
out:
	free(buf);

	return ret;
}

static struct option longopts[] = {
	{"split", no_argument, NULL, 's'}, 
	{"reassemble", no_argument, NULL, 'r'},
	{"xen-syms", required_argument, NULL, 'y'},
	{"xen-vmcoreinfo", required_argument, NULL, 'z'},
	{"xen_phys_start", required_argument, NULL, 'P'},
	{"message-level", required_argument, NULL, 'm'},
	{"vtop", required_argument, NULL, 'V'},
	{"dump-dmesg", no_argument, NULL, 'M'}, 
	{"help", no_argument, NULL, 'h'},
	{0, 0, 0, 0}
};

int
main(int argc, char *argv[])
{
	int i, opt, flag_debug = FALSE;

	if ((info = calloc(1, sizeof(struct DumpInfo))) == NULL) {
		ERRMSG("Can't allocate memory for the pagedesc cache. %s.\n",
		    strerror(errno));
		goto out;
	}
	if ((info->dump_header = calloc(1, sizeof(struct disk_dump_header)))
	    == NULL) {
		ERRMSG("Can't allocate memory for the dump header. %s\n",
		    strerror(errno));
		goto out;
	}
	initialize_tables();

	info->block_order = DEFAULT_ORDER;
	message_level = DEFAULT_MSG_LEVEL;
	while ((opt = getopt_long(argc, argv, "b:cDd:EFfg:hi:MRrsVvXx:", longopts,
	    NULL)) != -1) {
		switch (opt) {
		case 'b':
			info->block_order = atoi(optarg);
			break;
		case 'c':
			info->flag_compress = 1;
			break;
		case 'D':
			flag_debug = TRUE;
			break;
		case 'd':
			if (!parse_dump_level(optarg))
				goto out;
			break;
		case 'E':
			info->flag_elf_dumpfile = 1;
			break;
		case 'F':
			info->flag_flatten = 1;
			break;
		case 'f':
			info->flag_force = 1;
			break;
		case 'g':
			info->flag_generate_vmcoreinfo = 1;
			info->name_vmcoreinfo = optarg;
			break;
		case 'h':
			info->flag_show_usage = 1;
			break;
		case 'i':
			info->flag_read_vmcoreinfo = 1;
			info->name_vmcoreinfo = optarg;
			break;
		case 'm':
			message_level = atoi(optarg);
			break;
		case 'M':
			info->flag_dmesg = 1;
			break;
		case 'P':
			info->xen_phys_start = strtoul(optarg, NULL, 0);
			break;
		case 'R':
			info->flag_rearrange = 1;
			break;
		case 's':
			info->flag_split = 1;
			break;
		case 'r':
			info->flag_reassemble = 1;
			break;
		case 'V':
			info->vaddr_for_vtop = strtoul(optarg, NULL, 0);
			break;
		case 'v':
			info->flag_show_version = 1;
			break;
		case 'X':
			info->flag_exclude_xen_dom = 1;
			break;
		case 'x':
			info->name_vmlinux = optarg;
			break;
		case 'y':
			info->name_xen_syms = optarg;
			break;
		case 'z':
			info->flag_read_vmcoreinfo = 1;
			info->name_vmcoreinfo = optarg;
			break;
		case '?':
			MSG("Commandline parameter is invalid.\n");
			MSG("Try `makedumpfile --help' for more information.\n");
			goto out;
		}
	}
	if (flag_debug)
		message_level |= ML_PRINT_DEBUG_MSG;

	if (info->flag_show_usage) {
		print_usage();
		return COMPLETED;
	}
	if (info->flag_show_version) {
		show_version();
		return COMPLETED;
	}

	if (elf_version(EV_CURRENT) == EV_NONE ) {
		/*
		 * library out of date
		 */
		ERRMSG("Elf library out of date!\n");
		goto out;
	}
	if (info->flag_generate_vmcoreinfo) {
		if (!check_param_for_generating_vmcoreinfo(argc, argv)) {
			MSG("Commandline parameter is invalid.\n");
			MSG("Try `makedumpfile --help' for more information.\n");
			goto out;
		}
		if (!open_files_for_generating_vmcoreinfo())
			goto out;

		if (info->name_xen_syms) {
			if (!generate_vmcoreinfo_xen())
				goto out;
		} else {
			if (!generate_vmcoreinfo())
				goto out;
		}

		if (!close_files_for_generating_vmcoreinfo())
			goto out;

		MSG("\n");
		MSG("The vmcoreinfo is saved to %s.\n", info->name_vmcoreinfo);

	} else if (info->flag_rearrange) {
		if (!check_param_for_rearranging_dumpdata(argc, argv)) {
			MSG("Commandline parameter is invalid.\n");
			MSG("Try `makedumpfile --help' for more information.\n");
			goto out;
		}
		if (!open_files_for_rearranging_dumpdata())
			goto out;

		if (!rearrange_dumpdata())
			goto out;

		if (!close_files_for_rearranging_dumpdata())
			goto out;

		MSG("\n");
		MSG("The dumpfile is saved to %s.\n", info->name_dumpfile);
	} else if (info->flag_reassemble) {
		if (!check_param_for_reassembling_dumpfile(argc, argv)) {
			MSG("Commandline parameter is invalid.\n");
			MSG("Try `makedumpfile --help' for more information.\n");
			goto out;
		}
		if (!reassemble_dumpfile())
			goto out;

		MSG("\n");
		MSG("The dumpfile is saved to %s.\n", info->name_dumpfile);
	} else if (info->flag_dmesg) {
		if (!check_param_for_creating_dumpfile(argc, argv)) {
			MSG("Commandline parameter is invalid.\n");
			MSG("Try `makedumpfile --help' for more information.\n");
			goto out;
		}
		if (!dump_dmesg())
			goto out;

		MSG("\n");
		MSG("The dmesg log is saved to %s.\n", info->name_dumpfile);
	} else {
		if (!check_param_for_creating_dumpfile(argc, argv)) {
			MSG("Commandline parameter is invalid.\n");
			MSG("Try `makedumpfile --help' for more information.\n");
			goto out;
		}
		if (!create_dumpfile())
			goto out;

		MSG("\n");
		if (info->flag_split) {
			MSG("The dumpfiles are saved to ");
			for (i = 0; i < info->num_dumpfile; i++) {
				if (i != (info->num_dumpfile - 1))
					MSG("%s, ", SPLITTING_DUMPFILE(i));
				else
					MSG("and %s.\n", SPLITTING_DUMPFILE(i));
			}
		} else {
			MSG("The dumpfile is saved to %s.\n", info->name_dumpfile);
		}
	}
	retcd = COMPLETED;
out:
	MSG("\n");
	if (retcd == COMPLETED)
		MSG("makedumpfile Completed.\n");
	else
		MSG("makedumpfile Failed.\n");

	if (info->fd_memory)
		close(info->fd_memory);
	if (info->fd_dumpfile)
		close(info->fd_dumpfile);
	if (info->fd_bitmap)
		close(info->fd_bitmap);
	if (info->pt_load_segments != NULL)
		free(info->pt_load_segments);
	if (vt.node_online_map != NULL)
		free(vt.node_online_map);
	if (info->mem_map_data != NULL)
		free(info->mem_map_data);
	if (info->dump_header != NULL)
		free(info->dump_header);
	if (info->splitting_info != NULL)
		free(info->splitting_info);
	if (info != NULL)
		free(info);

	return retcd;
}
