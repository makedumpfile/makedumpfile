/* 
 * makedumpfile.c
 *
 * Copyright (C) 2006, 2007  NEC Corporation
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
#include "makedumpfile.h"

struct symbol_table	symbol_table;
struct size_table	size_table;
struct offset_table	offset_table;
struct array_table	array_table;
struct srcfile_table	srcfile_table;

struct dwarf_info	dwarf_info;
struct vm_table		*vt = 0;
struct DumpInfo		*info = NULL;

int message_level;

int retcd = FAILED;	/* return code */

void
show_version()
{
	MSG("makedumpfile: version " VERSION " (released on " RELEASE_DATE ")\n");
	MSG("\n");
}

/*
 * Convert Physical Address to File Offest.
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
vaddr_to_paddr(unsigned long long vaddr)
{
	int i;
	unsigned long long paddr;
	struct pt_load_segment *pls;

	for (i = paddr = 0; i < info->num_load_memory; i++) {
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
 * Convert Virtual Address to File Offest.
 *  If this function returns 0x0, File Offset isn't found.
 *  The File Offset 0x0 is the ELF header.
 *  It is not in the memory image.
 */
off_t
vaddr_to_offset_general(unsigned long long vaddr)
{
	int i;
	off_t offset;
	struct pt_load_segment *pls;

	for (i = offset = 0; i < info->num_load_memory; i++) {
		pls = &info->pt_load_segments[i];
		if ((vaddr >= pls->virt_start)
		    && (vaddr < pls->virt_end)) {
			offset = (off_t)(vaddr - pls->virt_start) +
				pls->file_offset;
				break;
		}
	}
	return offset;
}

/*
 * vaddr_to_offset_slow() is almost same as vaddr_to_offset_general().
 * This function is slow because it doesn't use the memory.
 * It is useful at few calls like get_str_osrelease_from_vmlinux().
 */
off_t
vaddr_to_offset_slow(int fd, char *filename, unsigned long vaddr)
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
unsigned long long
get_max_mapnr()
{
	int i;
	unsigned long long max_paddr;
	struct pt_load_segment *pls;

	for (i = 0, max_paddr = 0; i < info->num_load_memory; i++) {
		pls = &info->pt_load_segments[i];
		if (max_paddr < pls->phys_end)
			max_paddr = pls->phys_end;
	}
	return max_paddr / info->page_size;
}

int
readmem(int type_addr, unsigned long long addr, void *bufptr, size_t size)
{
	off_t offset = 0;
	unsigned long long paddr;
	const off_t failed = (off_t)-1;

	switch (type_addr) {
	case VADDR:
		/*
		 * Convert Virtual Address to File Offset.
		 */
		if (!(offset = vaddr_to_offset(addr))) {
			ERRMSG("Can't convert a virtual address(%llx) to offset.\n",
			    addr);
			return FALSE;
		}
		break;
	case PADDR:
		/*
		 * Convert Physical Address to File Offset.
		 */
		if (!(offset = paddr_to_offset(addr))) {
			ERRMSG("Can't convert a physical address(%llx) to offset.\n",
			    addr);
			return FALSE;
		}
		break;
	case VADDR_XEN:
		if (!(paddr = kvtop_xen(addr)))
			return FALSE;

		if (!(offset = paddr_to_offset(paddr))) {
			ERRMSG("Can't convert a physical address(%llx) to offset.\n",
			    paddr);
			return FALSE;
		}
		break;
	default:
		ERRMSG("Invalid address type (%d).\n", type_addr);
		return FALSE;
	}

	if (lseek(info->fd_memory, offset, SEEK_SET) == failed) {
		ERRMSG("Can't seek the dump memory(%s). %s\n",
		    info->name_memory, strerror(errno));
		return FALSE;
	}

	if (read(info->fd_memory, bufptr, size) != size) {
		ERRMSG("Can't read the dump memory(%s). %s\n",
		    info->name_memory, strerror(errno));
		return FALSE;
	}

	return size;
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
check_release()
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
			    dwarf_info.vmlinux_name, info->name_memory);
		return FALSE;
	}

	return TRUE;
}

void
print_usage()
{
	MSG("\n");
	MSG("Usage:\n");
	MSG("  Creating DUMPFILE:\n");
	MSG("  # makedumpfile    [-c|-E] [-d DL] [-x VMLINUX|-i VMCOREINFO] VMCORE DUMPFILE\n");
	MSG("\n");
	MSG("  Outputting the dump data in the flattened format to the standard output:\n");
	MSG("  # makedumpfile -F [-c|-E] [-d DL] [-x VMLINUX|-i VMCOREINFO] VMCORE\n");
	MSG("\n");
	MSG("  Re-arranging the dump data in the flattened format to a readable DUMPFILE:\n");
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
	MSG("      and it containes the first kernel's information. If Dump_Level is 2 or\n");
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
	MSG("      the dump data in the flattened format should be re-arranged to a readable\n");
	MSG("      DUMPFILE by -R option.\n");
	MSG("\n");
	MSG("  [-R]:\n");
	MSG("      Re-arrange the dump data in the flattened format from the standard input\n");
	MSG("      to a readable DUMPFILE.\n");
	MSG("\n");
	MSG("  [--xen-syms XEN-SYMS]:\n");
	MSG("      Specify the XEN-SYMS to analyze the xen's memory usage.\n");
	MSG("\n");
	MSG("  [--xen-vmcoreinfo VMCOREINFO]:\n");
	MSG("      Specify the VMCOREINFO of xen to analyze the xen's memory usage.\n");
	MSG("\n");
	MSG("  [--message-level ML]:\n");
	MSG("      Specify the message types.\n");
	MSG("      Users can restrict outputs printed by specifying Message_Level (ML) with\n");
	MSG("      this option. The message type marked with an X in the following table is\n");
	MSG("      printed to standard error output. For example, according to the table,\n");
	MSG("      specifying 7 as ML means progress indicator, common message, and error\n");
	MSG("      message are printed, and this is a default value.\n");
	MSG("      Note that the maximum value of message_level is 15.\n");
	MSG("\n");
	MSG("      Message | progress    common    error     debug\n");
	MSG("      Level   | indicator   message   message   message\n");
	MSG("     ---------+-----------------------------------------\n");
	MSG("            0 |\n");
	MSG("            1 |     X\n");
	MSG("            2 |                X\n");
	MSG("            4 |                          X\n");
	MSG("          * 7 |     X          X         X\n");
	MSG("            8 |                                    X\n");
	MSG("           15 |     X          X         X         X\n");
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
	MSG("      This file must have the debug information of the xen to analyze the\n");
	MSG("      xen's memory usage.\n");
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
open_kernel_file()
{
	int fd;

	if ((fd = open(dwarf_info.vmlinux_name, O_RDONLY)) < 0) {
		ERRMSG("Can't open the kernel file(%s). %s\n",
		    dwarf_info.vmlinux_name, strerror(errno));
		return FALSE;
	}
	dwarf_info.vmlinux_fd = fd;
	return TRUE;
}

int
open_dump_memory()
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
open_dump_file()
{
	int fd;
	int open_flags = O_RDWR|O_CREAT;

	if (!info->flag_force)
		open_flags |= O_EXCL;

	if (info->flag_flatten) {
		if ((info->name_dumpfile
		    = (char *)malloc(sizeof(FILENAME_STDOUT))) == NULL) {
			ERRMSG("Can't allocate memory for the filename. %s\n",
			    strerror(errno));
			return FALSE;
		}
		fd = STDOUT_FILENO;
		strcpy(info->name_dumpfile, FILENAME_STDOUT);

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
open_dump_bitmap()
{
	int fd;

	if ((info->name_bitmap
	    = (char *)malloc(sizeof(FILENAME_BITMAP))) == NULL) {
		ERRMSG("Can't allocate memory for the filename. %s\n",
		    strerror(errno));
		return FALSE;
	}
	strcpy(info->name_bitmap, FILENAME_BITMAP);
	if ((fd = open(info->name_bitmap, O_RDWR|O_CREAT,
	    S_IRUSR|S_IWUSR)) < 0) {
		ERRMSG("Can't open the dump file(%s). %s\n",
		    FILENAME_BITMAP, strerror(errno));
		return FALSE;
	}
	unlink(info->name_bitmap);
	info->fd_bitmap = fd;
	return TRUE;
}

/*
 * Open the following files when it generates the vmcoreinfo file.
 * - vmlinux
 * - vmcoreinfo file
 */
int
open_files_for_generating_vmcoreinfo()
{
	if (!open_kernel_file())
		return FALSE;

	if (!open_vmcoreinfo("w"))
		return FALSE;

	return TRUE;
}

/*
 * Open the following file when it re-arranges the dump data.
 * - dump file
 */
int
open_files_for_rearranging_dumpdata()
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
open_files_for_creating_dumpfile()
{
	if (info->flag_read_vmcoreinfo) {
		if (!open_vmcoreinfo("r"))
			return FALSE;
	} else if (info->dump_level > DL_EXCLUDE_ZERO) {
		if (!open_kernel_file())
			return FALSE;
	}
	if (!open_dump_memory())
		return FALSE;

	if (!open_dump_file())
		return FALSE;

	if (!open_dump_bitmap())
		return FALSE;

	return TRUE;
}

int
dump_Elf64_load(Elf64_Phdr *prog, int num_load)
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
get_elf64_phdr(int fd, char *filename, int num, Elf64_Phdr *phdr)
{
	off_t offset;
	const off_t failed = (off_t)-1;

	offset = sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr) * num;

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
dump_Elf32_load(Elf32_Phdr *prog, int num_load)
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
get_elf32_phdr(int fd, char *filename, int num, Elf32_Phdr *phdr)
{
	off_t offset;
	const off_t failed = (off_t)-1;

	offset = sizeof(Elf32_Ehdr) + sizeof(Elf32_Phdr) * num;

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
get_elf_info()
{
	int i, j, phnum, num_load, elf_format;
	unsigned long tmp;
	Elf64_Phdr load64;
	Elf32_Phdr load32;

	int ret = FALSE;

	/*
	 * Check ELF64 or ELF32.
	 */
	elf_format = check_elf_format(info->fd_memory, info->name_memory,
	    &phnum, &num_load);

	if (elf_format == ELF64)
		info->flag_elf64 = TRUE;
	else if (elf_format == ELF32)
		info->flag_elf64 = FALSE;
	else
		return FALSE;

	info->num_load_memory = num_load;

	if (!info->num_load_memory) {
		ERRMSG("Can't get the number of PT_LOAD.\n");
		goto out;
	}
	if ((info->pt_load_segments = (struct pt_load_segment *)
	    calloc(1, sizeof(struct pt_load_segment) *
	    info->num_load_memory)) == NULL) {
		ERRMSG("Can't allocate memory for the PT_LOAD. %s\n",
		    strerror(errno));
		goto out;
	}
	for (i = 0, j = 0; i < phnum; i++) {
		if (info->flag_elf64) { /* ELF64 */
			if (!get_elf64_phdr(info->fd_memory, info->name_memory,
			    i, &load64)) {
				ERRMSG("Can't find Phdr %d.\n", i);
				goto out;
			}
			if (load64.p_type != PT_LOAD)
				continue;

			if (j == 0) {
				info->offset_load_memory = load64.p_offset;
				if (!info->offset_load_memory) {
					ERRMSG("Can't get the offset of page data.\n");
					goto out;
				}
			}
			if (j >= info->num_load_memory)
				goto out;
			if(!dump_Elf64_load(&load64, j))
				goto out;
			j++;
		} else {                /* ELF32 */
			if (!get_elf32_phdr(info->fd_memory, info->name_memory,
			    i, &load32)) {
				ERRMSG("Can't find Phdr %d.\n", i);
				goto out;
			}
			if (load32.p_type != PT_LOAD)
				continue;

			if (j == 0) {
				info->offset_load_memory = load32.p_offset;
				if (!info->offset_load_memory) {
					ERRMSG("Can't get the offset of page data.\n");
					goto out;
				}
			}
			if (j >= info->num_load_memory)
				goto out;
			if(!dump_Elf32_load(&load32, j))
				goto out;
			j++;
		}
	}

	/*
	 * FIXME
	 *   If the page_size of 1st-kernel is different from the one of
	 *   capture(2nd)-kernel, the problem will happen.
	 */
	info->page_size = sysconf(_SC_PAGE_SIZE);
	info->page_shift = ffs(info->page_size) - 1;

	info->max_mapnr = get_max_mapnr();

	DEBUG_MSG("\n");
	DEBUG_MSG("max_mapnr    : %llx\n", info->max_mapnr);

	/*
	 * Create 2 bitmaps (1st-bitmap & 2nd-bitmap) on block_size boundary.
	 * The crash utility requires both of them to be aligned to block_size
	 * boundary.
	 */
	tmp = divideup(divideup(info->max_mapnr, BITPERBYTE), info->page_size);
	info->len_bitmap = tmp*info->page_size*2;

	ret = TRUE;
out:
	return ret;
}

unsigned long
get_symbol_addr(char *symname)
{
	int i;
	unsigned long symbol = NOT_FOUND_SYMBOL;
	Elf *elfd = NULL;
	GElf_Shdr shdr;
	GElf_Sym sym;
	Elf_Data *data = NULL;
	Elf_Scn *scn = NULL;
	char *sym_name = NULL;
	const off_t failed = (off_t)-1;

	if (lseek(dwarf_info.vmlinux_fd, 0, SEEK_SET) == failed) {
		ERRMSG("Can't seek the kernel file(%s). %s\n",
		    dwarf_info.vmlinux_name, strerror(errno));
		return NOT_FOUND_SYMBOL;
	}
	if (!(elfd = elf_begin(dwarf_info.vmlinux_fd, ELF_C_READ, NULL))) {
		ERRMSG("Can't get first elf header of %s.\n",
		    dwarf_info.vmlinux_name);
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

	if (lseek(dwarf_info.vmlinux_fd, 0, SEEK_SET) == failed) {
		ERRMSG("Can't seek the kernel file(%s). %s\n",
		    dwarf_info.vmlinux_name, strerror(errno));
		return NOT_FOUND_SYMBOL;
	}
	if (!(elfd = elf_begin(dwarf_info.vmlinux_fd, ELF_C_READ, NULL))) {
		ERRMSG("Can't get first elf header of %s.\n",
		    dwarf_info.vmlinux_name);
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
is_search_symbol(int cmd)
{
	if ((cmd == DWARF_INFO_GET_SYMBOL_ARRAY_LENGTH)
	    || (cmd == DWARF_INFO_CHECK_SYMBOL_ARRAY_TYPE))
		return TRUE;
	else
		return FALSE;
}

int
is_search_srcfile(int cmd)
{
	if (cmd == DWARF_INFO_GET_TYPEDEF_SRCNAME)
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
search_srcfile(Dwarf *dwarfd, Dwarf_Die *die, int *found)
{
	int tag = 0, rtag = 0;
	char *src_name = NULL;
	const char *name;

	switch (dwarf_info.cmd) {
	case DWARF_INFO_GET_TYPEDEF_SRCNAME:
		rtag = DW_TAG_typedef;
		break;
	}

	/*
	 * If we get to here then we don't have any more
	 * children, check to see if this is a relevant tag
	 */
	do {
		tag  = dwarf_tag(die);
		name = dwarf_diename(die);

		if ((tag != rtag) || (!name)
		    || strcmp(name, dwarf_info.decl_name))
			continue;

		src_name = (char *)dwarf_decl_file(die);

		if (!src_name)
			break;

	} while (!dwarf_siblingof(die, die));

	if (!src_name)
		return;

	/*
	 * Found the demanded one.
	 */
	strncpy(dwarf_info.src_name, src_name, LEN_SRCFILE);

	*found = TRUE;
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

	else if (is_search_symbol(dwarf_info.cmd))
		search_symbol(dwarfd, die, found);

	else if (is_search_srcfile(dwarf_info.cmd))
		search_srcfile(dwarfd, die, found);
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

	if (lseek(dwarf_info.vmlinux_fd, 0, SEEK_SET) == failed) {
		ERRMSG("Can't seek the kernel file(%s). %s\n",
		    dwarf_info.vmlinux_name, strerror(errno));
		return FALSE;
	}
	if (!(elfd = elf_begin(dwarf_info.vmlinux_fd, ELF_C_READ_MMAP, NULL))) {
		ERRMSG("Can't get first elf header of %s.\n",
		    dwarf_info.vmlinux_name);
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
		if (strcmp(name, ".debug_info"))
			continue;
	}
	if (!strcmp(name, ".debug_info")) {
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
get_structure_size(char *structname)
{
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

/*
 * Get the source filename.
 */
int
get_source_filename(char *decl_name, char *src_name, int cmd)
{
	dwarf_info.cmd = cmd;
	dwarf_info.decl_name = decl_name;

	if (!get_debug_info())
		return FALSE;

	strncpy(src_name, dwarf_info.src_name, LEN_SRCFILE);

	return TRUE;
}

int
get_symbol_info()
{
	/*
	 * Get symbol info.
	 */
	SYMBOL_INIT(mem_map, "mem_map");
	SYMBOL_INIT(mem_section, "mem_section");
	SYMBOL_INIT(pkmap_count, "pkmap_count");
	SYMBOL_INIT_NEXT(pkmap_count_next, "pkmap_count");
	SYMBOL_INIT(system_utsname, "system_utsname");
	SYMBOL_INIT(init_uts_ns, "init_uts_ns");
	SYMBOL_INIT(_stext, "_stext");
	SYMBOL_INIT(swapper_pg_dir, "swapper_pg_dir");
	SYMBOL_INIT(phys_base, "phys_base");
	SYMBOL_INIT(node_online_map, "node_online_map");
	SYMBOL_INIT(node_memblk, "node_memblk");
	SYMBOL_INIT(node_data, "node_data");
	SYMBOL_INIT(pgdat_list, "pgdat_list");
	SYMBOL_INIT(contig_page_data, "contig_page_data");

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
get_structure_info()
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

	return TRUE;
}

int
get_srcfile_info()
{
	TYPEDEF_SRCFILE_INIT(pud_t, "pud_t");

	return TRUE;
}

int
get_str_osrelease_from_vmlinux()
{
	struct utsname system_utsname;
	unsigned long utsname;
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
	offset = vaddr_to_offset_slow(dwarf_info.vmlinux_fd,
	    dwarf_info.vmlinux_name, utsname);

	if (!offset) {
		ERRMSG("Can't convert vaddr (%lx) of utsname to an offset.\n",
		    utsname);
		return FALSE;
	}
	if (lseek(dwarf_info.vmlinux_fd, offset, SEEK_SET) == failed) {
		ERRMSG("Can't seek %s. %s\n", dwarf_info.vmlinux_name,
		    strerror(errno));
		return FALSE;
	}
	if (read(dwarf_info.vmlinux_fd, &system_utsname, sizeof system_utsname)
	    != sizeof system_utsname) {
		ERRMSG("Can't read %s. %s\n", dwarf_info.vmlinux_name,
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
is_sparsemem_extreme()
{
	if (ARRAY_LENGTH(mem_section)
	     == (NR_MEM_SECTIONS() / _SECTIONS_PER_ROOT_EXTREME()))
		return TRUE;
	else
		return FALSE;
}

int
get_mem_type()
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
generate_vmcoreinfo()
{
	if ((info->page_size = sysconf(_SC_PAGE_SIZE)) <= 0) {
		ERRMSG("Can't get the size of page.\n");
		return FALSE;
	}
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
	WRITE_SYMBOL("mem_section", mem_section);
	WRITE_SYMBOL("pkmap_count", pkmap_count);
	WRITE_SYMBOL("pkmap_count_next", pkmap_count_next);
	WRITE_SYMBOL("system_utsname", system_utsname);
	WRITE_SYMBOL("init_uts_ns", init_uts_ns);
	WRITE_SYMBOL("_stext", _stext);
	WRITE_SYMBOL("swapper_pg_dir", swapper_pg_dir);
	WRITE_SYMBOL("phys_base", phys_base);
	WRITE_SYMBOL("node_online_map", node_online_map);
	WRITE_SYMBOL("node_data", node_data);
	WRITE_SYMBOL("pgdat_list", pgdat_list);
	WRITE_SYMBOL("contig_page_data", contig_page_data);

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

	if (SYMBOL(node_data) != NOT_FOUND_SYMBOL)
		WRITE_ARRAY_LENGTH("node_data", node_data);
	if (SYMBOL(pgdat_list) != NOT_FOUND_SYMBOL)
		WRITE_ARRAY_LENGTH("pgdat_list", pgdat_list);
	if (SYMBOL(mem_section) != NOT_FOUND_SYMBOL)
		WRITE_ARRAY_LENGTH("mem_section", mem_section);
	if (SYMBOL(node_memblk) != NOT_FOUND_SYMBOL)
		WRITE_ARRAY_LENGTH("node_memblk", node_memblk);

	WRITE_ARRAY_LENGTH("zone.free_area", zone.free_area);

	/*
	 * write the source file of 1st kernel
	 */
	WRITE_SRCFILE("pud_t", pud_t);

	return TRUE;
}

int
read_vmcoreinfo_basic_info()
{
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
		if (buf[i - 1] == '\n')
			buf[i - 1] = '\0';
		if (strncmp(buf, STR_OSRELEASE, strlen(STR_OSRELEASE)) == 0) {
			strcpy(info->release, buf + strlen(STR_OSRELEASE));
			get_release = TRUE;
		}
		if (strncmp(buf, STR_PAGESIZE, strlen(STR_PAGESIZE)) == 0) {
			page_size = strtol(buf+strlen(STR_PAGESIZE),&endp,10);
			if ((!page_size || page_size == LONG_MAX)
			    || strlen(endp) != 0) {
				ERRMSG("Invalid data in %s: %s",
				    info->name_vmcoreinfo, buf);
				return FALSE;
			}
			if (!is_page_size(page_size)) {
				ERRMSG("Invalid data in %s: %s",
				    info->name_vmcoreinfo, buf);
				return FALSE;
			}
		}
		if (get_release && page_size)
			break;
	}
	info->page_size = page_size;
	info->page_shift = ffs(info->page_size) - 1;

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
read_vmcoreinfo_structure(char *str_structure)
{
	long data = NOT_FOUND_STRUCTURE;
	char buf[BUFSIZE_FGETS], *endp;
	unsigned int i;

	if (fseek(info->file_vmcoreinfo, 0, SEEK_SET) < 0) {
		ERRMSG("Can't seek the vmcoreinfo file(%s). %s\n",
		    info->name_vmcoreinfo, strerror(errno));
		return INVALID_STRUCTURE_DATA;
	}

	while (fgets(buf, BUFSIZE_FGETS, info->file_vmcoreinfo)) {
		i = strlen(buf);
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
read_vmcoreinfo()
{
	if (!read_vmcoreinfo_basic_info())
		return FALSE;

	READ_SYMBOL("mem_map", mem_map);
	READ_SYMBOL("mem_section", mem_section);
	READ_SYMBOL("pkmap_count", pkmap_count);
	READ_SYMBOL("pkmap_count_next", pkmap_count_next);
	READ_SYMBOL("system_utsname", system_utsname);
	READ_SYMBOL("init_uts_ns", init_uts_ns);
	READ_SYMBOL("_stext", _stext);
	READ_SYMBOL("swapper_pg_dir", swapper_pg_dir);
	READ_SYMBOL("phys_base", phys_base);
	READ_SYMBOL("node_online_map", node_online_map);
	READ_SYMBOL("node_data", node_data);
	READ_SYMBOL("pgdat_list", pgdat_list);
	READ_SYMBOL("contig_page_data", contig_page_data);

	READ_STRUCTURE_SIZE("page", page);
	READ_STRUCTURE_SIZE("mem_section", mem_section);
	READ_STRUCTURE_SIZE("pglist_data", pglist_data);
	READ_STRUCTURE_SIZE("zone", zone);
	READ_STRUCTURE_SIZE("free_area", free_area);
	READ_STRUCTURE_SIZE("list_head", list_head);
	READ_STRUCTURE_SIZE("node_memblk_s", node_memblk_s);

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

	READ_ARRAY_LENGTH("node_data", node_data);
	READ_ARRAY_LENGTH("pgdat_list", pgdat_list);
	READ_ARRAY_LENGTH("mem_section", mem_section);
	READ_ARRAY_LENGTH("node_memblk", node_memblk);
	READ_ARRAY_LENGTH("zone.free_area", zone.free_area);

	READ_SRCFILE("pud_t", pud_t);

	return TRUE;
}

/*
 * Get the number of online nodes.
 */
int
get_nodes_online()
{
	int len, i, j, online;
	unsigned long bitbuf, *maskptr;

	if (SYMBOL(node_online_map) == NOT_FOUND_SYMBOL)
		return 0;
	/*
	 * FIXME
	 * Size of node_online_map must be dynamically got from debugging
	 * information each architecture or each vmcoreinfo.
	 */
	len = SIZEOF_NODE_ONLINE_MAP;
	if (!(vt->node_online_map = (unsigned long *)malloc(len))) {
		ERRMSG("Can't allocate memory for the node online map. %s\n",
		    strerror(errno));
		return 0;
	}
	if (!readmem(VADDR, SYMBOL(node_online_map), vt->node_online_map, len)){
		ERRMSG("Can't get the node online map.\n");
		return 0;
	}
	vt->node_online_map_len = len/sizeof(unsigned long);
	online = 0;
	maskptr = (unsigned long *)vt->node_online_map;
	for (i = 0; i < vt->node_online_map_len; i++, maskptr++) {
		bitbuf = *maskptr;
		for (j = 0; j < sizeof(bitbuf) * 8; j++) {
			online += bitbuf & 1;
			bitbuf = bitbuf >> 1;
		}
	}
	return online;
}

int
get_numnodes()
{
	if (!(vt->numnodes = get_nodes_online())) {
		vt->numnodes = 1;
	}
	DEBUG_MSG("\n");
	DEBUG_MSG("num of NODEs : %d\n", vt->numnodes);
	DEBUG_MSG("\n");

	return TRUE;
}

int
next_online_node(int first)
{
	int i, j, node;
	unsigned long mask, *maskptr;

	/* It cannot occur */
	if ((first/(sizeof(unsigned long) * 8)) >= vt->node_online_map_len) {
		ERRMSG("next_online_node: %d is too large!\n", first);
		return -1;
	}

	maskptr = (unsigned long *)vt->node_online_map;
	for (i = node = 0; i <  vt->node_online_map_len; i++, maskptr++) {
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
get_mm_flatmem()
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
get_num_mm_discontigmem()
{
	int i, nid;
	unsigned long start_paddr, size;

	if ((SYMBOL(node_memblk) == NOT_FOUND_SYMBOL)
	    || (ARRAY_LENGTH(node_memblk) == NOT_FOUND_STRUCTURE)
            || (SIZE(node_memblk_s) == NOT_FOUND_STRUCTURE)
            || (OFFSET(node_memblk_s.start_paddr) == NOT_FOUND_STRUCTURE)
            || (OFFSET(node_memblk_s.size) == NOT_FOUND_STRUCTURE)
            || (OFFSET(node_memblk_s.nid) == NOT_FOUND_STRUCTURE)) {
		return vt->numnodes;
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
			return vt->numnodes;
		} else {
			return i;
		}
	}
}

int
separate_mem_map(struct mem_map_data *mmd,
    int *id_mm, int nid_pgdat, unsigned long mem_map_pgdat,
    unsigned long pfn_start_pgdat)
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
get_mm_discontigmem()
{
	int i, j, id_mm, node, num_mem_map, separate_mm = FALSE;
	unsigned long pgdat, mem_map, pfn_start, pfn_end, node_spanned_pages;
	struct mem_map_data temp_mmd;

	num_mem_map = get_num_mm_discontigmem();
	if (num_mem_map < vt->numnodes) {
		ERRMSG("Can't get the number of mem_map.\n");
		return FALSE;
	}
	struct mem_map_data mmd[num_mem_map];
	if (vt->numnodes < num_mem_map) {
		separate_mm = TRUE;
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
	for (i = 0; i < vt->numnodes; i++) {
		if (!readmem(VADDR, pgdat + OFFSET(pglist_data.node_mem_map),
		    &mem_map, sizeof mem_map)) {
			ERRMSG("Can't get mem_map.\n");
			return FALSE;
		}
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

		if (separate_mm) {
			/*
			 * For some ia64 NUMA systems.
			 * On some systems, a node has the separated memory.
			 * And pglist_data(s) have the dumplicated memory range
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
		if (i < (vt->numnodes - 1)) {
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
		ERRMSG("Can't get a struct mem_section.\n");
		return NOT_KV_ADDR;
	}
	map = ULONG(mem_section + OFFSET(mem_section.section_mem_map));
	map &= SECTION_MAP_MASK;
	free(mem_section);

	return map;
}

unsigned long
sparse_decode_mem_map(ulong coded_mem_map,
    unsigned long section_nr)
{
	if (!is_kvaddr(coded_mem_map))
		return NOT_KV_ADDR;

	return coded_mem_map +
	    (SECTION_NR_TO_PFN(section_nr) * SIZE(page));
}

int
get_mm_sparsemem()
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
get_mem_map_without_mm()
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
get_mem_map()
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
initial()
{
	if (!get_elf_info())
		return FALSE;

	if (!get_phys_base())
		return FALSE;

	/*
	 * Get the debug information for analysis from the vmcoreinfo file 
	 */
	if (info->flag_read_vmcoreinfo) {
		if (!read_vmcoreinfo())
			return FALSE;
	/*
	 * Get the debug information for analysis from the kernel file 
	 */
	} else {
		if (info->dump_level <= DL_EXCLUDE_ZERO) {
			if (!get_mem_map_without_mm())
				return FALSE;
			else
				return TRUE;
		} else {
			if (!get_symbol_info())
				return FALSE;
		}
		if (!get_structure_info())
			return FALSE;

		if (!get_srcfile_info())
			return FALSE;
	}
	if (!get_machdep_info())
		return FALSE;

	if (!check_release())
		return FALSE;

	if (!get_numnodes())
		return FALSE;

	if (!get_mem_map())
		return FALSE;

	return TRUE;
}

static inline void
set_bitmap(char *bitmap, unsigned long long pfn, int val)
{
	int byte, bit;

	byte = pfn>>3;
	bit  = pfn & 7;

	if (val)
		bitmap[byte] |= 1<<bit;
	else
		bitmap[byte] &= ~(1<<bit);
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
is_memory_hole(struct dump_bitmap *bitmap, unsigned long long pfn)
{
	return !is_dumpable(bitmap, pfn);
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
is_bigendian()
{
	int i = 0x12345678;

	if (*(char *)&i == 0x12)
		return TRUE;
	else
		return FALSE;
}

int
write_buffer(int fd, off_t offset, void *buf, size_t buf_size,
    char *file_name)
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
		if (write(fd, &fdh, sizeof(fdh)) != sizeof(fdh)) {
			ERRMSG("Can't write the dump file(%s). %s\n",
			    file_name, strerror(errno));
			return FALSE;
		}
	} else {
		if (lseek(fd, offset, SEEK_SET) == failed) {
			ERRMSG("Can't seek the dump file(%s). %s\n",
			    file_name, strerror(errno));
			return FALSE;
		}
	}
	if (write(fd, buf, buf_size) != buf_size) {
		ERRMSG("Can't write the dump file(%s). %s\n",
		    file_name, strerror(errno));
		return FALSE;
	}
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
			 * while long time, break this loop.
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
read_start_flat_header()
{
	char *buf = NULL;
	struct makedumpfile_header fh;

	int ret = FALSE;

	if ((buf = malloc(MAX_SIZE_MDF_HEADER)) == NULL) {
		ERRMSG("Can't allocate memory for buffer of flat header. %s\n",
		    strerror(errno));
		return FALSE;
	}

	/*
	 * Get flat header.
	 */
	if (!read_buf_from_stdin(buf, MAX_SIZE_MDF_HEADER)) {
		ERRMSG("Can't get header of flattened format.\n");
		goto out;
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
		goto out;
	}
	if (fh.type != TYPE_FLAT_HEADER) {
		ERRMSG("Can't get type of flattened format.\n");
		goto out;
	}

	ret = TRUE;
out:
	if (buf != NULL)
		free(buf);

	return ret;
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
rearrange_dumpdata()
{
	int buf_size, read_size, tmp_read_size;
	char *buf = NULL;
	struct makedumpfile_data_header fdh;

	int ret = FALSE;

	buf_size = SIZE_BUF_STDIN;

	/*
	 * Get flat header.
	 */
	if (!read_start_flat_header()) {
		ERRMSG("Can't get header of flattened format.\n");
		goto out;
	}

	if ((buf = malloc(buf_size)) == NULL) {
		ERRMSG("Can't allocate memory for buffer of flattend format. %s\n",
		    strerror(errno));
		return FALSE;
	}

	/*
	 * Read the first data header.
	 */
	if (!read_flat_data_header(&fdh)) {
		ERRMSG("Can't get header of flattened format.\n");
		goto out;
	}

	do {
		read_size = 0;
		while (read_size < fdh.buf_size) {
			if (buf_size < (fdh.buf_size - read_size))
				tmp_read_size = buf_size;
			else
				tmp_read_size = fdh.buf_size - read_size;

			if (!read_buf_from_stdin(buf, tmp_read_size)) {
				ERRMSG("Can't get data of flattened format.\n");
				goto out;
			}
			if (!write_buffer(info->fd_dumpfile,
			    fdh.offset + read_size, buf, tmp_read_size,
			    info->name_dumpfile))
				goto out;

			read_size += tmp_read_size;
		} 
		/*
		 * Read the next header.
		 */
		if (!read_flat_data_header(&fdh)) {
			ERRMSG("Can't get data header of flattened format.\n");
			goto out;
		}

	} while ((0 <= fdh.offset) && (0 < fdh.buf_size)); 

	if ((fdh.offset != END_FLAG_FLAT_HEADER)
	    || (fdh.buf_size != END_FLAG_FLAT_HEADER)) {
		ERRMSG("Can't get valid end header of flattened format.\n");
		goto out;
	}

	ret = TRUE;
out:
	if (buf != NULL)
		free(buf);

	return ret;
}

/*
 * Sames as paddr_to_offset() but makes sure that the specified offset (hint)
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
		if (page < mmd->mem_map) {
			continue;
		} else {
			index = (page - mmd->mem_map) / SIZE(page);
			if (index > mmd->pfn_end - mmd->pfn_start)
				continue;
			pfn = mmd->pfn_start + index;
			break;
		}
	}
	if (!pfn) {
		ERRMSG("Can't convert the address of page descriptor (%lx) to pfn.\n", page);
		return ULONGLONG_MAX;
	}
	return pfn;
}

int
reset_2nd_bitmap(unsigned long long pfn)
{
	off_t offset_pfn;
	unsigned int buf_size;
	struct cache_data *bm2 = info->bm2;

	offset_pfn  = (info->len_bitmap/2) + (pfn/PFN_BUFBITMAP)*BUFSIZE_BITMAP;
	bm2->offset = offset_pfn;
	buf_size    = info->len_bitmap - bm2->offset;
	if (buf_size >= BUFSIZE_BITMAP) {
		bm2->cache_size = BUFSIZE_BITMAP;
		bm2->buf_size   = BUFSIZE_BITMAP;
	} else {
		bm2->cache_size = buf_size;
		bm2->buf_size   = buf_size;
	}

	if (!read_cache(bm2))
		return FALSE;

	set_bitmap(bm2->buf, pfn%PFN_BUFBITMAP, 0);

	bm2->offset = offset_pfn;
	if (!write_cache_bufsz(bm2))
		return FALSE;

	return TRUE;
}

int
reset_bitmap_of_free_pages(unsigned long node_zones)
{

	int order, i;
	unsigned long curr, previous, head, curr_page, curr_prev;
	unsigned long free_pages = 0, found_free_pages = 0;
	unsigned long long pfn, start_pfn;

	for (order = (ARRAY_LENGTH(zone.free_area) - 1); order >= 0; --order) {
		head = node_zones + OFFSET(zone.free_area)
			+ SIZE(free_area) * order + OFFSET(free_area.free_list);
		previous = head;
		if (!readmem(VADDR, head + OFFSET(list_head.next), &curr,
		    sizeof curr)) {
			ERRMSG("Can't get next list_head.\n");
			return FALSE;
		}
		for (;curr != head;) {
			curr_page = curr - OFFSET(page.lru);
			start_pfn = page_to_pfn(curr_page);
			if (start_pfn == ULONGLONG_MAX)
				return FALSE;

			if (!readmem(VADDR, curr + OFFSET(list_head.prev),
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
				reset_2nd_bitmap(pfn);
			}
			found_free_pages += i;

			previous=curr;
			if (!readmem(VADDR, curr + OFFSET(list_head.next),
			    &curr, sizeof curr)) {
				ERRMSG("Can't get next list_head.\n");
				return FALSE;
			}
		}
	}

	/*
	 * Check the number of free pages.
	 */
	if (OFFSET(zone.free_pages) != NOT_FOUND_STRUCTURE) {
		if (!readmem(VADDR, node_zones + OFFSET(zone.free_pages), 
		    &free_pages, sizeof free_pages)) {
			ERRMSG("Can't get free_pages.\n");
			return FALSE;
		}
	} else if (OFFSET(zone.vm_stat) != NOT_FOUND_STRUCTURE) {
		/*
		 * FIXME
		 * This code expects the NR_FREE_PAGES of zone_stat_item is 0.
		 * The NR_FREE_PAGES should be checked. 
		 */
		if (!readmem(VADDR, node_zones + OFFSET(zone.vm_stat), 
		    &free_pages, sizeof free_pages)) {
			ERRMSG("Can't get free_pages.\n");
			return FALSE;
		}
	}
	if (free_pages != found_free_pages) {
		ERRMSG("The number of free_pages is invalid.\n");
		ERRMSG("  free_pages       = %ld\n", free_pages);
		ERRMSG("  found_free_pages = %ld\n", found_free_pages);
		retcd = ANALYSIS_FAILED;
		return FALSE;
	}
	return TRUE;
}

int
_exclude_free_page()
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
	for (num_nodes = 1; num_nodes <= vt->numnodes; num_nodes++) {

		node_zones = pgdat + OFFSET(pglist_data.node_zones);

		if (!readmem(VADDR, pgdat + OFFSET(pglist_data.nr_zones),
		    &nr_zones, sizeof(nr_zones))) {
			ERRMSG("Can't get nr_zones.\n");
			return FALSE;
		}

		for (i = 0; i < nr_zones; i++) {
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
		if (num_nodes < vt->numnodes) {
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
	 * Flush 2nd-bitmap.
	 * info->bm2->buf_size is set at reset_2nd_bitmap().
	 */
	info->bm2->offset  -= info->bm2->buf_size;
	if (!write_cache_bufsz(info->bm2))
		return FALSE;
	return TRUE;
}

int
exclude_free_page(struct cache_data *bm2)
{

	/*
	 * Check having neccesary information.
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

	info->bm2 = bm2;

	/*
	 * Detect free pages and update 2nd-bitmap.
	 */
	if (!_exclude_free_page())
		return FALSE;

	return TRUE;
}

int
create_dump_bitmap()
{
	int val, not_found_mem_map;
	unsigned int i, mm, remain_size;
	unsigned long mem_map;
	unsigned long long pfn, paddr, pfn_mm;
	unsigned char *page_cache = NULL, *buf = NULL, *pcache;
	unsigned int _count;
	unsigned long flags, mapping;
	struct cache_data bm1, bm2;
	struct mem_map_data *mmd;
	off_t offset_page;
	const off_t failed = (off_t)-1;

	int ret = FALSE;

	bm1.fd         = info->fd_bitmap;
	bm1.file_name  = info->name_bitmap;
	bm1.cache_size = BUFSIZE_BITMAP;
	bm1.buf_size   = 0;
	bm1.offset     = 0;
	bm1.buf        = NULL;

	bm2.fd         = info->fd_bitmap;
	bm2.file_name  = info->name_bitmap;
	bm2.cache_size = BUFSIZE_BITMAP;
	bm2.buf_size   = 0;
	bm2.offset     = info->len_bitmap/2;
	bm2.buf        = NULL;

	if ((bm1.buf = calloc(1, BUFSIZE_BITMAP)) == NULL) {
		ERRMSG("Can't allocate memory for 1st-bitmap buffer. %s\n",
		    strerror(errno));
		goto out;
	}
	if ((bm2.buf = calloc(1, BUFSIZE_BITMAP)) == NULL) {
		ERRMSG("Can't allocate memory for 2nd-bitmap buffer. %s\n",
		    strerror(errno));
		goto out;
	}
	if ((info->dump_level > DL_EXCLUDE_ZERO)
	    && (page_cache = malloc(SIZE(page)*PGMM_CACHED)) == NULL) {
		ERRMSG("Can't allocate memory for the pagedesc cache. %s\n",
		    strerror(errno));
		goto out;
	}
	if ((buf = malloc(info->page_size)) == NULL) {
		ERRMSG("Can't allocate memory for the page. %s\n",
		    strerror(errno));
		goto out;
	}

	for (mm = 0; mm < info->num_mem_map; mm++) {
		mmd = &info->mem_map_data[mm];
		pfn   = mmd->pfn_start;
		paddr = pfn*info->page_size;
		mem_map = mmd->mem_map;

		if (mem_map == NOT_MEMMAP_ADDR)
			not_found_mem_map = TRUE;
		else
			not_found_mem_map = FALSE;

		for (; pfn < mmd->pfn_end;
		    pfn++, mem_map += SIZE(page),
		    paddr += info->page_size) {

			if ((pfn != 0) && (pfn%PFN_BUFBITMAP) == 0) {
				/*
				 * Write the 1st-bitmap and the 2nd-bitmap.
				 */
				bm1.buf_size = BUFSIZE_BITMAP;
				bm2.buf_size = BUFSIZE_BITMAP;
				if (!write_cache_bufsz(&bm1))
					goto out;
				if (!write_cache_bufsz(&bm2))
					goto out;

				/*
				 * Clear the remainder of the bitmap.
				 */
				if ((info->max_mapnr - pfn) <= PFN_BUFBITMAP) {
					for (i = 0; i < PFN_BUFBITMAP; i++) {
						set_bitmap(bm1.buf, i, 0);
						set_bitmap(bm2.buf, i, 0);
					}
				}
			}
			/*
			 * val  1: dump Page
			 *      0: not dump Page
			 */
			val = 1;

			/*
			 * Exclude the memory hole.
			 */
			if (!is_in_segs(paddr))
				val = 0;

			/*
			 * Set the 1st-bitmap.
			 *  val  1: not memory hole
			 *       0: memory hole
			 */
			set_bitmap(bm1.buf, pfn%PFN_BUFBITMAP, val);

			if (val == 0) {
				/*
				 * If the bit of 1st-bitmap is 0,
				 * also 2nd-bitmap's must be 0.
				 */
				set_bitmap(bm2.buf, pfn%PFN_BUFBITMAP, val);
				continue;
			}

			/*
			 * Exclude the page filled with zero in case of creating
			 * the elf dumpfile.
			 */
			if (info->flag_elf_dumpfile
			    && (info->dump_level & DL_EXCLUDE_ZERO)) {
				offset_page = paddr_to_offset(paddr);
				if (!offset_page) {
					ERRMSG("Can't convert physaddr(%llx) to a offset.\n",
					    paddr);
					goto out;
				}
				if (lseek(info->fd_memory, offset_page,
				    SEEK_SET) == failed) {
					ERRMSG("Can't seek the dump memory(%s). %s\n",
					    info->name_memory, strerror(errno));
					goto out;
				}
				if (read(info->fd_memory, buf, info->page_size)
				    != info->page_size) {
					ERRMSG("Can't read the dump memory(%s). %s\n",
					    info->name_memory, strerror(errno));
					goto out;
				}
				if (is_zero_page(buf, info->page_size))
					val = 0;
			}
			if ((info->dump_level <= DL_EXCLUDE_ZERO)
			    || not_found_mem_map) {
				set_bitmap(bm2.buf, pfn%PFN_BUFBITMAP, val);
				continue;
			}

			if ((pfn % PGMM_CACHED) == 0) {
				if (pfn + PGMM_CACHED < mmd->pfn_end)
					pfn_mm = PGMM_CACHED;
				else
					pfn_mm = mmd->pfn_end - pfn;
				if (!readmem(VADDR, mem_map, page_cache,
				    SIZE(page) * pfn_mm))
					goto out;
			}
			pcache  = page_cache + ((pfn%PGMM_CACHED) * SIZE(page));
			flags   = ULONG(pcache + OFFSET(page.flags));
			_count  = UINT(pcache + OFFSET(page._count));
			mapping = ULONG(pcache + OFFSET(page.mapping));

			/*
			 * Exclude the cache page without the private page.
			 */
			if ((info->dump_level & DL_EXCLUDE_CACHE)
			    && (isLRU(flags) || isSwapCache(flags))
			    && !isPrivate(flags) && !isAnon(mapping))
				val = 0;

			/*
			 * Exclude the cache page with the private page.
			 */
			else if ((info->dump_level & DL_EXCLUDE_CACHE_PRI)
			    && (isLRU(flags) || isSwapCache(flags))
			    && !isAnon(mapping))
				val = 0;

			/*
			 * Exclude the data page of the user process.
			 */
			else if ((info->dump_level & DL_EXCLUDE_USER_DATA)
			    && isAnon(mapping))
				val = 0;

			/*
			 * Set the 2nd-bitmap.
			 *  val  1: dump page
			 *       0: not dump page(memory hole, or page excluded)
			 */
			set_bitmap(bm2.buf, pfn%PFN_BUFBITMAP, val);
		}
	}

	/*
	 * Write the remainder of the bitmap.
	 */
	remain_size = info->len_bitmap/2 - bm1.offset;
	bm1.buf_size = remain_size;
	bm2.buf_size = remain_size;
	if (!write_cache_bufsz(&bm1))
		goto out;
	if (!write_cache_bufsz(&bm2))
		goto out;

	if (info->flag_exclude_free)
		if (!exclude_free_page(&bm2))
			goto out;

	ret = TRUE;
out:
	if (page_cache != NULL)
		free(page_cache);
	if (buf != NULL)
		free(buf);
	if (bm1.buf != NULL)
		free(bm1.buf);
	if (bm2.buf != NULL)
		free(bm2.buf);

	return ret;
}

int
get_loads_dumpfile()
{
	int i, phnum, num_new_load = 0;
	long page_size = info->page_size;
	unsigned long long pfn, pfn_start, pfn_end, num_excluded;
	unsigned long frac_head, frac_tail;
	Elf64_Ehdr ehdr64;
	Elf64_Phdr load64;
	Elf32_Ehdr ehdr32;
	Elf32_Phdr load32;
	struct dump_bitmap bitmap2;

	bitmap2.fd        = info->fd_bitmap;
	bitmap2.file_name = info->name_bitmap;
	bitmap2.no_block  = -1;
	bitmap2.buf       = NULL;
	bitmap2.offset    = info->len_bitmap/2;

	if ((bitmap2.buf = calloc(1, BUFSIZE_BITMAP)) == NULL) {
		ERRMSG("Can't allocate memory for the 2nd bitmap. %s\n",
		    strerror(errno));
		goto out;
	}
	if (info->flag_elf64) { /* ELF64 */
		if (!get_elf64_ehdr(&ehdr64)) {
			ERRMSG("Can't get ehdr64.\n");
			goto out;
		}
		phnum = ehdr64.e_phnum;
	} else {                /* ELF32 */
		if (!get_elf32_ehdr(&ehdr32)) {
			ERRMSG("Can't get ehdr32.\n");
			goto out;
		}
		phnum = ehdr32.e_phnum;
	}
	for (i = 0; i < phnum; i++) {
		if (info->flag_elf64) { /* ELF64 */
			if (!get_elf64_phdr(info->fd_memory, info->name_memory,
			    i, &load64)) {
				ERRMSG("Can't find Phdr %d.\n", i);
				goto out;
			}
			if (load64.p_type != PT_LOAD)
				continue;
			pfn_start = load64.p_paddr / page_size;
			pfn_end   = (load64.p_paddr+load64.p_memsz)/page_size;
			frac_head = page_size - (load64.p_paddr % page_size);
			frac_tail = (load64.p_paddr+load64.p_memsz)%page_size;
		} else {                /* ELF32 */
			if (!get_elf32_phdr(info->fd_memory, info->name_memory,
			    i, &load32)) {
				ERRMSG("Can't find Phdr %d.\n", i);
				goto out;
			}
			if (load32.p_type != PT_LOAD)
				continue;
			pfn_start = load32.p_paddr / page_size;
			pfn_end   = (load32.p_paddr+load32.p_memsz)/page_size;
			frac_head = page_size - (load32.p_paddr % page_size);
			frac_tail = (load32.p_paddr+load32.p_memsz)%page_size;
		}
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
out:
	if (bitmap2.buf != NULL)
		free(bitmap2.buf);
	return num_new_load;
}

int
write_start_flat_header()
{
	char *buf = NULL;
	struct makedumpfile_header fh;

	int ret = FALSE;

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

	if ((buf = calloc(1, MAX_SIZE_MDF_HEADER)) == NULL) {
		ERRMSG("Can't allocate memory for header of flattened format. %s\n",
		    strerror(errno));
		return FALSE;
	}
	memcpy(buf, &fh, sizeof(fh));
	if (write(info->fd_dumpfile, buf, MAX_SIZE_MDF_HEADER)
	    != MAX_SIZE_MDF_HEADER) {
		ERRMSG("Can't write the dump file(%s). %s\n",
		    info->name_dumpfile, strerror(errno));
		goto out;
	}
	ret = TRUE;
out:
	if (buf != NULL)
		free(buf);

	return ret;
}

int
write_end_flat_header()
{
	struct makedumpfile_data_header fdh;

	if (!info->flag_flatten)
		return FALSE;

	fdh.offset   = END_FLAG_FLAT_HEADER;
	fdh.buf_size = END_FLAG_FLAT_HEADER;

	if (write(info->fd_dumpfile, &fdh, sizeof(fdh)) != sizeof(fdh)) {
		ERRMSG("Can't write the dump file(%s). %s\n",
		    info->name_dumpfile, strerror(errno));
		return FALSE;
	}
	return TRUE;
}

int
write_elf_header()
{
	int i, num_loads_dumpfile;
	off_t offset_note_memory, offset_note_dumpfile;
	size_t size_note;
	Elf64_Ehdr ehdr64;
	Elf64_Phdr note64;
	Elf32_Ehdr ehdr32;
	Elf32_Phdr note32;

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

	if (info->flag_elf64) { /* ELF64 */
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
	 * Write a ELF header.
	 */
	if (info->flag_elf64) { /* ELF64 */
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
	if (info->flag_elf64) { /* ELF64 */
		for (i = 0; i < ehdr64.e_phnum; i++) {
			if (!get_elf64_phdr(info->fd_memory, info->name_memory,
			    i, &note64)) {
				ERRMSG("Can't find Phdr %d.\n", i);
				goto out;
			}
			if (note64.p_type == PT_NOTE)
				break;
		}
		if (note64.p_type != PT_NOTE) {
			ERRMSG("Can't get a PT_NOTE header.\n");
			goto out;
		}

		offset_note_memory   = note64.p_offset;
		offset_note_dumpfile = sizeof(ehdr64)
		    + sizeof(Elf64_Phdr) * ehdr64.e_phnum;
		note64.p_offset      = offset_note_dumpfile; 
		size_note            = note64.p_filesz;

		if (!write_buffer(info->fd_dumpfile, sizeof(ehdr64), &note64,
		    sizeof(note64), info->name_dumpfile))
			goto out;

	} else {                /* ELF32 */
		for (i = 0; i < ehdr32.e_phnum; i++) {
			if (!get_elf32_phdr(info->fd_memory, info->name_memory,
			    i, &note32)) {
				ERRMSG("Can't find Phdr %d.\n", i);
				goto out;
			}
			if (note32.p_type == PT_NOTE)
				break;
		}
		if (note32.p_type != PT_NOTE) {
			ERRMSG("Can't get a PT_NOTE header.\n");
			goto out;
		}

		offset_note_memory   = note32.p_offset;
		offset_note_dumpfile = sizeof(ehdr32)
		    + sizeof(Elf32_Phdr) * ehdr32.e_phnum;
		note32.p_offset      = offset_note_dumpfile; 
		size_note            = note32.p_filesz;

		if (!write_buffer(info->fd_dumpfile, sizeof(ehdr32), &note32,
		    sizeof(note32), info->name_dumpfile))
			goto out;
	}

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
	 * Set a offset of PT_LOAD segment.
	 */
	info->offset_load_dumpfile = offset_note_dumpfile + size_note;

	ret = TRUE;
out:
	if (buf != NULL)
		free(buf);

	return ret;
}

int
write_kdump_header()
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
	dh->header_version = 1;
	dh->block_size   = info->page_size;
	dh->sub_hdr_size = 1;
	dh->max_mapnr    = info->max_mapnr;
	dh->nr_cpus      = 1;
	dh->bitmap_blocks
	    = divideup(info->len_bitmap, dh->block_size);

	size = sizeof(struct disk_dump_header);
	if (!write_buffer(info->fd_dumpfile, 0, dh, size, info->name_dumpfile))
		return FALSE;

	/*
	 * Write sub header
	 */
	sub_dump_header.phys_base  = info->phys_base;
	sub_dump_header.dump_level = info->dump_level;
	size = sizeof(struct kdump_sub_header);
	if (!write_buffer(info->fd_dumpfile, dh->block_size, &sub_dump_header,
	    size, info->name_dumpfile))
		return FALSE;

	info->offset_bitmap1
	    = (1 + dh->sub_hdr_size) * dh->block_size;

	return TRUE;
}

void
print_progress(unsigned long current, unsigned long end)
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
	PROGRESS_MSG("[%3d %%]", progress);
}

int
write_elf_pages()
{
	int i, phnum;
	long page_size = info->page_size;
	long long bufsz_write, bufsz_remain;
	unsigned long long pfn, pfn_start, pfn_end, paddr, num_excluded;
	unsigned long long num_dumpable = 0, num_dumped = 0, per;
	unsigned long long memsz, filesz;
	unsigned long frac_head, frac_tail;
	off_t off_seg_load, off_memory;
	Elf64_Ehdr ehdr64;
	Elf64_Phdr load64;
	Elf32_Ehdr ehdr32;
	Elf32_Phdr load32;
	char *buf = NULL;
	struct dump_bitmap bitmap2;
	struct cache_data cd_hdr, cd_seg;
	const off_t failed = (off_t)-1;
	int ret = FALSE;

	if (!info->flag_elf_dumpfile)
		return FALSE;

	bitmap2.fd        = info->fd_bitmap;
	bitmap2.file_name = info->name_bitmap;
	bitmap2.no_block  = -1;
	bitmap2.buf       = NULL;
	bitmap2.offset    = info->len_bitmap/2;

	cd_hdr.fd         = info->fd_dumpfile;
	cd_hdr.file_name  = info->name_dumpfile;
	cd_hdr.cache_size = info->page_size<<info->block_order;
	cd_hdr.buf_size   = 0;
	cd_hdr.buf        = NULL;

	cd_seg.fd         = info->fd_dumpfile;
	cd_seg.file_name  = info->name_dumpfile;
	cd_seg.cache_size = info->page_size<<info->block_order;
	cd_seg.buf_size   = 0;
	cd_seg.buf        = NULL;

	if ((buf = malloc(info->page_size)) == NULL) {
		ERRMSG("Can't allocate memory for buffer. %s\n",
		    strerror(errno));
		goto out;
	}
	if ((bitmap2.buf = calloc(1, BUFSIZE_BITMAP)) == NULL) {
		ERRMSG("Can't allocate memory for the 2nd bitmap. %s\n",
		    strerror(errno));
		goto out;
	}
	if ((cd_hdr.buf = malloc(cd_hdr.cache_size + info->page_size))
	    == NULL) {
		ERRMSG("Can't allocate memory for the page data buffer. %s\n",
		    strerror(errno));
		goto out;
	}
	if ((cd_seg.buf = malloc(cd_seg.cache_size + info->page_size))
	    == NULL) {
		ERRMSG("Can't allocate memory for the page data buffer. %s\n",
		    strerror(errno));
		goto out;
	}

	/*
	 * Count the number of dumpable pages.
	 */
	for (pfn = 0 ; pfn < info->max_mapnr; pfn++) {
		if (is_dumpable(&bitmap2, pfn))
			num_dumpable++;
	}
	per = num_dumpable / 100;

	off_seg_load  = info->offset_load_dumpfile;
	cd_seg.offset = info->offset_load_dumpfile;

	if (info->flag_elf64) { /* ELF64 */
		cd_hdr.offset = sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr);
		if (!get_elf64_ehdr(&ehdr64)) {
			ERRMSG("Can't get ehdr64.\n");
			goto out;
		}
		phnum = ehdr64.e_phnum;
	} else {                /* ELF32 */
		cd_hdr.offset = sizeof(Elf32_Ehdr) + sizeof(Elf32_Phdr);
		if (!get_elf32_ehdr(&ehdr32)) {
			ERRMSG("Can't get ehdr32.\n");
			goto out;
		}
		phnum = ehdr32.e_phnum;
	}

	for (i = 0; i < phnum; i++) {
		if (info->flag_elf64) { /* ELF64 */
			if (!get_elf64_phdr(info->fd_memory, info->name_memory,
			    i, &load64)) {
				ERRMSG("Can't find Phdr %d.\n", i);
				goto out;
			}
			if (load64.p_type != PT_LOAD)
				continue;
			off_memory= load64.p_offset;
			paddr     = load64.p_paddr;
			pfn_start = load64.p_paddr / page_size;
			pfn_end   = (load64.p_paddr+ load64.p_memsz)/page_size;
			frac_head = page_size - (load64.p_paddr % page_size);
			frac_tail = (load64.p_paddr+ load64.p_memsz)%page_size;
		} else {                /* ELF32 */
			if (!get_elf32_phdr(info->fd_memory, info->name_memory,
			    i, &load32)) {
				ERRMSG("Can't find Phdr %d.\n", i);
				goto out;
			}
			if (load32.p_type != PT_LOAD)
				continue;
			off_memory= load32.p_offset;
			paddr     = load32.p_paddr;
			pfn_start = load32.p_paddr / page_size;
			pfn_end   = (load32.p_paddr+ load32.p_memsz)/page_size;
			frac_head = page_size - (load32.p_paddr % page_size);
			frac_tail = (load32.p_paddr+ load32.p_memsz)%page_size;
		}

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
			if (info->flag_elf64) { /* ELF64 */
				load64.p_memsz  = memsz;
				load64.p_filesz = filesz;
				load64.p_offset = off_seg_load;
			} else {                /* ELF32 */
				load32.p_memsz  = memsz;
				load32.p_filesz = filesz;
				load32.p_offset = off_seg_load;
			}

			/*
			 * Write a PT_LOAD header.
			 */
			if (info->flag_elf64) { /* ELF64 */
				if (!write_cache(&cd_hdr, &load64, sizeof(load64)))
					goto out;

			} else {                /* ELF32 */
				if (!write_cache(&cd_hdr, &load32, sizeof(load32)))
					goto out;
			}
			/*
			 * Write a PT_LOAD segment.
			 */
			off_memory = paddr_to_offset2(paddr, off_memory);
			if (!off_memory) {
				ERRMSG("Can't convert physaddr(%llx) to a offset.\n",
				    paddr);
				goto out;
			}
			if (lseek(info->fd_memory, off_memory, SEEK_SET)
			    == failed) {
				ERRMSG("Can't seek the dump memory(%s). %s\n",
				    info->name_memory, strerror(errno));
				goto out;
			}
			if (info->flag_elf64) /* ELF64 */
				bufsz_remain = load64.p_filesz;
			else                  /* ELF32 */
				bufsz_remain = load32.p_filesz;

			while (bufsz_remain > 0) {
				if ((num_dumped % per) == 0)
					print_progress(num_dumped, num_dumpable);

				if (bufsz_remain >= page_size)
					bufsz_write = page_size;
				else
					bufsz_write = bufsz_remain;

				if (read(info->fd_memory, buf, bufsz_write)
				    != bufsz_write) {
					ERRMSG("Can't read the dump memory(%s). %s\n",
					    info->name_memory, strerror(errno));
					goto out;
				}
				if (!write_cache(&cd_seg, buf, bufsz_write))
					goto out;

				bufsz_remain -= page_size;
				num_dumped++;
			}

			if (info->flag_elf64) { /* ELF64 */
				load64.p_paddr += load64.p_memsz;
#ifdef __x86__
				/*
				 * FIXME:
				 *  (x86) Fill PT_LOAD headers with appropriate
				 *        virtual addresses.
				 */
				if (load64.p_paddr < MAXMEM)
					load64.p_vaddr += load64.p_memsz;
#else
				load64.p_vaddr += load64.p_memsz;
#endif /* x86 */
				paddr  = load64.p_paddr;
				off_seg_load += load64.p_filesz;
			} else {                /* ELF32 */
				load32.p_paddr += load32.p_memsz;
#ifdef __x86__
				if (load32.p_paddr < MAXMEM)
					load32.p_vaddr += load32.p_memsz;
#else
				load32.p_vaddr += load32.p_memsz;
#endif /* x86 */
				paddr  = load32.p_paddr;
				off_seg_load += load32.p_filesz;
			}
			num_excluded = 0;
			memsz  = page_size;
			filesz = page_size;
		}
		/*
		 * Write the last PT_LOAD.
		 */
		if (info->flag_elf64) { /* ELF64 */
			load64.p_memsz  = memsz;
			load64.p_filesz = filesz;
			load64.p_offset = off_seg_load;
		} else {                /* ELF32 */
			load32.p_memsz  = memsz;
			load32.p_filesz = filesz;
			load32.p_offset = off_seg_load;
		}

		/*
		 * Write a PT_LOAD header.
		 */
		if (info->flag_elf64) { /* ELF64 */
			if (!write_cache(&cd_hdr, &load64, sizeof(load64)))
				goto out;

		} else {                /* ELF32 */
			if (!write_cache(&cd_hdr, &load32, sizeof(load32)))
				goto out;
		}

		/*
		 * Write a PT_LOAD segment.
		 */
		off_memory = paddr_to_offset2(paddr, off_memory);
		if (!off_memory) {
			ERRMSG("Can't convert physaddr(%llx) to a offset.\n",
			    paddr);
			goto out;
		}
		if (lseek(info->fd_memory, off_memory, SEEK_SET)
		    == failed) {
			ERRMSG("Can't seek the dump memory(%s). %s\n",
			    info->name_memory, strerror(errno));
			goto out;
		}
		if (info->flag_elf64) /* ELF64 */
			bufsz_remain = load64.p_filesz;
		else                  /* ELF32 */
			bufsz_remain = load32.p_filesz;

		while (bufsz_remain > 0) {
			if ((num_dumped % per) == 0)
				print_progress(num_dumped, num_dumpable);

			if (bufsz_remain >= page_size)
				bufsz_write = page_size;
			else
				bufsz_write = bufsz_remain;

			if (read(info->fd_memory, buf, bufsz_write)
			    != bufsz_write) {
				ERRMSG("Can't read the dump memory(%s). %s\n",
				    info->name_memory, strerror(errno));
				goto out;
			}
			if (!write_cache(&cd_seg, buf, bufsz_write))
				goto out;

			bufsz_remain -= page_size;
			num_dumped++;
		}
		if (info->flag_elf64) /* ELF64 */
			off_seg_load += load64.p_filesz;
		else                  /* ELF32 */
			off_seg_load += load32.p_filesz;
	}
	if (!write_cache_bufsz(&cd_hdr))
		goto out;
	if (!write_cache_bufsz(&cd_seg))
		goto out;

	print_progress(num_dumpable, num_dumpable);
	PROGRESS_MSG("\n");

	ret = TRUE;
out:
	if (buf != NULL)
		free(buf);
	if (bitmap2.buf != NULL)
		free(bitmap2.buf);
	if (cd_hdr.buf != NULL)
		free(cd_hdr.buf);
	if (cd_seg.buf != NULL)
		free(cd_seg.buf);

	return ret;
}

int
write_kdump_pages()
{
 	unsigned long long pfn, per, num_dumpable = 0, num_dumped = 0;
	unsigned long size_out;
	struct page_desc pd, pd_zero;
	off_t offset_data = 0, offset_memory = 0;
	struct disk_dump_header *dh = info->dump_header;
	unsigned char *buf = NULL, *buf_out = NULL;
	unsigned long len_buf_out;
	struct cache_data bm2, pdesc, pdata;
	struct dump_bitmap bitmap1, bitmap2;
	const off_t failed = (off_t)-1;

	int ret = FALSE;

	if (info->flag_elf_dumpfile)
		return FALSE;

	bm2.fd         = info->fd_bitmap;
	bm2.file_name  = info->name_bitmap;
	bm2.cache_size = BUFSIZE_BITMAP;
	bm2.buf_size   = 0;
	bm2.offset     = info->len_bitmap/2;
	bm2.buf        = NULL;

	pdesc.fd         = info->fd_dumpfile;
	pdesc.file_name  = info->name_dumpfile;
	pdesc.cache_size = info->page_size<<info->block_order;
	pdesc.buf_size   = 0;
	pdesc.buf        = NULL;

	pdata.fd         = info->fd_dumpfile;
	pdata.file_name  = info->name_dumpfile;
	pdata.cache_size = info->page_size<<info->block_order;
	pdata.buf_size   = 0;
	pdata.buf        = NULL;

	bitmap1.fd        = info->fd_bitmap;
	bitmap1.file_name = info->name_bitmap;
	bitmap1.no_block  = -1;
	bitmap1.buf       = NULL;
	bitmap1.offset    = 0;

	bitmap2.fd        = info->fd_bitmap;
	bitmap2.file_name = info->name_bitmap;
	bitmap2.no_block  = -1;
	bitmap2.buf       = NULL;
	bitmap2.offset    = info->len_bitmap/2;

	if ((buf = malloc(info->page_size)) == NULL) {
		ERRMSG("Can't allocate memory for the page. %s\n",
		    strerror(errno));
		goto out;
	}
	len_buf_out = compressBound(info->page_size);
	if ((buf_out = malloc(len_buf_out)) == NULL) {
		ERRMSG("Can't allocate memory for the compression buffer. %s\n",
		    strerror(errno));
		goto out;
	}
	if ((bm2.buf = calloc(1, BUFSIZE_BITMAP)) == NULL) {
		ERRMSG("Can't allocate memory for 2nd-bitmap buffer. %s\n",
		    strerror(errno));
		goto out;
	}
	if ((pdesc.buf = malloc(pdesc.cache_size + info->page_size))
	    == NULL) {
		ERRMSG("Can't allocate memory for the page desc buffer. %s\n",
		    strerror(errno));
		goto out;
	}
	if ((pdata.buf = malloc(pdata.cache_size + info->page_size))
	    == NULL) {
		ERRMSG("Can't allocate memory for the page data buffer. %s\n",
		    strerror(errno));
		goto out;
	}
	if ((bitmap1.buf = calloc(1, BUFSIZE_BITMAP)) == NULL) {
		ERRMSG("Can't allocate memory for the 1st bitmap. %s\n",
		    strerror(errno));
		goto out;
	}
	if ((bitmap2.buf = calloc(1, BUFSIZE_BITMAP)) == NULL) {
		ERRMSG("Can't allocate memory for the 2nd bitmap. %s\n",
		    strerror(errno));
		goto out;
	}

	/*
	 * Count the number of dumpable pages.
	 */
	for (pfn = 0 ; pfn < info->max_mapnr; pfn++) {
		if (is_dumpable(&bitmap2, pfn))
			num_dumpable++;
	}
	per = num_dumpable / 100;

	/*
	 * Calculate the offset of the page data.
	 */
	pdesc.offset
	    = (1 + dh->sub_hdr_size + dh->bitmap_blocks)*dh->block_size;
	pdata.offset = pdesc.offset + sizeof(page_desc_t)*num_dumpable;
	offset_data  = pdata.offset;

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
		if (!write_cache(&pdata, buf, pd_zero.size))
			goto out;
		offset_data  += pd_zero.size;
	}
	for (pfn = 0; pfn < info->max_mapnr; pfn++) {

		if ((num_dumped % per) == 0)
			print_progress(num_dumped, num_dumpable);

		if ((pfn % PFN_BUFBITMAP) == 0) {
			if (info->len_bitmap - bm2.offset < BUFSIZE_BITMAP)
				bm2.cache_size = info->len_bitmap - bm2.offset;
			if (!read_cache(&bm2))
				goto out;
		}

		/*
		 * Check the memory hole.
		 */
		if (is_memory_hole(&bitmap1, pfn))
			continue;
		/*
		 * Check the excluded page.
		 */
		if (!is_dumpable(&bitmap2, pfn))
			continue;

		num_dumped++;

		offset_memory = paddr_to_offset(info->page_size*pfn);
		if (lseek(info->fd_memory, offset_memory, SEEK_SET)
		    == failed) {
			ERRMSG("Can't seek the dump memory(%s). %s\n",
			    info->name_memory, strerror(errno));
			goto out;
		}
		if (read(info->fd_memory, buf, info->page_size)
		    != info->page_size) {
			ERRMSG("Can't read the dump memory(%s). %s\n",
			    info->name_memory, strerror(errno));
			goto out;
		}

		/*
		 * Exclude the page filled with zeros.
		 */
		if ((info->dump_level & DL_EXCLUDE_ZERO)
		    && is_zero_page(buf, info->page_size)) {
			if (!write_cache(&pdesc, &pd_zero, sizeof(page_desc_t)))
				goto out;
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
		if (!write_cache(&pdesc, &pd, sizeof(page_desc_t)))
			goto out;

		/*
		 * Write the page data.
		 */
		if (!write_cache(&pdata, buf, pd.size))
			goto out;
	}

	/*
	 * Write the remainder.
	 */
	if (!write_cache_bufsz(&pdata))
		goto out;
	if (!write_cache_bufsz(&pdesc))
		goto out;

	/*
	 * Print the progress of the end.
	 */
	print_progress(num_dumpable, num_dumpable);
	PROGRESS_MSG("\n");

	ret = TRUE;
out:
	if (buf != NULL)
		free(buf);
	if (buf_out != NULL)
		free(buf_out);
	if (bm2.buf != NULL)
		free(bm2.buf);
	if (pdesc.buf != NULL)
		free(pdesc.buf);
	if (pdata.buf != NULL)
		free(pdata.buf);
	if (bitmap1.buf != NULL)
		free(bitmap1.buf);
	if (bitmap2.buf != NULL)
		free(bitmap2.buf);

	return ret;
}

int
write_kdump_bitmap()
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
close_vmcoreinfo()
{
	if(fclose(info->file_vmcoreinfo) < 0)
		ERRMSG("Can't close the vmcoreinfo file(%s). %s\n",
		    info->name_vmcoreinfo, strerror(errno));
}

void
close_dump_memory()
{
	if ((info->fd_memory = close(info->fd_memory)) < 0)
		ERRMSG("Can't close the dump memory(%s). %s\n",
		    info->name_memory, strerror(errno));
}

void
close_dump_file()
{
	if (info->flag_flatten)
		return;

	if ((info->fd_dumpfile = close(info->fd_dumpfile)) < 0)
		ERRMSG("Can't close the dump file(%s). %s\n",
		    info->name_dumpfile, strerror(errno));
}

void
close_dump_bitmap()
{
	if ((info->fd_bitmap = close(info->fd_bitmap)) < 0)
		ERRMSG("Can't close the bitmap file(%s). %s\n",
		    info->name_bitmap, strerror(errno));
	free(info->name_bitmap);
}

void
close_kernel_file()
{
	if ((dwarf_info.vmlinux_fd = close(dwarf_info.vmlinux_fd)) < 0)
		ERRMSG("Can't close the kernel file(%s). %s\n",
			dwarf_info.vmlinux_name, strerror(errno));
}

/*
 * Close the following files when it generates the vmcoreinfo file.
 * - vmlinux
 * - vmcoreinfo file
 */
int
close_files_for_generating_vmcoreinfo()
{
	close_kernel_file();

	close_vmcoreinfo();

	return TRUE;
}

/*
 * Close the following file when it re-arranges the dump data.
 * - dump file
 */
int
close_files_for_rearranging_dumpdata()
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
close_files_for_creating_dumpfile()
{
	if (info->flag_read_vmcoreinfo)
		close_vmcoreinfo();
	else if (info->dump_level > DL_EXCLUDE_ZERO)
		close_kernel_file();

	close_dump_memory();

	close_dump_file();

	close_dump_bitmap();

	return TRUE;
}

/*
 * for Xen extraction
 */
int
get_symbol_info_xen()
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
	SYMBOL_INIT(pgd_l4, "idle_pg_table_4");		/* x86_64 */
	SYMBOL_INIT(xen_heap_start, "xen_heap_start");	/* ia64 */
	SYMBOL_INIT(xen_pstart, "xen_pstart");		/* ia64 */
	SYMBOL_INIT(frametable_pg_dir, "frametable_pg_dir");	/* ia64 */

	return TRUE;
}

int
get_structure_info_xen()
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
get_xen_info()
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
show_data_xen()
{
	int i;

	/*
	 * Show data for debug
	 */
	MSG("\n");
	MSG("SYMBOL(dom_xen): %lx\n", SYMBOL(dom_xen));
	MSG("SYMBOL(dom_io): %lx\n", SYMBOL(dom_io));
	MSG("SYMBOL(domain_list): %lx\n", SYMBOL(domain_list));
	MSG("SYMBOL(xen_heap_start): %lx\n", SYMBOL(xen_heap_start));
	MSG("SYMBOL(frame_table): %lx\n", SYMBOL(frame_table));
	MSG("SYMBOL(alloc_bitmap): %lx\n", SYMBOL(alloc_bitmap));
	MSG("SYMBOL(max_page): %lx\n", SYMBOL(max_page));
	MSG("SYMBOL(pgd_l2): %lx\n", SYMBOL(pgd_l2));
	MSG("SYMBOL(pgd_l3): %lx\n", SYMBOL(pgd_l3));
	MSG("SYMBOL(pgd_l4): %lx\n", SYMBOL(pgd_l4));
	MSG("SYMBOL(xenheap_phys_end): %lx\n", SYMBOL(xenheap_phys_end));
	MSG("SYMBOL(xen_pstart): %lx\n", SYMBOL(xen_pstart));
	MSG("SYMBOL(frametable_pg_dir): %lx\n", SYMBOL(frametable_pg_dir));

	MSG("SIZE(page_info): %ld\n", SIZE(page_info));
	MSG("OFFSET(page_info.count_info): %ld\n", OFFSET(page_info.count_info));
	MSG("OFFSET(page_info._domain): %ld\n", OFFSET(page_info._domain));
	MSG("SIZE(domain): %ld\n", SIZE(domain));
	MSG("OFFSET(domain.domain_id): %ld\n", OFFSET(domain.domain_id));
	MSG("OFFSET(domain.next_in_list): %ld\n", OFFSET(domain.next_in_list));

	MSG("\n");
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
generate_vmcoreinfo_xen()
{
	if ((info->page_size = sysconf(_SC_PAGE_SIZE)) <= 0) {
		ERRMSG("Can't get the size of page.\n");
		return FALSE;
	}

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
read_vmcoreinfo_basic_info_xen()
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
			if (!is_page_size(page_size)) {
				ERRMSG("Invalid data in %s: %s",
				    info->name_vmcoreinfo, buf);
				return FALSE;
			}
			break;
		}
	}
	info->page_size = page_size;

	if (!info->page_size) {
		ERRMSG("Invalid format in %s", info->name_vmcoreinfo);
		return FALSE;
	}
	return TRUE;
}

int
read_vmcoreinfo_xen()
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
allocated_in_map(unsigned long pfn)
{
	static int cur_idx = -1;
	static unsigned long cur_word;
	int idx;

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
create_dump_bitmap_xen()
{
	unsigned int remain_size;
	struct cache_data bm2;
	unsigned long page_info_addr;
	unsigned long pfn;
	unsigned int count_info;
	unsigned int _domain;
	int i;
	struct pt_load_segment *pls;
	int ret = FALSE;

	/*
	 * NOTE: the first half of bitmap is not used for Xen extraction
	 */
	bm2.fd         = info->fd_bitmap;
	bm2.file_name  = info->name_bitmap;
	bm2.cache_size = BUFSIZE_BITMAP;
	bm2.buf_size   = 0;
	bm2.offset     = info->len_bitmap/2;
	bm2.buf        = NULL;

	if ((bm2.buf = calloc(1, BUFSIZE_BITMAP)) == NULL) {
		ERRMSG("Can't allocate memory for 2nd-bitmap buffer. %s\n",
		    strerror(errno));
		goto out;
	}

	pfn = 0;
	for (i = 0; i < info->num_load_memory; i++) {
		pls = &info->pt_load_segments[i];

		for (; pfn < (unsigned long)(pls->phys_start >> PAGESHIFT()); pfn++) { /* memory hole */
			if ((pfn != 0) && (pfn%PFN_BUFBITMAP) == 0) {
				bm2.buf_size = BUFSIZE_BITMAP;
				if (!write_cache_bufsz(&bm2))
					goto out;
				memset(bm2.buf, 0, BUFSIZE_BITMAP);
			}
		}

		for (; pfn < (unsigned long)(pls->phys_end >> PAGESHIFT()); pfn++) {

			if ((pfn != 0) && (pfn%PFN_BUFBITMAP) == 0) {
				bm2.buf_size = BUFSIZE_BITMAP;
				if (!write_cache_bufsz(&bm2))
					goto out;
				memset(bm2.buf, 0, BUFSIZE_BITMAP);
			}

			if (!allocated_in_map(pfn))
				continue;

			page_info_addr = info->frame_table_vaddr + pfn * SIZE(page_info);
			if (!readmem(VADDR_XEN,
			      page_info_addr + OFFSET(page_info.count_info),
		 	      &count_info, sizeof(count_info))) {
				continue;	/* page_info may not exist */
			}
			if (!readmem(VADDR_XEN,
			      page_info_addr + OFFSET(page_info._domain),
			      &_domain, sizeof(_domain))) {
				ERRMSG("Can't get page_info._domain.\n");
				goto out;
			}
			/*
			 * select:
			 *  - anonymous (_domain == 0), or
			 *  - xen heap area, or
			 *  - selected domain page
			 */
			if (_domain == 0 ||
				(info->xen_heap_start <= pfn && pfn < info->xen_heap_end) ||
				((count_info & 0xffff) && is_select_domain(_domain))) {
				set_bitmap(bm2.buf, pfn%PFN_BUFBITMAP, 1);
			}
		}
	}

	/*
	 * Write the remainder of the bitmap.
	 */
	remain_size = info->len_bitmap - bm2.offset;
	bm2.buf_size = remain_size;
	if (!write_cache_bufsz(&bm2))
		goto out;

	ret = TRUE;
out:
	if (bm2.buf != NULL)
		free(bm2.buf);

	return ret;
}

int
initial_xen()
{
	if (!get_elf_info())
		return FALSE;

	if (info->flag_read_vmcoreinfo) {
		if (!read_vmcoreinfo_xen())
			return FALSE;
	} else {
		if (!get_symbol_info_xen())
			return FALSE;
		if (!get_structure_info_xen())
			return FALSE;
	}
	if (!get_xen_info())
		return FALSE;

	if (message_level & ML_PRINT_DEBUG_MSG)
		show_data_xen();

	return TRUE;
}

int
handle_xen()
{
#ifdef __powerpc__
	MSG("\n");
	MSG("ppc64 xen is not supported.\n");

	return FALSE;
#else
	if (!open_files_for_creating_dumpfile())
		goto out;

	if (!initial_xen())
		goto out;

	if (!create_dump_bitmap_xen())
		goto out;

	if (!write_elf_header())
		goto out;

	if (!write_elf_pages())
		goto out;

	if (!close_files_for_creating_dumpfile())
		goto out;

	MSG("\n");
	MSG("The dumpfile is saved to %s.\n", info->name_dumpfile);

	return COMPLETED;
out:
	return FALSE;
#endif
}

static struct option longopts[] = {
	{"xen-syms", required_argument, NULL, 'X'},
	{"xen-vmcoreinfo", required_argument, NULL, 'z'},
	{"message-level", required_argument, NULL, 'm'},
	{0, 0, 0, 0}
};

int
main(int argc, char *argv[])
{
	int opt, flag_debug = FALSE;

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
	vt = &info->vm_table;

	info->block_order = DEFAULT_ORDER;
	message_level = DEFAULT_MSG_LEVEL;
	while ((opt = getopt_long(argc, argv, "b:cDd:EFfg:hi:Rvx:", longopts,
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
			info->dump_level = atoi(optarg);
			if (info->dump_level & DL_EXCLUDE_FREE)
				info->flag_exclude_free = 1;
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
		case 'R':
			info->flag_rearrange = 1;
			break;
		case 'v':
			info->flag_show_version = 1;
			break;
		case 'X':
			info->flag_xen = 1;
			dwarf_info.vmlinux_name = optarg;
			break;
		case 'x':
			info->flag_vmlinux = 1;
			dwarf_info.vmlinux_name = optarg;
			break;
		case 'z':
			info->flag_xen = 1;
			info->flag_read_vmcoreinfo = 1;
			info->name_vmcoreinfo = optarg;
			break;
		case '?':
			MSG("Commandline parameter is invalid.\n");
			print_usage();
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
	if (info->flag_generate_vmcoreinfo) {
		/*
		 * Check parameters to generate the vmcoreinfo file.
		 */
		if (argc != optind) {
			MSG("Commandline parameter is invalid.\n");
			print_usage();
			goto out;
		}
		if (info->flag_compress || info->dump_level
		    || info->flag_elf_dumpfile || info->flag_read_vmcoreinfo
		    || !dwarf_info.vmlinux_name || info->flag_flatten
		    || info->flag_rearrange) {
			MSG("Commandline parameter is invalid.\n");
			print_usage();
			goto out;
		}
	} else {
		/*
		 * Check parameters to create the dump file.
		 */
		if ((info->dump_level < MIN_DUMP_LEVEL)
		    || (MAX_DUMP_LEVEL < info->dump_level)) {
			MSG("Dump_level is invalid.\n");
			print_usage();
			goto out;
		}
		if ((message_level < MIN_MSG_LEVEL)
		    || (MAX_MSG_LEVEL < message_level)) {
			message_level = DEFAULT_MSG_LEVEL;
			MSG("Message_level is invalid.\n");
			print_usage();
			goto out;
		}
		if ((info->flag_compress && info->flag_elf_dumpfile)
		    || (info->flag_vmlinux && info->flag_read_vmcoreinfo)) {
			MSG("Commandline parameter is invalid.\n");
			print_usage();
			goto out;
		}
		if ((argc == optind + 2)
		    && !info->flag_flatten && !info->flag_rearrange) {
			/*
			 * Parameters for creating the dumpfile from vmcore.
			 */
			info->name_memory   = argv[optind];
			info->name_dumpfile = argv[optind+1];

		} else if ((argc == optind + 1)
		    && info->flag_flatten && !info->flag_rearrange) {
			/*
			 * Parameters for outputting the dump data of the
			 * flattened format to STDOUT.
			 */
			info->name_memory   = argv[optind];

		} else if ((argc == optind + 1)
		    && !info->flag_flatten && info->flag_rearrange
		    && !info->dump_level   && !info->flag_compress
		    && !info->flag_vmlinux && !info->flag_read_vmcoreinfo
		    && !info->flag_elf_dumpfile) {
			/*
			 * Parameters for creating dumpfile from the dump data
			 * of flattened format by re-arranging the dump data.
			 */
			info->name_dumpfile = argv[optind];

		} else {
			MSG("Commandline parameter is invalid.\n");
			print_usage();
			goto out;
		}
	}

	if (elf_version(EV_CURRENT) == EV_NONE ) {
		/*
		 * library out of date
		 */
		ERRMSG("Elf library out of date!\n");
		goto out;
	}
	if (info->flag_generate_vmcoreinfo) {
		if (!open_files_for_generating_vmcoreinfo())
			goto out;

		if (info->flag_xen) {
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

	} else if (info->flag_xen) {
		if (!info->flag_elf_dumpfile) {
			MSG("-E must be specified with --xen-syms or --xen-vmcoreinfo.\n");
			goto out;
		}
		info->dump_level = DL_EXCLUDE_XEN;
		return handle_xen();

	} else if (info->flag_rearrange) {
		if (!open_files_for_rearranging_dumpdata())
			goto out;

		if (!rearrange_dumpdata())
			goto out;

		if (!close_files_for_rearranging_dumpdata())
			goto out;

		MSG("\n");
		MSG("The dumpfile is saved to %s.\n", info->name_dumpfile);
	} else {
		if (!open_files_for_creating_dumpfile())
			goto out;

		if (!initial())
			goto out;

		if (!create_dump_bitmap())
			goto out;

		if (info->flag_flatten) {
			if (!write_start_flat_header())
				goto out;
		}
		if (info->flag_elf_dumpfile) {
			if (!write_elf_header())
				goto out;
			if (!write_elf_pages())
				goto out;
		} else {
			if (!write_kdump_header())
				goto out;
			if (!write_kdump_pages())
				goto out;
			if (!write_kdump_bitmap())
				goto out;
		}
		if (info->flag_flatten) {
			if (!write_end_flat_header())
				goto out;
		}

		if (!close_files_for_creating_dumpfile())
			goto out;

		MSG("\n");
		MSG("The dumpfile is saved to %s.\n", info->name_dumpfile);
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
	if (info->mem_map_data != NULL)
		free(info->mem_map_data);
	if (info->dump_header != NULL)
		free(info->dump_header);
	if (info != NULL)
		free(info);

	return retcd;
}
