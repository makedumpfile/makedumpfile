/* 
 * makedumpfile.c
 *
 * Copyright (C) 2006  NEC Corporation
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

/*
 * TODO
 * 1. get the memory management information from the symbol "pgdat_list".
 * 2. (i386) fill PT_LOAD headers with appropriate virtual addresses.
 */

#include "makedumpfile.h"

struct symbol_table	symbol_table;
struct size_table	size_table;
struct offset_table	offset_table;

struct dwarf_info	dwarf_info;
struct vm_table		*vt = 0;

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
paddr_to_offset(struct DumpInfo *info, unsigned long paddr)
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

/*
 * Convert Virtual Address to File Offest.
 *  If this function returns 0x0, File Offset isn't found.
 *  The File Offset 0x0 is the ELF header.
 *  It is not in the memory image.
 */
off_t
vaddr_to_offset_general(struct DumpInfo *info, unsigned long vaddr)
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
 * Get the number of the page descriptors from the ELF info.
 */
unsigned long
get_max_mapnr(struct DumpInfo *info)
{
	int i;
	off_t max_paddr;
	struct pt_load_segment *pls;

	for (i = 0, max_paddr = 0; i < info->num_load_memory; i++) {
		pls = &info->pt_load_segments[i];
		if (max_paddr < pls->phys_end)
			max_paddr = pls->phys_end;
	}
	return max_paddr / info->page_size;
}

int
readmem(struct DumpInfo *info, unsigned long vaddr, void *bufptr, size_t size)
{
	off_t offset;
	const off_t failed = (off_t)-1;

	/*
	 * Convert Virtual Address to File Offset.
	 */
	if (!(offset = vaddr_to_offset(info, vaddr))) {
		ERRMSG("Can't convert a virtual address(%lx) to offset.\n",
		    vaddr);
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

int
get_kernel_version(char *release)
{
	if (!strncmp(release, "2.6.15", strlen("2.6.15"))) {
		return VERSION_2_6_15;
	} else if (!strncmp(release, "2.6.16", strlen("2.6.16"))) {
		return VERSION_2_6_16;
	} else if (!strncmp(release, "2.6.17", strlen("2.6.17"))) {
		return VERSION_2_6_17;
	} else if (!strncmp(release, "2.6.18", strlen("2.6.18"))) {
		return VERSION_2_6_18;
	} else {
		ERRMSG("Can't get kernel version from system_utsname.\n");
		return FALSE;
	}
}

int
is_page_size(unsigned long page_size)
{
	unsigned long bitbuf = page_size;
	unsigned int i, sum = 0;

	/* Only 1 bit is set because of page size. */
	for (i = 0; i < sizeof(bitbuf) * 8; i++) {
		sum += bitbuf & 1;
		bitbuf = bitbuf >> 1;
	}
	if (sum != 1) {
		return FALSE;
	}
	return TRUE;
}

int
check_release(struct DumpInfo *info)
{
	unsigned long sym_system_utsname;
	struct utsname system_utsname;

	sym_system_utsname = SYMBOL(system_utsname);
	/*
	 * Get the kernel version from the symbol "system_utsname".
	 */
	if (SYMBOL(system_utsname) == NOT_FOUND_SYMBOL) {
		ERRMSG("Can't get the symbol of system_utsname.\n");
		return FALSE;
	}
	if (!readmem(info, sym_system_utsname, &system_utsname,
	    sizeof(struct utsname))) {
		ERRMSG("Can't get the address of system_utsname.\n");
		return FALSE;
	}

	if (info->flag_read_config) {
		if (strcmp(system_utsname.release, info->release)) {
			ERRMSG("%s doesn't suit the dump_mem.\n",
			    info->name_configfile);
			retcd = WRONG_RELEASE;
			return FALSE;
		}
	}

	info->kernel_version = get_kernel_version(system_utsname.release);
	if (info->kernel_version == FALSE)
		return FALSE;

	return TRUE;
}

void
print_usage()
{
	MSG("\n");
	MSG("Usage:\n");
	MSG("  makedumpfile [-c|-E] [-d dump_level] [-g config_file]|[-i config_file]\n");
	MSG("  [-v] [-x vmlinux] dump_mem dump_file\n");
	MSG("\n");
	MSG("  Making dump_file with vmlinux:\n");
	MSG("    makedumpfile [-c|-E] [-d dump_level] -x vmlinux dump_mem dump_file\n");
	MSG("\n");
	MSG("  Making dump_file with config_file:\n");
	MSG("    makedumpfile [-c|-E] [-d dump_level] -i config_file dump_mem dump_file\n");
	MSG("\n");
	MSG("  Generating config_file:\n");
	MSG("    makedumpfile -g config_file -x vmlinux\n");
	MSG("\n");
	MSG("  Showing the version of makedumpfile:\n");
	MSG("    makedumpfile -v\n");
	MSG("\n");
	MSG("Available options:\n");
	MSG("  [-c]:\n");
	MSG("      This option enables the compression function of each page.\n");
	MSG("      You can not specify this opiton with [-E].\n");
	MSG("      This is only for crash. [dump_mem] and [dump_file] must be specified.\n");
	MSG("\n");
	MSG("  [-E]:\n");
	MSG("      Create the ELF dump file.\n");
	MSG("      You can not specify this opiton with [-c].\n");
	MSG("      This is only for gdb. [dump_mem] and [dump_file] must be specified.\n");
	MSG("\n");
	MSG("  [-d dump_level]:\n");
	MSG("      This is specification of the skipped pages. \n");
	MSG("      The page type marked in the following table is skipped.\n");
	MSG("\n");
	MSG("      dump  |  zero   cache   cache    user    free\n");
	MSG("      level |  page   page    private  data    page\n");
	MSG("     -----------------------------------------------\n");
	MSG("         0  |\n");
	MSG("         1  |  X\n");
	MSG("         2  |         X\n");
//	MSG("         3  |  X      X\n");
	MSG("         4  |         X       X\n");
//	MSG("         5  |  X      X       X\n");
//	MSG("         6  |         X       X\n");
//	MSG("         7  |  X      X       X\n");
	MSG("         8  |                          X\n");
//	MSG("         9  |  X                       X\n");
//	MSG("        10  |         X                X\n");
//	MSG("        11  |  X      X                X\n");
//	MSG("        12  |         X       X        X\n");
//	MSG("        13  |  X      X       X        X\n");
//	MSG("        14  |         X       X        X\n");
	MSG("        15  |  X      X       X        X\n");
	MSG("        16  |                                  X\n");
	MSG("        17  |  X                               X\n");
	MSG("        18  |         X                        X\n");
//	MSG("        19  |  X      X                        X\n");
	MSG("        20  |         X       X                X\n");
//	MSG("        21  |  X      X       X                X\n");
//	MSG("        22  |         X       X                X\n");
//	MSG("        23  |  X      X       X                X\n");
	MSG("        24  |                          X       X\n");
//	MSG("        25  |  X                       X       X\n");
//	MSG("        26  |         X                X       X\n");
//	MSG("        27  |  X      X                X       X\n");
//	MSG("        28  |         X       X        X       X\n");
//	MSG("        29  |  X      X       X        X       X\n");
//	MSG("        30  |         X       X        X       X\n");
	MSG("        31  |  X      X       X        X       X\n");
	MSG("\n");
	MSG("      [-i config_file] or [-x vmlinux] must be specified,\n");
	MSG("      when dump_level is two or more.\n");
	MSG("      [dump_mem] and [dump_file] must be specified.\n");
	MSG("\n");
	MSG("  [-g config_file]:\n");
	MSG("      Generate the configuration file. Debugging information\n");
	MSG("      necessary for executing a partial dump is output to this file. A partial\n");
	MSG("      dump can be executed even if the output this file is read by -i option,\n");
	MSG("      and there is no kernel file with debugging information. When this option\n");
	MSG("      is specified, the dump is not output. [-x vmlinux] must be specified.\n");
	MSG("\n");
	MSG("  [-i config_file]:\n");
	MSG("      Read the configuration file. This file is the one\n");
	MSG("      output beforehand by specifying -g option, and debugging information\n");
	MSG("      necessary for executing a partial dump is contained. A partial dump can\n");
	MSG("      be executed even if this file is read, and there is no kernel file with\n");
	MSG("      debugging information. When this option is specified, -g option,\n");
	MSG("      [-x vmlinux] cannot be specified.\n");
	MSG("      Note:\n");
	MSG("      When this file is not specified, this command uses the page size of\n");
	MSG("      the system under operation(Capture kernel) as the one of dump_mem\n");
	MSG("      (First-kernel).\n");
	MSG("\n");
	MSG("  [-v]:\n");
	MSG("      Show the version of makedumpfile\n");
	MSG("\n");
	MSG("  [-x vmlinux]:\n");
	MSG("      This is a pathname to the first-kernel's vmlinux file compiled with\n");
	MSG("      -g option.\n");
	MSG("      This is necessary when dump_level is 2 or more and [-i config_file] is\n");
	MSG("      not specified.\n");
	MSG("\n");
	MSG("  dump_mem:\n");
	MSG("      This is a pathname to a first-kernel memory core image.\n");
	MSG("      This argument is generally /proc/vmcore.\n");
	MSG("\n");
	MSG("  dump_file:\n");
	MSG("      This is a pathname to a filename created by this command.\n");
	MSG("\n");
}

int
open_config_file(struct DumpInfo *info, char *mode)
{
	FILE *file_configfile;

	if ((file_configfile = fopen(info->name_configfile, mode)) == NULL) {
		ERRMSG("Can't open the config file(%s). %s\n",
		    info->name_configfile, strerror(errno));
		return FALSE;
	}
	info->file_configfile = file_configfile;
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
open_dump_memory(struct DumpInfo *info)
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
open_dump_file(struct DumpInfo *info)
{
	int fd;

	if ((fd = open(info->name_dumpfile, O_RDWR|O_CREAT|O_EXCL,
	    S_IRUSR|S_IWUSR)) < 0) {
		ERRMSG("Can't open the dump file(%s). %s\n",
		    info->name_dumpfile, strerror(errno));
		return FALSE;
	}
	info->fd_dumpfile = fd;
	return TRUE;
}

int
open_3rd_bitmap(struct DumpInfo *info)
{
	int fd;

	if ((info->name_3rd_bitmap
	    = (char *)malloc(sizeof(FILENAME_3RD_BITMAP))) == NULL) {
		ERRMSG("Can't allocate memory for the filename. %s\n",
		    strerror(errno));
		return FALSE;
	}
	strcpy(info->name_3rd_bitmap, FILENAME_3RD_BITMAP);
	if ((fd = open(info->name_3rd_bitmap, O_RDWR|O_CREAT,
	    S_IRUSR|S_IWUSR)) < 0) {
		ERRMSG("Can't open the dump file(%s). %s\n",
		    FILENAME_3RD_BITMAP, strerror(errno));
		return FALSE;
	}
	unlink(info->name_3rd_bitmap);
	info->fd_3rd_bitmap = fd;
	return TRUE;
}

int
open_dump_bitmap(struct DumpInfo *info)
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
 * Open the following files when it generates the configuration file.
 * - vmlinux
 * - configuration file
 */
int
open_files_for_generating_configfile(struct DumpInfo *info)
{
	if (!open_kernel_file())
		return FALSE;

	if (!open_config_file(info, "w"))
		return FALSE;

	return TRUE;
}

/*
 * Open the following files when it creates the dump file.
 * - dump mem
 * - dump file
 * - bit map
 * if it reads the configuration file
 *   - configuration file
 * else
 *   - vmlinux
 */
int
open_files_for_creating_dumpfile(struct DumpInfo *info)
{
	if (info->flag_read_config) {
		if (!open_config_file(info, "r"))
			return FALSE;
	} else if (info->dump_level > DL_EXCLUDE_ZERO) {
		if (!open_kernel_file())
			return FALSE;
	}
	if (!open_dump_memory(info))
		return FALSE;

	if (!open_dump_file(info))
		return FALSE;

	if (!open_dump_bitmap(info))
		return FALSE;

	if (!open_3rd_bitmap(info))
		return FALSE;

	return TRUE;
}

int
dump_Elf_pt_load(struct DumpInfo *info, GElf_Phdr *prog, int num_load)
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
	return TRUE;
}

int
get_elf_info(struct DumpInfo *info)
{
	int i, j;
	unsigned long tmp;
	Elf *elfd = NULL;
	GElf_Ehdr ehdr;
	GElf_Phdr load;
	const off_t failed = (off_t)-1;

	int ret = FALSE;

	if (lseek(info->fd_memory, 0, SEEK_SET) == failed) {
		ERRMSG("Can't seek the dump memory(%s). %s\n",
		    info->name_memory, strerror(errno));
		return FALSE;
	}
	if (!(elfd = elf_begin(info->fd_memory, ELF_C_READ, NULL))) {
		ERRMSG("Can't get first elf header of %s.\n",
		    info->name_memory);
		goto out;
	}
	if (gelf_getehdr(elfd, &ehdr) == NULL) {
		ERRMSG("Can't find file header of %s.\n",
		    info->name_memory);
		goto out;
	}

	/*
	 * get the ident string
	 */
	if (ehdr.e_ident[EI_CLASS] == ELFCLASSNONE) {
		ERRMSG("Elf File has no class.\n");
		goto out;
	}

	info->flag_elf = (ehdr.e_ident[EI_CLASS] == ELFCLASS32) ? ELF32 : ELF64;
	info->num_load_memory = ehdr.e_phnum - 1;
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

	for (i = 0, j = 0; i < ehdr.e_phnum; i++) {
		if (gelf_getphdr(elfd, i, &load) == NULL) {
			ERRMSG("Can't find Phdr %d.\n", i);
			goto out;
		}

		if (load.p_type == PT_LOAD) {
			if (j == 0) {
				info->offset_load_memory = load.p_offset;
				if (!info->offset_load_memory) {
					ERRMSG("Can't get the offset of page data.\n");
					goto out;
				}
			}
			if (j >= info->num_load_memory)
				goto out;

			if(!dump_Elf_pt_load(info, &load, j))
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

	info->max_mapnr = get_max_mapnr(info);
	tmp = 2*divideup(info->max_mapnr, BITPERBYTE);
	tmp = divideup(tmp, info->page_size);
	info->len_bitmap = tmp*info->page_size;
	if (info->flag_exclude_free)
		info->len_3rd_bitmap = info->len_bitmap / 2;

	ret = TRUE;
out:
	if (elfd != NULL)
		elf_end(elfd);

	return ret;
}

unsigned long
get_symbol_addr(struct DumpInfo *info, char *symname, int get_next_symbol)
{
	int i, got_symbol = FALSE;
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
		return FALSE;
	}
	if (!(elfd = elf_begin(dwarf_info.vmlinux_fd, ELF_C_READ, NULL))) {
		ERRMSG("Can't get first elf header of %s.\n",
		    dwarf_info.vmlinux_name);
		return FALSE;
	}
	while ((scn = elf_nextscn(elfd, scn)) != NULL) {
		if (gelf_getshdr (scn, &shdr) == NULL) {
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

		if (got_symbol) {
			symbol = sym.st_value;
			break;
		}
		if (!strcmp(sym_name, symname)) {
			if (get_next_symbol) {
				got_symbol = TRUE;
				continue;
			} else {
				symbol = sym.st_value;
				break;
			}
		}
	}
out:
	if (elfd != NULL)
		elf_end(elfd);

	return symbol;
}

int
get_symbol_info(struct DumpInfo *info)
{
	/*
	 * Get symbol info.
	 */
	SYMBOL_INIT(mem_map, "mem_map");
	SYMBOL_INIT(mem_section, "mem_section");
	SYMBOL_INIT(pkmap_count, "pkmap_count");
	SYMBOL_INIT_NEXT(pkmap_count_next, "pkmap_count");
	SYMBOL_INIT(system_utsname, "system_utsname");
	SYMBOL_INIT(_stext, "_stext");
	SYMBOL_INIT(phys_base, "phys_base");
	SYMBOL_INIT(node_online_map, "node_online_map");
	SYMBOL_INIT(node_data, "node_data");
	SYMBOL_INIT(pgdat_list, "pgdat_list");
	SYMBOL_INIT(contig_page_data, "contig_page_data");

	return TRUE;
}

int
is_kvaddr(unsigned long addr)
{
	return (addr >= (unsigned long)(KVBASE));
}

static int
process_attribute(Dwarf_Attribute *attr, void *cb_data)
{
	struct dwarf_values *args = cb_data;
	Dwarf_Op *expr;
	size_t expcnt;

	switch (attr->code) {
	case DW_AT_data_member_location:
		dwarf_getlocation (attr, &expr, &expcnt);
		if (dwarf_info.member_offset == NOT_FOUND_STRUCTURE)
			dwarf_info.member_offset = expr[0].number;
		*args->found_map |= DWARF_INFO_FOUND_LOCATION;
		break;
	default:
		break;
	}

	return 0;
}

static int
process_children(Dwarf_Die *die, uint32_t *found_map)
{
	Dwarf_Die child;
	Dwarf_Die *walker;
	int rc;
	const char *name;
	struct dwarf_values args;

	rc = dwarf_child(die, &child);
	walker = &child;
	
	while (rc == 0) {
		name = dwarf_diename(walker);
		if ((dwarf_info.cmd == DWARF_INFO_GET_MEMBER_OFFSET)
		    && (dwarf_tag(walker) == DW_TAG_member)
		    && (name) && (!strcmp(name, dwarf_info.member_name))) {
			/*
			 * get the attirbutes of this die to record the
			 * location of the symbol
			 */
			*found_map |= DWARF_INFO_FOUND_MEMBER;
		}
		if ((dwarf_info.cmd == DWARF_INFO_GET_NOT_NAMED_UNION_OFFSET)
		    && (dwarf_tag(walker) == DW_TAG_member)
		    && (!name)) {
			*found_map |= DWARF_INFO_FOUND_MEMBER;
		}
		if (*found_map & DWARF_INFO_FOUND_MEMBER) {
			args.die = walker;
			args.found_map = found_map;
			dwarf_getattrs(walker, process_attribute, &args, 0);
			if ((*found_map & DWARF_INFO_FOUND_ALL)
			    == DWARF_INFO_FOUND_ALL)
				return TRUE;
		}

		rc = dwarf_siblingof(walker, walker); 
	}

	/*
	 * Return TRUE even if not found. Return FALSE if I/O error
	 * in the future.
	 */
	return TRUE;
}

static void
search_die_tree(Dwarf *dwarfd, Dwarf_Die *die, uint32_t *found_map)
{
	Dwarf_Die child; 
	int tag;
	const char *name;

	/* 
	 * start by looking at the children
	 */
	if (dwarf_child(die, &child) == 0)
		search_die_tree(dwarfd, &child, found_map);

	/*
	 * If we get to here then we don't have any more
	 * children, check to see if this is a relevant tag
	 */
next_tag:
	tag = dwarf_tag(die);
	name = dwarf_diename(die);
	if ((tag == DW_TAG_structure_type)
	    && (name) && (!strcmp(name, dwarf_info.struct_name))) {
		/*
		 * this is our structure
		 * process the children
		 */
		dwarf_info.struct_size = dwarf_bytesize(die);
		if (dwarf_info.struct_size > 0) {
			*found_map |= DWARF_INFO_FOUND_STRUCT;
			if (dwarf_info.cmd == DWARF_INFO_GET_STRUCT_SIZE)
				return;
			if (process_children(die, found_map) == TRUE)
				return;
		}
		/*
		 * Skip if DW_AT_byte_size is not included.
		 */
	}

	if (dwarf_siblingof(die,die) == 0)
		goto next_tag;

}


int
get_debug_info(void)
{
	Dwarf *dwarfd = NULL;
	Elf *elfd = NULL;
	Dwarf_Off off = 0;
	Dwarf_Off next_off = 0;
	Elf_Scn *scn = NULL;
	GElf_Shdr scnhdr_mem;
	GElf_Shdr *scnhdr = NULL;
	size_t header_size;
	Dwarf_Off abbrev_offset = 0;
	Dwarf_Die cu_die;
	uint8_t address_size;
	uint8_t offset_size;
	uint32_t found_map = 0;
	char *name = NULL;
	size_t shstrndx;
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

	if (elf_getshstrndx (elfd, &shstrndx) < 0) {
		ERRMSG("Can't get the section index of the string table.\n");
		goto out;
	}
	while ((scn = elf_nextscn (elfd, scn)) != NULL) {

		scnhdr = gelf_getshdr(scn, &scnhdr_mem);

		name = elf_strptr(elfd, shstrndx, scnhdr->sh_name);

		if (strcmp(name,".debug_info"))
			continue;

		while (dwarf_nextcu(dwarfd, off, &next_off, &header_size,
		    &abbrev_offset, &address_size, &offset_size) == 0) {
			off += header_size;
			if (dwarf_offdie(dwarfd, off, &cu_die) == NULL) {
				ERRMSG("Can't get CU die.\n");
				goto out;
			}
			search_die_tree(dwarfd, &cu_die, &found_map);
			if (found_map & DWARF_INFO_FOUND_STRUCT)
				break;
			off = next_off;
		}
		if (found_map & DWARF_INFO_FOUND_STRUCT)
			break;
	}
	ret = TRUE;
out:
	if (dwarfd != NULL)
		dwarf_end(dwarfd);
	if (elfd != NULL)
		elf_end(elfd);
	dwarf_info.status = found_map;

	return ret;
}

/*
 * Get the size of structure.
 */
long
get_structure_size(char *structname)
{
	dwarf_info.cmd = DWARF_INFO_GET_STRUCT_SIZE;
	dwarf_info.status = 0;
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
	dwarf_info.status = 0;
	dwarf_info.struct_name = structname;
	dwarf_info.struct_size = NOT_FOUND_STRUCTURE;
	dwarf_info.member_name = membername;
	dwarf_info.member_offset = NOT_FOUND_STRUCTURE;

	if (!get_debug_info())
		return FAILED_DWARFINFO;

	return dwarf_info.member_offset;
}

int
get_structure_info(struct DumpInfo *info)
{
	/*
	 * Get offsets of the page_discriptor's members.
	 */
	SIZE_INIT(page, "page");
	OFFSET_INIT(page.flags, "page", "flags");
	OFFSET_INIT(page._count, "page", "_count");

	if (info->kernel_version == VERSION_2_6_15)
		OFFSET_INIT(page.mapping, "page", "mapping");
	else
		OFFSET_INIT_NONAME(page.mapping, "page",
		   sizeof(unsigned long));

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

	/*
	 * Get offsets of the zone's members.
	 */
	SIZE_INIT(zone, "zone");
	OFFSET_INIT(zone.free_pages, "zone", "free_pages");
	OFFSET_INIT(zone.free_area, "zone", "free_area");
	OFFSET_INIT(zone.spanned_pages, "zone", "spanned_pages");

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

	return TRUE;
}

int
is_sparsemem_extreme(struct DumpInfo *info)
{
	/*
	 * FIXME
	 *   This makedumpfile command can not distinguish between SPARSEMEM
	 *   and SPARSEMEM_EXTREME. Because it can not get the size of the
	 *   area that starts from symbol "mem_section" yet.
	 */
	return TRUE;
}

int
get_mem_type(struct DumpInfo *info)
{
	int ret;

	if ((SIZE(page) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(page.flags) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(page._count) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(page.mapping) == NOT_FOUND_STRUCTURE))
		ret = NOT_FOUND_MEMTYPE;
	else if ((SYMBOL(mem_section) != NOT_FOUND_SYMBOL)
	    && (SIZE(mem_section) != NOT_FOUND_STRUCTURE)
	    && (OFFSET(mem_section.section_mem_map) != NOT_FOUND_STRUCTURE))
		ret = SPARSEMEM;
	else if (SYMBOL(mem_map) != NOT_FOUND_SYMBOL)
		ret = FLATMEM;
	else
		ret = NOT_FOUND_MEMTYPE;

	return ret;
}

int
generate_config(struct DumpInfo *info)
{
	struct utsname utsname_buf;

	if (uname(&utsname_buf)) {
		ERRMSG("Can't get uname. %s\n", strerror(errno));
		return FALSE;
	}
	if ((info->page_size = sysconf(_SC_PAGE_SIZE)) <= 0) {
		ERRMSG("Can't get the size of page.\n");
		return FALSE;
	}
	if (!(info->kernel_version = get_kernel_version(utsname_buf.release)))
		return FALSE;

	if (!get_symbol_info(info))
		return FALSE;

	if (!get_structure_info(info))
		return FALSE;

	if (SYMBOL(system_utsname) == NOT_FOUND_SYMBOL) {
		ERRMSG("Can't get the symbol of system_utsname.\n");
		return FALSE;
	}
	if (get_mem_type(info) == NOT_FOUND_MEMTYPE) {
		ERRMSG("Can't find the memory type.\n");
		return FALSE;
	}

	/*
	 * write 1st kernel's OSRELEASE
	 */
	fprintf(info->file_configfile, "%s%s\n", STR_OSRELEASE,
	    utsname_buf.release);

	/*
	 * write 1st kernel's PAGESIZE
	 */
	fprintf(info->file_configfile, "%s%d\n", STR_PAGESIZE,
	    (int)info->page_size);

	/*
	 * write the symbol of 1st kernel
	 */
	WRITE_SYMBOL("mem_map", mem_map);
	WRITE_SYMBOL("mem_section", mem_section);
	WRITE_SYMBOL("pkmap_count", pkmap_count);
	WRITE_SYMBOL("pkmap_count_next", pkmap_count_next);
	WRITE_SYMBOL("system_utsname", system_utsname);
	WRITE_SYMBOL("_stext", _stext);
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
	WRITE_MEMBER_OFFSET("zone.free_pages", zone.free_pages);
	WRITE_MEMBER_OFFSET("zone.free_area", zone.free_area);
	WRITE_MEMBER_OFFSET("zone.spanned_pages", zone.spanned_pages);
	WRITE_MEMBER_OFFSET("free_area.free_list", free_area.free_list);
	WRITE_MEMBER_OFFSET("list_head.next", list_head.next);
	WRITE_MEMBER_OFFSET("list_head.prev", list_head.prev);

	return TRUE;
}

int
read_config_basic_info(struct DumpInfo *info)
{
	unsigned long page_size;
	char buf[BUFSIZE_FGETS], *endp;
	unsigned int get_release = FALSE, i;

	if (fseek(info->file_configfile, 0, SEEK_SET) < 0) {
		ERRMSG("Can't seek the config file(%s). %s\n",
		    info->name_configfile, strerror(errno));
		return FALSE;
	}

	while (fgets(buf, BUFSIZE_FGETS, info->file_configfile)) {
		i = strlen(buf);
		if (buf[i - 1] == '\n')
			buf[i - 1] = '\0';
		if (strncmp(buf, STR_OSRELEASE, strlen(STR_OSRELEASE)) == 0) {
			strcpy(info->release, buf + strlen(STR_OSRELEASE));
			get_release = TRUE;
		}
		if (strncmp(buf, STR_PAGESIZE, strlen(STR_PAGESIZE)) == 0) {
			page_size = strtoul(buf+strlen(STR_PAGESIZE),&endp,10);
			if ((!page_size || page_size == ULONG_MAX)
			    || strlen(endp) != 0) {
				ERRMSG("Invalid data in %s: %s",
				    info->name_configfile, buf);
				return FALSE;
			}
			if (!is_page_size(page_size)) {
				ERRMSG("Invalid data in %s: %s",
				    info->name_configfile, buf);
				return FALSE;
			}
			info->page_size = page_size;
		}
		if (get_release && info->page_size)
			break;
	}
	if (!get_release || !info->page_size) {
		ERRMSG("Invalid format in %s", info->name_configfile);
		return FALSE;
	}
	return TRUE;
}

unsigned long
read_config_symbol(struct DumpInfo *info, char *str_symbol)
{
	unsigned long symbol = NOT_FOUND_SYMBOL;
	char buf[BUFSIZE_FGETS], *endp;
	unsigned int i;

	if (fseek(info->file_configfile, 0, SEEK_SET) < 0) {
		ERRMSG("Can't seek the config file(%s). %s\n",
		    info->name_configfile, strerror(errno));
		return INVALID_SYMBOL_DATA;
	}

	while (fgets(buf, BUFSIZE_FGETS, info->file_configfile)) {
		i = strlen(buf);
		if (buf[i - 1] == '\n')
			buf[i - 1] = '\0';
		if (strncmp(buf, str_symbol, strlen(str_symbol)) == 0) {
			symbol = strtoul(buf + strlen(str_symbol), &endp, 16);
			if ((!symbol || symbol == ULONG_MAX)
			    || strlen(endp) != 0) {
				ERRMSG("Invalid data in %s: %s",
				    info->name_configfile, buf);
				return INVALID_SYMBOL_DATA;
			}
			break;
		}
	}
	return symbol;
}

long
read_config_structure(struct DumpInfo *info, char *str_structure)
{
	long data = NOT_FOUND_STRUCTURE;
	char buf[BUFSIZE_FGETS], *endp;
	unsigned int i;

	if (fseek(info->file_configfile, 0, SEEK_SET) < 0) {
		ERRMSG("Can't seek the config file(%s). %s\n",
		    info->name_configfile, strerror(errno));
		return INVALID_STRUCTURE_DATA;
	}

	while (fgets(buf, BUFSIZE_FGETS, info->file_configfile)) {
		i = strlen(buf);
		if (buf[i - 1] == '\n')
			buf[i - 1] = '\0';
		if (strncmp(buf, str_structure, strlen(str_structure)) == 0) {
			data = strtol(buf + strlen(str_structure), &endp, 10);
			if ((data == LONG_MAX) || strlen(endp) != 0) {
				ERRMSG("Invalid data in %s: %s",
				    info->name_configfile, buf);
				return INVALID_STRUCTURE_DATA;
			}
			break;
		}
	}
	return data;
}

int
read_config(struct DumpInfo *info)
{
	if (!read_config_basic_info(info))
		return FALSE;

	READ_SYMBOL("mem_map", mem_map);
	READ_SYMBOL("mem_section", mem_section);
	READ_SYMBOL("pkmap_count", pkmap_count);
	READ_SYMBOL("pkmap_count_next", pkmap_count_next);
	READ_SYMBOL("system_utsname", system_utsname);
	READ_SYMBOL("_stext", _stext);
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

	READ_MEMBER_OFFSET("page.flags", page.flags);
	READ_MEMBER_OFFSET("page._count", page._count);
	READ_MEMBER_OFFSET("page.mapping", page.mapping);
	READ_MEMBER_OFFSET("page.lru", page.lru);
	READ_MEMBER_OFFSET("mem_section.section_mem_map",
	    mem_section.section_mem_map);
	READ_MEMBER_OFFSET("pglist_data.node_zones", pglist_data.node_zones);
	READ_MEMBER_OFFSET("zone.free_pages", zone.free_pages);
	READ_MEMBER_OFFSET("zone.free_area", zone.free_area);
	READ_MEMBER_OFFSET("zone.spanned_pages", zone.spanned_pages);
	READ_MEMBER_OFFSET("free_area.free_list", free_area.free_list);
	READ_MEMBER_OFFSET("list_head.next", list_head.next);
	READ_MEMBER_OFFSET("list_head.prev", list_head.prev);

	return TRUE;
}

void
dump_mem_map(struct DumpInfo *info, unsigned long pfn_start,
    unsigned long pfn_end, unsigned long mem_map, int num_mm)
{
	struct mem_map_data *mmd;

	mmd = &info->mem_map_data[num_mm];
	mmd->pfn_start = pfn_start;
	mmd->pfn_end   = pfn_end;
	mmd->mem_map   = mem_map;

	return;
}

int
get_mm_flatmem(struct DumpInfo *info)
{
	unsigned long addr_mem_map;

	/*
	 * Get the address of the symbol "mem_map".
	 */
	if (!readmem(info, SYMBOL(mem_map), &addr_mem_map, sizeof addr_mem_map)
	    || !addr_mem_map) {
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
	dump_mem_map(info, 0, info->max_mapnr, addr_mem_map, 0);

	return TRUE;
}

unsigned long
nr_to_section(struct DumpInfo *info, unsigned long nr, unsigned long *mem_sec)
{
	unsigned long addr;

	if (!is_kvaddr(mem_sec[SECTION_NR_TO_ROOT(nr)]))
		return NOT_KV_ADDR;

	if (is_sparsemem_extreme(info))
		addr = mem_sec[SECTION_NR_TO_ROOT(nr)] +
		    (nr & SECTION_ROOT_MASK()) * SIZE(mem_section);
	else
		addr = SYMBOL(mem_section) + (nr * SIZE(mem_section));

	if (!is_kvaddr(addr))
		return NOT_KV_ADDR;

	return addr;
}

unsigned long
section_mem_map_addr(struct DumpInfo *info, unsigned long addr)
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
	if (!readmem(info, addr, mem_section, SIZE(mem_section))) {
		ERRMSG("Can't get a struct mem_section.\n");
		return NOT_KV_ADDR;
	}
	map = ULONG(mem_section + OFFSET(mem_section.section_mem_map));
	map &= SECTION_MAP_MASK;
	free(mem_section);

	return map;
}

unsigned long
sparse_decode_mem_map(struct DumpInfo *info, ulong coded_mem_map,
    unsigned long section_nr)
{
	if (!is_kvaddr(coded_mem_map))
		return NOT_KV_ADDR;

	return coded_mem_map +
	    (SECTION_NR_TO_PFN(section_nr) * SIZE(page));
}

int
get_mm_sparsemem(struct DumpInfo *info)
{
	unsigned int section_nr, mem_section_size, num_section;
	unsigned long pfn_start, pfn_end;
	unsigned long addr_section, addr_mem_map;
	unsigned long *mem_sec = NULL;

	int ret = FALSE;

	/*
	 * Get the address of the symbol "mem_section".
	 */
	num_section = divideup(info->max_mapnr, PAGES_PER_SECTION());
	if (is_sparsemem_extreme(info)) {
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
	if (!readmem(info, SYMBOL(mem_section), mem_sec, mem_section_size)) {
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
		addr_section = nr_to_section(info, section_nr, mem_sec);
		addr_mem_map = section_mem_map_addr(info, addr_section);
		addr_mem_map = sparse_decode_mem_map(info, addr_mem_map, section_nr);
		if (!is_kvaddr(addr_mem_map))
			addr_mem_map = NOT_MEMMAP_ADDR;
		pfn_start = section_nr * PAGES_PER_SECTION();
		pfn_end   = pfn_start + PAGES_PER_SECTION();
		if (info->max_mapnr < pfn_end)
			pfn_end = info->max_mapnr;
		dump_mem_map(info, pfn_start, pfn_end, addr_mem_map, section_nr);
	}
	ret = TRUE;
out:
	if (mem_sec != NULL)
		free(mem_sec);

	return ret;
}

int
get_mem_map_without_mm(struct DumpInfo *info)
{
	info->num_mem_map = 1;
	if ((info->mem_map_data = (struct mem_map_data *)
	    malloc(sizeof(struct mem_map_data)*info->num_mem_map)) == NULL) {
		ERRMSG("Can't allocate memory for the mem_map_data. %s\n",
		    strerror(errno));
		return FALSE;
	}
	dump_mem_map(info, 0, info->max_mapnr, NOT_MEMMAP_ADDR, 0);

	return TRUE;
}

int
get_mem_map(struct DumpInfo *info)
{
	int ret;

	switch (get_mem_type(info)) {
	case SPARSEMEM:
		MSG("Memory type : SPARSEMEM\n");
		ret = get_mm_sparsemem(info);
		break;
	case FLATMEM:
		MSG("Memory type : FLATMEM\n");
		ret = get_mm_flatmem(info);
		break;
	default:
		ERRMSG("Can't distinguish the memory type.\n");
		ret = FALSE;
		break;
	}
	return ret;
}

int
initial(struct DumpInfo *info)
{
	if (!get_elf_info(info))
		return FALSE;

	if (!get_phys_base(info))
		return FALSE;

	if (!info->flag_read_config) {
		if (info->dump_level <= DL_EXCLUDE_ZERO) {
			if (!get_mem_map_without_mm(info))
				return FALSE;
			else
				return TRUE;
		} else {
			if (!get_symbol_info(info))
				return FALSE;
		}
		if (!check_release(info))
			return FALSE;
		if (!get_structure_info(info))
			return FALSE;
	} else {
		if (!read_config(info))
			return FALSE;
		if (!check_release(info))
			return FALSE;
	}
	if (!get_machdep_info(info))
		return FALSE;

	if (!get_mem_map(info))
		return FALSE;

	return TRUE;
}

static inline void
set_bitmap(char *bitmap, unsigned long pfn, int val)
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
is_dumpable(struct dump_bitmap *bitmap, unsigned long pfn)
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
is_memory_hole(struct dump_bitmap *bitmap, unsigned long pfn)
{
	return !is_dumpable(bitmap, pfn);
}

static inline int
is_in_segs(struct DumpInfo *info, unsigned long long paddr)
{
	if (paddr_to_offset(info, paddr))
		return TRUE;
	else
		return FALSE;
}

static inline int
is_zero_page(unsigned char *buf, size_t page_size)
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
write_cache(struct cache_data *cd, void *buf, size_t size)
{
	const off_t failed = (off_t)-1;

	memcpy(cd->buf + cd->buf_size, buf, size);
	cd->buf_size += size;

	if (cd->buf_size < cd->cache_size)
		return TRUE;

	if (lseek(cd->fd, cd->offset, SEEK_SET) == failed) {
		ERRMSG("Can't seek the dump file(%s). %s\n",
		    cd->file_name, strerror(errno));
		return FALSE;
	}
	if (write(cd->fd, cd->buf, cd->cache_size) != cd->cache_size) {
		ERRMSG("Can't write the dump file(%s). %s\n",
		    cd->file_name, strerror(errno));
		return FALSE;
	}

	cd->buf_size -= cd->cache_size;
	memcpy(cd->buf, cd->buf + cd->cache_size, cd->buf_size);
	cd->offset += cd->cache_size;
	return TRUE;
}

int
write_cache_bufsz(struct cache_data *cd)
{
	const off_t failed = (off_t)-1;

	if (!cd->buf_size)
		return TRUE;

	if (lseek(cd->fd, cd->offset, SEEK_SET) == failed) {
		ERRMSG("Can't seek the dump file(%s). %s\n",
		    cd->file_name, strerror(errno));
		return FALSE;
	}
	if (write(cd->fd, cd->buf, cd->buf_size) != cd->buf_size) {
		ERRMSG("Can't write the dump file(%s). %s\n",
		    cd->file_name, strerror(errno));
		return FALSE;
	}
	cd->offset  += cd->buf_size;
	cd->buf_size = 0;
	return TRUE;
}

int
create_contig_bitmap(struct DumpInfo *info)
{
	unsigned int i, remain_size, contig_exclude;
	unsigned int num_load_dumpfile;
	unsigned long pfn, last_pfn;
	int lastpage_mhole;
	struct cache_data bm2;
	struct dump_bitmap bitmap1, bitmap2;

	bm2.fd         = info->fd_bitmap;
	bm2.file_name  = info->name_bitmap;
	bm2.cache_size = BUFSIZE_BITMAP;
	bm2.buf_size   = 0;
	bm2.offset     = info->len_bitmap/2;
	bm2.buf        = NULL;

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

	if ((bm2.buf = calloc(1, BUFSIZE_BITMAP)) == NULL) {
		ERRMSG("Can't allocate memory for 2nd-bitmap buffer. %s\n",
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
	num_load_dumpfile = info->num_load_memory;

	for (pfn = 0, last_pfn = 0,
	    contig_exclude = 0; pfn < info->max_mapnr; pfn++) {
		if (is_memory_hole(&bitmap1, pfn)) {
			for (i = 0; i <= contig_exclude; i++) {
				if ((last_pfn+i) != 0
				    && (last_pfn+i)%PFN_BUFBITMAP == 0) {
					bm2.buf_size = BUFSIZE_BITMAP;
					if (!write_cache_bufsz(&bm2))
						goto out;
				}
				set_bitmap(bm2.buf,
				    (last_pfn+i)%PFN_BUFBITMAP, 0);
			}
			contig_exclude = 0;
			last_pfn = pfn+1;
			lastpage_mhole = 1;
			continue;
		}
		lastpage_mhole = 0;
		if (!is_dumpable(&bitmap2, pfn)) {
			contig_exclude++;
			continue;
		}
		for (i = 0; i <= contig_exclude; i++) {
			if ((last_pfn+i) != 0
			    && (last_pfn+i)%PFN_BUFBITMAP == 0) {
				bm2.buf_size = BUFSIZE_BITMAP;
				if (!write_cache_bufsz(&bm2))
					goto out;
			}
			if (contig_exclude < PFN_EXCLUDED)
				set_bitmap(bm2.buf,
				    (last_pfn+i)%PFN_BUFBITMAP, 1);
			else if (i == contig_exclude)
				set_bitmap(bm2.buf,
				    (last_pfn+i)%PFN_BUFBITMAP, 1);
			else
				set_bitmap(bm2.buf,
				    (last_pfn+i)%PFN_BUFBITMAP, 0);
		}
		if (contig_exclude >= PFN_EXCLUDED)
			num_load_dumpfile++;
		contig_exclude = 0;
		last_pfn = pfn+1;
	}
	if (contig_exclude)
		num_load_dumpfile++;

	for (i = 0; i <= contig_exclude; i++) {
		if ((last_pfn+i)%PFN_BUFBITMAP == 0) {
			bm2.buf_size = BUFSIZE_BITMAP;
			if (!write_cache_bufsz(&bm2))
				goto out;
		}
		set_bitmap(bm2.buf, (last_pfn+i)%PFN_BUFBITMAP, 0);
	}
	remain_size = info->len_bitmap - bm2.offset;
	bm2.buf_size = remain_size;
	if (!write_cache_bufsz(&bm2))
		goto out;

	info->num_load_dumpfile = num_load_dumpfile;

	free(bm2.buf);
	free(bitmap1.buf);
	free(bitmap2.buf);
	return TRUE;
out:
	if (bm2.buf != NULL)
		free(bm2.buf);
	if (bitmap1.buf != NULL)
		free(bitmap1.buf);
	if (bitmap2.buf != NULL)
		free(bitmap2.buf);
	return FALSE;
}

/*
 * Get the number of online nodes.
 */
int
get_nodes_online(struct DumpInfo *info)
{
	int len, i, j, online;
	unsigned long bitbuf, *maskptr;

	if (SYMBOL(node_online_map) == NOT_FOUND_SYMBOL)
		return 0;
	/*
	 * FIXME
	 * Size of node_online_map must be dynamically got from debugging
	 * information each architecture or each config.
	 */
	len = SIZEOF_NODE_ONLINE_MAP;
	if (!(vt->node_online_map = (unsigned long *)malloc(len))) {
		ERRMSG("Can't allocate memory for the node online map. %s\n",
		    strerror(errno));
		return 0;
	}
	if (!readmem(info, SYMBOL(node_online_map), vt->node_online_map, len)) {
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
next_online_node(first)
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
next_online_pgdat(struct DumpInfo *info, int node)
{
	unsigned long pgdat;
	/*
	 * node_data must be an array.
	 */
	if (SYMBOL(node_data) == NOT_FOUND_SYMBOL)
		goto pgdat2;
	if (!readmem(info, SYMBOL(node_data) + (node * sizeof(void *)),
	    &pgdat, sizeof pgdat))
		goto pgdat2;
	/*
	 * FIXME
	 * Must be able to check whether pgdat is kernel vertual address or not.
	 */
	return pgdat;

pgdat2:
	/*
	 * pgdat_list must be an array.
	 */
	if (SYMBOL(pgdat_list) == NOT_FOUND_SYMBOL)
		goto pgdat3;
	if (!readmem(info, SYMBOL(pgdat_list) + (node * sizeof(void *)),
	    &pgdat, sizeof pgdat))
		goto pgdat3;
	return pgdat;

pgdat3:
	if (SYMBOL(contig_page_data) == NOT_FOUND_SYMBOL)
		return FALSE;
	if (node != 0)
		return FALSE;
	return SYMBOL(contig_page_data);
}

unsigned long
page_to_pfn(struct DumpInfo *info, unsigned long page)
{
	unsigned int num;
	unsigned long pfn = 0;
	struct mem_map_data *mmd;
	unsigned long index;

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
		return ULONG_MAX;
	}
	return pfn;
}

int
reset_3rd_bitmap(struct DumpInfo *info, unsigned long pfn)
{
	off_t offset_pfn;
	unsigned int buf_size;
	struct cache_data *bm3 = info->bm3;

	offset_pfn  = (pfn / PFN_BUFBITMAP) * BUFSIZE_BITMAP;
	bm3->offset = offset_pfn;
	buf_size    = info->len_3rd_bitmap - bm3->offset;
	if (buf_size >= BUFSIZE_BITMAP) {
		bm3->cache_size = BUFSIZE_BITMAP;
		bm3->buf_size   = BUFSIZE_BITMAP;
	} else {
		bm3->cache_size = buf_size;
		bm3->buf_size   = buf_size;
	}

	if (!read_cache(bm3))
		return FALSE;

	set_bitmap(bm3->buf, pfn%PFN_BUFBITMAP, 0);

	bm3->offset = offset_pfn;
	if (!write_cache_bufsz(bm3))
		return FALSE;

	return TRUE;
}

int
reset_bitmap_of_free_pages(struct DumpInfo *info, unsigned long node_zones)
{

	int order, free_page_cnt = 0, i;
	unsigned long curr, previous, head, curr_page, curr_prev, start_pfn,
		pfn, free_pages;

	for (order = MAX_ORDER - 1; order >= 0; --order) {
		head = node_zones + OFFSET(zone.free_area)
			+ SIZE(free_area) * order + OFFSET(free_area.free_list);
		previous = head;
		if (!readmem(info, head + OFFSET(list_head.next), &curr,
		    sizeof curr)) {
			ERRMSG("Can't get next list_head.\n");
			return FALSE;
		}
		for (;curr != head;) {
			curr_page = curr - OFFSET(page.lru);
			start_pfn = page_to_pfn(info, curr_page);
			if (start_pfn == ULONG_MAX)
				return FALSE;

			if (!readmem(info, curr + OFFSET(list_head.prev),
			    &curr_prev, sizeof curr_prev)) {
				ERRMSG("Can't get prev list_head.\n");
				return FALSE;
			}
			if (previous != curr_prev) {
				retcd = ANALYSIS_FAILED;
				return FALSE;
			}
			for (i = 0; i < (1<<order); i++) {
				pfn = start_pfn + i;
				reset_3rd_bitmap(info, pfn);
			}
			free_page_cnt += i;

			previous=curr;
			if (!readmem(info, curr + OFFSET(list_head.next), &curr,
			    sizeof curr)) {
				ERRMSG("Can't get next list_head.\n");
				return FALSE;
			}
		}
	}

	/*
	 * Check the number of free pages.
	 */
	if (!readmem(info, node_zones + OFFSET(zone.free_pages), &free_pages,
	    sizeof free_pages)) {
		ERRMSG("Can't get free_pages.\n");
		return FALSE;
	}
	if (free_pages != free_page_cnt) {
		retcd = ANALYSIS_FAILED;
		return FALSE;
	}
	return TRUE;
}

int
dump_memory_nodes(struct DumpInfo *info)
{
	int i, num_nodes, node;
	unsigned long node_zones, zone, spanned_pages, pgdat;

	/*
	 * In case that (vt->flags & NODES_ONLINE) is 1.
	 */
	if ((node = next_online_node(0)) < 0) {
		ERRMSG("Can't get next online node.\n");
		return FALSE;
	}
	if (!(pgdat = next_online_pgdat(info, node))) {
		ERRMSG("Can't get pgdat list.\n");
		return FALSE;
	}
	for (num_nodes = 1;; num_nodes++) {
		if (num_nodes > vt->numnodes) {
			ERRMSG("numnodes out of sync with pgdat_list\n");
			return FALSE;
		}
		node_zones = pgdat + OFFSET(pglist_data.node_zones);
		for (i = 0; i < MAX_NR_ZONES; i++) {
			zone = node_zones + (i * SIZE(zone));
			if (!readmem(info, zone + OFFSET(zone.spanned_pages),
			    &spanned_pages, sizeof spanned_pages)) {
				ERRMSG("Can't get spanned_pages.\n");
				return FALSE;
			}
			if (!spanned_pages)
				continue;
			if (!reset_bitmap_of_free_pages(info, zone))
				return FALSE;
		}
		if (vt->flags & NODES_ONLINE) {
			if ((node = next_online_node(node + 1)) < 0)
				break;
			else if (!(pgdat = next_online_pgdat(info, node))) {
				ERRMSG("Can't determine pgdat list (node %d).\n",
				    node);
				return FALSE;
			}
		}
	}
	if (num_nodes != vt->numnodes) {
		ERRMSG("numnodes out of sync with pgdat_list\n");
		return FALSE;
	}
	/*
	 * Flush the 3rd bit map.
	 * info->bm3->buf_size is set at reset_3rd_bitmap().
	 */
	info->bm3->offset  -= info->bm3->buf_size;
	if (!write_cache_bufsz(info->bm3))
		return FALSE;
	return TRUE;
}

int
_exclude_free_page(struct DumpInfo *info)
{
	if ((vt->numnodes = get_nodes_online(info))) {
		vt->flags |= NODES_ONLINE;
	} else {
		vt->numnodes = 1;
	}
	/*
	 * FIXME
	 * Array length of zone.free_area must be dynamically got
	 * each architecture or each config.
	 */
	vt->nr_free_areas = MAX_ORDER;

	if (!dump_memory_nodes(info))
		return FALSE;
	return TRUE;
}

int
cp_cache(struct cache_data *source, struct cache_data *dest, int size)
{
	while (size > 0) {
		if (size >= BUFSIZE_BITMAP) {
			source->cache_size = BUFSIZE_BITMAP;
			dest->cache_size = BUFSIZE_BITMAP;
		} else {
			source->cache_size = size;
			dest->cache_size = size;
		}
		dest->buf_size = 0;

		if(!read_cache(source)) {
			ERRMSG("Can't read the dump cache file(%s). %s\n",
			    source->file_name, strerror(errno));
			return FALSE;
		}
		if(!write_cache(dest, source->buf, source->cache_size)) {
			ERRMSG("Can't write the dump cache file(%s). %s\n",
			    dest->file_name, strerror(errno));
			return FALSE;
		}

		size -= BUFSIZE_BITMAP;
	}
	return TRUE;
}

int
exclude_free_page(struct DumpInfo *info, struct cache_data *bm2, struct cache_data *bm3)
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
	    || (OFFSET(zone.free_pages) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(zone.free_area) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(zone.spanned_pages) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(pglist_data.node_zones) == NOT_FOUND_STRUCTURE)
	    || (SIZE(free_area) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(free_area.free_list) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(list_head.next) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(list_head.prev) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(page.lru) == NOT_FOUND_STRUCTURE)) {
		ERRMSG("Can't get necessary structures for excluding free pages.\n");
		return FALSE;
	}

	/*
	 * Copy bitmap2 to bitmap3.
	 */
	info->bm3 = bm3;
	bm2->offset = info->len_bitmap / 2;
	bm3->offset = 0;
	if (!cp_cache(bm2, bm3, info->len_bitmap / 2))
		return FALSE;

	/*
	 * Update bitmap3.
	 */
	if (!_exclude_free_page(info))
		return FALSE;

	/*
	 * Write back bitmap3 to bitmap2.
	 */
	bm2->offset = info->len_bitmap / 2;
	bm3->offset = 0;
	if (!cp_cache(bm3, bm2, info->len_bitmap / 2))
		return FALSE;
	return TRUE;
}

int
create_dump_bitmap(struct DumpInfo *info)
{
	int val, not_found_mem_map;
	unsigned int i, mm, remain_size;
	unsigned long pfn, addr_mem_map, paddr;
	unsigned char *page_cache = NULL, *buf = NULL, *pcache;
	unsigned int _count;
	unsigned long flags, mapping;
	struct cache_data bm1, bm2, bm3;
	struct mem_map_data *mmd;
	off_t offset_page;
	const off_t failed = (off_t)-1;

	int ret = FALSE;

	offset_page  = info->offset_load_memory;

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

	bm3.fd         = info->fd_3rd_bitmap;
	bm3.file_name  = info->name_3rd_bitmap;
	bm3.cache_size = BUFSIZE_BITMAP;
	bm3.buf_size   = 0;
	bm3.offset     = 0;
	bm3.buf        = NULL;

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
	if (info->flag_exclude_free
	    && (bm3.buf = calloc(1, BUFSIZE_BITMAP)) == NULL) {
		ERRMSG("Can't allocate memory for 3rd-bitmap buffer. %s\n",
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
		addr_mem_map = mmd->mem_map;

		if (addr_mem_map == NOT_MEMMAP_ADDR)
			not_found_mem_map = TRUE;
		else
			not_found_mem_map = FALSE;

		for (; pfn < mmd->pfn_end;
		    pfn++, addr_mem_map += SIZE(page),
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
			if (!is_in_segs(info, paddr))
				val = 0;

			/*
			 * Set the 1st-bitmap.
			 *  val  1: not memory hole
			 *       0: memory hole
			 */
			set_bitmap(bm1.buf, pfn%PFN_BUFBITMAP, val);

			/*
			 * Exclude the page filled with zero in case of creating
			 * the elf dumpfile.
			 */
			if (info->flag_elf_dumpfile
			    && (val != 0)
			    && (info->dump_level & DL_EXCLUDE_ZERO)) {
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
				offset_page += info->page_size;
				if (is_zero_page(buf, info->page_size))
					val = 0;
			}
			if ((info->dump_level <= DL_EXCLUDE_ZERO)
			    || not_found_mem_map) {
				set_bitmap(bm2.buf, pfn%PFN_BUFBITMAP, val);
				continue;
			}

			if ((pfn % PGMM_CACHED) == 0) {
				if (!readmem(info, addr_mem_map, page_cache,
				    SIZE(page) * PGMM_CACHED))
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
		if (!exclude_free_page(info, &bm2, &bm3))
			goto out;

	if (info->flag_elf_dumpfile)
		if (!create_contig_bitmap(info))
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
	if (bm3.buf != NULL)
		free(bm3.buf);

	return ret;
}

int
write_elf_header(struct DumpInfo *info)
{
	int i, lastpage_dumpable;
	size_t size_hdr_memory, size_Ehdr, size_Phdr, size_note;
	unsigned long pfn, pfn_start, pfn_end, num_file, num_mem;
	loff_t offset_seg, offset_note_memory, offset_note_dumpfile;
	unsigned long long  vaddr_seg, paddr_seg;
	unsigned char *header_memory = NULL;
	Elf32_Ehdr *elf32;
	Elf64_Ehdr *elf64;
	Elf32_Phdr *note32;
	Elf64_Phdr *note64;
	Elf32_Phdr *load32 = NULL;
	Elf64_Phdr *load64 = NULL;
	char *buf = NULL;
	struct pt_load_segment *pls;
	struct dump_bitmap bitmap2;
	const off_t failed = (off_t)-1;

	int ret = FALSE;

	size_hdr_memory = info->offset_load_memory;

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
	if ((header_memory = calloc(1, size_hdr_memory)) == NULL) {
		ERRMSG("Can't allocate memory for the ELF header. %s\n",
		    strerror(errno));
		goto out;
	}
	if (lseek(info->fd_memory, 0, SEEK_SET) == failed) {
		ERRMSG("Can't seek the dump memory(%s). %s\n",
		    info->name_memory, strerror(errno));
		goto out;
	}
	if (read(info->fd_memory, header_memory, size_hdr_memory)
	    != size_hdr_memory) {
		ERRMSG("Can't read the dump memory(%s). %s\n",
		    info->name_memory, strerror(errno));
		goto out;
	}

	/*
	 * ELF header & PT_NOTE header
	 */
	if (lseek(info->fd_dumpfile, 0, SEEK_SET) == failed) {
		ERRMSG("Can't seek the dump file(%s). %s\n",
		    info->name_dumpfile, strerror(errno));
		goto out;
	}
	if (info->flag_elf & ELF32) {
		size_Ehdr = sizeof(Elf32_Ehdr);
		size_Phdr = sizeof(Elf32_Phdr);
		elf32  = (Elf32_Ehdr *)header_memory;
		elf32->e_phnum = 1 + info->num_load_dumpfile;
		if (write(info->fd_dumpfile, elf32, size_Ehdr) != size_Ehdr) {
			ERRMSG("Can't write the dump file(%s). %s\n",
			    info->name_dumpfile, strerror(errno));
			goto out;
		}
		note32 = (Elf32_Phdr *)(header_memory + size_Ehdr);
		size_note = note32->p_filesz;
		offset_note_memory   = note32->p_offset;
		offset_note_dumpfile = size_Ehdr + size_Phdr * elf32->e_phnum;
		note32->p_offset     = offset_note_dumpfile;
		if (write(info->fd_dumpfile, note32, size_Phdr) != size_Phdr) {
			ERRMSG("Can't write the dump file(%s). %s\n",
			    info->name_dumpfile, strerror(errno));
			goto out;
		}
	} else {
		size_Ehdr = sizeof(Elf64_Ehdr);
		size_Phdr = sizeof(Elf64_Phdr);
		elf64  = (Elf64_Ehdr *)header_memory;
		elf64->e_phnum = 1 + info->num_load_dumpfile;
		if (write(info->fd_dumpfile, elf64, size_Ehdr) != size_Ehdr) {
			ERRMSG("Can't write the dump file(%s). %s\n",
			    info->name_dumpfile, strerror(errno));
			goto out;
		}
		note64 = (Elf64_Phdr *)(header_memory + size_Ehdr);
		size_note = note64->p_filesz;
		offset_note_memory   = note64->p_offset;
		offset_note_dumpfile = size_Ehdr + size_Phdr * elf64->e_phnum;
		note64->p_offset     = offset_note_dumpfile;
		if (write(info->fd_dumpfile, note64, size_Phdr) != size_Phdr) {
			ERRMSG("Can't write the dump file(%s). %s\n",
			    info->name_dumpfile, strerror(errno));
			goto out;
		}
	}
	info->offset_load_dumpfile = offset_note_dumpfile + size_note;

	/*
	 * PT_LOAD header
	 */
	if (info->flag_elf & ELF32) {
		if ((load32 = malloc(size_Phdr)) == NULL) {
			ERRMSG("Can't allocate memory for PT_LOAD header. %s\n",
			    strerror(errno));
			goto out;
		}
		load32->p_type   = PT_LOAD;
		load32->p_flags  = 0;
		load32->p_offset = 0;
		load32->p_vaddr  = 0;
		load32->p_paddr  = 0;
		load32->p_filesz = 0;
		load32->p_memsz  = 0;
		load32->p_align  = 0;
	} else {
		if ((load64 = malloc(size_Phdr)) == NULL) {
			ERRMSG("Can't allocate memory for PT_LOAD header. %s\n",
			    strerror(errno));
			goto out;
		}
		load64->p_type   = PT_LOAD;
		load64->p_flags  = 0;
		load64->p_offset = 0;
		load64->p_vaddr  = 0;
		load64->p_paddr  = 0;
		load64->p_filesz = 0;
		load64->p_memsz  = 0;
	}
	offset_seg = info->offset_load_dumpfile;

	for (i = 0, num_mem = 0, num_file = 0;
	    i < info->num_load_memory; i++) {
		pls = &info->pt_load_segments[i];
		paddr_seg = pls->phys_start;
		vaddr_seg = pls->virt_start;
		if (info->flag_elf & ELF32) {
			load32->p_vaddr  = vaddr_seg;
			load32->p_paddr  = paddr_seg;
			load32->p_offset = offset_seg;
		} else {
			load64->p_vaddr  = vaddr_seg;
			load64->p_paddr  = paddr_seg;
			load64->p_offset = offset_seg;
		}
		if (pls->phys_start == 0)
			pfn_start = 0;
		else
			pfn_start = pls->phys_start/info->page_size;

		if (pls->phys_end == 0)
			pfn_end = 0;
		else
			pfn_end = pls->phys_end/info->page_size;

		if (is_dumpable(&bitmap2, pfn_start)) {
			lastpage_dumpable = 1;
			num_mem  = 1;
			num_file = 1;
		} else {
			lastpage_dumpable = 0;
			num_mem  = 1;
			num_file = 0;
		}
		for (pfn = pfn_start + 1; pfn < pfn_end; pfn++) {
			if (!is_dumpable(&bitmap2, pfn)) {
				num_mem++;
				lastpage_dumpable = 0;
				continue;
			}
			if (lastpage_dumpable) {
				num_mem++;
				num_file++;
				continue;
			}
			/*
			 * Create new PT_LOAD segment.
			 */
			if (info->flag_elf & ELF32) {
				load32->p_memsz  = info->page_size*num_mem;
				load32->p_filesz = info->page_size*num_file;
				if (write(info->fd_dumpfile, load32, size_Phdr)
				    != size_Phdr) {
					ERRMSG("Can't write the dump file(%s). %s\n",
					    info->name_dumpfile, strerror(errno));
					goto out;
				}
				offset_seg += load32->p_filesz;
				if (load32->p_paddr < MAXMEM)
					load32->p_vaddr += load32->p_memsz;
				load32->p_paddr += load32->p_memsz;
				load32->p_offset = offset_seg;
			} else {
				load64->p_memsz  = info->page_size*num_mem;
				load64->p_filesz = info->page_size*num_file;
				if (write(info->fd_dumpfile, load64, size_Phdr)
				    != size_Phdr) {
					ERRMSG("Can't write the dump file(%s). %s\n",
					    info->name_dumpfile, strerror(errno));
					goto out;
				}
				offset_seg += load64->p_filesz;
				if (load64->p_paddr < MAXMEM)
					load64->p_vaddr += load64->p_memsz;
				load64->p_paddr += load64->p_memsz;
				load64->p_offset = offset_seg;
			}
			num_mem  = 1;
			num_file = 1;
			lastpage_dumpable = 1;
		}
		if (info->flag_elf & ELF32) {
			load32->p_memsz  = info->page_size*num_mem;
			load32->p_filesz = info->page_size*num_file;
			if (write(info->fd_dumpfile, load32, size_Phdr)
			    != size_Phdr) {
				ERRMSG("Can't write the dump file(%s). %s\n",
				    info->name_dumpfile, strerror(errno));
				goto out;
			}
			offset_seg += load32->p_filesz;
		} else {
			load64->p_memsz  = info->page_size*num_mem;
			load64->p_filesz = info->page_size*num_file;
			if (write(info->fd_dumpfile, load64, size_Phdr)
			    != size_Phdr) {
				ERRMSG("Can't write the dump file(%s). %s\n",
				    info->name_dumpfile, strerror(errno));
				goto out;
			}
			offset_seg += load64->p_filesz;
		}
	}
	/*
	 * Write PT_NOTE segment.
	 */
	if ((buf = malloc(size_note)) == NULL) {
		ERRMSG("Can't allocate memory for the ELF header. %s\n",
		    strerror(errno));
		goto out;
	}
	if (lseek(info->fd_memory, offset_note_memory, SEEK_SET) == failed) {
		ERRMSG("Can't seek the dump memory(%s). %s\n",
		    info->name_memory, strerror(errno));
		goto out;
	}
	if (lseek(info->fd_dumpfile, offset_note_dumpfile, SEEK_SET)
	    == failed) {
		ERRMSG("Can't seek the dump file(%s). %s\n",
		    info->name_dumpfile, strerror(errno));
		goto out;
	}
	if (read(info->fd_memory, buf, size_note) != size_note) {
		ERRMSG("Can't read the dump memory(%s). %s\n",
		    info->name_memory, strerror(errno));
		goto out;
	}
	if (write(info->fd_dumpfile, buf, size_note) != size_note) {
		ERRMSG("Can't write the dump file(%s). %s\n",
		    info->name_dumpfile, strerror(errno));
		goto out;
	}

	ret = TRUE;
out:
	if (bitmap2.buf != NULL)
		free(bitmap2.buf);
	if (header_memory != NULL)
		free(header_memory);
	if (load32 != NULL)
		free(load32);
	if (load64 != NULL)
		free(load64);
	if (buf != NULL)
		free(buf);

	return ret;
}

int
write_diskdump_header(struct DumpInfo *info)
{
	size_t size;
	struct disk_dump_header *dh = info->dump_header;
	struct kdump_sub_header sub_dump_header;
	const off_t failed = (off_t)-1;

	/*
	 * Write common header
	 */
	strcpy(dh->signature, KDUMP_SIGNATURE);
	dh->block_size   = info->page_size;
	dh->sub_hdr_size = 1;
	dh->max_mapnr    = info->max_mapnr;
	dh->nr_cpus      = 1;
	dh->bitmap_blocks
	    = divideup(info->len_bitmap, dh->block_size);

	if (lseek(info->fd_dumpfile, 0, SEEK_SET) == failed) {
		ERRMSG("Can't seek the dump file(%s). %s\n",
		    info->name_dumpfile, strerror(errno));
		return FALSE;
	}
	size = sizeof(struct disk_dump_header);
	if (write(info->fd_dumpfile, dh, size) != size) {
		ERRMSG("Can't write the dump file(%s). %s\n",
		    info->name_dumpfile, strerror(errno));
		return FALSE;
	}

	/*
	 * Write sub header
	 */
	sub_dump_header.phys_base = info->phys_base;
	if (lseek(info->fd_dumpfile, dh->block_size, SEEK_SET) == failed) {
		ERRMSG("Can't seek the dump file(%s). %s\n",
		    info->name_dumpfile, strerror(errno));
		return FALSE;
	}
	size = sizeof(struct kdump_sub_header);
	if (write(info->fd_dumpfile, &sub_dump_header, size) != size) {
		ERRMSG("Can't write the dump file(%s). %s\n",
		    info->name_dumpfile, strerror(errno));
		return FALSE;
	}

	info->offset_bitmap1
	    = (1 + dh->sub_hdr_size) * dh->block_size;

	return TRUE;
}

int
write_dump_header(struct DumpInfo *info)
{
	if (info->flag_elf_dumpfile) {
		if (!write_elf_header(info))
			return FALSE;
	} else {
		if (!write_diskdump_header(info))
			return FALSE;
	}
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

	ERRMSG("\r");
	ERRMSG("[%3d %%]", progress);
}

int
write_pages(struct DumpInfo *info)
{
	unsigned int flag_change_bitmap = 0;
 	unsigned long pfn, per, num_dumpable = 0, num_dumped = 0;
	unsigned long size_out;
	struct page_desc pd;
	off_t offset_data = 0, offset_memory = 0;
	struct disk_dump_header *dh = info->dump_header;
	unsigned char *buf = NULL, *buf_out = NULL;
	struct cache_data bm2, pdesc, pdata;
	struct dump_bitmap bitmap1, bitmap2;
	const off_t failed = (off_t)-1;

	int ret = FALSE;

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
	if ((buf_out = malloc(info->page_size)) == NULL) {
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
	for (pfn = 0 ; pfn < dh->max_mapnr; pfn++) {
		if (is_dumpable(&bitmap2, pfn))
			num_dumpable++;
	}
	per = num_dumpable / 100;

	if (info->flag_elf_dumpfile) {
		pdata.offset = info->offset_load_dumpfile;
	} else {
		/*
		 * Calculate the offset of the page data.
		 */
		pdesc.offset
		    = (1 + dh->sub_hdr_size + dh->bitmap_blocks)*dh->block_size;
		pdata.offset = pdesc.offset + sizeof(page_desc_t)*num_dumpable;
		offset_data  = pdata.offset;
	}
	/*
	 * Set a fileoffset of Physical Address 0x0.
	 */
	if (lseek(info->fd_memory, info->offset_load_memory, SEEK_SET)
	    == failed) {
		ERRMSG("Can't seek the dump memory(%s). %s\n",
		    info->name_memory, strerror(errno));
		goto out;
	}

	for (pfn = 0; pfn < info->max_mapnr; pfn++) {

		if ((num_dumped % per) == 0)
			print_progress(num_dumped, num_dumpable);

		if ((pfn % PFN_BUFBITMAP) == 0) {
			if (flag_change_bitmap) {
				bm2.buf_size = BUFSIZE_BITMAP;
				bm2.offset  -= BUFSIZE_BITMAP;
				if (!write_cache_bufsz(&bm2))
					goto out;
			}
			if (info->len_bitmap - bm2.offset < BUFSIZE_BITMAP)
				bm2.cache_size = info->len_bitmap - bm2.offset;
			if (!read_cache(&bm2))
				goto out;
			flag_change_bitmap = 0;
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

		offset_memory = paddr_to_offset(info, info->page_size*pfn);
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

		if (info->flag_elf_dumpfile) {
			pd.size = info->page_size;
		} else {
			/*
			 * Exclude the page filled with zeros.
			 * In case of the elf dumpfile, the zero page had been
			 * checked.
			 */
			if ((info->dump_level & DL_EXCLUDE_ZERO)
			    && is_zero_page(buf, info->page_size)) {
				set_bitmap(bm2.buf, pfn%PFN_BUFBITMAP, 0);
				flag_change_bitmap = 1;
				continue;
			}
			/*
			 * Compress the page data.
			 */
			size_out = info->page_size;
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
		}
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

	if (!info->flag_elf_dumpfile) {
		if (!write_cache_bufsz(&pdesc))
			goto out;
		if (flag_change_bitmap) {
			bm2.buf_size = BUFSIZE_BITMAP;
			bm2.offset  -= BUFSIZE_BITMAP;
			if (!write_cache_bufsz(&bm2))
				goto out;
		}
	}
	/*
	 * Print the progress of the end.
	 */
	print_progress(num_dumpable, num_dumpable);

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

int write_dump_bitmap(struct DumpInfo *info)
{
	struct cache_data bm;
	long buf_size;
	const off_t failed = (off_t)-1;

	int ret = FALSE;

	if (info->flag_elf_dumpfile)
		return TRUE;

	bm.fd        = info->fd_bitmap;
	bm.file_name = info->name_bitmap;
	bm.offset    = 0;
	bm.buf       = NULL;

	if ((bm.buf = calloc(1, BUFSIZE_BITMAP)) == NULL) {
		ERRMSG("Can't allocate memory for dump bitmap buffer. %s\n",
		    strerror(errno));
		goto out;
	}
	if (lseek(info->fd_dumpfile, info->offset_bitmap1, SEEK_SET)
	    == failed) {
		ERRMSG("Can't seek the dump file(%s). %s\n",
		    info->name_dumpfile, strerror(errno));
		goto out;
	}
	buf_size = info->len_bitmap;

	while (buf_size > 0) {
		if (buf_size >= BUFSIZE_BITMAP)
			bm.cache_size = BUFSIZE_BITMAP;
		else
			bm.cache_size = buf_size;

		if(!read_cache(&bm))
			goto out;

		if (write(info->fd_dumpfile, bm.buf, bm.cache_size)
		    != bm.cache_size) {
			ERRMSG("Can't write the dump file(%s). %s\n",
			    info->name_dumpfile, strerror(errno));
			goto out;
		}
		buf_size -= BUFSIZE_BITMAP;
	}
	ret = TRUE;
out:
	if (bm.buf != NULL)
		free(bm.buf);

	return ret;
}

void
close_config_file(struct DumpInfo *info)
{
	if(fclose(info->file_configfile) < 0)
		ERRMSG("Can't close the config file(%s). %s\n",
		    info->name_configfile, strerror(errno));
}

void
close_dump_memory(struct DumpInfo *info)
{
	if ((info->fd_memory = close(info->fd_memory)) < 0)
		ERRMSG("Can't close the dump memory(%s). %s\n",
		    info->name_memory, strerror(errno));
}

void
close_dump_file(struct DumpInfo *info)
{
	if ((info->fd_dumpfile = close(info->fd_dumpfile)) < 0)
		ERRMSG("Can't close the dump file(%s). %s\n",
		    info->name_dumpfile, strerror(errno));
}

void
close_3rd_bitmap(struct DumpInfo *info)
{
	if ((info->fd_3rd_bitmap = close(info->fd_3rd_bitmap)) < 0)
		ERRMSG("Can't close the bitmap file(%s). %s\n",
		    info->name_3rd_bitmap, strerror(errno));
	free(info->name_3rd_bitmap);
}

void
close_dump_bitmap(struct DumpInfo *info)
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
 * Close the following files when it generates the configuration file.
 * - vmlinux
 * - system.map
 * - configuration file
 */
int
close_files_for_generating_configfile(struct DumpInfo *info)
{
	close_kernel_file();

	close_config_file(info);

	return TRUE;
}

/*
 * Close the following files when it creates the dump file.
 * - dump mem
 * - dump file
 * - bit map
 * if it reads the configuration file
 *   - configuration file
 * else
 *   - vmlinux
 *   - system.map
 */
int
close_files_for_creating_dumpfile(struct DumpInfo *info)
{
	if (info->flag_read_config)
		close_config_file(info);
	else if (info->dump_level > DL_EXCLUDE_ZERO)
		close_kernel_file();

	close_dump_memory(info);

	close_dump_file(info);

	close_dump_bitmap(info);

	if (info->flag_exclude_free)
		close_3rd_bitmap(info);

	return TRUE;
}

int
main(int argc, char *argv[])
{
	int opt;
	struct DumpInfo *info = NULL;

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

	while ((opt = getopt(argc, argv, "b:cd:Eg:i:vx:")) != -1) {
		switch (opt) {
		case 'b':
			info->block_order = atoi(optarg);
			break;
		case 'c':
			info->flag_compress = 1;
			break;
		case 'd':
			info->dump_level = atoi(optarg);
			if (info->dump_level & DL_EXCLUDE_FREE)
				info->flag_exclude_free = 1;
			break;
		case 'E':
			info->flag_elf_dumpfile = 1;
			break;
		case 'g':
			info->flag_generate_config = 1;
			info->name_configfile = optarg;
			break;
		case 'i':
			info->flag_read_config = 1;
			info->name_configfile = optarg;
			break;
		case 'v':
			info->flag_show_version = 1;
			break;
		case 'x':
			info->flag_vmlinux = 1;
			dwarf_info.vmlinux_name = optarg;
			break;
		case '?':
			ERRMSG("Commandline parameter is invalid.\n");
			print_usage();
			goto out;
		}
	}
	if (info->flag_show_version) {
		show_version();
		return COMPLETED;
	}
	if (info->flag_generate_config) {
		/*
		 * generate the configuration file
		 */
		if (argc != optind) {
			ERRMSG("Commandline parameter is invalid.\n");
			print_usage();
			goto out;
		}
		if (info->flag_compress || info->dump_level
		    || info->flag_elf_dumpfile || info->flag_read_config
		    || !info->flag_vmlinux) {
			ERRMSG("Commandline parameter is invalid.\n");
			print_usage();
			goto out;
		}
	} else if (info->flag_read_config) {
		/*
		 * check parameters to read the configuration file
		 */
		if ((info->dump_level < MIN_DUMP_LEVEL)
		    || (MAX_DUMP_LEVEL < info->dump_level)) {
			ERRMSG("Dump_level is invalid.\n");
			print_usage();
			goto out;
		}
		if ((argc != optind + 2)
		    || (info->flag_compress && info->flag_elf_dumpfile)
		    || info->flag_vmlinux) {
			ERRMSG("Commandline parameter is invalid.\n");
			print_usage();
			goto out;
		}
		info->name_memory   = argv[optind];
		info->name_dumpfile = argv[optind+1];
	} else {
		if ((info->dump_level < MIN_DUMP_LEVEL)
		    || (MAX_DUMP_LEVEL < info->dump_level)) {
			ERRMSG("Dump_level is invalid.\n");
			print_usage();
			goto out;
		}
		if ((argc != optind + 2)
		    || (info->flag_compress && info->flag_elf_dumpfile)) {
			ERRMSG("Commandline parameter is invalid.\n");
			print_usage();
			goto out;
		}
		info->name_memory   = argv[optind];
		info->name_dumpfile = argv[optind+1];
	}

	if (elf_version(EV_CURRENT) == EV_NONE ) {
		/*
		 * library out of date
		 */
		ERRMSG("Elf library out of date!n");
		goto out;
	}
	if (info->flag_generate_config) {
		if (!open_files_for_generating_configfile(info))
			goto out;

		if (!generate_config(info))
			goto out;

		if (!close_files_for_generating_configfile(info))
			goto out;

		MSG("\n");
		MSG("The configfile is saved to %s.\n", info->name_configfile);
	} else {
		if (!open_files_for_creating_dumpfile(info))
			goto out;

		if (!initial(info))
			goto out;

		if (!create_dump_bitmap(info))
			goto out;

		if (!write_dump_header(info))
			goto out;

		if (!write_pages(info))
			goto out;

		if (!write_dump_bitmap(info))
			goto out;

		if (!close_files_for_creating_dumpfile(info))
			goto out;

		MSG("\n");
		MSG("The dumpfile is saved to %s.\n", info->name_dumpfile);
	}
	retcd = COMPLETED;
out:
	ERRMSG("\n");
	if (retcd == COMPLETED)
		MSG("makedumpfile Completed.\n");
	else
		ERRMSG("makedumpfile Failed.\n");

	if (info->fd_memory)
		close(info->fd_memory);
	if (info->fd_dumpfile)
		close(info->fd_dumpfile);
	if (info->fd_bitmap)
		close(info->fd_bitmap);
	if (info->fd_3rd_bitmap)
		close(info->fd_3rd_bitmap);
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
