/*
 * dwarf_info.c
 *
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
#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>
#include <dwarf.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#include "common.h"
#include "print_info.h"
#include "dwarf_info.h"

/*
 * Debugging information
 */
#define DEFAULT_DEBUGINFO_PATH	"/usr/lib/debug"

struct dwarf_info {
	unsigned int	cmd;		/* IN */
	int	fd_debuginfo;		/* IN */
	char	*name_debuginfo;	/* IN */
	char	*module_name;		/* IN */
	char	*struct_name;		/* IN */
	char	*symbol_name;		/* IN */
	char	*member_name;		/* IN */
	char	*enum_name;		/* IN */
	Elf	*elfd;			/* OUT */
	Dwarf	*dwarfd;		/* OUT */
	Dwfl	*dwfl;			/* OUT */
	char	*type_name;		/* OUT */
	long	struct_size;		/* OUT */
	long	member_offset;		/* OUT */
	long	array_length;		/* OUT */
	long	enum_number;		/* OUT */
	unsigned char	type_flag;	/* OUT */
	char	src_name[LEN_SRCFILE];	/* OUT */
	Dwarf_Off die_offset;		/* OUT */
};
static struct dwarf_info	dwarf_info = {
	.fd_debuginfo = -1,
};


/*
 * Internal functions.
 */
static int
is_search_structure(int cmd)
{
	if ((cmd == DWARF_INFO_GET_STRUCT_SIZE)
	    || (cmd == DWARF_INFO_GET_MEMBER_OFFSET)
	    || (cmd == DWARF_INFO_GET_MEMBER_TYPE)
	    || (cmd == DWARF_INFO_GET_MEMBER_OFFSET_1ST_UNION)
	    || (cmd == DWARF_INFO_GET_MEMBER_ARRAY_LENGTH))
		return TRUE;
	else
		return FALSE;
}

static int
is_search_number(int cmd)
{
	if (cmd == DWARF_INFO_GET_ENUM_NUMBER)
		return TRUE;
	else
		return FALSE;
}

static int
is_search_symbol(int cmd)
{
	if ((cmd == DWARF_INFO_GET_SYMBOL_ARRAY_LENGTH)
	    || (cmd == DWARF_INFO_GET_SYMBOL_TYPE)
	    || (cmd == DWARF_INFO_CHECK_SYMBOL_ARRAY_TYPE))
		return TRUE;
	else
		return FALSE;
}

static int
is_search_typedef(int cmd)
{
	if ((cmd == DWARF_INFO_GET_TYPEDEF_SIZE)
	    || (cmd == DWARF_INFO_GET_TYPEDEF_SRCNAME))
		return TRUE;
	else
		return FALSE;
}

static int
is_search_domain(int cmd)
{
	if ((cmd == DWARF_INFO_GET_DOMAIN_STRUCT)
		|| (cmd == DWARF_INFO_GET_DOMAIN_TYPEDEF)
		|| (cmd == DWARF_INFO_GET_DOMAIN_ARRAY)
		|| (cmd == DWARF_INFO_GET_DOMAIN_UNION)
		|| (cmd == DWARF_INFO_GET_DOMAIN_ENUM)
		|| (cmd == DWARF_INFO_GET_DOMAIN_REF)
		|| (cmd == DWARF_INFO_GET_DOMAIN_STRING)
		|| (cmd == DWARF_INFO_GET_DOMAIN_BASE))
		return TRUE;
	else
		return FALSE;
}

static int
is_search_die(int cmd)
{
	if (cmd == DWARF_INFO_GET_DIE)
		return TRUE;
	else
		return FALSE;
}

static int
process_module (Dwfl_Module *dwflmod,
		void **userdata __attribute__ ((unused)),
		const char *name __attribute__ ((unused)),
		Dwarf_Addr base __attribute__ ((unused)),
		void *arg)
{
	const char *fname, *mod_name, *debugfile;
	Dwarf_Addr dwbias;

	/* get a debug context descriptor.*/
	dwarf_info.dwarfd = dwfl_module_getdwarf (dwflmod, &dwbias);
	if (dwarf_info.dwarfd == NULL) {
		ERRMSG("dwfl_module_getdwarf error.\n");
		return DWARF_CB_ABORT;
	}
	dwarf_info.elfd = dwarf_getelf(dwarf_info.dwarfd);

	mod_name = dwfl_module_info(dwflmod, NULL, NULL, NULL, NULL, NULL,
							&fname, &debugfile);

	if (!strcmp(dwarf_info.module_name, mod_name) &&
		!dwarf_info.name_debuginfo && debugfile) {
		/*
		 * Store the debuginfo filename. Next time we will
		 * open debuginfo file direclty instead of searching
		 * for it again.
		 */
		dwarf_info.name_debuginfo = strdup(debugfile);
	}

	return DWARF_CB_OK;
}

static int
dwfl_report_module_p(const char *modname, const char *filename)
{
	if (filename && !strcmp(modname, dwarf_info.module_name))
		return 1;
	return 0;
}

static void
clean_dwfl_info(void)
{
	if (dwarf_info.dwfl)
		dwfl_end(dwarf_info.dwfl);

	dwarf_info.dwfl = NULL;
	dwarf_info.dwarfd = NULL;
	dwarf_info.elfd = NULL;
}

/*
 * Search module debuginfo.
 * This function searches for module debuginfo in default debuginfo path for
 * a given module in dwarf_info.module_name.
 *
 * On success, dwarf_info.name_debuginfo is set to absolute path of
 * module debuginfo.
 */
static int
search_module_debuginfo(char *os_release)
{
	Dwfl *dwfl = NULL;
	static char *debuginfo_path = DEFAULT_DEBUGINFO_PATH;
	static const Dwfl_Callbacks callbacks = {
		.section_address = dwfl_offline_section_address,
		.find_debuginfo = dwfl_standard_find_debuginfo,
		.debuginfo_path = &debuginfo_path,
	};

	/*
	 * Check if We already have debuginfo file name with us. If yes,
	 * then we don't need to proceed with search method.
	 */
	if (dwarf_info.name_debuginfo)
		return TRUE;

	if ((dwfl = dwfl_begin(&callbacks)) == NULL) {
		ERRMSG("Can't create a handle for a new dwfl session.\n");
		return FALSE;
	}

	/* Search for module debuginfo file. */
	if (dwfl_linux_kernel_report_offline(dwfl,
						os_release,
						&dwfl_report_module_p)) {
		ERRMSG("Can't get Module debuginfo for module '%s'\n",
					dwarf_info.module_name);
		dwfl_end(dwfl);
		return FALSE;
	}
	dwfl_report_end(dwfl, NULL, NULL);
	dwfl_getmodules(dwfl, &process_module, NULL, 0);

	dwfl_end(dwfl);
	clean_dwfl_info();

	/* Return success if module debuginfo is found. */
	if (dwarf_info.name_debuginfo)
		return TRUE;

	return FALSE;
}

static int
dwarf_no_debuginfo_found(Dwfl_Module *mod, void **userdata,
            const char *modname, Dwarf_Addr base,
            const char *file_name,
            const char *debuglink_file, GElf_Word debuglink_crc,
            char **debuginfo_file_name)
{
    return -1;
}

/*
 * Initialize the dwarf info.
 * Linux kernel module debuginfo are of ET_REL (relocatable) type.
 * This function uses dwfl API's to apply relocation before reading the
 * dwarf information from module debuginfo.
 * On success, this function sets the dwarf_info.elfd and dwarf_info.dwarfd
 * after applying relocation to module debuginfo.
 */
static int
init_dwarf_info(void)
{
	Dwfl *dwfl = NULL;
	int dwfl_fd = -1;
	static const Dwfl_Callbacks callbacks = {
		.section_address = dwfl_offline_section_address,
	/*
	 * By the time init_dwarf_info() function is called, we already
	 * know absolute path of debuginfo either resolved through
	 * search_module_debuginfo() call OR user specified vmlinux
	 * debuginfo through '-x' option. In which case .find_debuginfo
	 * callback is never invoked.
	 * But we can not deny a situation where user may pass invalid
	 * file name through '-x' option, where .find_debuginfo gets
	 * invoked to find a valid vmlinux debuginfo and hence we run
	 * into seg fault issue. Hence, set .find_debuginfo to a
	 * funtion pointer that returns -1 to avoid seg fault and let
	 * the makedumpfile throw error messages against the invalid
	 * vmlinux file input.
	 */
		.find_debuginfo  = dwarf_no_debuginfo_found
	};

	dwarf_info.elfd = NULL;
	dwarf_info.dwarfd = NULL;

	 /*
	  * We already know the absolute path of debuginfo file. Fail if we
	  * still don't have one. Ideally we should never be in this situation.
	  */
	if (!dwarf_info.name_debuginfo) {
		ERRMSG("Can't find absolute path to debuginfo file.\n");
		return FALSE;
	}

	if ((dwfl = dwfl_begin(&callbacks)) == NULL) {
		ERRMSG("Can't create a handle for a new dwfl session.\n");
		return FALSE;
	}

	/* Open the debuginfo file if it is not already open.  */
	if (dwarf_info.fd_debuginfo < 0)
		dwarf_info.fd_debuginfo =
			open(dwarf_info.name_debuginfo, O_RDONLY);

	dwfl_fd = dup(dwarf_info.fd_debuginfo);
	if (dwfl_fd < 0) {
		ERRMSG("Failed to get a duplicate handle for"
			" debuginfo.\n");
		goto err_out;
	}
	/* Apply relocations. */
	if (dwfl_report_offline(dwfl, dwarf_info.module_name,
			dwarf_info.name_debuginfo, dwfl_fd) == NULL) {
		ERRMSG("Failed reading %s: %s\n",
			dwarf_info.name_debuginfo, dwfl_errmsg (-1));
		/* dwfl_fd is consumed on success, not on failure */
		close(dwfl_fd);
		goto err_out;
	}
	dwfl_report_end(dwfl, NULL, NULL);

	dwfl_getmodules(dwfl, &process_module, NULL, 0);

	if (dwarf_info.elfd == NULL) {
		ERRMSG("Can't get first elf header of %s.\n",
		    dwarf_info.name_debuginfo);
		goto err_out;
	}

	if (dwarf_info.dwarfd == NULL) {
		ERRMSG("Can't get debug context descriptor for %s.\n",
		    dwarf_info.name_debuginfo);
		goto err_out;
	}
	dwarf_info.dwfl = dwfl;
	return TRUE;
err_out:
	if (dwfl)
		dwfl_end(dwfl);

	return FALSE;
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
get_die_type(Dwarf_Die *die, Dwarf_Die *die_type)
{
	Dwarf_Attribute attr;

	if (dwarf_attr(die, DW_AT_type, &attr) == NULL)
		return FALSE;

	if (dwarf_formref_die(&attr, die_type) < 0) {
		ERRMSG("Can't get CU die.\n");
		return FALSE;
	}
	return TRUE;
}

static int
get_data_array_length(Dwarf_Die *die)
{
	int tag;
	Dwarf_Attribute attr;
	Dwarf_Die die_type;
	Dwarf_Word upper_bound;

	if (!get_die_type(die, &die_type)) {
		ERRMSG("Can't get CU die of DW_AT_type.\n");
		return FALSE;
	}
	tag = dwarf_tag(&die_type);
	if (tag == DW_TAG_const_type) {
		/* This array is of const type. Get the die type again */
		if (!get_die_type(&die_type, &die_type)) {
			ERRMSG("Can't get CU die of DW_AT_type.\n");
			return FALSE;
		}
		tag = dwarf_tag(&die_type);
	}
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
check_array_type(Dwarf_Die *die)
{
	int tag;
	Dwarf_Die die_type;

	if (!get_die_type(die, &die_type)) {
		ERRMSG("Can't get CU die of DW_AT_type.\n");
		return FALSE;
	}
	tag = dwarf_tag(&die_type);
	if (tag == DW_TAG_array_type)
		dwarf_info.array_length = FOUND_ARRAY_TYPE;

	return TRUE;
}

static int
get_dwarf_base_type(Dwarf_Die *die)
{
	int tag;
	const char *name;

	while (get_die_type(die, die)) {
		tag = dwarf_tag(die);
		switch (tag) {
		case DW_TAG_array_type:
			dwarf_info.type_flag |= TYPE_ARRAY;
			break;
		case DW_TAG_pointer_type:
			dwarf_info.type_flag |= TYPE_PTR;
			break;
		case DW_TAG_structure_type:
			dwarf_info.type_flag |= TYPE_STRUCT;
			break;
		case DW_TAG_base_type:
			dwarf_info.type_flag |= TYPE_BASE;
			break;
		}
	}

	name = dwarf_diename(die);
	if (name)
		dwarf_info.type_name = strdup(name);
	else if (dwarf_info.type_flag == TYPE_PTR)
		dwarf_info.type_name = strdup("void");

	dwarf_info.struct_size = dwarf_bytesize(die);

	return TRUE;
}

/*
 * Get the die, given the offset
 */
static int
get_die_from_offset(Dwarf_Off offset, Dwarf_Die *die)
{
	if (!init_dwarf_info())
		return FALSE;

	if ((!offset) || (!die))
		return FALSE;

	if (!dwarf_offdie(dwarf_info.dwarfd, offset, die)) {
		return FALSE;
	}

	return TRUE;
}

/*
 * Function for searching struct page.union.struct.mapping.
 */
static int
is_container(Dwarf_Die *die)
{
	if (dwarf_tag(die) == DW_TAG_structure_type)
		return TRUE;
	if (dwarf_info.cmd != DWARF_INFO_GET_MEMBER_OFFSET_1ST_UNION
	    && dwarf_tag(die) == DW_TAG_union_type)
		return TRUE;
	return FALSE;
}

static void
adjust_member_offset(Dwarf_Die *die)
{
	long offset;

	if (dwarf_info.member_offset == NOT_FOUND_STRUCTURE)
		return;
	if (!get_data_member_location(die, &offset))
		return;
	dwarf_info.member_offset += offset;
}

static int
search_member(Dwarf_Die *die)
{
	int tag;
	long offset;
	const char *name;
	Dwarf_Die child, *walker, die_type;

	if (dwarf_child(die, &child) != 0)
		return FALSE;

	walker = &child;

	do {
		tag  = dwarf_tag(walker);
		name = dwarf_diename(walker);

		if (tag != DW_TAG_member)
			continue;

		/*
		 * Descend into structures/unions and search for member
		 * there.
		 */
		if ((!name) || (strcmp(name, dwarf_info.member_name) != 0)) {
			if (!get_die_type(walker, &die_type))
				continue;
			if (is_container(&die_type))
				if (search_member(&die_type)) {
					adjust_member_offset(walker);
					return TRUE;
				}
		}

		switch (dwarf_info.cmd) {
		case DWARF_INFO_GET_MEMBER_TYPE:
			if ((!name) || strcmp(name, dwarf_info.member_name))
				continue;
			/*
			 * Get the member offset.
			 */
			if (!get_dwarf_base_type(walker))
				continue;
			return TRUE;
		case DWARF_INFO_GET_MEMBER_OFFSET:
			if ((!name) || strcmp(name, dwarf_info.member_name))
				continue;
			/*
			 * Get the member offset.
			 */
			if (dwarf_tag(die) == DW_TAG_union_type)
				offset = 0;
			else if (!get_data_member_location(walker, &offset))
				continue;
			dwarf_info.member_offset = offset;
			return TRUE;
		case DWARF_INFO_GET_MEMBER_OFFSET_1ST_UNION:
			if (!get_die_type(walker, &die_type))
				continue;
			if (dwarf_tag(&die_type) != DW_TAG_union_type)
				continue;
			/*
			 * Get the member offset.
			 */
			if (!get_data_member_location(walker, &offset))
				continue;
			dwarf_info.member_offset = offset;
			return TRUE;
		case DWARF_INFO_GET_MEMBER_ARRAY_LENGTH:
			if ((!name) || strcmp(name, dwarf_info.member_name))
				continue;
			/*
			 * Get the member length.
			 */
			if (!get_data_array_length(walker))
				continue;
			return TRUE;
		}
	} while (!dwarf_siblingof(walker, walker));

	/*
	 * Return even if not found.
	 */
	return FALSE;
}

static void
search_structure(Dwarf_Die *die, int *found)
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
	case DWARF_INFO_GET_MEMBER_TYPE:
	case DWARF_INFO_GET_MEMBER_OFFSET:
	case DWARF_INFO_GET_MEMBER_OFFSET_1ST_UNION:
	case DWARF_INFO_GET_MEMBER_ARRAY_LENGTH:
		search_member(die);
		break;
	}
}

static void
search_number(Dwarf_Die *die, int *found)
{
	int tag, bytesize;
	Dwarf_Word const_value;
	Dwarf_Attribute attr;
	Dwarf_Die child, *walker;
	const char *name;

	do {
		tag  = dwarf_tag(die);
		if (tag != DW_TAG_enumeration_type)
			continue;

		if (dwarf_info.cmd == DWARF_INFO_GET_ENUMERATION_TYPE_SIZE) {
		   		   name = dwarf_diename(die);

			if (!name || strcmp(name, dwarf_info.struct_name))
			   	     continue;

			if ((bytesize = dwarf_bytesize(die)) <= 0)
			   	      	continue;

			*found = TRUE;

			dwarf_info.struct_size = bytesize;

			return;
				}

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
search_typedef(Dwarf_Die *die, int *found)
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
			if (!get_die_type(die, &die_type)) {
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
			strncpy(dwarf_info.src_name, src_name, LEN_SRCFILE-1);
			dwarf_info.src_name[LEN_SRCFILE-1] = '\0';
			break;
		}
	} while (!dwarf_siblingof(die, die));
}

static void
search_symbol(Dwarf_Die *die, int *found)
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
		get_data_array_length(die);
		break;
	case DWARF_INFO_CHECK_SYMBOL_ARRAY_TYPE:
		check_array_type(die);
		break;
	case DWARF_INFO_GET_SYMBOL_TYPE:
		get_dwarf_base_type(die);
		break;
	}
}

static void
search_domain(Dwarf_Die *die, int *found)
{
	int tag;
	const char *name;
	short flag = 0;
	Dwarf_Die die_type;

	do {
		tag  = dwarf_tag(die);
		name = dwarf_diename(die);

		/*
		 * Descend into members and search for the
		 * needed domain there.
		 */
		if ((!name) || strcmp(name, dwarf_info.symbol_name)) {
			if (!get_die_type(die, &die_type))
				continue;

			if (is_container(&die_type)) {
				Dwarf_Die child;

				if (dwarf_child(&die_type, &child) != 0)
					continue;

				search_domain(&child, found);

				if (*found)
					return;
			}
		}

		if ((!name) || strcmp(name, dwarf_info.symbol_name))
			continue;

		switch (dwarf_info.cmd) {
		case DWARF_INFO_GET_DOMAIN_STRUCT:
			if (tag == DW_TAG_structure_type)
				flag = 1;
			break;
		case DWARF_INFO_GET_DOMAIN_UNION:
			if (tag == DW_TAG_union_type)
				flag = 1;
			break;
		case DWARF_INFO_GET_DOMAIN_TYPEDEF:
			if (tag == DW_TAG_typedef)
				flag = 1;
			break;
		/* TODO
		 * Implement functionality for the rest of the domains
		 */
		}

		if (!flag)
			continue;

		dwarf_info.struct_size = dwarf_bytesize(die);

		if (dwarf_info.struct_size > 0) {
			if (found)
				*found = TRUE;
			dwarf_info.die_offset = dwarf_dieoffset(die);
			break;
		}
	} while (!dwarf_siblingof(die, die));
}

static void
search_die(Dwarf_Die *die, int *found)
{
	const char *name;

	do {
		name = dwarf_diename(die);

		if ((!name) || strcmp(name, dwarf_info.symbol_name))
			continue;

		if (found)
			*found = TRUE;

		dwarf_info.die_offset = dwarf_dieoffset(die);
		return;
	} while (!dwarf_siblingof(die, die));
}

static void
search_die_tree(Dwarf_Die *die, int *found)
{
	Dwarf_Die child;

	/*
	 * start by looking at the children
	 */
	if (dwarf_child(die, &child) == 0)
		search_die_tree(&child, found);

	if (*found)
		return;

	if (is_search_structure(dwarf_info.cmd))
		search_structure(die, found);

	else if (is_search_number(dwarf_info.cmd))
		search_number(die, found);

	else if (is_search_symbol(dwarf_info.cmd))
		search_symbol(die, found);

	else if (is_search_typedef(dwarf_info.cmd))
		search_typedef(die, found);

	else if (is_search_domain(dwarf_info.cmd))
		search_domain(die, found);

	else if (is_search_die(dwarf_info.cmd))
		search_die(die, found);
}

static int
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

	int ret = FALSE;

	if (!init_dwarf_info())
		return FALSE;

	elfd = dwarf_info.elfd;
	dwarfd = dwarf_info.dwarfd;

	if (elf_getshdrstrndx(elfd, &shstrndx) < 0) {
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
		search_die_tree(&cu_die, &found);
		if (found)
			break;
		off = next_off;
	}
	ret = TRUE;
out:
	clean_dwfl_info();

	return ret;
}


/*
 * External functions.
 */
char *
get_dwarf_module_name(void)
{
	return dwarf_info.module_name;
}

void
get_fileinfo_of_debuginfo(int *fd, char **name)
{
	*fd = dwarf_info.fd_debuginfo;
	*name = dwarf_info.name_debuginfo;
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

	if (!init_dwarf_info())
		return NOT_FOUND_SYMBOL;

	elfd = dwarf_info.elfd;

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
	clean_dwfl_info();

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

	if (!init_dwarf_info())
		return NOT_FOUND_SYMBOL;

	elfd = dwarf_info.elfd;

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
	clean_dwfl_info();

	return next_symbol;
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
 * Get the size of pointer.
 */
long
get_pointer_size(void)
{
	return sizeof(void *);
}

/*
 * Get the type of given symbol.
 */
char *
get_symbol_type_name(char *symname, int cmd, long *size,
					unsigned long *flag)
{
	dwarf_info.cmd = cmd;
	dwarf_info.symbol_name = symname;
	dwarf_info.type_name = NULL;
	dwarf_info.struct_size = NOT_FOUND_STRUCTURE;
	dwarf_info.type_flag = 0;

	if (!get_debug_info())
		return NULL;

	if (size)
		*size = dwarf_info.struct_size;

	if (flag)
		*flag = dwarf_info.type_flag;

	return dwarf_info.type_name;
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
	dwarf_info.member_offset = NOT_FOUND_STRUCTURE;

	/*
	 * When searching a offset of 1st union, member_name is unnecessary.
	 */
	if (dwarf_info.cmd == DWARF_INFO_GET_MEMBER_OFFSET_1ST_UNION)
		dwarf_info.member_name = "";
	else
		dwarf_info.member_name = membername;

	if (!get_debug_info())
		return FAILED_DWARFINFO;

	return dwarf_info.member_offset;
}

/*
 * Get the type name and size of member.
 */
char *
get_member_type_name(char *structname, char *membername, int cmd, long *size,
						unsigned long *flag)
{
	dwarf_info.cmd = cmd;
	dwarf_info.struct_name = structname;
	dwarf_info.struct_size = NOT_FOUND_STRUCTURE;
	dwarf_info.member_name = membername;
	dwarf_info.type_name = NULL;
	dwarf_info.type_flag = 0;

	if (!get_debug_info())
		return NULL;

	if (dwarf_info.struct_size == NOT_FOUND_STRUCTURE)
		return NULL;

	if (size)
		*size = dwarf_info.struct_size;

	if (flag)
		*flag = dwarf_info.type_flag;

	return dwarf_info.type_name;
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
get_enum_number(char *enum_name)
{
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

/*
 * Get the domain information of the symbol
 */
long
get_domain(char *symname, int cmd, unsigned long long *die)
{
	dwarf_info.cmd         = cmd;
	dwarf_info.symbol_name = symname;
	dwarf_info.type_name   = NULL;
	dwarf_info.struct_size = NOT_FOUND_STRUCTURE;
	dwarf_info.die_offset  = 0;

	if (!get_debug_info())
		return 0;

	if (die)
		*die = (unsigned long long) dwarf_info.die_offset;

	return dwarf_info.struct_size;
}

/*
 * Get the number of fields in a structure or union provided the
 * die offset of the structure or union
 */
int
get_die_nfields(unsigned long long die_off)
{
	int tag, nfields = 0;
	Dwarf_Die result, child, *die;

	if (!get_die_from_offset((Dwarf_Off) die_off, &result)) {
		return -1;
	}

	die = &result;
	tag = dwarf_tag(die);
	if (tag != DW_TAG_structure_type && tag != DW_TAG_union_type) {
		clean_dwfl_info();
		return -1;
	}

	if (dwarf_child(die, &child) != 0) {
		clean_dwfl_info();
		return -1;
	}

	/* Find the number of fields in the structure */
	die = &child;
	do {
		tag = dwarf_tag(die);
		if (tag == DW_TAG_member)
			nfields++;
		else
			continue;
	} while (!dwarf_siblingof(die, die));

	clean_dwfl_info();
	return nfields;
}

/*
 * Get the information of the structure member given by index
 */
int
get_die_member(unsigned long long die_off, int index, long *offset,
		char **name, int *nbits, int *fbits, unsigned long long *m_die)
{
	const char *diename;
	int tag, size, nfields = 0;
	Dwarf_Die result, child, die_base, *die;

	if (!offset || !nbits || !fbits || !name || !m_die)
		return -1;

	if (!get_die_from_offset((Dwarf_Off) die_off, &result)) {
		return -1;
	}

	die = &result;
	tag = dwarf_tag(die);
	if (tag != DW_TAG_structure_type && tag != DW_TAG_union_type) {
		clean_dwfl_info();
		return -1;
	}

	if (dwarf_child(die, &child) != 0) {
		clean_dwfl_info();
		return -1;
	}

	/* Find the correct field in the structure */
	die = &child;
	do {
		tag = dwarf_tag(die);
		if (tag == DW_TAG_member) {
			if (nfields == index)
				break;
			else
				nfields++;
		}
	} while (!dwarf_siblingof(die, die));

	if (nfields != index) {
		ERRMSG("No member found at index %d.\n", index);
		clean_dwfl_info();
		return -1;
	}

	/* Fill in the required info for the member */
	if (!get_data_member_location(die, offset))
		*offset = 0;

	diename = dwarf_diename(die);
	/*
	 * Duplicate the string before we pass it to eppic layer. The
	 * original string returned by dwarf layer will become invalid
	 * after clean_dwfl_info() call.
	 */
	if (diename)
		*name = strdup(diename);
	*m_die = dwarf_dieoffset(die);

	get_die_type(die, &die_base);
	if (dwarf_tag(&die_base) == DW_TAG_array_type) {
		dwarf_info.array_length = 0;
		get_data_array_length(die);
		size = dwarf_info.array_length;
	} else {
		size = dwarf_bytesize(&die_base);
	}

	/* TODO
	 * Correctly update fbits and nbits
	 */
	*nbits = *fbits = 0;

	clean_dwfl_info();
	if (size < 0)
		return 0;
	else
		return size;
}

/*
 * Get the die attribute type
 */
int
get_die_attr_type(unsigned long long die_off, int *type_flag,
		unsigned long long *die_attr_off)
{
	Dwarf_Die result;

	if (!die_attr_off || !die_off)
		return FALSE;

	if (!get_die_from_offset((Dwarf_Off) die_off, &result)) {
		return FALSE;
	}

	if (!get_die_type(&result, &result)) {
		clean_dwfl_info();
		return FALSE;
	}

	*die_attr_off = dwarf_dieoffset(&result);
	*type_flag = dwarf_tag(&result);
	clean_dwfl_info();
	return TRUE;
}

/*
 * Get name attribute given the die offset This function is called by eppic
 * layer directly as one of the callback functions.
 *
 * This function returns a pointer to newly allocated string which is a
 * duplicate of original string returned from dwarf APIs. The reason for doing
 * this is because the original string returned by dwarf layer will become
 * invalid (freed) as soon as we close the dwarf handle through
 * clean_dwfl_info(). This avoids the segfault when caller (eppic layer) of
 * this function tries to access the string pointer.
 *
 * NOTE: It is callers responsibility to free the memory of new string.
 */
char *
get_die_name(unsigned long long die_off)
{
	Dwarf_Die result;
	char *name = NULL;
	const char *diename;

	if (!die_off)
		return NULL;

	if (!get_die_from_offset((Dwarf_Off) die_off, &result)) {
		return NULL;
	}

	diename = dwarf_diename(&result);
	if (diename)
		name = strdup(diename);
	clean_dwfl_info();
	return name;
}

/*
 * Get the die offset given the die name
 */
unsigned long long
get_die_offset(char *sysname)
{
	dwarf_info.cmd         = DWARF_INFO_GET_DIE;
	dwarf_info.symbol_name = sysname;
	dwarf_info.type_name   = NULL;
	dwarf_info.struct_size = NOT_FOUND_STRUCTURE;
	dwarf_info.die_offset  = 0;

	if (!sysname)
		return 0;

	if (!get_debug_info())
		return 0;

	return (unsigned long long)dwarf_info.die_offset;
}

/*
 * Get length attribute given the die offset
 */
int
get_die_length(unsigned long long die_off, int flag)
{
	Dwarf_Die result, die_base;
	int size = 0;

	if (!die_off)
		return FALSE;

	if (!get_die_from_offset((Dwarf_Off) die_off, &result)) {
		return FALSE;
	}

	if (flag) {
		size = dwarf_bytesize(&result);
		goto out;
	}

	get_die_type(&result, &die_base);
	if (dwarf_tag(&die_base) == DW_TAG_array_type) {
		dwarf_info.array_length = 0;
		get_data_array_length(&result);
		size = dwarf_info.array_length;
	} else {
		size = dwarf_bytesize(&die_base);
	}
out:
	clean_dwfl_info();
	return size;
}

/*
 * Set the dwarf_info with kernel/module debuginfo file information.
 */
int
set_dwarf_debuginfo(char *mod_name, char *os_release,
		    char *name_debuginfo, int fd_debuginfo)
{
	if (!mod_name)
		return FALSE;
	if (dwarf_info.module_name && !strcmp(dwarf_info.module_name, mod_name))
		return TRUE;

	/* Switching to different module.
	 *
	 * Close the file descriptor if previous module is != kernel and
	 * xen-syms. The reason is, vmlinux file will always be supplied
	 * by user and code to open/close kernel debuginfo file already
	 * in place. The module debuginfo files are opened only if '--config'
	 * option is used. This helps not to break the existing functionlity
	 * if called without '--config' option.
	 */

	if (dwarf_info.module_name
			&& strcmp(dwarf_info.module_name, "vmlinux")
			&& strcmp(dwarf_info.module_name, "xen-syms")) {
		if (dwarf_info.fd_debuginfo >= 0)
			close(dwarf_info.fd_debuginfo);
		if (dwarf_info.name_debuginfo)
			free(dwarf_info.name_debuginfo);
	}
	if (dwarf_info.module_name)
		free(dwarf_info.module_name);

	dwarf_info.fd_debuginfo = fd_debuginfo;
	dwarf_info.name_debuginfo = name_debuginfo;
	dwarf_info.module_name = strdup(mod_name);

	if (!strcmp(dwarf_info.module_name, "vmlinux") ||
		!strcmp(dwarf_info.module_name, "xen-syms"))
		return TRUE;

	/* check to see whether module debuginfo is available */
	return search_module_debuginfo(os_release);
}

