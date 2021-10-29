/*
 * erase_info.c
 *
 * Created by: Mahesh J Salgaonkar <mahesh@linux.vnet.ibm.com>
 *
 * Copyright (C) 2011  IBM Corporation
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
#include "makedumpfile.h"
#include "print_info.h"
#include "dwarf_info.h"
#include "erase_info.h"

#include <dlfcn.h>

struct erase_info	*erase_info = NULL;
unsigned long		num_erase_info = 1; /* Node 0 is unused. */

struct call_back eppic_cb = {
	&get_domain_all,
	&readmem,
	&get_die_attr_type,
	&get_die_name,
	&get_die_offset,
	&get_die_length,
	&get_die_member_all,
	&get_die_nfields_all,
	&get_symbol_addr_all,
	&update_filter_info_raw
};


/*
 * flags for config_entry.flag
 */ 
#define FILTER_ENTRY		0x0001
#define SIZE_ENTRY		0x0002
#define ITERATION_ENTRY		0x0004
#define LIST_ENTRY		0x0008
#define SYMBOL_ENTRY		0x0010
#define VAR_ENTRY		0x0020
#define TRAVERSAL_ENTRY		0x0040
#define ENTRY_RESOLVED		0x8000

/*
 * flags for get_config()
 */ 
#define CONFIG_SKIP_SECTION	0x01
#define CONFIG_NEW_CMD		0x02

#define IS_KEYWORD(tkn)	\
	(!strcmp(tkn, "erase") || !strcmp(tkn, "size") || \
	!strcmp(tkn, "nullify") || !strcmp(tkn, "for") || \
	!strcmp(tkn, "in") || !strcmp(tkn, "within") || \
	!strcmp(tkn, "endfor"))

struct module_sym_table {
	unsigned int		num_modules;
	unsigned int		current_mod;
	struct module_info	*modules;
};

/*
 * Filtering physical address range.
 */
struct filter_info {
	unsigned long long      vaddr; /* symbol address for debugging */
	unsigned long long      paddr;
	long			size;

	/* direct access to update erase information node */
	int			erase_info_idx;	/* 0= invalid index */
	int			size_idx;

	int			erase_ch;

	struct filter_info      *next;
	unsigned short          nullify;
};

/*
 * Filter config information
 */
struct filter_config {
	char		*name_filterconfig;
	FILE		*file_filterconfig;
	char		*cur_module;
	char		*saved_token;
	char		*token;
	int		new_section;
	int		line_count;
};

struct config_entry {
	char			*name;
	char			*type_name;
	char			*symbol_expr;	/* original symbol expression */
	unsigned short		flag;
	unsigned short		nullify;
	unsigned long long	sym_addr;	/* Symbol address */
	unsigned long		vaddr;		/* Symbol address or
						   value pointed by sym_addr */
	unsigned long long	cmp_addr;	/* for LIST_ENTRY */
	unsigned long		offset;
	unsigned long		type_flag;
	long			array_length;
	long			index;
	long			size;
	int			line;	/* Line number in config file. */
	int			erase_info_idx;	/* 0= invalid index */
	struct config_entry	*refer_to;
	struct config_entry	*next;
};

struct config {
	char			*module_name;
	struct config_entry	*iter_entry;
	struct config_entry	*list_entry;
	int			num_filter_symbols;
	struct config_entry	**filter_symbol;
	struct config_entry	**size_symbol;
};

static struct module_sym_table	mod_st = { 0 };
static struct filter_info	*filter_info = NULL;
static struct filter_config	filter_config;
static char			config_buf[BUFSIZE_FGETS];


/*
 * Internal functions.
 */
static struct module_info *
get_loaded_module(char *mod_name)
{
	unsigned int i;
	struct module_info *modules;

	modules = mod_st.modules;
	if (strcmp(mod_name, modules[mod_st.current_mod].name)) {
		for (i = 0; i < mod_st.num_modules; i++) {
			if (!strcmp(mod_name, modules[i].name))
				break;
		}
		if (i == mod_st.num_modules)
			return NULL;
		/* set the current_mod for fast lookup next time */
		mod_st.current_mod = i;
	}

	return &modules[mod_st.current_mod];
}

static unsigned long long
find_module_symbol(struct module_info *module_ptr, char *symname)
{
	int i;
	struct symbol_info *sym_info;

	sym_info = module_ptr->sym_info;
	if (!sym_info)
		return FALSE;
	for (i = 1; i < module_ptr->num_syms; i++) {
		if (sym_info[i].name && !strcmp(sym_info[i].name, symname))
			return sym_info[i].value;
	}
	return NOT_FOUND_SYMBOL;
}

static int
sym_in_module(char *symname, unsigned long long *symbol_addr)
{
	char *module_name;
	struct module_info *module_ptr;

	module_name = get_dwarf_module_name();
	if (!mod_st.num_modules
		|| !strcmp(module_name, "vmlinux")
		|| !strcmp(module_name, "xen-syms"))
		return FALSE;

	module_ptr = get_loaded_module(module_name);
	if (!module_ptr)
		return FALSE;
	*symbol_addr = find_module_symbol(module_ptr, symname);
	if (*symbol_addr == NOT_FOUND_SYMBOL)
		return FALSE;
	else
		return TRUE;
}

static unsigned int
get_num_modules(unsigned long head, unsigned int *num)
{
	unsigned long cur;
	unsigned int num_modules = 0;

	if (!num)
		return FALSE;

	if (!readmem(VADDR, head + OFFSET(list_head.next), &cur, sizeof cur)) {
		ERRMSG("Can't get next list_head.\n");
		return FALSE;
	}
	while (cur != head) {
		num_modules++;
		if (!readmem(VADDR, cur + OFFSET(list_head.next),
					&cur, sizeof cur)) {
			ERRMSG("Can't get next list_head.\n");
			return FALSE;
		}
	}
	*num = num_modules;
	return TRUE;
}

static void
free_symbol_info(struct module_info *module)
{
	int i;

	if (module->num_syms == 0)
		return;

	for (i = 1; i < module->num_syms; i++)
		if (module->sym_info[i].name)
			free(module->sym_info[i].name);
	free(module->sym_info);
}

static void
clean_module_symbols(void)
{
	int i;

	for (i = 0; i < mod_st.num_modules; i++)
		free_symbol_info(&mod_st.modules[i]);

	if (mod_st.num_modules) {
		free(mod_st.modules);
		mod_st.modules     = NULL;
		mod_st.num_modules = 0;
	}
}

static int
__load_module_symbol(struct module_info *modules, unsigned long addr_module)
{
	int ret = FALSE;
	unsigned int nsym;
	unsigned long symtab, strtab;
	unsigned long mod_base, mod_init;
	unsigned int mod_size, mod_init_size;
	unsigned char *module_struct_mem = NULL;
	unsigned char *module_core_mem = NULL;
	unsigned char *module_init_mem = NULL;
	unsigned char *symtab_mem;
	char *module_name, *strtab_mem, *nameptr;
	unsigned int num_symtab;

	/* Allocate buffer to read struct module data from vmcore. */
	if ((module_struct_mem = calloc(1, SIZE(module))) == NULL) {
		ERRMSG("Failed to allocate buffer for module\n");
		return FALSE;
	}
	if (!readmem(VADDR, addr_module, module_struct_mem,
						SIZE(module))) {
		ERRMSG("Can't get module info.\n");
		goto out;
	}

	module_name = (char *)(module_struct_mem + OFFSET(module.name));
	strncpy(modules->name, module_name, MOD_NAME_LEN - 1);
	modules->name[MOD_NAME_LEN - 1] = '\0';

	mod_init = ULONG(module_struct_mem +
					OFFSET(module.module_init));
	mod_init_size = UINT(module_struct_mem +
					OFFSET(module.init_size));
	mod_base = ULONG(module_struct_mem +
					OFFSET(module.module_core));
	mod_size = UINT(module_struct_mem +
					OFFSET(module.core_size));

	DEBUG_MSG("Module: %s, Base: 0x%lx, Size: %u\n",
			module_name, mod_base, mod_size);
	if (mod_init_size > 0) {
		module_init_mem = calloc(1, mod_init_size);
		if (module_init_mem == NULL) {
			ERRMSG("Can't allocate memory for module "
							"init\n");
			goto out;
		}
		if (!readmem(VADDR, mod_init, module_init_mem,
						mod_init_size)) {
			ERRMSG("Can't access module init in memory.\n");
			goto out;
		}
	}

	if ((module_core_mem = calloc(1, mod_size)) == NULL) {
		ERRMSG("Can't allocate memory for module\n");
		goto out;
	}
	if (!readmem(VADDR, mod_base, module_core_mem, mod_size)) {
		ERRMSG("Can't access module in memory.\n");
		goto out;
	}

	num_symtab = UINT(module_struct_mem +
					OFFSET(module.num_symtab));
	if (!num_symtab) {
		ERRMSG("%s: Symbol info not available\n", module_name);
		goto out;
	}
	modules->num_syms = num_symtab;
	DEBUG_MSG("num_sym: %d\n", num_symtab);

	symtab = ULONG(module_struct_mem + OFFSET(module.symtab));
	strtab = ULONG(module_struct_mem + OFFSET(module.strtab));

	/* check if symtab and strtab are inside the module space. */
	if (!IN_RANGE(symtab, mod_base, mod_size) &&
		!IN_RANGE(symtab, mod_init, mod_init_size)) {
		ERRMSG("%s: module symtab is outside of module "
			"address space\n", module_name);
		goto out;
	}
	if (IN_RANGE(symtab, mod_base, mod_size))
		symtab_mem = module_core_mem + (symtab - mod_base);
	else
		symtab_mem = module_init_mem + (symtab - mod_init);

	if (!IN_RANGE(strtab, mod_base, mod_size) &&
		!IN_RANGE(strtab, mod_init, mod_init_size)) {
		ERRMSG("%s: module strtab is outside of module "
			"address space\n", module_name);
		goto out;
	}
	if (IN_RANGE(strtab, mod_base, mod_size))
		strtab_mem = (char *)(module_core_mem
					+ (strtab - mod_base));
	else
		strtab_mem = (char *)(module_init_mem
					+ (strtab - mod_init));

	modules->sym_info = calloc(num_symtab, sizeof(struct symbol_info));
	if (modules->sym_info == NULL) {
		ERRMSG("Can't allocate memory to store sym info\n");
		goto out;
	}

	/* symbols starts from 1 */
	for (nsym = 1; nsym < num_symtab; nsym++) {
		Elf32_Sym *sym32;
		Elf64_Sym *sym64;
		/* 
		 * TODO:
		 * If case of ELF vmcore then the word size can be
		 * determined using flag_elf64_memory flag.
		 * But in case of kdump-compressed dump, kdump header
		 * does not carry word size info. May be in future
		 * this info will be available in kdump header.
		 * Until then, in order to make this logic work on both
		 * situation we depend on pointer_size that is
		 * extracted from vmlinux dwarf information.
		 */
		if ((get_pointer_size() * 8) == 64) {
			sym64 = (Elf64_Sym *) (symtab_mem
					+ (nsym * sizeof(Elf64_Sym)));
			modules->sym_info[nsym].value =
				(unsigned long long) sym64->st_value;
			nameptr = strtab_mem + sym64->st_name;
		} else {
			sym32 = (Elf32_Sym *) (symtab_mem
					+ (nsym * sizeof(Elf32_Sym)));
			modules->sym_info[nsym].value =
				(unsigned long long) sym32->st_value;
			nameptr = strtab_mem + sym32->st_name;
		}
		if (strlen(nameptr))
			modules->sym_info[nsym].name = strdup(nameptr);
		DEBUG_MSG("\t[%d] %llx %s\n", nsym,
					modules->sym_info[nsym].value, nameptr);
	}
	ret = TRUE;
out:
	free(module_struct_mem);
	free(module_core_mem);
	free(module_init_mem);

	return ret;
}

static int
load_module_symbols(void)
{
	unsigned long head, cur, cur_module;
	struct module_info *modules = NULL;
	unsigned int i = 0;

	head = SYMBOL(modules);
	if (!get_num_modules(head, &mod_st.num_modules) ||
	    !mod_st.num_modules) {
		ERRMSG("Can't get module count\n");
		return FALSE;
	}
	mod_st.modules = calloc(mod_st.num_modules,
					sizeof(struct module_info));
	if (!mod_st.modules) {
		ERRMSG("Can't allocate memory for module info\n");
		return FALSE;
	}
	modules = mod_st.modules;

	if (!readmem(VADDR, head + OFFSET(list_head.next), &cur, sizeof cur)) {
		ERRMSG("Can't get next list_head.\n");
		return FALSE;
	}

	/* Travese the list and read module symbols */
	while (cur != head) {
		cur_module = cur - OFFSET(module.list);

		if (!__load_module_symbol(&modules[i], cur_module))
			return FALSE;

		if (!readmem(VADDR, cur + OFFSET(list_head.next),
					&cur, sizeof cur)) {
			ERRMSG("Can't get next list_head.\n");
			return FALSE;
		}
		i++;
	}
	return TRUE;
}

static void
free_config_entry(struct config_entry *ce)
{
	struct config_entry *p;

	while(ce) {
		p  = ce;
		ce = p->next;
		if (p->name)
			free(p->name);
		if (p->type_name)
			free(p->type_name);
		if (p->symbol_expr)
			free(p->symbol_expr);
		free(p);
	}
}

static void
free_config(struct config *config)
{
	int i;

	if (config == NULL)
		return;

	if (config->module_name)
		free(config->module_name);
	for (i = 0; i < config->num_filter_symbols; i++) {
		if (config->filter_symbol[i])
			free_config_entry(config->filter_symbol[i]);
		if (config->size_symbol[i])
			free_config_entry(config->size_symbol[i]);
	}
	if (config->filter_symbol)
		free(config->filter_symbol);
	if (config->size_symbol)
		free(config->size_symbol);
	free(config);
}

static void
print_config_entry(struct config_entry *ce)
{
	while (ce) {
		DEBUG_MSG("Name: %s\n", ce->name);
		DEBUG_MSG("Type Name: %s, ", ce->type_name);
		DEBUG_MSG("flag: %x, ", ce->flag);
		DEBUG_MSG("Type flag: %lx, ", ce->type_flag);
		DEBUG_MSG("sym_addr: %llx, ", ce->sym_addr);
		DEBUG_MSG("vaddr: %lx, ", ce->vaddr);
		DEBUG_MSG("offset: %llx, ", (unsigned long long)ce->offset);
		DEBUG_MSG("size: %ld\n", ce->size);

		ce = ce->next;
	}
}

/*
 * Read the non-terminal's which are in the form of <Symbol>[.member[...]]
 */
static struct config_entry *
create_config_entry(const char *token, unsigned short flag, int line)
{
	struct config_entry *ce = NULL, *ptr, *prev_ce;
	char *str, *cur, *next;
	long len;
	int depth = 0;

	if (!token)
		return NULL;

	cur = str = strdup(token);
	prev_ce = ptr = NULL;
	while (cur != NULL) {
		if ((next = strchr(cur, '.')) != NULL) {
			*next++ = '\0';
		}
		if (!strlen(cur)) {
			cur = next;
			continue;
		}

		if ((ptr = calloc(1, sizeof(struct config_entry))) == NULL) {
			ERRMSG("Can't allocate memory for config_entry\n");
			goto err_out;
		}
		ptr->line = line;
		ptr->flag |= flag;
		if (depth == 0) {
			/* First node is always a symbol name */
			ptr->flag |= SYMBOL_ENTRY;
		}
		if (flag & ITERATION_ENTRY) {
			/* Max depth for iteration entry is 1 */
			if (depth > 0) {
				ERRMSG("Config error at %d: Invalid iteration "
					"variable entry.\n", line);
				goto err_out;
			}
			ptr->name = strdup(cur);
		}
		if (flag & (FILTER_ENTRY | LIST_ENTRY)) {
			ptr->name = strdup(cur);
		}
		if (flag & SIZE_ENTRY) {
			char ch = '\0';
			int n = 0;
			/* See if absolute length is provided */
			if ((depth == 0) &&
				((n = sscanf(cur, "%ld%c", &len, &ch)) > 0)) {
				if (len < 0) {
					ERRMSG("Config error at %d: size "
						"value must be positive.\n",
						line);
					goto err_out;
				}
				ptr->size = len;
				ptr->flag |= ENTRY_RESOLVED;
				if (n == 2) {
					/* Handle suffix.
					 * K = Kilobytes
					 * M = Megabytes
					 */
					switch (ch) {
					case 'M':
					case 'm':
						ptr->size *= 1024;
					case 'K':
					case 'k':
						ptr->size *= 1024;
						break;
					}
				}
			}
			else
				ptr->name = strdup(cur);
		}
		if (prev_ce) {
			prev_ce->next = ptr;
			prev_ce       = ptr;
		} else
			ce = prev_ce = ptr;

		cur = next;
		ptr = NULL;
		depth++;
	}
	free(str);
	return ce;

err_out:
	if (ce)
		free_config_entry(ce);
	if (ptr)
		free_config_entry(ptr);
	free(str);
	return NULL;
}

static int
is_module_loaded(char *mod_name)
{
	if (!strcmp(mod_name, "vmlinux") || get_loaded_module(mod_name))
		return TRUE;
	return FALSE;
}

/*
 * read filter config file and return each string token. If the parameter
 * expected_token is non-NULL, then return the current token if it matches
 * with expected_token otherwise save the current token and return NULL.
 * At start of every module section filter_config.new_section is set to 1 and
 * subsequent function invocations return NULL untill filter_config.new_section
 * is reset to 0 by passing @flag = CONFIG_NEW_CMD (0x02).
 *
 * Parameters:
 * @expected_token	INPUT
 *	Token string to match with currnet token.
 *	=NULL - return the current available token.
 *
 * @flag		INPUT
 *	=0x01 - Skip to next module section.
 *	=0x02 - Treat the next token as next filter command and reset.
 *
 * @line		OUTPUT
 *	Line number of current token in filter config file.
 *
 * @cur_mod		OUTPUT
 *	Points to current module section name on non-NULL return value.
 *
 * @eof			OUTPUT
 *	set to -1 when end of file is reached.
 *	set to -2 when end of section is reached.
 */
#define NOT_REACH_END		(0)
#define REACH_END_OF_FILE	(-1)
#define REACH_END_OF_SECTION	(-2)

static char *
get_config_token(char *expected_token, unsigned char flag, int *line,
			char **cur_mod, int *eof)
{
	char *p;
	struct filter_config *fc = &filter_config;
	int skip = flag & CONFIG_SKIP_SECTION;

	if (!fc->file_filterconfig)
		return NULL;

	if (eof)
		*eof = NOT_REACH_END;

	/*
	 * set token and saved_token to NULL if skip module section is set
	 * to 1.
	 */
	if (skip) {
		fc->token       = NULL;
		fc->saved_token = NULL;

	} else if (fc->saved_token) {
		fc->token       = fc->saved_token;
		fc->saved_token = NULL;

	} else if (fc->token)
		fc->token       = strtok(NULL, " ");

	/* Read next line if we are done all tokens from previous line */
	while (!fc->token && fgets(config_buf, sizeof(config_buf),
					fc->file_filterconfig)) {
		if ((p = strchr(config_buf, '\n'))) {
			*p = '\0';
			fc->line_count++;
		}
		if ((p = strchr(config_buf, '#'))) {
			*p = '\0';
		}
		/* replace all tabs with spaces */
		for (p = config_buf; *p != '\0'; p++)
			if (*p == '\t')
				*p = ' ';
		if (config_buf[0] == '[') {
			/* module section entry */
			p = strchr(config_buf, ']');
			if (!p) {
				ERRMSG("Config error at %d: Invalid module "
					"section entry.\n", fc->line_count);
				/* skip to next valid module section */
				skip = 1;
			} else {
				/*
				 * Found the valid module section. Reset the
				 * skip flag.
				 */
				*p = '\0';
				if (fc->cur_module)
					free(fc->cur_module);
				fc->cur_module  = strdup(&config_buf[1]);
				fc->new_section = 1;
				skip = 0;
			}
			continue;
		}
		/*
		 * If symbol info for current module is not loaded then
		 * skip to next module section.
		 */
		if (skip ||
			(fc->cur_module && !is_module_loaded(fc->cur_module)))
			continue;

		fc->token = strtok(config_buf, " ");
	}
	if (!fc->token) {
		if (eof)
			*eof = REACH_END_OF_FILE;
		return NULL;
	}
	if (fc->new_section && !(flag & CONFIG_NEW_CMD)) {
		fc->saved_token = fc->token;
		if (eof)
			*eof = REACH_END_OF_SECTION;
		return NULL;
	}

	fc->new_section = 0;

	if (cur_mod)
		*cur_mod = fc->cur_module;

	if (line)
		*line = fc->line_count;

	if (expected_token && strcmp(fc->token, expected_token)) {
		fc->saved_token = fc->token;
		return NULL;
	}
	return fc->token;
}

static int
read_size_entry(struct config *config, int line, int idx)
{
	char *token = get_config_token(NULL, 0, &line, NULL, NULL);

	if (!token || IS_KEYWORD(token)) {
		ERRMSG("Config error at %d: expected size symbol after"
		" 'size' keyword.\n", line);
		return FALSE;
	}
	config->size_symbol[idx] = create_config_entry(token, SIZE_ENTRY, line);
	if (!config->size_symbol[idx]) {
		ERRMSG("Error at line %d: Failed to read size symbol\n",
									line);
		return FALSE;
	}
	if (config->iter_entry && config->size_symbol[idx]->name &&
					(!strcmp(config->size_symbol[idx]->name,
					config->iter_entry->name))) {
		config->size_symbol[idx]->flag &= ~SYMBOL_ENTRY;
		config->size_symbol[idx]->flag |= VAR_ENTRY;
		config->size_symbol[idx]->refer_to = config->iter_entry;
	}
	return TRUE;
}

/*
 * Read erase command entry. The erase command syntax is:
 *
 *	erase <Symbol>[.member[...]] [size <SizeValue>[K|M]]
 *	erase <Symbol>[.member[...]] [size <SizeSymbol>]
 *	erase <Symbol>[.member[...]] [nullify]
 */
static int
read_erase_cmd_entry(struct config *config, int line)
{
	int size, idx;
	char *token = get_config_token(NULL, 0, &line, NULL, NULL);

	if (!token || IS_KEYWORD(token)) {
		ERRMSG("Config error at %d: expected kernel symbol after"
		" 'erase' command.\n", line);
		return FALSE;
	}

	idx = config->num_filter_symbols;
	config->num_filter_symbols++;
	size = config->num_filter_symbols * sizeof(struct config_entry *);
	config->filter_symbol = realloc(config->filter_symbol, size);
	config->size_symbol   = realloc(config->size_symbol, size);

	if (!config->filter_symbol || !config->size_symbol) {
		ERRMSG("Can't get memory to read config symbols.\n");
		return FALSE;
	}
	config->filter_symbol[idx] = NULL;
	config->size_symbol[idx]   = NULL;

	config->filter_symbol[idx] =
			create_config_entry(token, FILTER_ENTRY, line);
	if (!config->filter_symbol[idx]) {
		ERRMSG("Error at line %d: Failed to read filter symbol\n",
									line);
		return FALSE;
	}

	/*
	 * Save the symbol expression string for generation of eraseinfo data
	 * later while writing dumpfile.
	 */
	config->filter_symbol[idx]->symbol_expr = strdup(token);

	if (config->iter_entry) {
		if (strcmp(config->filter_symbol[idx]->name,
				config->iter_entry->name)) {
			ERRMSG("Config error at %d: unused iteration"
				" variable '%s'.\n", line,
				config->iter_entry->name);
			return FALSE;
		}
		config->filter_symbol[idx]->flag &= ~SYMBOL_ENTRY;
		config->filter_symbol[idx]->flag |= VAR_ENTRY;
		config->filter_symbol[idx]->refer_to = config->iter_entry;
	}
	if (get_config_token("nullify", 0, &line, NULL, NULL)) {
		config->filter_symbol[idx]->nullify = 1;

	} else if (get_config_token("size", 0, &line, NULL, NULL)) {
		if (!read_size_entry(config, line, idx))
			return FALSE;
	}
	return TRUE;
}

static int
add_traversal_entry(struct config_entry *ce, char *member, int line)
{
	if (!ce)
		return FALSE;

	while (ce->next)
		ce = ce->next;

	ce->next = create_config_entry(member, LIST_ENTRY, line);
	if (ce->next == NULL) {
		ERRMSG("Error at line %d: Failed to read 'via' member\n",
									line);
		return FALSE;
	}

	ce->next->flag |= TRAVERSAL_ENTRY;
	ce->next->flag &= ~SYMBOL_ENTRY;
	return TRUE;
}

static int
read_list_entry(struct config *config, int line)
{
	char *token = get_config_token(NULL, 0, &line, NULL, NULL);

	if (!token || IS_KEYWORD(token)) {
		ERRMSG("Config error at %d: expected list symbol after"
		" 'in' keyword.\n", line);
		return FALSE;
	}
	config->list_entry = create_config_entry(token, LIST_ENTRY, line);
	if (!config->list_entry) {
		ERRMSG("Error at line %d: Failed to read list symbol\n",
									line);
		return FALSE;
	}
	/* Check if user has provided 'via' or 'within' keyword */
	if (get_config_token("via", 0, &line, NULL, NULL)) {
		/* next token is traversal member NextMember */
		token = get_config_token(NULL, 0, &line, NULL, NULL);
		if (!token) {
			ERRMSG("Config error at %d: expected member name after"
			" 'via' keyword.\n", line);
			return FALSE;
		}
		if (!add_traversal_entry(config->list_entry, token, line))
			return FALSE;
	}
	else if (get_config_token("within", 0, &line, NULL, NULL)) {
		char *s_name, *lh_member;
		/* next value is StructName:ListHeadMember */
		s_name = get_config_token(NULL, 0, &line, NULL, NULL);
		if (!s_name || IS_KEYWORD(s_name)) {
			ERRMSG("Config error at %d: expected struct name after"
			" 'within' keyword.\n", line);
			return FALSE;
		}
		lh_member = strchr(s_name, ':');
		if (lh_member) {
			*lh_member++ = '\0';
			if (!strlen(lh_member)) {
				ERRMSG("Config error at %d: expected list_head"
					" member after ':'.\n", line);
				return FALSE;
			}
			config->iter_entry->next =
				create_config_entry(lh_member,
							ITERATION_ENTRY, line);
			if (!config->iter_entry->next)
				return FALSE;
			config->iter_entry->next->flag &= ~SYMBOL_ENTRY;
		}
		if (!strlen(s_name)) {
			ERRMSG("Config error at %d: Invalid token found "
				"after 'within' keyword.\n", line);
			return FALSE;
		}
		config->iter_entry->type_name = strdup(s_name);
	}
	return TRUE;
}

/*
 * Read the iteration entry (LoopConstruct). The syntax is:
 *
 *	for <id> in {<ArrayVar> |
 *		    <StructVar> via <NextMember> |
 *		    <ListHeadVar> within <StructName>:<ListHeadMember>}
 *		erase <id>[.MemberExpression] [size <SizeExpression>|nullify]
 *		[erase <id>...]
 *		[...]
 *	endfor
 */
static int
read_iteration_entry(struct config *config, int line)
{
	int eof = NOT_REACH_END;
	char *token = get_config_token(NULL, 0, &line, NULL, NULL);

	if (!token || IS_KEYWORD(token)) {
		ERRMSG("Config error at %d: expected iteration VAR entry after"
		" 'for' keyword.\n", line);
		return FALSE;
	}
	config->iter_entry =
		create_config_entry(token, ITERATION_ENTRY, line);
	if (!config->iter_entry) {
		ERRMSG("Error at line %d: "
			"Failed to read iteration VAR entry.\n", line);
		return FALSE;
	}
	if (!get_config_token("in", 0, &line, NULL, NULL)) {
		char *token;
		token = get_config_token(NULL, 0, &line, NULL, NULL);
		if (token)
			ERRMSG("Config error at %d: Invalid token '%s'.\n",
								line, token);
		ERRMSG("Config error at %d: expected token 'in'.\n", line);
		return FALSE;
	}
	if (!read_list_entry(config, line))
		return FALSE;

	while (!get_config_token("endfor", 0, &line, NULL, &eof) && !eof) {
		if (get_config_token("erase", 0, &line, NULL, NULL)) {
			if (!read_erase_cmd_entry(config, line))
				return FALSE;
		} else {
			token = get_config_token(NULL, 0, &line, NULL, NULL);
			ERRMSG("Config error at %d: "
				"Invalid token '%s'.\n", line, token);
			return FALSE;
		}
	}
	if (eof != NOT_REACH_END) {
		ERRMSG("Config error at %d: No matching 'endfor' found.\n",
									line);
		return FALSE;
	}
	return TRUE;
}

/*
 * Configuration file 'makedumpfile.conf' contains filter commands.
 * Every individual filter command is considered as a config entry.
 * A config entry can be provided on a single line or multiple lines.
 */
static struct config *
get_config(int skip)
{
	struct config *config;
	char *token = NULL;
	static int line_count = 0;
	char *cur_module = NULL;
	int eof = NOT_REACH_END;
	unsigned char flag = CONFIG_NEW_CMD;

	if (skip)
		flag |= CONFIG_SKIP_SECTION;

	if ((config = calloc(1, sizeof(struct config))) == NULL)
		return NULL;

	if (get_config_token("erase", flag, &line_count, &cur_module, &eof)) {
		if (cur_module)
			config->module_name = strdup(cur_module);

		if (!read_erase_cmd_entry(config, line_count))
			goto err_out;

	} else if (get_config_token("for", 0, &line_count, &cur_module, &eof)) {
		if (cur_module)
			config->module_name = strdup(cur_module);

		if (!read_iteration_entry(config, line_count))
			goto err_out;
	} else {
		if (eof == NOT_REACH_END) {
			token = get_config_token(NULL, 0, &line_count,
								NULL, NULL);
			ERRMSG("Config error at %d: Invalid token '%s'.\n",
							line_count, token);
		}
		goto err_out;
	}
	return config;
err_out:
	if (config)
		free_config(config);
	return NULL;
}

static unsigned long
read_pointer_value(unsigned long long vaddr)
{
	unsigned long val;

	if (!readmem(VADDR, vaddr, &val, sizeof(val))) {
		ERRMSG("Can't read pointer value\n");
		return 0;
	}
	return val;
}

static long
get_strlen(unsigned long long vaddr)
{
	char buf[BUFSIZE + 1];
	long len = 0;

	/*
	 * Determine the string length for 'char' pointer.
	 * BUFSIZE(1024) is the upper limit for string length.
	 */
	if (readmem(VADDR, vaddr, buf, BUFSIZE)) {
		buf[BUFSIZE] = '\0';
		len = strlen(buf);
	}
	return len;
}

static int
resolve_config_entry(struct config_entry *ce, unsigned long long base_vaddr,
						char *base_struct_name)
{
	unsigned long long symbol;

	if (ce->flag & SYMBOL_ENTRY) {
		/* find the symbol info */
		if (!ce->name)
			return FALSE;

		/*
		 * If we are looking for module symbol then traverse through
		 * mod_st.modules for symbol lookup
		 */
		if (sym_in_module(ce->name, &symbol))
			ce->sym_addr = symbol;
		else
			ce->sym_addr = get_symbol_addr(ce->name);
		if (!ce->sym_addr) {
			ERRMSG("Config error at %d: Can't find symbol '%s'.\n",
							ce->line, ce->name);
			return FALSE;
		}
		ce->sym_addr += get_kaslr_offset(ce->sym_addr);
		ce->type_name = get_symbol_type_name(ce->name,
					DWARF_INFO_GET_SYMBOL_TYPE,
					&ce->size, &ce->type_flag);
		if (ce->type_flag & TYPE_ARRAY) {
			ce->array_length = get_array_length(ce->name, NULL,
					DWARF_INFO_GET_SYMBOL_ARRAY_LENGTH);
			if (ce->array_length < 0)
				ce->array_length = 0;
		}
	} else if (ce->flag & VAR_ENTRY) {
		/* iteration variable.
		 * read the value from ce->refer_to
		 */
		ce->vaddr     = ce->refer_to->vaddr;
		ce->sym_addr  = ce->refer_to->sym_addr;
		ce->size      = ce->refer_to->size;
		ce->type_flag = ce->refer_to->type_flag;
		if (!ce->type_name)
			ce->type_name = strdup(ce->refer_to->type_name);

		/* This entry has been changed hence next entry needs to
		 * be resolved accordingly.
		 */
		if (ce->next)
			ce->next->flag &= ~ENTRY_RESOLVED;
		return TRUE;
	} else {
		/* find the member offset */
		ce->offset = get_member_offset(base_struct_name,
				ce->name, DWARF_INFO_GET_MEMBER_OFFSET);
		ce->sym_addr = base_vaddr + ce->offset;
		ce->type_name = get_member_type_name(base_struct_name,
				ce->name, DWARF_INFO_GET_MEMBER_TYPE,
				&ce->size, &ce->type_flag);
		if (ce->type_flag & TYPE_ARRAY) {
			ce->array_length = get_array_length(base_struct_name,
					ce->name,
					DWARF_INFO_GET_MEMBER_ARRAY_LENGTH);
			if (ce->array_length < 0)
				ce->array_length = 0;
		}
	}
	if (ce->type_name == NULL) {
		if (!(ce->flag & SYMBOL_ENTRY))
			ERRMSG("Config error at %d: struct '%s' has no member"
				" with name '%s'.\n",
				ce->line, base_struct_name, ce->name);
		return FALSE;
	}
	if (!strcmp(ce->type_name, "list_head")) {
		ce->type_flag |= TYPE_LIST_HEAD;
		/* If this list head expression is a LIST entry then
		 * mark the next entry as TRAVERSAL_ENTRY, if any.
		 * Error out if next entry is not a last node.
		 */
		if ((ce->flag & LIST_ENTRY) && ce->next) {
			if (ce->next->next) {
				ERRMSG("Config error at %d: Only one traversal"
					" entry is allowed for list_head type"
					" LIST entry", ce->line);
				return FALSE;
			}
			ce->next->flag |= TRAVERSAL_ENTRY;
		}
	}
	ce->vaddr = ce->sym_addr;
	if (ce->size < 0)
		ce->size = 0;
	if ((ce->flag & LIST_ENTRY) && !ce->next) {
		/* This is the last node of LIST entry.
		 * For the list entry symbol, the allowed data types are:
		 * Array, Structure Pointer (with 'next' member) and list_head.
		 *
		 * If this is a struct or list_head data type then
		 * create a leaf node entry with 'next' member.
		 */
		if (((ce->type_flag & (TYPE_BASE | TYPE_ARRAY)) == TYPE_BASE)
					&& (strcmp(ce->type_name, "void")))
			return FALSE;

		if ((ce->type_flag & TYPE_LIST_HEAD)
			|| ((ce->type_flag & (TYPE_STRUCT | TYPE_ARRAY))
							== TYPE_STRUCT)) {
			if (!(ce->flag & TRAVERSAL_ENTRY)) {
				ce->next = create_config_entry("next",
							LIST_ENTRY, ce->line);
				if (ce->next == NULL)
					return FALSE;

				ce->next->flag |= TRAVERSAL_ENTRY;
				ce->next->flag &= ~SYMBOL_ENTRY;
			}
		}
		if (ce->flag & TRAVERSAL_ENTRY) {
			/* type name of traversal entry should match with
			 * that of parent node.
			 */
			if (strcmp(base_struct_name, ce->type_name))
				return FALSE;
		}
	}
	if ((ce->type_flag & (TYPE_ARRAY | TYPE_PTR)) == TYPE_PTR) {
		/* If it's a pointer variable (not array) then read the
		 * pointer value. */
		ce->vaddr = read_pointer_value(ce->sym_addr);

		/*
		 * if it is a void pointer then reset the size to 0
		 * User need to provide a size to filter data referenced
		 * by 'void *' pointer or nullify option.
		 */
		if (!strcmp(ce->type_name, "void"))
			ce->size = 0;

	}
	if ((ce->type_flag & TYPE_BASE) && (ce->type_flag & TYPE_PTR)
					&& !(ce->type_flag & TYPE_ARRAY)) {
		if (!strcmp(ce->type_name, "char"))
			ce->size = get_strlen(ce->vaddr);
	}
	if (!ce->next && (ce->flag & SIZE_ENTRY)) {
		void *val;

		/* leaf node of size entry */
		/* If it is size argument then update the size with data
		 * value of this symbol/member.
		 * Check if current symbol/member is of base data type.
		 */

		if (((ce->type_flag & (TYPE_ARRAY | TYPE_BASE)) != TYPE_BASE)
				|| (ce->size > sizeof(long))) {
			ERRMSG("Config error at %d: size symbol/member '%s' "
				"is not of base type.\n", ce->line, ce->name);
			return FALSE;
		}
		if ((val = calloc(1, ce->size)) == NULL) {
			ERRMSG("Can't get memory for size parameter\n");
			return FALSE;
		}

		if (!readmem(VADDR, ce->vaddr, val, ce->size)) {
			ERRMSG("Can't read symbol/member data value\n");
			return FALSE;
		}
		switch (ce->size) {
		case 1:
			ce->size = (long)(*((uint8_t *)val));
			break;
		case 2:
			ce->size = (long)(*((uint16_t *)val));
			break;
		case 4:
			ce->size = (long)(*((uint32_t *)val));
			break;
		case 8:
			ce->size = (long)(*((uint64_t *)val));
			break;
		}
		free(val);
	}
	ce->flag |= ENTRY_RESOLVED;
	if (ce->next)
		ce->next->flag &= ~ENTRY_RESOLVED;
	return TRUE;
}

static unsigned long long
get_config_symbol_addr(struct config_entry *ce,
			unsigned long long base_vaddr,
			char *base_struct_name)
{
	if (!(ce->flag & ENTRY_RESOLVED)) {
		if (!resolve_config_entry(ce, base_vaddr, base_struct_name))
			return 0;
	}

	if (ce->next && ce->vaddr) {
		/* Populate nullify flag down the list */
		ce->next->nullify = ce->nullify;
		return get_config_symbol_addr(ce->next, ce->vaddr,
							ce->type_name);
	} else if (!ce->next && ce->nullify) {
		/* nullify is applicable to pointer type */
		if (ce->type_flag & TYPE_PTR)
			return ce->sym_addr;
		else
			return 0;
	} else
		return ce->vaddr;
}

static long
get_config_symbol_size(struct config_entry *ce,
			unsigned long long base_vaddr,
			char *base_struct_name)
{
	if (!(ce->flag & ENTRY_RESOLVED)) {
		if (!resolve_config_entry(ce, base_vaddr, base_struct_name))
			return 0;
	}

	if (ce->next && ce->vaddr)
		return get_config_symbol_size(ce->next, ce->vaddr,
							ce->type_name);
	else {
		if (ce->type_flag & TYPE_ARRAY) {
			if (ce->type_flag & TYPE_PTR)
				return ce->array_length * get_pointer_size();
			else
				return ce->array_length * ce->size;
		}
		return ce->size;
	}
}

static int
get_next_list_entry(struct config_entry *ce, unsigned long long base_vaddr,
			char *base_struct_name, struct config_entry *out_ce)
{
	unsigned long vaddr = 0;

	/* This function only deals with LIST_ENTRY config entry. */
	if (!(ce->flag & LIST_ENTRY))
		return FALSE;

	if (!(ce->flag & ENTRY_RESOLVED)) {
		if (!resolve_config_entry(ce, base_vaddr, base_struct_name))
			return FALSE;
	}

	if (!ce->next) {
		/* leaf node. */
		if (ce->type_flag & TYPE_ARRAY) {
			if (ce->index == ce->array_length)
				return FALSE;

			if (ce->type_flag & TYPE_PTR) {
				/* Array of pointers.
				 *
				 * Array may contain NULL pointers at some
				 * indexes. Hence jump to the next non-null
				 * address value.
				 */
				while (ce->index < ce->array_length) {
					vaddr = read_pointer_value(ce->vaddr +
						(ce->index * get_pointer_size()));
					if (vaddr)
						break;
					ce->index++;
				}
				if (ce->index == ce->array_length)
					return FALSE;
				out_ce->sym_addr = ce->vaddr + (ce->index *
							get_pointer_size());
				out_ce->vaddr = vaddr;
				if (!strcmp(ce->type_name, "char"))
					out_ce->size = get_strlen(vaddr);
				else
					out_ce->size = ce->size;
			} else {
				out_ce->sym_addr = ce->vaddr +
							(ce->index * ce->size);
				out_ce->vaddr = out_ce->sym_addr;
				out_ce->size  = ce->size;
			}
			ce->index++;
		} else {
			if (ce->vaddr == ce->cmp_addr)
				return FALSE;

			out_ce->vaddr = ce->vaddr;
			/* Set the leaf node as unresolved, so that
			 * it will be resolved every time when
			 * get_next_list_entry is called untill
			 * it hits the exit condiftion.
			 */
			ce->flag &= ~ENTRY_RESOLVED;
		}
		return TRUE;

	} else if ((ce->next->next == NULL) &&
				!(ce->next->type_flag & TYPE_ARRAY)) {
		/* the next node is leaf node. for non-array element
		 * Set the sym_addr and addr of this node with that of
		 * leaf node.
		 */
		if (!(ce->type_flag & TYPE_LIST_HEAD)) {
			if (!ce->vaddr || ce->vaddr == ce->next->cmp_addr)
				return FALSE;

			if (!ce->next->cmp_addr) {
				/* safeguard against circular
				 * link-list
				 */
				ce->next->cmp_addr = ce->vaddr;
			}
			out_ce->vaddr    = ce->vaddr;
			out_ce->sym_addr = ce->sym_addr;
			out_ce->size     = ce->size;

			ce->sym_addr = ce->next->sym_addr;
			ce->vaddr    = ce->next->vaddr;

			/* Force resolution of traversal node */
			if (ce->vaddr && !resolve_config_entry(ce->next,
					ce->vaddr, ce->type_name))
				return FALSE;

			return TRUE;
		} else {
			ce->sym_addr = ce->next->sym_addr;
			ce->vaddr    = ce->next->vaddr;
		}
	}

	if (ce->next && ce->vaddr)
		return get_next_list_entry(ce->next, ce->vaddr,
						ce->type_name, out_ce);
	return FALSE;
}

static int
resolve_list_entry(struct config_entry *ce, unsigned long long base_vaddr,
			char *base_struct_name, char **out_type_name,
			unsigned char *out_type_flag)
{
	if (!(ce->flag & ENTRY_RESOLVED)) {
		if (!resolve_config_entry(ce, base_vaddr, base_struct_name))
			return FALSE;
	}

	if (ce->next && (ce->next->flag & TRAVERSAL_ENTRY) &&
				(ce->type_flag & TYPE_ARRAY)) {
		/*
		 * We are here because user has provided
		 * traversal member for ArrayVar using 'via' keyword.
		 *
		 * Print warning and continue.
		 */
		ERRMSG("Warning: line %d: 'via' keyword not required "
			"for ArrayVar.\n", ce->next->line);
		free_config_entry(ce->next);
		ce->next = NULL;
	}
	if ((ce->type_flag & TYPE_LIST_HEAD) && ce->next &&
			(ce->next->flag & TRAVERSAL_ENTRY)) {
		/* set cmp_addr for list empty condition.  */
		ce->next->cmp_addr = ce->sym_addr;
	}
	if (ce->next && ce->vaddr) {
		return resolve_list_entry(ce->next, ce->vaddr,
				ce->type_name, out_type_name, out_type_flag);
	}
	else {
		ce->index = 0;
		if (out_type_name)
			*out_type_name = ce->type_name;
		if (out_type_flag)
			*out_type_flag = ce->type_flag;
	}
	return TRUE;
}

/*
 * Insert the filter info node using insertion sort.
 * If filter node for a given paddr is aready present then update the size
 * and delete the fl_info node passed.
 *
 * Return 1 on successfull insertion.
 * Return 0 if filter node with same paddr is found.
 */
static int
insert_filter_info(struct filter_info *fl_info)
{
	struct filter_info *prev = NULL;
	struct filter_info *ptr  = filter_info;

	if (!ptr) {
		filter_info = fl_info;
		return 1;
	}

	while (ptr) {
		if (fl_info->paddr <= ptr->paddr)
			break;
		prev = ptr;
		ptr  = ptr->next;
	}
	if (ptr && (fl_info->paddr == ptr->paddr)) {
		if (fl_info->size > ptr->size)
			ptr->size = fl_info->size;
		free(fl_info);
		return 0;
	}

	if (prev) {
		fl_info->next = ptr;
		prev->next    = fl_info;
	}
	else {
		fl_info->next = filter_info;
		filter_info   = fl_info;
	}
	return 1;
}

/*
 * Create an erase info node for each erase command. One node per erase
 * command even if it is part of loop construct.
 * For erase commands that are not part of loop construct, the num_sizes will
 * always be 1
 * For erase commands that are part of loop construct, the num_sizes may be
 * 1 or >1 depending on number iterations. This function will called multiple
 * times depending on iterations. At first invokation create a node and
 * increment num_sizes for subsequent invokations.
 *
 * The valid erase info node starts from index value 1. (index 0 is invalid
 * index).
 *
 *            Index 0     1        2        3
 *             +------+--------+--------+--------+
 * erase_info->|Unused|        |        |        |......
 *             +------+--------+--------+--------+
 *                        |        .        .        .....
 *                        V
 *                   +---------+
 *                   | char*   |----> Original erase command string
 *                   +---------+
 *                   |num_sizes|
 *                   +---------+      +--+--+--+
 *                   | sizes   |----> |  |  |  |... Sizes array of num_sizes
 *                   +---------+      +--+--+--+
 *
 * On success, return the index value of erase node for given erase command.
 * On failure, return 0.
 */
static int
add_erase_info_node(struct config_entry *filter_symbol)
{
	int idx = filter_symbol->erase_info_idx;

	/*
	 * Check if node is already created, if yes, increment the num_sizes.
	 */
	if (idx) {
		erase_info[idx].num_sizes++;
		return idx;
	}

	/* Allocate a new node. */
	DEBUG_MSG("Allocating new erase info node for command \"%s\"\n",
			filter_symbol->symbol_expr);
	idx = num_erase_info++;
	erase_info = realloc(erase_info,
			sizeof(struct erase_info) * num_erase_info);
	if (!erase_info) {
		ERRMSG("Can't get memory to create erase information.\n");
		return 0;
	}

	memset(&erase_info[idx], 0, sizeof(struct erase_info));
	erase_info[idx].symbol_expr = filter_symbol->symbol_expr;
	erase_info[idx].num_sizes   = 1;

	filter_symbol->symbol_expr    = NULL;
	filter_symbol->erase_info_idx = idx;

	return idx;
}

/* Return the index value in sizes array for given erase command index. */
static inline int
get_size_index(int ei_idx)
{
	if (ei_idx)
		return erase_info[ei_idx].num_sizes - 1;
	return 0;
}

static int
update_filter_info(struct config_entry *filter_symbol,
			struct config_entry *size_symbol)
{
	unsigned long long sym_addr;
	long size;
	struct filter_info *fl_info;

	sym_addr = get_config_symbol_addr(filter_symbol, 0, NULL);
	if (message_level & ML_PRINT_DEBUG_MSG)
		print_config_entry(filter_symbol);
	if (!sym_addr)
		return FALSE;

	if (filter_symbol->nullify)
		size = get_pointer_size();
	else if (size_symbol) {
		size = get_config_symbol_size(size_symbol, 0, NULL);
		if (message_level & ML_PRINT_DEBUG_MSG)
			print_config_entry(size_symbol);
	} else
		size = get_config_symbol_size(filter_symbol, 0, NULL);

	if (size <= 0)
		return FALSE;

	if ((fl_info = calloc(1, sizeof(struct filter_info))) == NULL) {
		ERRMSG("Can't allocate filter info\n");
		return FALSE;
	}
	fl_info->vaddr   = sym_addr;
	fl_info->paddr   = vaddr_to_paddr(sym_addr);
	fl_info->size    = size;
	fl_info->nullify = filter_symbol->nullify;
	fl_info->erase_ch = 'X';

	if (insert_filter_info(fl_info)) {
		fl_info->erase_info_idx = add_erase_info_node(filter_symbol);
		fl_info->size_idx = get_size_index(fl_info->erase_info_idx);
	}
	return TRUE;
}

int
update_filter_info_raw(unsigned long long sym_addr, int ch, int len)
{
	struct filter_info *fl_info;

	fl_info = calloc(1, sizeof(struct filter_info));
	if (fl_info == NULL) {
		ERRMSG("Can't allocate filter info\n");
		return FALSE;
	}

	fl_info->vaddr   = sym_addr;
	fl_info->paddr   = vaddr_to_paddr(sym_addr);
	fl_info->size    = len;
	fl_info->nullify = 0;
	fl_info->erase_ch = ch;

	if (insert_filter_info(fl_info)) {
		/* TODO
		 * Add support to update erase information to the
		 * resulting dump file
		 */
		fl_info->erase_info_idx = 0;
		fl_info->size_idx = 0;
	}
	return TRUE;
}

static int
initialize_iteration_entry(struct config_entry *ie,
				char *type_name, unsigned char type_flag)
{
	if (!(ie->flag & ITERATION_ENTRY))
		return FALSE;

	if (type_flag & TYPE_LIST_HEAD) {
		if (!ie->type_name) {
			ERRMSG("Config error at %d: Use 'within' keyword "
				"to specify StructName:ListHeadMember.\n",
				ie->line);
			return FALSE;
		}
		/*
		 * If the LIST entry is of list_head type and user has not
		 * specified the member name where iteration entry is hooked
		 * on to list_head, then we default to member name 'list'.
		 */
		if (!ie->next) {
			ie->next = create_config_entry("list", ITERATION_ENTRY,
								ie->line);
			ie->next->flag &= ~SYMBOL_ENTRY;
		}

		/*
		 * For list_head find out the size of the StructName and
		 * populate ie->size now. For array and link list we get the
		 * size info from config entry returned by
		 * get_next_list_entry().
		 */
		ie->size = get_structure_size(ie->type_name, 0);
		if (ie->size == FAILED_DWARFINFO) {
			ERRMSG("Config error at %d: "
				"Can't get size for type: %s.\n",
				ie->line, ie->type_name);
			return FALSE;

		} else if (ie->size == NOT_FOUND_STRUCTURE) {
			ERRMSG("Config error at %d: "
				"Can't find structure: %s.\n",
				ie->line, ie->type_name);
			return FALSE;
		}

		if (!resolve_config_entry(ie->next, 0, ie->type_name))
			return FALSE;

		if (strcmp(ie->next->type_name, "list_head")) {
			ERRMSG("Config error at %d: "
				"Member '%s' is not of 'list_head' type.\n",
				ie->next->line, ie->next->name);
			return FALSE;
		}
		ie->type_flag = TYPE_STRUCT;
	} else {
		if (ie->type_name) {
			/* looks like user has used 'within' keyword for
			 * non-list_head VAR. Print the warning and continue.
			 */
			ERRMSG("Warning: line %d: 'within' keyword not "
				"required for ArrayVar/StructVar.\n", ie->line);
			free(ie->type_name);

			/* remove the next list_head member from iteration
			 * entry that would have added as part of 'within'
			 * keyword processing.
			 */
			if (ie->next) {
				free_config_entry(ie->next);
				ie->next = NULL;
			}
		}
		/*
		 * Set type flag for iteration entry. The iteration entry holds
		 * individual element from array/list, hence strip off the
		 * array type flag bit.
		 */
		ie->type_name = strdup(type_name);
		ie->type_flag = type_flag;
		ie->type_flag &= ~TYPE_ARRAY;
	}
	return TRUE;
}

static int
list_entry_empty(struct config_entry *le, struct config_entry *ie)
{
	struct config_entry ce;

	/* Error out if arguments are not correct */
	if (!(le->flag & LIST_ENTRY) || !(ie->flag & ITERATION_ENTRY)) {
		ERRMSG("Invalid arguments\n");
		return TRUE;
	}

	memset(&ce, 0, sizeof(struct config_entry));
	/* get next available entry from LIST entry. */
	if (!get_next_list_entry(le, 0, NULL, &ce))
		return TRUE;

	if (ie->next) {
		/* we are dealing with list_head */
		ie->next->vaddr = ce.vaddr;
		ie->vaddr       = ce.vaddr - ie->next->offset;
	} else {
		ie->vaddr    = ce.vaddr;
		ie->sym_addr = ce.sym_addr;
		ie->size     = ce.size;
	}
	return FALSE;
}

/*
 * Process the config entry that has been read by get_config.
 * return TRUE on success
 */
static int
process_config(struct config *config)
{
	int i;
	unsigned char type_flag;
	char *type_name = NULL;

	if (config->list_entry) {
		/*
		 * We are dealing with 'for' command.
		 * - First resolve list entry.
		 * - Initialize iteration entry for iteration.
		 * - Populate iteration entry untill list entry empty.
		 */
		if (!resolve_list_entry(config->list_entry, 0, NULL,
					&type_name, &type_flag)) {
			return FALSE;
		}
		if (!initialize_iteration_entry(config->iter_entry,
						type_name, type_flag)) {
			return FALSE;
		}

		while (!list_entry_empty(config->list_entry,
						config->iter_entry)) {
			for (i = 0; i < config->num_filter_symbols; i++)
				update_filter_info(config->filter_symbol[i],
						   config->size_symbol[i]);
		}
	} else
		update_filter_info(config->filter_symbol[0],
				   config->size_symbol[0]);

	return TRUE;
}

static void
print_filter_info()
{
	struct filter_info *fl_info = filter_info;

	DEBUG_MSG("\n");
	while (fl_info) {
		DEBUG_MSG("filter address: paddr (%llx), sym_addr (%llx),"
			" Size (%ld)\n",
			fl_info->paddr, fl_info->vaddr, fl_info->size);
		fl_info = fl_info->next;
	}
}

static void
init_filter_config()
{
	filter_config.name_filterconfig = info->name_filterconfig;
	filter_config.file_filterconfig = info->file_filterconfig;
	filter_config.saved_token = NULL;
	filter_config.token       = NULL;
	filter_config.cur_module  = NULL;
	filter_config.new_section = 0;
	filter_config.line_count  = 0;
}

/*
 * Read and process each config entry (filter commands) from filter config
 * file. If no module debuginfo found for specified module section then skip
 * to next module section.
 */
static int
process_config_file(const char *name_config)
{
	struct config *config;
	int skip_section = 0;

	if (!name_config)
		return FALSE;

	if ((info->file_filterconfig = fopen(name_config, "r")) == NULL) {
		ERRMSG("Can't open config file(%s). %s\n",
		    name_config, strerror(errno));
		return FALSE;
	}

	init_filter_config();

	while((config = get_config(skip_section)) != NULL) {
		skip_section = 0;
		if (config->module_name &&
				strcmp(config->module_name, "vmlinux")) {
			/*
			 * if Module debuginfo is not available, then skip to
			 * next module section.
			 */
			if (!set_dwarf_debuginfo(config->module_name,
				  info->system_utsname.release, NULL, -1)) {
				ERRMSG("Skipping to next Module section\n");
				skip_section = 1;
				free_config(config);
				continue;
			}
		} else {
			set_dwarf_debuginfo("vmlinux", NULL,
				info->name_vmlinux, info->fd_vmlinux);
		}
		process_config(config);
		free_config(config);
	}

	fclose(info->file_filterconfig);
	print_filter_info();
	return TRUE;
}

/*
 * Search for symbol in modules as well as vmlinux
 */
unsigned long long
get_symbol_addr_all(char *name) {

	short vmlinux_searched = 0;
	unsigned long long symbol_addr = 0;
	unsigned int i, current_mod;
	struct module_info *modules;

	/* Search in vmlinux if debuginfo is set to vmlinux */
	if (!strcmp(get_dwarf_module_name(), "vmlinux")) {
		symbol_addr = get_symbol_addr(name);
		if (symbol_addr)
			return symbol_addr;

		vmlinux_searched = 1;
	}

	/*
	 * Proceed the search in modules. Try in the module
	 * which resulted in a hit in the previous search
	 */

	modules = mod_st.modules;
	current_mod = mod_st.current_mod;

	if (strcmp(get_dwarf_module_name(), modules[current_mod].name)) {
		if (!set_dwarf_debuginfo(modules[current_mod].name,
				info->system_utsname.release, NULL, -1)) {
			ERRMSG("Cannot set to current module %s\n",
					modules[current_mod].name);
			return NOT_FOUND_SYMBOL;
		}
	}

	symbol_addr = find_module_symbol(&modules[current_mod], name);
	if (symbol_addr)
		return symbol_addr;

	/* Search in all modules */
	for (i = 0; i < mod_st.num_modules; i++) {

		/* Already searched. Skip */
		if (i == current_mod)
			continue;

		if (!set_dwarf_debuginfo(modules[i].name,
				info->system_utsname.release, NULL, -1)) {
			ERRMSG("Skipping Module section %s\n", modules[i].name);
			continue;
		}

		symbol_addr = find_module_symbol(&modules[i], name);

		if (!symbol_addr)
			continue;

		/*
		 * Symbol found. Set the current_mod to this module index, a
		 * minor optimization for fast lookup next time
		 */
		mod_st.current_mod = i;
		return symbol_addr;
	}

	/* Symbol not found in any module. Set debuginfo back to vmlinux  */
	set_dwarf_debuginfo("vmlinux", NULL, info->name_vmlinux,
			info->fd_vmlinux);

	/*
	 * Search vmlinux if not already searched. This can happen when
	 * this function is called with debuginfo set to a particular
	 * kernel module and we are looking for symbol in vmlinux
	 */
	if (!vmlinux_searched)
		return get_symbol_addr(name);
	else
		return NOT_FOUND_SYMBOL;
}


/*
 * Search for domain in modules as well as vmlinux
 */
long
get_domain_all(char *symname, int cmd, unsigned long long *die) {

	short vmlinux_searched = 0;
	long size = 0;
	unsigned int i, current_mod;
	struct module_info *modules;

	/* Search in vmlinux if debuginfo is set to vmlinux */
	if (!strcmp(get_dwarf_module_name(), "vmlinux")) {
		size = get_domain(symname, cmd, die);
		if (size > 0 && die)
			return size;

		vmlinux_searched = 1;
	}

	/*
	 * Proceed the search in modules. Try in the module
	 * which resulted in a hit in the previous search
	 */

	modules = mod_st.modules;
	current_mod = mod_st.current_mod;

	if (strcmp(get_dwarf_module_name(), modules[current_mod].name)) {
		if (!set_dwarf_debuginfo(modules[current_mod].name,
				info->system_utsname.release, NULL, -1)) {
			ERRMSG("Cannot set to current module %s\n",
					modules[current_mod].name);
			return NOT_FOUND_STRUCTURE;
		}
	}

	size = get_domain(symname, cmd, die);
	if (size > 0 && die)
		return size;

	/* Search in all modules */
	for (i = 0; i < mod_st.num_modules; i++) {

		/* Already searched. Skip */
		if (i == current_mod)
			continue;

		if (!set_dwarf_debuginfo(modules[i].name,
				info->system_utsname.release, NULL, -1)) {
			ERRMSG("Skipping Module section %s\n", modules[i].name);
			continue;
		}

		size = get_domain(symname, cmd, die);

		if (size <= 0 || !die)
			continue;

		/*
		 * Domain found. Set the current_mod to this module index, a
		 * minor optimization for fast lookup next time
		 */
		mod_st.current_mod = i;
		return size;
	}

	/* Domain not found in any module. Set debuginfo back to vmlinux */
	set_dwarf_debuginfo("vmlinux", NULL, info->name_vmlinux,
			info->fd_vmlinux);

	if (!vmlinux_searched)
		return get_domain(symname, cmd, die);
	else
		return NOT_FOUND_STRUCTURE;
}

/*
 * Search for die in modules as well as vmlinux
 */
int
get_die_nfields_all(unsigned long long die_off)
{
	short vmlinux_searched = 0;
	long nfields = -1;
	unsigned int i, current_mod;
	struct module_info *modules;

	/* Search in vmlinux if debuginfo is set to vmlinux */
	if (!strcmp(get_dwarf_module_name(), "vmlinux")) {
		nfields = get_die_nfields(die_off);
		if (nfields > 0)
			return nfields;

		vmlinux_searched = 1;
	}

	/*
	 * Proceed the search in modules. Try in the module
	 * which resulted in a hit in the previous search
	 */

	modules = mod_st.modules;
	current_mod = mod_st.current_mod;

	if (strcmp(get_dwarf_module_name(), modules[current_mod].name)) {
		if (!set_dwarf_debuginfo(modules[current_mod].name,
				info->system_utsname.release, NULL, -1)) {
			ERRMSG("Cannot set to current module %s\n",
					modules[current_mod].name);
			return -1;
		}
	}

	nfields = get_die_nfields(die_off);
	if (nfields > 0)
		return nfields;

	/* Search in all modules */
	for (i = 0; i < mod_st.num_modules; i++) {

		/* Already searched. Skip */
		if (i == current_mod)
			continue;

		if (!set_dwarf_debuginfo(modules[i].name,
				info->system_utsname.release, NULL, -1)) {
			ERRMSG("Skipping Module section %s\n", modules[i].name);
			continue;
		}

		nfields = get_die_nfields(die_off);

		if (nfields < 0)
			continue;

		/*
		 * Die found. Set the current_mod to this module index,
		 * a minor optimization for fast lookup next time
		 */
		mod_st.current_mod = i;
		return nfields;
	}

	/* Die not found in any module. Set debuginfo back to vmlinux */
	set_dwarf_debuginfo("vmlinux", NULL, info->name_vmlinux,
			info->fd_vmlinux);

	if (!vmlinux_searched)
		return get_die_nfields(die_off);
	else
		return -1;

}

/*
 * Search for die member in modules as well as vmlinux
 */
int
get_die_member_all(unsigned long long die_off, int index, long *offset,
		char **name, int *nbits, int *fbits, unsigned long long *m_die)
{
	short vmlinux_searched = 0;
	long size = -1;
	unsigned int i, current_mod;
	struct module_info *modules;

	/* Search in vmlinux if debuginfo is set to vmlinux */
	if (!strcmp(get_dwarf_module_name(), "vmlinux")) {
		size = get_die_member(die_off, index, offset, name,
				nbits, fbits, m_die);
		if (size >= 0)
			return size;

		vmlinux_searched = 1;
	}

	/*
	 * Proceed the search in modules. Try in the module
	 * which resulted in a hit in the previous search
	 */

	modules = mod_st.modules;
	current_mod = mod_st.current_mod;

	if (strcmp(get_dwarf_module_name(), modules[current_mod].name)) {
		if (!set_dwarf_debuginfo(modules[current_mod].name,
				info->system_utsname.release, NULL, -1)) {
			ERRMSG("Cannot set to current module %s\n",
					modules[current_mod].name);
			return -1;
		}
	}

	size = get_die_member(die_off, index, offset, name,
				nbits, fbits, m_die);
	if (size >= 0)
		return size;

	/* Search in all modules */
	for (i = 0; i < mod_st.num_modules; i++) {

		/* Already searched. Skip */
		if (i == current_mod)
			continue;

		if (!set_dwarf_debuginfo(modules[i].name,
				info->system_utsname.release, NULL, -1)) {
			ERRMSG("Skipping Module section %s\n", modules[i].name);
			continue;
		}

		size = get_die_member(die_off, index, offset, name,
				nbits, fbits, m_die);

		if (size < 0)
			continue;

		/*
		 * Die member found. Set the current_mod to this module index,
		 * a minor optimization for fast lookup next time
		 */
		mod_st.current_mod = i;
		return size;
	}

	/* Die member not found in any module. Set debuginfo back to vmlinux */
	set_dwarf_debuginfo("vmlinux", NULL, info->name_vmlinux,
			info->fd_vmlinux);

	if (!vmlinux_searched)
		return get_die_member(die_off, index, offset, name,
				nbits, fbits, m_die);
	else
		return -1;
}

/* Process the eppic macro using eppic library */
static int
process_eppic_file(char *name_config)
{
	void *handle;
	void (*eppic_load)(char *), (*eppic_unload)(char *);
	int (*eppic_init)();

	/*
	 * Dynamically load the eppic_makedumpfile.so library.
	 */
	handle = dlopen("eppic_makedumpfile.so", RTLD_LAZY);
	if (!handle) {
		ERRMSG("dlopen failed: %s\n", dlerror());
		return FALSE;
	}

	/* TODO
	 * Support specifying eppic macros in makedumpfile.conf file
	 */

	eppic_init = dlsym(handle, "eppic_init");
	if (!eppic_init) {
		ERRMSG("Could not find eppic_init function\n");
		return FALSE;
	}

	eppic_load = dlsym(handle, "eppic_load");
	if (!eppic_load) {
		ERRMSG("Could not find eppic_load function\n");
		return FALSE;
	}

	eppic_unload = dlsym(handle, "eppic_unload");
	if (!eppic_unload)
		ERRMSG("Could not find eppic_unload function\n");

	if (eppic_init(&eppic_cb)) {
		ERRMSG("Init failed \n");
		return FALSE;
	}

	/* Load/compile, execute and unload the eppic macro */
	eppic_load(name_config);
	eppic_unload(name_config);

	if (dlclose(handle))
		ERRMSG("dlclose failed: %s\n", dlerror());

	return TRUE;
}

static void
split_filter_info(struct filter_info *prev, unsigned long long next_paddr,
						size_t size)
{
	struct filter_info *new;

	if ((new = calloc(1, sizeof(struct filter_info))) == NULL) {
		ERRMSG("Can't allocate memory to split filter info\n");
		return;
	}

	/*
	 * copy over existing data from prev node and only update fields
	 * that differ. This approach will take care of copying over of any
	 * future member addition to filter_info structure.
	 */
	*new = *prev;
	new->paddr          = next_paddr;
	new->size           = size;
	prev->next          = new;
}

static void
update_erase_info(struct filter_info *fi)
{
	struct erase_info *ei;

	if (!fi->erase_info_idx)
		return;

	ei = &erase_info[fi->erase_info_idx];

	if (!ei->sizes) {
		/* First time, allocate sizes array */
		ei->sizes = calloc(ei->num_sizes, sizeof(long));
		if (!ei->sizes) {
			ERRMSG("Can't allocate memory for erase info sizes\n");
			return;
		}
	}
	ei->erased = 1;
	if (!fi->nullify)
		ei->sizes[fi->size_idx] += fi->size;
	else
		ei->sizes[fi->size_idx] = -1;
}

static int
extract_filter_info(unsigned long long start_paddr,
			unsigned long long end_paddr,
			struct filter_info *fl_info)
{
	struct filter_info *fi = filter_info;
	struct filter_info *prev = NULL;
	size_t size1, size2;

	if (!fl_info)
		return FALSE;

	while (fi) {
		if ((fi->paddr >= start_paddr) && (fi->paddr < end_paddr)) {
			size1 = end_paddr - fi->paddr;
			if (fi->size <= size1)
				break;
			size2 = fi->size - size1;
			fi->size = size1;
			split_filter_info(fi, fi->paddr + size1, size2);
			break;
		}
		prev = fi;
		fi   = fi->next;
	}
	if (!fi)
		return FALSE;

	*fl_info      = *fi;
	fl_info->next = NULL;

	/* Delete this node */
	if (!prev)
		filter_info = fi->next;
	else
		prev->next  = fi->next;
	update_erase_info(fi);
	free(fi);

	return TRUE;
}

/*
 * External functions.
 */
int
gather_filter_info(void)
{
	int ret = TRUE;

	/*
	 * Before processing filter config file, load the symbol data of
	 * loaded modules from vmcore.
	 */
	set_dwarf_debuginfo("vmlinux", NULL,
			    info->name_vmlinux, info->fd_vmlinux);
	if (!load_module_symbols())
		return FALSE;

	/*
	 * XXX: We support specifying both makedumpfile.conf and
	 * eppic macro at the same time. Whether to retain or discard the
	 * functionality provided by makedumpfile.conf is open for
	 * discussion
	 */
	if (info->name_filterconfig)
		ret = process_config_file(info->name_filterconfig);

	if (info->name_eppic_config)
		ret &= process_eppic_file(info->name_eppic_config);

	/*
	 * Remove modules symbol information, we dont need now.
	 * Reset the dwarf debuginfo to vmlinux to close open file
	 * descripter of module debuginfo file, if any.
	 */
	clean_module_symbols();
	set_dwarf_debuginfo("vmlinux", NULL,
			    info->name_vmlinux, info->fd_vmlinux);
	return ret;
}

void
clear_filter_info(void)
{
	struct filter_info *prev, *fi = filter_info;
	int i;

	/* Delete filter_info nodes that are left out. */
	while (fi) {
		prev = fi;
		fi = fi->next;
		free(prev);
	}
	filter_info = NULL;

	if (erase_info == NULL)
		return;

	for (i = 1; i < num_erase_info; i++) {
		free(erase_info[i].symbol_expr);
		free(erase_info[i].sizes);
	}
	free(erase_info);
	erase_info = NULL;
}

/*
 * Filter buffer if the physical address is in filter_info.
 */
void
filter_data_buffer(unsigned char *buf, unsigned long long paddr,
					size_t size)
{
	struct filter_info fl_info;
	unsigned char *buf_ptr;

	while (extract_filter_info(paddr, paddr + size, &fl_info)) {
		buf_ptr = buf + (fl_info.paddr - paddr);
		if (fl_info.nullify)
			memset(buf_ptr, 0, fl_info.size);
		else
			memset(buf_ptr, fl_info.erase_ch, fl_info.size);
	}
}

/*
 * Filter buffer if the physical address is in filter_info.
 */
void
filter_data_buffer_parallel(unsigned char *buf, unsigned long long paddr,
					size_t size, pthread_mutex_t *mutex)
{
	struct filter_info fl_info;
	unsigned char *buf_ptr;
	int found = FALSE;

	while (TRUE) {
		pthread_mutex_lock(mutex);
		found = extract_filter_info(paddr, paddr + size, &fl_info);
		pthread_mutex_unlock(mutex);

		if (found) {
			buf_ptr = buf + (fl_info.paddr - paddr);
			if (fl_info.nullify)
				memset(buf_ptr, 0, fl_info.size);
			else
				memset(buf_ptr, fl_info.erase_ch, fl_info.size);
		} else {
			break;
		}
	}
}

unsigned long
get_size_eraseinfo(void)
{
	unsigned long size_eraseinfo = 0;
	char size_str[MAX_SIZE_STR_LEN];
	struct erase_info *ei;
	struct filter_info *fl_info = filter_info;

	while (fl_info) {

		if (!fl_info->erase_info_idx)
			continue;
		ei = &erase_info[fl_info->erase_info_idx];
		if (fl_info->nullify)
			sprintf(size_str, "nullify\n");
		else
			sprintf(size_str, "size %ld\n", fl_info->size);

		size_eraseinfo += strlen("erase ") +
				strlen(ei->symbol_expr) + 1 +
				strlen(size_str);
		fl_info = fl_info->next;
	}

	return size_eraseinfo;
}

