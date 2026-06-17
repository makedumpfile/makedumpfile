#define _GNU_SOURCE
#include <stdbool.h>
#ifdef EXTENSION
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "makedumpfile.h"
#include "kallsyms.h"

static uint32_t *kallsyms_offsets = NULL;
static uint16_t *kallsyms_token_index = NULL;
static uint8_t  *kallsyms_token_table = NULL;
static uint8_t  *kallsyms_names = NULL;
static unsigned long kallsyms_relative_base = 0;
static unsigned int kallsyms_num_syms = 0;

/* makedumpfile & extensions' .init_ksyms section range array */
static struct section_range **sr = NULL;
static int sr_len = 0;
static int sr_cap = 0;

/* Which mod's kallsyms should be inited? */
static char **mods = NULL;
static int mods_len = 0;
static int mods_cap = 0;

INIT_MOD_SYM(vmlinux, _stext);

/*
 * Utility: add elem to arr, which can auto extend its capacity.
 * (*arr) is a pointer array, holding pointers of elem
*/
bool add_to_arr(void ***arr, int *arr_len, int *arr_cap, void *elem)
{
	void *tmp;
	int new_cap = 0;

	if (*arr == NULL) {
		*arr_len = 0;
		new_cap = 4;
	} else if (*arr_len >= *arr_cap) {
		new_cap = (*arr_cap) + ((*arr_cap) >> 1);
	}

	if (new_cap) {
		tmp = reallocarray(*arr, new_cap, sizeof(void *));
		if (!tmp)
			goto no_mem;
		*arr = tmp;
		*arr_cap = new_cap;
	}

	(*arr)[(*arr_len)++] = elem;
	return true;

no_mem:
	ERRMSG("Not enough memory!\n");
	return false;
}

/*
 * Utility: add uniq string to arr, which can auto extend its capacity.
*/
bool push_uniq_str(void ***arr, int *arr_len, int *arr_cap, char *str)
{
	for (int i = 0; i < (*arr_len); i++) {
		if (!strcmp((*arr)[i], str))
			/* String already exists, skip it */
			return true;
	}
	return add_to_arr(arr, arr_len, arr_cap, str);
}

static bool add_ksym_modname(char *modname)
{
	return push_uniq_str((void ***)&mods, &mods_len, &mods_cap, modname);
}

bool check_ksyms_require_modname(char *modname, int *total)
{
	if (total)
		*total = mods_len;
	for (int i = 0; i < mods_len; i++) {
		if (!strcmp(modname, mods[i]))
			return true;
	}
	return false;
}

static void cleanup_ksyms_modname(void)
{
	if (mods) {
		free(mods);
		mods = NULL;
	}
	mods_len = 0;
	mods_cap = 0;
}

/*
 * Used by makedumpfile and extensions, to register their .init_ksyms section.
 * so kallsyms can know which module/sym should be inited.
*/
REGISTER_SECTION(ksym)

static void cleanup_ksyms_section_range(void)
{
	for (int i = 0; i < sr_len; i++) {
		free(sr[i]);
	}
	if (sr) {
		free(sr);
		sr = NULL;
	}
	sr_len = 0;
	sr_cap = 0;
}

static uint64_t absolute_percpu(uint64_t base, int32_t val)
{
	if (val >= 0)
		return (uint64_t)val;
	else
		return base - 1 - val;
}

static uint64_t calc_addr_absolute_percpu(struct ksym_info *p)
{
	return absolute_percpu(kallsyms_relative_base, p->value);
}

static uint64_t calc_addr_relative_base(struct ksym_info *p)
{
	return p->value + kallsyms_relative_base;
}

static uint64_t calc_addr_place_relative(struct ksym_info *p)
{
	return SYMBOL(kallsyms_offsets) + p->index * sizeof(uint32_t) +
		(int32_t)kallsyms_offsets[p->index];
}

static bool parse_kernel_kallsyms(void)
{
	char buf[BUFSIZE];
	int index = 0, i, j;
	uint8_t *compressd_data;
	uint8_t *uncompressd_data;
	uint8_t len, len_old;
	struct ksym_info **p;
	uint64_t (*calc_addr)(struct ksym_info *);
	struct ksym_info *stext_p;
	bool skip_symbol;

	for (i = 0; i < kallsyms_num_syms; i++) {
		skip_symbol = false;
		memset(buf, 0, BUFSIZE);
		len = kallsyms_names[index];
		if (len & 0x80) {
			index++;
			len_old = len;
			len = kallsyms_names[index];
			if (len & 0x80) {
				ERRMSG("BUG! Unexpected 3-byte length, "
				       "should be detected in init_kernel_kallsyms()\n");
				goto out;
			}
			len = (len_old & 0x7F) | (len << 7);
		}
		index++;

		compressd_data = &kallsyms_names[index];
		index += len;
		while (len--) {
			uncompressd_data = &kallsyms_token_table[kallsyms_token_index[*compressd_data]];
			if (strlen(buf) + strlen((char *)uncompressd_data) >= BUFSIZE) {
				skip_symbol = true;
				break;
			}
			strcat(buf, (char *)uncompressd_data);
			compressd_data++;
		}

		if (skip_symbol)
			continue;

		/* Now check if the symbol is we wanted */
		for (j = 0; j < sr_len; j++) {
			for (p = (struct ksym_info **)(sr[j]->start);
			     p < (struct ksym_info **)(sr[j]->stop);
			     p++) {
				if (!strcmp((*p)->modname, "vmlinux") &&
				    !strcmp((*p)->symname, &buf[1])) {
					(*p)->value = kallsyms_offsets[i];
					(*p)->index = i;
				}
			}
		}
	}

	/* Check the approach for calc absolute kallsyms address
	 *
	 * A complete comment of each approaches please refer to:
	 * https://github.com/osandov/drgn/commit/744f36ec3c3f64d7e1323a0037898158698585c4
	 */
	if (!MOD_SYM_EXIST(vmlinux, _stext)) {
		ERRMSG("symbol _stext not found!\n");
		goto out;
	}

	stext_p = GET_MOD_SYM_PTR(vmlinux, _stext);

	if (SYMBOL(_stext) == calc_addr_absolute_percpu(stext_p)) {
		calc_addr = calc_addr_absolute_percpu;
	} else if (SYMBOL(_stext) == calc_addr_relative_base(stext_p)) {
		calc_addr = calc_addr_relative_base;
	} else if (SYMBOL(_stext) == calc_addr_place_relative(stext_p)) {
		calc_addr = calc_addr_place_relative;
	} else {
		ERRMSG("Wrong calculate kallsyms symbol value!\n");
		goto out;
	}

	/* Now do the calc */
	for (j = 0; j < sr_len; j++) {
		for (p = (struct ksym_info **)(sr[j]->start);
		     p < (struct ksym_info **)(sr[j]->stop);
		     p++) {
			if (!strcmp((*p)->modname, "vmlinux") &&
			    SYM_EXIST(*p)) {
				(*p)->value = calc_addr(*p);
			}
		}
	}

	return true;
out:
	return false;
}

static bool vmcore_info_ready = false;

bool read_vmcoreinfo_kallsyms(void)
{
	READ_SYMBOL("kallsyms_names", kallsyms_names);
	READ_SYMBOL("kallsyms_num_syms", kallsyms_num_syms);
	READ_SYMBOL("kallsyms_token_table", kallsyms_token_table);
	READ_SYMBOL("kallsyms_token_index", kallsyms_token_index);
	READ_SYMBOL("kallsyms_offsets", kallsyms_offsets);
	READ_SYMBOL("kallsyms_relative_base", kallsyms_relative_base);
	if (SYMBOL(kallsyms_names) != NOT_FOUND_SYMBOL) {
		vmcore_info_ready = true;
	} else {
		vmcore_info_ready = false;
	}
	return true;
}

/*
 * Makedumpfile's .init_ksyms section
*/
extern struct ksym_info *__start_init_ksyms[];
extern struct ksym_info *__stop_init_ksyms[];

bool init_kernel_kallsyms(void)
{
	const int token_index_size = (UINT8_MAX + 1) * sizeof(uint16_t);
	uint64_t last_token, len;
	unsigned char data, data_old;
	int i;
	bool ret = false;

	if (vmcore_info_ready == false) {
		ERRMSG("vmcoreinfo not ready for kallsyms!\n");
		return ret;
	}

	if (!readmem(VADDR, SYMBOL(kallsyms_num_syms), &kallsyms_num_syms,
		sizeof(kallsyms_num_syms))) {
		ERRMSG("Can't get kallsyms_num_syms!\n");
		goto out;
	}
	if (SYMBOL(kallsyms_relative_base) != NOT_FOUND_SYMBOL) {
		if (!readmem(VADDR, SYMBOL(kallsyms_relative_base),
			&kallsyms_relative_base, sizeof(kallsyms_relative_base))) {
			ERRMSG("Can't get kallsyms_relative_base!\n");
			goto out;
		}
	}

	kallsyms_offsets = malloc(sizeof(uint32_t) * kallsyms_num_syms);
	if (!kallsyms_offsets)
		goto no_mem;
	if (!readmem(VADDR, SYMBOL(kallsyms_offsets), kallsyms_offsets,
		kallsyms_num_syms * sizeof(uint32_t))) {
		ERRMSG("Can't get kallsyms_offsets!\n");
		goto out;
	}

	kallsyms_token_index = malloc(token_index_size);
	if (!kallsyms_token_index)
		goto no_mem;
	if (!readmem(VADDR, SYMBOL(kallsyms_token_index), kallsyms_token_index,
		token_index_size)) {
		ERRMSG("Can't get kallsyms_token_index!\n");
		goto out;
	}

	last_token = SYMBOL(kallsyms_token_table) + kallsyms_token_index[UINT8_MAX];
	do {
		if (!readmem(VADDR, last_token++, &data, 1)) {
			ERRMSG("Can't get last_token!\n");
			goto out;
		}
	} while(data);
	len = last_token - SYMBOL(kallsyms_token_table);
	kallsyms_token_table = malloc(len);
	if (!kallsyms_token_table)
		goto no_mem;
	if (!readmem(VADDR, SYMBOL(kallsyms_token_table), kallsyms_token_table, len)) {
		ERRMSG("Can't get kallsyms_token_table!\n");
		goto out;
	}

	for (len = 0, i = 0; i < kallsyms_num_syms; i++) {
		if (!readmem(VADDR, SYMBOL(kallsyms_names) + len, &data, 1)) {
			ERRMSG("Can't get kallsyms_names len1!\n");
			goto out;
		}
		/*
		 * The 2-byte representation was added in commit 73bbb94466fd3
		 * ("kallsyms: support "big" kernel symbols") in v6.1, thus for
		 * v6.1+, they indicate a long symbol, but for kernel versions
		 * prior to v6.1, they might be ambiguous.
		 */
		if (data & 0x80) {
			len += 1;
			data_old = data;
			if (!readmem(VADDR, SYMBOL(kallsyms_names) + len, &data, 1)) {
				ERRMSG("Can't get kallsyms_names len2!\n");
				goto out;
			}
			if (data & 0x80) {
				ERRMSG("BUG! Unexpected 3-byte length "
					"encoding in kallsyms names\n");
				goto out;
			}
			data = (data_old & 0x7F) | (data << 7);
		}
		len += data + 1;
	}
	kallsyms_names = malloc(len);
	if (!kallsyms_names)
		goto no_mem;
	if (!readmem(VADDR, SYMBOL(kallsyms_names), kallsyms_names, len)) {
		ERRMSG("Can't get kallsyms_names!\n");
		goto out;
	}

	ret = parse_kernel_kallsyms();
	goto out;

no_mem:
	ERRMSG("Not enough memory!\n");
out:
	if (kallsyms_offsets) {
		free(kallsyms_offsets);
		kallsyms_offsets = NULL;
	}
	if (kallsyms_token_index) {
		free(kallsyms_token_index);
		kallsyms_token_index = NULL;
	}
	if (kallsyms_token_table) {
		free(kallsyms_token_table);
		kallsyms_token_table = NULL;
	}
	if (kallsyms_names) {
		free(kallsyms_names);
		kallsyms_names = NULL;
	}
	return ret;
}
#else /* EXTENSION */

bool read_vmcoreinfo_kallsyms(void)
{
	return true;
}

#endif /* EXTENSION */

