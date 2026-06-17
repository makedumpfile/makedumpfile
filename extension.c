#include <stdio.h>
#include "extension.h"
#include "makedumpfile.h"
#ifdef EXTENSION
#include <string.h>
#include <dirent.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <unistd.h>
#include "kallsyms.h"
#include "btf_info.h"

typedef int (*callback_fn)(unsigned long, const void *);

struct extension_handle_cb {
	void *handle;
	callback_fn cb;
};

/* Extension .so extension_handle_cb array */
static struct extension_handle_cb **handle_cbs = NULL;
static int handle_cbs_len = 0;
static int handle_cbs_cap = 0;

/* Extension option array */
static char **extension_opts = NULL;
static int extension_opts_len = 0;
static int extension_opts_cap = 0;

static const char *dirs[] = {
	"./",
	"./extensions/",
	"/usr/lib64/makedumpfile/extensions/",
};

bool add_extension_opts(char *opt)
{
	if (!add_to_arr((void ***)&extension_opts, &extension_opts_len,
			&extension_opts_cap, opt)) {
		/*
		 * If fail, print error info and skip the extension.
		*/
		ERRMSG("Fail to add extension %s\n", opt);
		return false;
	} else {
		return true;
	}
}

static bool init_kallsyms_btf(void)
{
	int count;
	bool ret = false;
	/* We will load module's btf/kallsyms on demand */
	bool init_ksyms_module = false;
	bool init_ktypes_module = false;

	if (check_ksyms_require_modname("vmlinux", &count)) {
		if (!init_kernel_kallsyms())
			goto out;
		if (count >= 2)
			init_ksyms_module = true;
	}
	if (check_ktypes_require_modname("vmlinux", &count)) {
		if (!init_kernel_btf())
			goto out;
		if (count >= 2)
			init_ktypes_module = true;
	}
	if (init_ksyms_module && !init_module_kallsyms())
		goto out;
	if (init_ktypes_module && !init_module_btf())
		goto out;
	ret = true;
out:
	return ret;
}

static void cleanup_kallsyms_btf(void)
{
	cleanup_kallsyms();
	cleanup_btf();
}

static void load_extensions(void)
{
	char path[512];
	int len, i, j;
	void *handle;
	struct extension_handle_cb *ehc;

	for (i = 0; i < extension_opts_len; i++) {
		handle = NULL;
		if (!extension_opts[i])
			continue;
		if ((len = strlen(extension_opts[i])) <= 3 ||
		    (strcmp(extension_opts[i] + len - 3, ".so") != 0)) {
			ERRMSG("Skip invalid extension: %s\n", extension_opts[i]);
			continue;
		}

		if (extension_opts[i][0] == '/') {
			/* Path & filename */
			snprintf(path, sizeof(path), "%s", extension_opts[i]);
			handle = dlopen(path, RTLD_NOW);
			if (!handle) {
				ERRMSG("Failed to load %s\n", dlerror());
				continue;
			}
		} else {
			/* Only filename */
			for (j = 0; j < sizeof(dirs) / sizeof(char *); j++) {
				snprintf(path, sizeof(path), "%s", dirs[j]);
				len = strlen(path);
				snprintf(path + len, sizeof(path) - len, "%s",
					extension_opts[i]);
				if (access(path, F_OK) == 0) {
					handle = dlopen(path, RTLD_NOW);
					if (handle)
						break;
					else
						ERRMSG("Failed to load %s\n", dlerror());
				}
			}
			if (!handle && j >= sizeof(dirs) / sizeof(char *)) {
				ERRMSG("Not found %s\n", extension_opts[i]);
				continue;
			}
		}

		if (dlsym(handle, "extension_init") == NULL) {
			ERRMSG("Skip extension %s: No extension_init()\n", path);
			dlclose(handle);
			continue;
		}

		if ((ehc = malloc(sizeof(struct extension_handle_cb))) == NULL) {
			ERRMSG("Skip extension %s: No memory\n", path);
			dlclose(handle);
			continue;
		}

		ehc->handle = handle;
		ehc->cb = dlsym(handle, "extension_callback");

		if (!add_to_arr((void ***)&handle_cbs, &handle_cbs_len, &handle_cbs_cap, ehc)) {
			ERRMSG("Failed to load %s\n", extension_opts[i]);
			free(ehc);
			dlclose(handle);
			continue;
		}
		MSG("Loaded extension: %s\n", path);
	}
}

static bool register_ksyms_ktypes_sections(void)
{
	char *start, *stop;
	int i;
	bool ret = false;

	for (i = 0; i < handle_cbs_len; i++) {
		start = dlsym(handle_cbs[i]->handle, "__start_init_ksyms");
		stop = dlsym(handle_cbs[i]->handle, "__stop_init_ksyms");
		if (!register_ksym_section(start, stop))
			goto out;

		start = dlsym(handle_cbs[i]->handle, "__start_init_ktypes");
		stop = dlsym(handle_cbs[i]->handle, "__stop_init_ktypes");
		if (!register_ktype_section(start, stop))
			goto out;
	}
	/* If no extensions, don't register makedumpfile's section */
	if (handle_cbs_len > 0) {
		start = dlsym(NULL, "__start_init_ksyms");
		stop = dlsym(NULL, "__stop_init_ksyms");
		if (!register_ksym_section(start, stop))
			goto out;

		start = dlsym(NULL, "__start_init_ktypes");
		stop = dlsym(NULL, "__stop_init_ktypes");
		if (!register_ktype_section(start, stop))
			goto out;
	}
	ret = true;
out:
	return ret;
}

void cleanup_extensions(void)
{
	for (int i = 0; i < handle_cbs_len; i++) {
		dlclose(handle_cbs[i]->handle);
		free(handle_cbs[i]);
	}
	if (handle_cbs) {
		free(handle_cbs);
		handle_cbs = NULL;
	}
	handle_cbs_len = 0;
	handle_cbs_cap = 0;
	if (extension_opts) {
		free(extension_opts);
		extension_opts = NULL;
	}
	extension_opts_len = 0;
	extension_opts_cap = 0;

	cleanup_kallsyms_btf();
}

static bool check_required_ksyms_all_resolved(void *handle)
{
	char *start, *stop;
	struct ksym_info **p;
	bool ret = true;

	start = dlsym(handle, "__start_init_ksyms");
	stop = dlsym(handle, "__stop_init_ksyms");

	for (p = (struct ksym_info **)start;
	     p < (struct ksym_info **)stop;
	     p++) {
		if ((*p)->sym_required && !SYM_EXIST(*p)) {
			ret = false;
			ERRMSG("Symbol %s in %s not found\n",
				(*p)->symname, (*p)->modname);
		}
	}

	return ret;
}

static bool check_required_ktypes_all_resolved(void *handle)
{
	char *start, *stop;
	struct ktype_info **p;
	bool ret = true;

	start = dlsym(handle, "__start_init_ktypes");
	stop = dlsym(handle, "__stop_init_ktypes");

	for (p = (struct ktype_info **)start;
	     p < (struct ktype_info **)stop;
	     p++) {
		if (!TYPE_EXIST(*p)) {
			if ((*p)->member_required) {
				ret = false;
				ERRMSG("Member %s of struct %s in %s not found\n",
					(*p)->member_name, (*p)->struct_name,
					(*p)->modname);
			} else if ((*p)->struct_required) {
				ret = false;
				ERRMSG("Struct %s in %s not found\n",
					(*p)->struct_name, (*p)->modname);
			}
		}
	}

	return ret;
}

static bool extension_runnable(void *handle)
{
	return check_required_ksyms_all_resolved(handle) &&
		check_required_ktypes_all_resolved(handle);
}

void init_extensions(void)
{
	/* Entry of extension init */
	void (*init)(void);

	load_extensions();
	if (!register_ksyms_ktypes_sections())
		goto fail;
	if (!init_kallsyms_btf())
		goto fail;
	for (int i = 0; i < handle_cbs_len; i++) {
		if (extension_runnable(handle_cbs[i]->handle)) {
			init = dlsym(handle_cbs[i]->handle, "extension_init");
			init();
		} else {
			/*
			* Skip init() & reset callback for the
			* un-runnable extension
			*/
			handle_cbs[i]->cb = NULL;
			ERRMSG("Skip %dth extension\n", i + 1);
		}
	}
	return;
fail:
	ERRMSG("fail & skip all extensions\n");
	cleanup_extensions();
}

/*
 * For a single pfn/pcache, multiple extensions will decide whether to:
 * 1) include the page (PG_INCLUDE), or
 * 2) exclude the page (PG_EXCLUDE), or
 * 3) make no decision to pass to others or fallback to traditional page-flags
 *    based filtering (PG_UNDECID).
 *
 * The arbitration is:
 * 1) Include the page if anyone says PG_INCLUDE, and
 * 2) Exclude the page if no one says PG_INCLUDE, but one or more say PG_EXCLUDE.
 */
int run_extension_callback(unsigned long pfn, const void *pcache)
{
	int result;
	int ret = PG_UNDECID;

	for (int i = 0; i < handle_cbs_len; i++) {
		if (handle_cbs[i]->cb) {
			result = handle_cbs[i]->cb(pfn, pcache);
			if (result == PG_INCLUDE) {
				ret = result;
				goto out;
			} else if (result == PG_EXCLUDE) {
				ret = result;
			}
		}
	}
out:
	return ret;
}

bool extension_has_callback(void)
{
	return handle_cbs_len > 0;
}

#else /* EXTENSION */

void init_extensions(void) { }
void cleanup_extensions(void) { }
bool add_extension_opts(char *opt)
{
	ERRMSG("extension unsupported. Try `make EXTENSION=on` when building\n");
	return false;
}

int run_extension_callback(unsigned long pfn, const void *pcache)
{
	return PG_UNDECID;
}

bool extension_has_callback(void)
{
	return false;
}

#endif /* EXTENSION */

