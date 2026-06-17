#ifndef _EXTENSION_H
#define _EXTENSION_H
#include <stdbool.h>

enum {
	PG_INCLUDE,	// Exntesion will keep the page
	PG_EXCLUDE,	// Exntesion will discard the page
	PG_UNDECID,	// Exntesion makes no decision
};
int run_extension_callback(unsigned long pfn, const void *pcache);
void init_extensions(void);
void cleanup_extensions(void);
bool add_extension_opts(char *opt);
bool extension_has_callback(void);
#endif /* _EXTENSION_H */

