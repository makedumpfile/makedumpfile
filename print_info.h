/*
 * print_info.h
 *
 * Copyright (C) 2011 NEC Corporation
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
#ifndef _PRINT_INFO_H
#define _PRINT_INFO_H

#include <stdio.h>
#include <time.h>

extern int message_level;
extern int flag_strerr_message;
extern int flag_ignore_r_char;

void show_version(void);
void print_usage(void);
void print_progress(const char *msg, unsigned long current, unsigned long end, struct timespec *start);

void print_execution_time(char *step_name, struct timespec *ts_start);

/*
 * Message texts
 */
#define PROGRESS_COPY   	"Copying data               "
#define PROGRESS_HOLES		"Checking for memory holes  "
#define PROGRESS_UNN_PAGES 	"Excluding unnecessary pages"
#define PROGRESS_FREE_PAGES 	"Excluding free pages       "
#define PROGRESS_ZERO_PAGES 	"Excluding zero pages       "
#define PROGRESS_XEN_DOMAIN 	"Excluding xen user domain  "

/*
 * Message Level
 */
#define MIN_MSG_LEVEL		(0)
#define MAX_MSG_LEVEL		(31)
#define DEFAULT_MSG_LEVEL	(7)	/* Print the progress indicator, the
					   common message, the error message */
#define ML_PRINT_PROGRESS	(0x001) /* Print the progress indicator */
#define ML_PRINT_COMMON_MSG	(0x002)	/* Print the common message */
#define ML_PRINT_ERROR_MSG	(0x004)	/* Print the error message */
#define ML_PRINT_DEBUG_MSG	(0x008) /* Print the debugging message */
#define ML_PRINT_REPORT_MSG	(0x010) /* Print the report message */

#define MSG(x...) \
do { \
	if (message_level & ML_PRINT_COMMON_MSG) { \
		if (flag_strerr_message) \
			fprintf(stderr, x); \
		else \
			fprintf(stdout, x); \
	} \
} while (0)

#define ERRMSG(x...) \
do { \
	if (message_level & ML_PRINT_ERROR_MSG) { \
		fprintf(stderr, __FUNCTION__); \
		fprintf(stderr, ": "); \
		fprintf(stderr, x); \
	} \
} while (0)

#define PROGRESS_MSG(x...) \
do { \
	if (message_level & ML_PRINT_PROGRESS) { \
		fprintf(stderr, x); \
	} \
} while (0)

#define DEBUG_MSG(x...) \
do { \
	if (message_level & ML_PRINT_DEBUG_MSG) { \
		if (flag_strerr_message) \
			fprintf(stderr, x); \
		else \
			fprintf(stdout, x); \
	} \
} while (0)

#define REPORT_MSG(x...) \
do { \
	if (message_level & ML_PRINT_REPORT_MSG) { \
		if (flag_strerr_message) \
			fprintf(stderr, x); \
		else \
			fprintf(stdout, x); \
	} \
} while (0)

#endif  /* PRINT_INFO_H */

