/*
 * print_info.c
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
#include "print_info.h"
#include <time.h>
#include <string.h>

#define PROGRESS_MAXLEN		"50"

#define NSEC_PER_SEC		1000000000L

int message_level;
int flag_strerr_message;
int flag_ignore_r_char; /* 0: '\r' is effective. 1: not effective. */

void
show_version(void)
{
	MSG("makedumpfile: version " VERSION " (released on " RELEASE_DATE ")\n");
#ifdef USELZO
	MSG("lzo\tenabled\n");
#else
	MSG("lzo\tdisabled\n");
#endif
#ifdef USESNAPPY
	MSG("snappy\tenabled\n");
#else
	MSG("snappy\tdisabled\n");
#endif
	MSG("\n");
}

void
print_usage(void)
{
	MSG("\n");
	MSG("LZO support:\n");
#ifdef USELZO
	MSG("  enabled\n");
#else
	MSG("  disabled ('-l' option will be ignored.)\n");
#endif
	MSG("snappy support:\n");
#ifdef USESNAPPY
	MSG("  enabled\n");
#else
	MSG("  disabled ('-p' option will be ignored.)\n");
#endif
	MSG("\n");
	MSG("Usage:\n");
	MSG("  Creating DUMPFILE:\n");
	MSG("  # makedumpfile    [-c|-l|-p|-E] [-d DL] [-e] [-x VMLINUX|-i VMCOREINFO] VMCORE\n");
	MSG("    DUMPFILE\n");
	MSG("\n");
	MSG("  Creating DUMPFILE with filtered kernel data specified through filter config\n");
	MSG("  file or eppic macro:\n");
	MSG("  # makedumpfile    [-c|-l|-p|-E] [-d DL] -x VMLINUX [--config FILTERCONFIGFILE]\n");
	MSG("    [--eppic EPPICMACRO] VMCORE DUMPFILE\n");
	MSG("\n");
	MSG("  Outputting the dump data in the flattened format to the standard output:\n");
	MSG("  # makedumpfile -F [-c|-l|-p|-E] [-d DL] [-x VMLINUX|-i VMCOREINFO] VMCORE\n");
	MSG("\n");
	MSG("  Rearranging the dump data in the flattened format to a readable DUMPFILE:\n");
	MSG("  # makedumpfile -R DUMPFILE\n");
	MSG("\n");
	MSG("  Split the dump data to multiple DUMPFILEs in parallel:\n");
	MSG("  # makedumpfile --split [OPTION] [-x VMLINUX|-i VMCOREINFO] VMCORE DUMPFILE1\n");
	MSG("    DUMPFILE2 [DUMPFILE3 ..]\n");
	MSG("\n");
	MSG("  Using multiple threads to create DUMPFILE in parallel:\n");
	MSG("  # makedumpfile [OPTION] [-x VMLINUX|-i VMCOREINFO] --num-threads THREADNUM\n");
	MSG("    VMCORE DUMPFILE1\n");
	MSG("\n");
	MSG("  Reassemble multiple DUMPFILEs:\n");
	MSG("  # makedumpfile --reassemble DUMPFILE1 DUMPFILE2 [DUMPFILE3 ..] DUMPFILE\n");
	MSG("\n");
	MSG("  Generating VMCOREINFO:\n");
	MSG("  # makedumpfile -g VMCOREINFO -x VMLINUX\n");
	MSG("\n");
	MSG("  Extracting the dmesg log from a VMCORE:\n");
	MSG("  # makedumpfile --dump-dmesg [-x VMLINUX|-i VMCOREINFO] VMCORE LOGFILE\n");
	MSG("\n");
	MSG("\n");
	MSG("  Creating DUMPFILE of Xen:\n");
	MSG("  # makedumpfile [-c|-l|-p|-E] [--xen-syms XEN-SYMS|--xen-vmcoreinfo VMCOREINFO]\n");
	MSG("    VMCORE DUMPFILE\n");
	MSG("\n");
	MSG("  Filtering domain-0 of Xen:\n");
	MSG("  # makedumpfile [-c|-l|-p|-E] -d DL -x vmlinux VMCORE DUMPFILE\n");
	MSG("\n");
	MSG("  Generating VMCOREINFO of Xen:\n");
	MSG("  # makedumpfile -g VMCOREINFO --xen-syms XEN-SYMS\n");
	MSG("\n");
	MSG("\n");
	MSG("  Creating DUMPFILE from multiple VMCOREs generated on sadump diskset configuration:\n");
	MSG("  # makedumpfile [-c|-l|-p] [-d DL] -x VMLINUX --diskset=VMCORE1 --diskset=VMCORE2\n");
	MSG("    [--diskset=VMCORE3 ..] DUMPFILE\n");
	MSG("\n");
	MSG("\n");
	MSG("Available options:\n");
	MSG("  [-c|-l|-p]:\n");
	MSG("      Compress dump data by each page using zlib for -c option, lzo for -l option\n");
	MSG("      or snappy for -p option. A user cannot specify either of these options with\n");
	MSG("      -E option, because the ELF format does not support compressed data.\n");
	MSG("      THIS IS ONLY FOR THE CRASH UTILITY.\n");
	MSG("\n");
	MSG("  [-e]:\n");
	MSG("      Exclude the page structures (vmemmap) which represent excluded pages.\n");
	MSG("      This greatly shortens the dump of a very large memory system.\n");
	MSG("      The --work-dir option must also be specified, as it will be used\n");
	MSG("      to hold bitmaps and a file of page numbers that are to be excluded.\n");
	MSG("      The -e option will cause a noncyclic dump procedure.\n");
	MSG("      This option is only for x86_64.\n");
	MSG("\n");
	MSG("  [-d DL]:\n");
	MSG("      Specify the type of unnecessary page for analysis.\n");
	MSG("      Pages of the specified type are not copied to DUMPFILE. The page type\n");
	MSG("      marked in the following table is excluded. A user can specify multiple\n");
	MSG("      page types by setting the sum of each page type for Dump_Level (DL).\n");
	MSG("      The maximum of Dump_Level is 31.\n");
	MSG("      Note that Dump_Level for Xen dump filtering is 0 or 1 except on x86_64\n");
	MSG("\n");
	MSG("            |         non-\n");
	MSG("      Dump  |  zero   private  private  user    free\n");
	MSG("      Level |  page   cache    cache    data    page\n");
	MSG("     -------+---------------------------------------\n");
	MSG("         0  |\n");
	MSG("         1  |   X\n");
	MSG("         2  |           X\n");
	MSG("         4  |           X        X\n");
	MSG("         8  |                            X\n");
	MSG("        16  |                                    X\n");
	MSG("        31  |   X       X        X       X       X\n");
	MSG("\n");
	MSG("  [-E]:\n");
	MSG("      Create DUMPFILE in the ELF format.\n");
	MSG("      This option cannot be specified with the -c, -l or -p options,\n");
	MSG("      because the ELF format does not support compressed data.\n");
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
	MSG("      and it contains the first kernel's information. This option is necessary\n");
	MSG("      if VMCORE does not contain VMCOREINFO, [-x VMLINUX] is not specified,\n");
	MSG("      and dump_level is 2 or more.\n");
	MSG("\n");
	MSG("  [-g VMCOREINFO]:\n");
	MSG("      Generate VMCOREINFO from the first kernel's VMLINUX.\n");
	MSG("      VMCOREINFO must be generated on the system that is running the first\n");
	MSG("      kernel. With -i option, a user can specify VMCOREINFO generated on the\n");
	MSG("      other system that is running the same first kernel. [-x VMLINUX] must\n");
	MSG("      be specified.\n");
	MSG("\n");
	MSG("  [--config FILTERCONFIGFILE]:\n");
	MSG("      Used in conjunction with -x VMLINUX option, to specify the filter config\n");
	MSG("      file that contains filter commands to filter out desired kernel data\n");
	MSG("      from vmcore while creating DUMPFILE.\n");
	MSG("\n");
	MSG("  [--eppic EPPICMACRO]:\n");
	MSG("      Used in conjunction with -x VMLINUX option, to specify the eppic macro\n");
	MSG("      file that contains filter rules or directory that contains eppic macro\n");
	MSG("      files to filter out desired kernel data from vmcore while creating DUMPFILE.\n");
	MSG("      When directory is specified, all the eppic macros in the directory are\n");
	MSG("      processed\n");
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
	MSG("  [--split]:\n");
	MSG("      Split the dump data to multiple DUMPFILEs in parallel. If specifying\n");
	MSG("      DUMPFILEs on different storage devices, a device can share I/O load with\n");
	MSG("      other devices and it reduces time for saving the dump data. The file size\n");
	MSG("      of each DUMPFILE is smaller than the system memory size which is divided\n");
	MSG("      by the number of DUMPFILEs.\n");
	MSG("      This feature supports only the kdump-compressed format.\n");
	MSG("\n");
	MSG("  [--num-threads THREADNUM]:\n");
	MSG("      Using multiple threads to read and compress data of each page in parallel.\n");
	MSG("      And it will reduces time for saving DUMPFILE.\n");
	MSG("      Note that if the usable cpu number is less than the thread number, it may\n");
	MSG("      lead to great performance degradation.\n");
	MSG("      This feature only supports creating DUMPFILE in kdump-compressed format from\n");
	MSG("      VMCORE in kdump-compressed format or elf format.\n");
	MSG("\n");
	MSG("  [--reassemble]:\n");
	MSG("      Reassemble multiple DUMPFILEs, which are created by --split option,\n");
	MSG("      into one DUMPFILE. dumpfile1 and dumpfile2 are reassembled into dumpfile.\n");
	MSG("\n");
	MSG("  [-b <order>]\n");
	MSG("      Specify the cache 2^order pages in ram when generating DUMPFILE before\n");
	MSG("      writing to output. The default value is 4.\n");
	MSG("\n");
	MSG("  [--cyclic-buffer BUFFER_SIZE]:\n");
	MSG("      Specify the buffer size in kilo bytes for bitmap data.\n");
	MSG("      Filtering processing will be divided into multi cycles to fix the memory\n");
	MSG("      consumption, the number of cycles is represented as:\n");
	MSG("\n");
	MSG("          num_of_cycles = system_memory / \n");
	MSG("                          (BUFFER_SIZE * 1024 * bit_per_bytes * page_size)\n");
	MSG("\n");
	MSG("      The lesser number of cycles, the faster working speed is expected.\n");
	MSG("      By default, BUFFER_SIZE will be calculated automatically depending on\n");
	MSG("      system memory size, so ordinary users don't need to specify this option.\n");
	MSG("\n");
	MSG("  [--splitblock-size SPLITBLOCK_SIZE]:\n");
	MSG("      Specify the splitblock size in kilo bytes for analysis with --split.\n");
	MSG("      If --splitblock N is specified, difference of each splitted dumpfile\n");
	MSG("      size is at most N kilo bytes.\n");
	MSG("\n");
	MSG("  [--work-dir]:\n");
	MSG("      Specify the working directory for the temporary bitmap file.\n");
	MSG("      If this option isn't specified, the bitmap will be saved on memory.\n");
	MSG("      Filtering processing has to do 2 pass scanning to fix the memory consumption,\n");
	MSG("      but it can be avoided by using working directory on file system.\n");
	MSG("      So if you specify this option, the filtering speed may be bit faster.\n");
	MSG("\n");
	MSG("  [--non-mmap]:\n");
	MSG("      Never use mmap(2) to read VMCORE even if it supports mmap(2).\n");
	MSG("      Generally, reading VMCORE with mmap(2) is faster than without it,\n");
	MSG("      so ordinary users don't need to specify this option.\n");
	MSG("      This option is mainly for debugging.\n");
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
	MSG("  [--diskset=VMCORE]:\n");
	MSG("      Specify multiple VMCOREs created on sadump diskset configuration the same\n");
	MSG("      number of times as the number of VMCOREs in increasing order from left to\n");
	MSG("      right.\n");
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
	MSG("      of virtual address. If specifying the VIRTUAL_ADDRESS, its physical\n");
	MSG("      address is printed.\n");
	MSG("\n");
	MSG("  [--dump-dmesg]:\n");
	MSG("      This option overrides the normal behavior of makedumpfile. Instead of\n");
	MSG("      compressing and filtering a VMCORE to make it smaller, it simply\n");
	MSG("      extracts the dmesg log from a VMCORE and writes it to the specified\n");
	MSG("      LOGFILE. If a VMCORE does not contain VMCOREINFO for dmesg, it is\n");
	MSG("      necessary to specify [-x VMLINUX] or [-i VMCOREINFO].\n");
	MSG("\n");
	MSG("  [--mem-usage]:\n");
	MSG("      This option is only for x86_64.\n");
	MSG("      This option is used to show the page numbers of current system in different\n");
	MSG("      use. It should be executed in 1st kernel. By the help of this, user can know\n");
	MSG("      how many pages is dumpable when different dump_level is specified. It analyzes\n");
	MSG("      the 'System Ram' and 'kernel text' program segment of /proc/kcore excluding\n");
	MSG("      the crashkernel range, then calculates the page number of different kind per\n");
	MSG("      vmcoreinfo. So currently /proc/kcore need be specified explicitly.\n");
	MSG("\n");
	MSG("  [-D]:\n");
	MSG("      Print debugging message.\n");
	MSG("\n");
	MSG("  [-f]:\n");
	MSG("      Overwrite DUMPFILE even if it already exists.\n");
	MSG("      Force mem-usage to work with older kernel as well.\n");
	MSG("\n");
	MSG("  [-h, --help]:\n");
	MSG("      Show help message and LZO/snappy support status (enabled/disabled).\n");
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

static void calc_delta(struct timespec *ts_start, struct timespec *delta)
{
	struct timespec ts_end;

	clock_gettime(CLOCK_MONOTONIC, &ts_end);
	delta->tv_sec = ts_end.tv_sec - ts_start->tv_sec;
	delta->tv_nsec = ts_end.tv_nsec - ts_start->tv_nsec;
	if (delta->tv_nsec < 0) {
		delta->tv_sec--;
		delta->tv_nsec += NSEC_PER_SEC;
	}
}

/* produce less than 12 bytes on msg */
static int eta_to_human_short (unsigned long secs, char* msg)
{
	strcpy(msg, "eta: ");
	msg += strlen("eta: ");
	if (secs < 100)
		sprintf(msg, "%lus", secs);
	else if (secs < 100 * 60)
		sprintf(msg, "%lum%lus", secs / 60, secs % 60);
	else if (secs < 48 * 3600)
		sprintf(msg, "%luh%lum", secs / 3600, (secs / 60) % 60);
	else if (secs < 100 * 86400)
		sprintf(msg, "%lud%luh", secs / 86400, (secs / 3600) % 24);
	else
		sprintf(msg, ">2day");
	return 0;
}


void
print_progress(const char *msg, unsigned long current, unsigned long end, struct timespec *start)
{
	unsigned progress;	/* in promilles (tenths of a percent) */
	time_t tm;
	static time_t last_time = 0;
	static unsigned int lapse = 0;
	static const char *spinner = "/|\\-";
	struct timespec delta;
	unsigned long eta;
	char eta_msg[16] = " ";

	if (current < end) {
		tm = time(NULL);
		if (tm - last_time < 1)
			return;
		last_time = tm;
		progress = current * 1000 / end;
	} else
		progress = 1000;

	if (start != NULL && progress != 0) {
		calc_delta(start, &delta);
		eta = 1000 * delta.tv_sec + delta.tv_nsec / (NSEC_PER_SEC / 1000);
		eta = eta / progress - delta.tv_sec;
		eta_to_human_short(eta, eta_msg);
	}
	if (flag_ignore_r_char) {
		PROGRESS_MSG("%-" PROGRESS_MAXLEN "s: [%3u.%u %%] %c  %16s\n",
			     msg, progress / 10, progress % 10,
			     spinner[lapse % 4], eta_msg);
	} else {
		PROGRESS_MSG("\r");
		PROGRESS_MSG("%-" PROGRESS_MAXLEN "s: [%3u.%u %%] %c  %16s",
			     msg, progress / 10, progress % 10,
			     spinner[lapse % 4], eta_msg);
	}
	lapse++;
}

void
print_execution_time(char *step_name, struct timespec *ts_start)
{
	struct timespec delta;

	calc_delta(ts_start, &delta);
	REPORT_MSG("STEP [%s] : %ld.%06ld seconds\n",
		   step_name, delta.tv_sec, delta.tv_nsec / 1000);
}

