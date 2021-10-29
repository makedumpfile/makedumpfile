/* tools.c - Borrowed from crash utility code
 *           (https://github.com/crash-utility/crash)
 *
 * Copyright (C) 1999, 2000, 2001, 2002 Mission Critical Linux, Inc.
 * Copyright (C) 2002-2017 David Anderson
 * Copyright (C) 2002-2018 Red Hat, Inc. All rights reserved.
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

#include "common.h"
#include "makedumpfile.h"
#include <ctype.h>

#define FAULT_ON_ERROR		(0x1)
#define RETURN_ON_ERROR		(0x2)
#define QUIET			(0x4)
#define HEX_BIAS		(0x8)
#define LONG_LONG		(0x10)
#define RETURN_PARTIAL		(0x20)
#define NO_DEVMEM_SWITCH	(0x40)

#define MAX_HEXADDR_STRLEN	(16)

#define FIRSTCHAR(s)		(s[0])

/*
 * Determine whether a file exists, using the caller's stat structure if
 * one was passed in.
 */
int
file_exists(char *file)
{
	struct stat sbuf;

	if (stat(file, &sbuf) == 0)
		return TRUE;

	return FALSE;
}

/*
 * Parse a line into tokens, populate the passed-in argv[] array, and
 * return the count of arguments found. This function modifies the
 * passed-string by inserting a NULL character at the end of each token.
 * Expressions encompassed by parentheses, and strings encompassed by
 * apostrophes, are collected into single tokens.
 */
int
parse_line(char *str, char *argv[])
{
	int i, j, k;
	int string;
	int expression;

	for (i = 0; i < MAXARGS; i++)
		argv[i] = NULL;

	clean_line(str);

	if (str == NULL || strlen(str) == 0)
		return(0);

	i = j = k = 0;
	string = expression = FALSE;

	/*
	 * Special handling for when the first character is a '"'.
	 */
	if (str[0] == '"') {
next:
		do {
			i++;
		} while ((str[i] != NULLCHAR) && (str[i] != '"'));

		switch (str[i])
		{
		case NULLCHAR:
			argv[j] = &str[k];
			return j+1;
		case '"':
			argv[j++] = &str[k+1];
			str[i++] = NULLCHAR;
			if (str[i] == '"') {
				k = i;
				goto next;
			}
			break;
		}
	} else
		argv[j++] = str;

	while (TRUE) {
		if (j == MAXARGS)
			ERRMSG("too many arguments in string!\n");

		while (str[i] != ' ' && str[i] != '\t' && str[i] != NULLCHAR) {
			i++;
		}

		switch (str[i])
		{
		case ' ':
		case '\t':
			str[i++] = NULLCHAR;

			while (str[i] == ' ' || str[i] == '\t') {
				i++;
			}

			if (str[i] == '"') {
				str[i] = ' ';
				string = TRUE;
				i++;
			}

			if (!string && str[i] == '(') {
				expression = TRUE;
			}

			if (str[i] != NULLCHAR && str[i] != '\n') {
				argv[j++] = &str[i];
				if (string) {
					string = FALSE;
					while (str[i] != '"' && str[i] != NULLCHAR)
						i++;
					if (str[i] == '"')
						str[i] = ' ';
				}
				if (expression) {
					expression = FALSE;
					while (str[i] != ')' && str[i] != NULLCHAR)
						i++;
				}
				break;
			}
			/* else fall through */
		case '\n':
			str[i] = NULLCHAR;
			/* keep falling... */
		case NULLCHAR:
			return(j);
		}
	}
}

/*
 * Defuse controversy re: extensions to ctype.h
 */
int
whitespace(int c)
{
	return ((c == ' ') ||(c == '\t'));
}

int
ascii(int c)
{
	return ((c >= 0) && (c <= 0x7f));
}

/*
 * Strip line-ending whitespace and linefeeds.
 */
char *
strip_line_end(char *line)
{
	strip_linefeeds(line);
	strip_ending_whitespace(line);
	return(line);
}

/*
 * Strip line-beginning and line-ending whitespace and linefeeds.
 */
char *
clean_line(char *line)
{
	strip_beginning_whitespace(line);
	strip_linefeeds(line);
	strip_ending_whitespace(line);
	return(line);
}

/*
 * Strip line-ending linefeeds in a string.
 */
char *
strip_linefeeds(char *line)
{
	char *p;

	if (line == NULL || strlen(line) == 0)
		return(line);

	p = &LASTCHAR(line);

	while (*p == '\n') {
		*p = NULLCHAR;
		if (--p < line)
			break;
	}

	return(line);
}

/*
 * Strip a specified line-ending character in a string.
 */
char *
strip_ending_char(char *line, char c)
{
	char *p;

	if (line == NULL || strlen(line) == 0)
		return(line);

	p = &LASTCHAR(line);

	if (*p == c)
		*p = NULLCHAR;

	return(line);
}

/*
 * Strip a specified line-beginning character in a string.
 */
char *
strip_beginning_char(char *line, char c)
{
	if (line == NULL || strlen(line) == 0)
		return(line);

	if (FIRSTCHAR(line) == c)
		shift_string_left(line, 1);

	return(line);
}

/*
 * Strip line-ending whitespace.
 */
char *
strip_ending_whitespace(char *line)
{
	char *p;

	if (line == NULL || strlen(line) == 0)
		return(line);

	p = &LASTCHAR(line);

	while (*p == ' ' || *p == '\t') {
		*p = NULLCHAR;
		if (p == line)
			break;
		p--;
	}

	return(line);
}

/*
 * Strip line-beginning whitespace.
 */
char *
strip_beginning_whitespace(char *line)
{
	size_t len;
	char *p;

	if (line == NULL)
		return line;

	len = strlen(line);

	if (len == 0)
		return line;

	p = line;
	while (whitespace(*p)) {
		p++;
		len--;
	}
	/* for memmove src and dest may overlap */
	memmove(line, p, len);
	line[len + 1] = '\0';

	return line;
}

/*
 * End line at first comma found.
 */
char *
strip_comma(char *line)
{
	char *p;

	if ((p = strstr(line, ",")))
		*p = NULLCHAR;

	return(line);
}

/*
 * Strip the 0x from the beginning of a hexadecimal value string.
 */
char *
strip_hex(char *line)
{
	if (STRNEQ(line, "0x"))
		shift_string_left(line, 2);

	return(line);
}

/*
 * Turn a string into upper-case.
 */
char *
upper_case(const char *s, char *buf)
{
	const char *p1;
	char *p2;

	p1 = s;
	p2 = buf;

	while (*p1) {
		*p2 = toupper(*p1);
		p1++, p2++;
	}

	*p2 = NULLCHAR;

	return(buf);
}

/*
 * Return pointer to first non-space/tab in a string.
 */
char *
first_nonspace(char *s)
{
	return(s + strspn(s, " \t"));
}

/*
 * Return pointer to first space/tab in a string. If none are found,
 * return a pointer to the string terminating NULL.
 */
char *
first_space(char *s)
{
	return(s + strcspn(s, " \t"));
}

/*
 * Replace the first space/tab found in a string with a NULL character.
 */
char *
null_first_space(char *s)
{
	char *p1;

	p1 = first_space(s);
	if (*p1)
		*p1 = NULLCHAR;

	return s;
}

/*
 * Replace any instances of the characters in string c that are found in
 * string s with the character passed in r.
 */
char *
replace_string(char *s, char *c, char r)
{
	int i, j;

	for (i = 0; s[i]; i++) {
		for (j = 0; c[j]; j++) {
			if (s[i] == c[j])
				s[i] = r;
		}
	}

	return s;
}

/*
 * Find the rightmost instance of a substring in a string.
 */
char *
strstr_rightmost(char *s, char *lookfor)
{
	char *next, *last, *p;

	for (p = s, last = NULL; *p; p++) {
		if (!(next = strstr(p, lookfor)))
			break;
		last = p = next;
	}

	return last;
}

/*
 * Shifts the contents of a string to the left by cnt characters,
 * disposing the leftmost characters.
 */
char *
shift_string_left(char *s, int cnt)
{
	int origlen;

	if (!cnt)
		return(s);

	origlen = strlen(s);
	memmove(s, s+cnt, (origlen-cnt));
	*(s+(origlen-cnt)) = NULLCHAR;
	return(s);
}

/*
 * Prints a string verbatim, allowing strings with % signs to be displayed
 * without printf conversions.
 */
void
print_verbatim(FILE *filep, char *line)
{
	int i;

	for (i = 0; i < strlen(line); i++) {
		fputc(line[i], filep);
		fflush(filep);
	}
}

char *
fixup_percent(char *s)
{
	char *p1;

	if ((p1 = strstr(s, "%")) == NULL)
		return s;

	s[strlen(s)+1] = NULLCHAR;
	memmove(p1+1, p1, strlen(p1));
	*p1 = '%';

	return s;
}

/*
 * Determine whether a string contains only decimal characters.
 * If count is non-zero, limit the search to count characters.
 */
int
decimal(char *s, int count)
{
	char *p;
	int cnt, digits;

	if (!count) {
		strip_line_end(s);
		cnt = 0;
	} else
		cnt = count;

	for (p = &s[0], digits = 0; *p; p++) {
		switch(*p)
		{
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			digits++;
		case ' ':
			break;
		default:
			return FALSE;
		}

		if (count && (--cnt == 0))
			break;
	}

	return (digits ? TRUE : FALSE);
}

/*
 * Determine whether a string contains only ASCII characters.
 */
int
ascii_string(char *s)
{
	char *p;

	for (p = &s[0]; *p; p++) {
		if (!ascii(*p))
			return FALSE;
	}

	return TRUE;
}

/*
 * Check whether a string contains only printable ASCII characters.
 */
int
printable_string(char *s)
{
	char *p;

	for (p = &s[0]; *p; p++) {
		if (!isprint(*p))
			return FALSE;
	}

	return TRUE;
}

/*
 * Convert a string to a hexadecimal long value.
 */
ulong
htol(char *s, int flags)
{
	ulong i, j;
	ulong n;

	if (s == NULL) {
		if (!(flags & QUIET))
			ERRMSG("received NULL string\n");
		goto htol_error;
	}

	if (STRNEQ(s, "0x") || STRNEQ(s, "0X"))
		s += 2;

	if (strlen(s) > MAX_HEXADDR_STRLEN) {
		if (!(flags & QUIET))
			ERRMSG("input string too large: \"%s\" (%d vs %d)\n",
					s, (int)strlen(s), (int)MAX_HEXADDR_STRLEN);
		goto htol_error;
	}

	for (n = i = 0; s[i] != 0; i++) {
		switch (s[i])
		{
		case 'a':
		case 'b':
		case 'c':
		case 'd':
		case 'e':
		case 'f':
			j = (s[i] - 'a') + 10;
			break;
		case 'A':
		case 'B':
		case 'C':
		case 'D':
		case 'E':
		case 'F':
			j = (s[i] - 'A') + 10;
			break;
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case '0':
			j = s[i] - '0';
			break;
		case 'x':
		case 'X':
		case 'h':
			continue;
		default:
			if (!(flags & QUIET))
				ERRMSG("invalid input: \"%s\"\n", s);
			goto htol_error;
		}
		n = (16 * n) + j;
	}

	return(n);

htol_error:
	return BADADDR;
}

/*
 * Determine whether a string contains only hexadecimal characters.
 * If count is non-zero, limit the search to count characters.
 */
int
hexadecimal(char *s, int count)
{
	char *p;
	int cnt, digits;

	if (!count) {
		strip_line_end(s);
		cnt = 0;
	} else
		cnt = count;

	for (p = &s[0], digits = 0; *p; p++) {
		switch(*p)
		{
		case 'a':
		case 'b':
		case 'c':
		case 'd':
		case 'e':
		case 'f':
		case 'A':
		case 'B':
		case 'C':
		case 'D':
		case 'E':
		case 'F':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case '0':
			digits++;
		case 'x':
		case 'X':
			break;

		case ' ':
			if (*(p+1) == NULLCHAR)
				break;
			else
				return FALSE;
		default:
			return FALSE;
		}

		if (count && (--cnt == 0))
			break;
	}

	return (digits ? TRUE : FALSE);
}

/*
 * Determine whether a string contains only hexadecimal characters.
 * and cannot be construed as a decimal number.
 * If count is non-zero, limit the search to count characters.
 */
int
hexadecimal_only(char *s, int count)
{
	char *p;
	int cnt, only;

	if (!count) {
		strip_line_end(s);
		cnt = 0;
	} else
		cnt = count;

	only = 0;

	for (p = &s[0]; *p; p++) {
		switch(*p)
		{
		case 'a':
		case 'b':
		case 'c':
		case 'd':
		case 'e':
		case 'f':
		case 'A':
		case 'B':
		case 'C':
		case 'D':
		case 'E':
		case 'F':
		case 'x':
		case 'X':
			only++;
			break;
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case '0':
			break;

		case ' ':
			if (*(p+1) == NULLCHAR)
				break;
			else
				return FALSE;
		default:
			return FALSE;
		}

		if (count && (--cnt == 0))
			break;
	}

	return only;
}

/*
 * Parse a string of [size[KMG]@]offset[KMG]
 * Import from Linux kernel(lib/cmdline.c)
 */
unsigned long long memparse(char *ptr, char **retptr)
{
	char *endptr;

	unsigned long long ret = strtoull(ptr, &endptr, 0);

	switch (*endptr) {
	case 'E':
	case 'e':
		ret <<= 10;
	case 'P':
	case 'p':
		ret <<= 10;
	case 'T':
	case 't':
		ret <<= 10;
	case 'G':
	case 'g':
		ret <<= 10;
	case 'M':
	case 'm':
		ret <<= 10;
	case 'K':
	case 'k':
		ret <<= 10;
		endptr++;
	default:
		break;
	}

	if (retptr)
		*retptr = endptr;

	return ret;
}
