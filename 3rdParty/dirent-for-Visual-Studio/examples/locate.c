/*
 * Find file name from locatedb database.
 *
 * Compile and run updatedb command first to create locate.db file.  Then,
 * compile this program with Visual Studio and run the program in console with
 * a file name argument.  For example, the command
 *
 *     locate autoexec
 *
 * might output something like
 *
 *     c:/AUTOEXEC.BAT
 *     c:/WINDOWS/repair/autoexec.nt
 *     c:/WINDOWS/system32/AUTOEXEC.NT
 *
 * Be ware that this file uses wide-character API which is not compatible
 * with Linux or other major Unixes.
 *
 * Copyright (C) 1998-2019 Toni Ronkko
 * This file is part of dirent.  Dirent may be freely distributed
 * under the MIT license.  For all details and documentation, see
 * https://github.com/tronkko/dirent
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#ifdef WIN32
#	include <io.h>
#	include <fcntl.h>
#endif
#include <dirent.h>

/* File name and location of database file */
#define DB_LOCATION L"locate.db"

/* Forward-decl */
static int db_locate(const wchar_t *pattern);
static int db_match(const wchar_t *fn, const wchar_t *pattern);
static void db_open(void);
static void db_close(void);
static int db_read(wchar_t *buffer, size_t max);

/* Module local variables */
static FILE *db = NULL;

#ifdef _MSC_VER
int
wmain(int argc, wchar_t *argv[])
{
	/* Prepare for unicode output */
	_setmode(_fileno(stdout), _O_U16TEXT);

	/* For each pattern in command line */
	int i = 1;
	while (i < argc) {
		int count = 0;

		/* Find files matching pattern */
		count = db_locate(argv[i]);

		/* Output warning if string is not found */
		if (count == 0) {
			wprintf(L"%s not found\n", argv[i]);
		}

		i++;
	}

	if (argc < 2) {
		wprintf(L"Usage: locate pattern\n");
		exit(EXIT_FAILURE);
	}
	return EXIT_SUCCESS;
}
#else
int
main(int argc, char *argv[])
{
	printf("locate only works on Microsoft Windows\n");
	return EXIT_SUCCESS;
}
#endif

/* Match pattern against files in locate.db file */
static int
db_locate(const wchar_t *pattern)
{
	int count = 0;

#ifdef WIN32
	wchar_t buffer[PATH_MAX + 1];

	/* Open locate.db for read */
	db_open();

	/* Read one directory and file name at a time from database file */
	while (db_read(buffer, PATH_MAX + 1)) {
		/* See if file name in buffer matches the search pattern */
		if (db_match(buffer, pattern)) {
			/* Match found => output file name and path */
			wprintf(L"%s\n", buffer);
			count++;
		}
	}

	db_close();
#endif

	return count;
}

/* Match pattern against file name */
static int
db_match(const wchar_t *fn, const wchar_t *pattern)
{
	int found = 0;

#ifdef WIN32
	/* Locate zero-terminator from fn */
	wchar_t *p = wcschr(fn, '\0');

	/* Find base name from buffer */
	int done = 0;
	while (fn < p && !done) {
		switch (p[-1]) {
		case ':':
		case '/':
		case '\\':
			/* Final path separator found */
			done = 1;
			break;

		default:
			/* No path separator yet */
			p--;
		}
	}

	/* Convert base name to lower case */
	int i = 0;
	wchar_t base[PATH_MAX + 1];
	while (i < PATH_MAX && p[i] != '\0') {
		base[i] = towlower(p[i]);
		i++;
	}
	base[i] = '\0';

	/* Convert search pattern to lower case */
	i = 0;
	wchar_t patt[PATH_MAX + 1];
	while (i < PATH_MAX && pattern[i] != '\0') {
		patt[i] = towlower(pattern[i]);
		i++;
	}
	patt[i] = '\0';

	/* See if file name matches pattern */
	if (wcsstr(base, patt) != NULL) {
		found = 1;
	} else {
		found = 0;
	}
#endif

	return found;
}

/*
 * Read line from locate.db.  This function is same as fgetws() except
 * that new-line at the end of line is not included.
 */
static int
db_read(wchar_t *buffer, size_t max)
{
	int ok = 0;

#ifdef WIN32
	size_t i = 0;
	wchar_t c;
	int done = 0;

	if (!db) {
		wprintf(L"Database not open\n");
		exit(EXIT_SUCCESS);
	}

	do {
		/* Read wide-character from stream */
		c = fgetwc(db);

		/* Determine how to process character */
		switch (c) {
		case '\r':
			/* Ignore, should be handled by run-time libraries */
			/*NOP*/;
			break;

		case '\n':
			/* End of string => return file name */
			done = 1;
			ok = 1;
			break;

		case /*EOF*/WEOF:
			/* End of file */
			done = 1;
			if (i == 0) {
				/* No data in buffer => return false */
				ok = 0;
			} else {
				/* Data in buffer => return file name */
				ok = 1;
			}
			break;

		default:
			/* Store character */
			if (i < max - 1) {
				buffer[i++] = c;
			} else {
				buffer[max - 1] = '\0';
				wprintf(L"Buffer too small: %s", buffer);
				exit(EXIT_FAILURE);
			}
		}
	} while (!done);

	/* Zero-terminate buffer */
	buffer[i] = '\0';
#endif

	return ok;
}

/* Open database file locate.db */
static void
db_open(void)
{
#ifdef WIN32
	if (db)
		return;

	/* Open file for writing */
	errno_t error = _wfopen_s(&db, DB_LOCATION, L"rt, ccs=UNICODE");
	if (error) {
		wprintf(L"Cannot open %s\n", DB_LOCATION);
		exit(EXIT_FAILURE);
	}
#endif
}

/* Close database file */
static void
db_close(void)
{
	if (!db)
		return;

	fclose(db);
	db = NULL;
}
