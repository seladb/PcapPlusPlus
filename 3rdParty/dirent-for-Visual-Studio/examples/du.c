/*
 * Compute disk usage of files and sub-directories in bytes.
 *
 * Compile this file with Visual Studio and run the produced command in
 * console with a directory name argument.  For example, command
 *
 *     du "c:\Program Files"
 *
 * might produce listing such as
 *
 *     5204927     7-Zip
 *     140046882   CCleaner
 *     83140342    CMake
 *     2685264     Internet Explorer
 *     686314712   LibreOffice
 *     214025459   Mozilla Firefox
 *     174753900   VideoLAN
 *
 * If you compare this program to a genuine du command in Linux, then be ware
 * directories themselves consume some space in Linux.  This program, however,
 * only counts the files and hence the size will always be smaller than that
 * reported by Linux du.
 *
 * Copyright (C) 1998-2019 Toni Ronkko
 * This file is part of dirent.  Dirent may be freely distributed
 * under the MIT license.  For all details and documentation, see
 * https://github.com/tronkko/dirent
 */
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <locale.h>

static long long list_directory(const char *dirname, int level);
static int _main(int argc, char *argv[]);

static int
_main(int argc, char *argv[])
{
	/* For each directory in command line */
	int i = 1;
	while (i < argc) {
		list_directory(argv[i], 0);
		i++;
	}

	/* List current working directory if no arguments on command line */
	if (argc == 1)
		list_directory(".", 0);

	return EXIT_SUCCESS;
}

/* Find files and subdirectories recursively; list their sizes */
static long long
list_directory(const char *dirname, int level)
{
	char buffer[PATH_MAX + 2];
	char *p = buffer;
	char *end = &buffer[PATH_MAX];
	
	/* Copy directory name to buffer */
	const char *src = dirname;
	while (p < end && *src != '\0') {
		*p++ = *src++;
	}
	*p = '\0';

	/* Get final character of directory name */
	char c;
	if (buffer < p)
		c = p[-1];
	else
		c = ':';

	/* Append directory separator if not already there */
	if (c != ':' && c != '/' && c != '\\')
		*p++ = '/';

	/* Open directory stream */
	DIR *dir = opendir(dirname);
	if (!dir) {
		fprintf(stderr,
			"Cannot open %s (%s)\n", dirname, strerror(errno));
		return 0LL;
	}

	/* Compute total disk usage of all files and directories */
	struct stat stbuf;
	struct dirent *ent;
	long long total = 0;
	while ((ent = readdir(dir)) != NULL) {
		/* Skip pseudo directories . and .. */
		if (strcmp(ent->d_name, ".") == 0
			|| strcmp(ent->d_name, "..") == 0)
			continue;

		/* Skip links as they consume no space */
		if (ent->d_type == DT_LNK)
			continue;

		/* Skip device entries */
		if (ent->d_type != DT_REG && ent->d_type != DT_DIR)
			continue;

		/* Append file name to buffer */
		src = ent->d_name;
		char *q = p;
		while (q < end && *src != '\0') {
			*q++ = *src++;
		}
		*q = '\0';

		/* Add file size */
		long long size = 0;
		if (ent->d_type == DT_REG) {
			if (stat(buffer, &stbuf) == /*Error*/-1) {
				fprintf(stderr, "Cannot access %s\n", buffer);
				continue;
			}
			size += (long long) stbuf.st_size;
		}

		/* Compute size of subdirectories recursively */
		if (ent->d_type == DT_DIR)
			size += list_directory(buffer, level + 1);

		/* Update total size of directory */
		total += size;

		/* Output file/directory size in bytes */
		if (level == 0)
			printf("%-10lld  %s\n", size, ent->d_name);
	}

	closedir(dir);

	/* Return total size of directory */
	return total;
}

/* Stub for converting arguments to UTF-8 on Windows */
#ifdef _MSC_VER
int
wmain(int argc, wchar_t *argv[])
{
	/* Select UTF-8 locale */
	setlocale(LC_ALL, ".utf8");
	SetConsoleCP(CP_UTF8);
	SetConsoleOutputCP(CP_UTF8);

	/* Allocate memory for multi-byte argv table */
	char **mbargv;
	mbargv = (char**) malloc(argc * sizeof(char*));
	if (!mbargv) {
		puts("Out of memory");
		exit(3);
	}

	/* Convert each argument in argv to UTF-8 */
	for (int i = 0; i < argc; i++) {
		size_t n;
		wcstombs_s(&n, NULL, 0, argv[i], 0);

		/* Allocate room for ith argument */
		mbargv[i] = (char*) malloc(n + 1);
		if (!mbargv[i]) {
			puts("Out of memory");
			exit(3);
		}

		/* Convert ith argument to utf-8 */
		wcstombs_s(NULL, mbargv[i], n + 1, argv[i], n);
	}

	/* Pass UTF-8 converted arguments to the main program */
	int errorcode = _main(argc, mbargv);

	/* Release UTF-8 arguments */
	for (int i = 0; i < argc; i++) {
		free(mbargv[i]);
	}

	/* Release the argument table */
	free(mbargv);
	return errorcode;
}
#else
int
main(int argc, char *argv[])
{
	return _main(argc, argv);
}
#endif

