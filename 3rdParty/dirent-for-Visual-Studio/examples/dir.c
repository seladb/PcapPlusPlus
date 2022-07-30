/*
 * List files with date, type and size.
 *
 * Compile this file with Visual Studio and run the produced command in
 * console with a directory name argument.  For example, command
 *
 *     dir "C:\Users\User 1\Documents"
 *
 * might output something like
 *
 *     Directory of c:\Users\User 1\Documents
 *
 *     2021-06-06  20:04       <DIR>               .
 *     2021-07-20  13:42       <DIR>               ..
 *     2020-06-21  15:00                       402 desktop.ini
 *     2020-06-21  15:00       <DIR>               Omat kuvatiedostot
 *     2020-06-21  15:00       <DIR>               Omat musiikkitiedostot
 *     2020-06-21  15:00       <DIR>               Omat videotiedostot
 *     2018-12-21  18:34       <DIR>               Visual Studio 2017
 *                        3 File(s)       402 bytes
 *                        7 Dir(s)
 *
 * The dir command provided by this file is only an example: the command
 * does not have any fancy options.
 *
 * Copyright (C) 2006-2012 Toni Ronkko
 * This file is part of dirent.  Dirent may be freely distributed
 * under the MIT license.  For all details and documentation, see
 * https://github.com/tronkko/dirent
 */
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <locale.h>
#include <time.h>
#include <sys/stat.h>

#define ERR_MSG_LEN 256

static void list_directory(const char* dirname);
static void fail(const char* dirname);
static int _main(int argc, char *argv[]);

static int
_main(int argc, char* argv[])
{
	/* For each directory in command line */
	int i = 1;
	while (i < argc) {
		list_directory(argv[i]);
		i++;
	}

	/* List current working directory if no arguments on command line */
	if (argc == 1)
		list_directory(".");

	return EXIT_SUCCESS;
}

/* List files and file sizes in directory */
static void
list_directory(const char* dirname)
{
	char path[PATH_MAX + 2];
	char *p = path;
	char *end = &path[PATH_MAX];

	/* Copy directory name to path */
	const char *src = dirname;
	while (p < end && *src != '\0') {
		*p++ = *src++;
	}

	/* Get final character of directory name */
	char c = (path < p ? p[-1] : ':');

	/* Append directory separator if not already there */
	if (c != ':' && c != '/' && c != '\\')
		*p++ = '/';

	/* Print directory name to screen */
	printf("Directory of %s\n\n", dirname);

	/* Open directory stream */
	DIR *dir = opendir(dirname);
	if (!dir) {
		/* Could not open directory */
		fprintf(stderr,
			"Cannot open %s (%s)\n", dirname, strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Loop through file names */
	int filecount = 0;
	int dircount = 0;
	long long bytecount = 0;
	struct dirent *ent;
	while ((ent = readdir(dir)) != NULL) {
		/* Append file name to path */
		char *q = p;
		src = ent->d_name;
		while (q < end && *src != '\0') {
			*q++ = *src++;
		}
		*q = '\0';

		/* Get file properties such as size and modification time */
		struct stat stbuf;
		if (stat(path, &stbuf) == /*error*/-1) {
			fail(path);
		}

		/* Get file type from stat buffer */
		const char *type;
		if (S_ISDIR(stbuf.st_mode)) {
			/* Directory */
			type = "<DIR>";
		} else if (S_ISREG(stbuf.st_mode)) {
			/* Regular file */
			type = "";
		} else if (S_ISLNK(stbuf.st_mode)) {
			/* Link */
			type = "<LNK>";
		} else {
			/* Named pipe, socket, character device or else */
			type = "<UNK>";
		}

		/* Get last modification date as a string */
		struct tm *tp = localtime(&stbuf.st_mtime);
		char mtime[40];
		sprintf(mtime, "%04d-%02d-%02d  %02d:%02d",
			tp->tm_year + 1900,
			tp->tm_mon + 1,
			tp->tm_mday,
			tp->tm_hour,
			tp->tm_min);

		/* Get file size as a string */
		char size[40];
		if (S_ISREG(stbuf.st_mode)) {
			sprintf(size, "%lld", (long long) stbuf.st_size);
		} else {
			size[0] = '\0';
		}

		/* Output file info */
		printf("%-20s    %-5s  %12s %s\n",
			mtime, type, size, ent->d_name);

		/* Compute totals */
		if (S_ISREG(stbuf.st_mode)) {
			filecount++;
			bytecount += (long long) stbuf.st_size;
		}
		if (S_ISDIR(stbuf.st_mode)) {
			dircount++;
		}
	}

	/* Output sums */
	printf("%20d File(s) %12lld bytes\n", filecount, bytecount);
	printf("%20d Dir(s)\n", dircount);
}

/* Print error message and exit with error condition */
static void
fail(const char* msg)
{
	/* Output error message */
	perror(msg);

	/* Exit the program immediately */
	exit(EXIT_FAILURE);
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

