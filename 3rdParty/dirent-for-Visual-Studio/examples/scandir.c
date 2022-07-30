/*
 * List contents of a directory in an alphabetical order.
 *
 * Compile this file with Visual Studio and run the produced command in
 * console with a directory name argument.  For example, command
 *
 *     scandir "c:\Program Files"
 *
 * might output something like
 *
 *     ./
 *     ../
 *     7-Zip/
 *     Internet Explorer/
 *     Microsoft Visual Studio 9.0/
 *     Microsoft.NET/
 *     Mozilla Firefox/
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
#include <errno.h>
#include <locale.h>

static void list_directory(const char *dirname);
static int _main(int argc, char *argv[]);

static int
_main(int argc, char *argv[])
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

/*
 * List files and directories within a directory.
 */
static void
list_directory(
	const char *dirname)
{
	/* Scan files in directory */
	struct dirent **files;
	int n = scandir(dirname, &files, NULL, alphasort);
	if (n < 0) {
		fprintf(stderr,
			"Cannot open %s (%s)\n", dirname, strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Loop through file names */
	for (int i = 0; i < n; i++) {
		/* Get pointer to file entry */
		struct dirent *ent = files[i];

		/* Output file name */
		switch (ent->d_type) {
		case DT_REG:
			printf("%s\n", ent->d_name);
			break;

		case DT_DIR:
			printf("%s/\n", ent->d_name);
			break;

		case DT_LNK:
			printf("%s@\n", ent->d_name);
			break;

		default:
			printf("%s*\n", ent->d_name);
		}
	}

	/* Release file names */
	for (int i = 0; i < n; i++) {
		free(files[i]);
	}
	free(files);
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

