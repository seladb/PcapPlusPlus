/*
 * Output contents of a file.
 *
 * Compile this file with Visual Studio and run the produced command in
 * console with a file name argument.  For example, command
 *
 *     cat include\dirent.h
 *
 * will output the dirent.h to screen.
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

static void output_file(const char *fn);
static int _main(int argc, char *argv[]);

static int
_main(int argc, char *argv[])
{
	/* Require at least one file */
	if (argc == 1) {
		fprintf(stderr, "Usage: cat filename\n");
		return EXIT_FAILURE;
	}

	/* For each file name argument in command line */
	int i = 1;
	while (i < argc) {
		output_file(argv[i]);
		i++;
	}
	return EXIT_SUCCESS;
}

/*
 * Output file to screen
 */
static void
output_file(const char *fn)
{
	/* Open file */
	FILE *fp = fopen(fn, "r");
	if (!fp) {
		/* Could not open directory */
		fprintf(stderr, "Cannot open %s (%s)\n", fn, strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Output file to screen */
	size_t n;
	do {
		/* Read some bytes from file */
		char buffer[4096];
		n = fread(buffer, 1, 4096, fp);

		/* Output bytes to screen */
		fwrite(buffer, 1, n, stdout);
	} while (n != 0);

	/* Close file */
	fclose(fp);
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

