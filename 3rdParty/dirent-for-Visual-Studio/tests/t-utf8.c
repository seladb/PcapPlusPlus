/*
 * Test program to try UTF-8 file names.
 *
 * Copyright (C) 1998-2019 Toni Ronkko
 * This file is part of dirent.  Dirent may be freely distributed
 * under the MIT license.  For all details and documentation, see
 * https://github.com/tronkko/dirent
 */

/* Silence warning about fopen being insecure */
#define _CRT_SECURE_NO_WARNINGS

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <time.h>
#include <locale.h>

#undef NDEBUG
#include <assert.h>

int
main(int argc, char *argv[])
{
#ifdef WIN32
	/*
	 * Select UTF-8 locale.  This will change the way how C runtime
	 * functions such as fopen() and mkdir() handle character strings.
	 * For more information, please see:
	 * https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/setlocale-wsetlocale?view=msvc-160#utf-8-support
	 */
	setlocale(LC_ALL, "LC_CTYPE=.utf8");

	/* Initialize random number generator */
	srand(((int) time(NULL)) * 257 + ((int) GetCurrentProcessId()));

	/* Get path to temporary directory */
	wchar_t wpath[MAX_PATH+1];
	DWORD i = GetTempPathW(MAX_PATH, wpath);
	assert(i > 0);

	/* Ensure that path name ends in directory separator */
	assert(wpath[i - 1] == '\\');

	/* Append random prefix */
	DWORD k;
	for (k = 0; k < 8; k++) {
		/* Generate random character */
		char c = "abcdefghijklmnopqrstuvwxyz"[rand() % 26];

		/* Append character to path */
		assert(i < MAX_PATH);
		wpath[i++] = c;
	}

	/* Append a wide character to the path name */
	wpath[i++] = 0x00c4;

	/* Terminate the path name */
	assert(i < MAX_PATH);
	wpath[i] = '\0';

	/* Create directory with unicode name */
	BOOL ok = CreateDirectoryW(wpath, NULL);
	if (!ok) {
		DWORD e = GetLastError();
		wprintf(L"Cannot create directory %ls (code %u)\n", wpath, e);
		abort();
	}

	/* Overwrite zero terminator with path separator */
	assert(i < MAX_PATH);
	wpath[i++] = '\\';

	/* Append a few unicode characters */
	assert(i < MAX_PATH);
	wpath[i++] = 0x00f6;
	assert(i < MAX_PATH);
	wpath[i++] = 0x00e4;

	/* Terminate string */
	assert(i < MAX_PATH);
	wpath[i] = '\0';

	/* Create file with unicode name */
	HANDLE fh = CreateFileW(
		wpath,
		/* Access */ GENERIC_READ | GENERIC_WRITE,
		/* Share mode */ 0,
		/* Security attributes */ NULL,
		/* Creation disposition */ CREATE_NEW,
		/* Attributes */ FILE_ATTRIBUTE_NORMAL,
		/* Template files */ NULL
		);
	assert(fh != INVALID_HANDLE_VALUE);

	/* Write some data to file */
	ok = WriteFile(
		/* File handle */ fh,
		/* Pointer to data */ "hep\n",
		/* Number of bytes to write */ 4,
		/* Number of bytes written */ NULL,
		/* Overlapped */ NULL
		);
	assert(ok);

	/* Close file */
	ok = CloseHandle(fh);
	assert(ok);

	/* Convert file name to UTF-8 */
	char path[MAX_PATH+1];
	int n = WideCharToMultiByte(
		/* Code page to use in conversion */ CP_UTF8,
		/* Flags */ 0,
		/* Pointer to unicode string */ wpath,
		/* Length of unicode string in characters */ i,
		/* Pointer to output buffer */ path,
		/* Size of output buffer in bytes */ MAX_PATH,
		/* Pointer to default character */ NULL,
		/* Pointer to boolean variable */ NULL
	);
	assert(n > 0);

	/* Zero-terminate path */
	path[(size_t) n] = '\0';

	/* Make sure that fopen() can open the file with UTF-8 file name */
	FILE *fp = fopen(path, "r");
	if (!fp) {
		fprintf(stderr, "Cannot open file %s\n", path);
		abort();
	}

	/* Read data from file */
	char buffer[100];
	if (fgets(buffer, sizeof(buffer), fp) == NULL) {
		fprintf(stderr, "Cannot read file %s\n", path);
		abort();
	}

	/* Make sure that we got the file contents right */
	assert(buffer[0] == 'h');
	assert(buffer[1] == 'e');
	assert(buffer[2] == 'p');
	assert(buffer[3] == '\n');
	assert(buffer[4] == '\0');

	/* Close file */
	fclose(fp);

	/* Truncate path name to the last directory separator */
	i = 0;
	k = 0;
	while (path[k] != '\0') {
		if (path[k] == '\\' || path[k] == '/') {
			i = k;
		}
		k++;
	}
	path[i] = '\0';

	/* Ensure that opendir() can open the directory with UTF-8 name */
	DIR *dir = opendir(path);
	if (dir == NULL) {
		fprintf(stderr, "Cannot open directory %s\n", path);
		abort();
	}

	/* Read entries */
	int counter = 0;
	struct dirent *entry;
	while ((entry = readdir(dir)) != NULL) {
		/* Skip pseudo directories */
		if (strcmp(entry->d_name, ".") == 0) {
			continue;
		}
		if (strcmp(entry->d_name, "..") == 0) {
			continue;
		}

		/* Found a file */
		counter++;
		assert(entry->d_type == DT_REG);

		/* Append file name to path */
		k = i;
		assert(i < MAX_PATH);
		path[i++] = '\\';
		DWORD x = 0;
		while (entry->d_name[x] != '\0') {
			assert(i < MAX_PATH);
			path[i++] = entry->d_name[x++];
		}
		assert(i < MAX_PATH);
		path[i] = '\0';

		/* Reset buffer */
		for (x = 0; x < sizeof(buffer); x++) {
			buffer[x] = '\0';
		}

		/* Open file for read */
		fp = fopen(path, "r");
		if (!fp) {
			fprintf(stderr, "Cannot open file %s\n", path);
			abort();
		}

		/* Read data from file */
		if (fgets(buffer, sizeof(buffer), fp) == NULL) {
			fprintf(stderr, "Cannot read file %s\n", path);
			abort();
		}

		/* Make sure that we got the file contents right */
		assert(buffer[0] == 'h');
		assert(buffer[1] == 'e');
		assert(buffer[2] == 'p');
		assert(buffer[3] == '\n');
		assert(buffer[4] == '\0');

		/* Close file */
		fclose(fp);
	}
	assert(counter == 1);

	/* Close directory */
	closedir(dir);
#else
	/* Linux */
	(void) argc;
	(void) argv;
#endif
	return EXIT_SUCCESS;
}
