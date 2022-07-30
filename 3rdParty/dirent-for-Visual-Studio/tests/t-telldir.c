/*
 * A test program to make sure that dirent works correctly.
 *
 * Copyright (C) 1998-2019 Toni Ronkko
 * This file is part of dirent.  Dirent may be freely distributed
 * under the MIT license.  For all details and documentation, see
 * https://github.com/tronkko/dirent
 */

/* Silence warning about strcmp being insecure (MS Visual Studio) */
#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>

#undef NDEBUG
#include <assert.h>

static void test_telldir(void);

int
main(int argc, char *argv[])
{
	(void) argc;
	(void) argv;

	test_telldir();

	return EXIT_SUCCESS;
}

static void
test_telldir(void)
{
	DIR *dir = opendir("tests/4");
	if (dir == NULL) {
		fprintf(stderr, "Directory tests/4 not found\n");
		abort();
	}

	/* Get position of first file */
	long pos1 = telldir(dir);
	printf("pos1: %lx\n", (long) pos1);
	assert(pos1 >= 0);

	/* Read first file */
	struct dirent *ent = readdir(dir);
	assert(ent != NULL);
	struct dirent ent1 = *ent;
	printf("ent1: %s %lx\n", ent->d_name, (long) ent->d_off);

	/* Seek back to the first position */
	seekdir(dir, pos1);

	/* Re-read the first entry */
	ent = readdir(dir);
	assert(ent != NULL);
	assert(strcmp(ent->d_name, ent1.d_name) == 0);

	/* Get position to second file */
	long pos2 = telldir(dir);
	printf("pos2: %lx\n", (long) pos2);
	assert(pos2 >= 0);

	/* Read second file */
	ent = readdir(dir);
	assert(ent != NULL);
	struct dirent ent2 = *ent;
	printf("ent2: %s %lx\n", ent->d_name, (long) ent->d_off);

	/* Get position to third file */
	long pos3 = telldir(dir);
	printf("pos3: %lx\n", (long) pos3);
	assert(pos3 >= 0);

	/* Read third file */
	ent = readdir(dir);
	assert(ent != NULL);
	struct dirent ent3 = *ent;
	printf("ent3: %s %lx\n", ent->d_name, (long) ent->d_off);

	/* Get position to fourth file */
	long pos4 = telldir(dir);
	printf("pos4: %lx\n", (long) pos4);
	assert(pos4 >= 0);

	/* Read fourth file */
	ent = readdir(dir);
	assert(ent != NULL);
	struct dirent ent4 = *ent;
	printf("ent4: %s %lx\n", ent->d_name, (long) ent->d_off);

	/* Get position to fifth file */
	long pos5 = telldir(dir);
	printf("pos5: %lx\n", (long) pos5);
	assert(pos5 >= 0);

	/* Read fifth file */
	ent = readdir(dir);
	assert(ent != NULL);
	struct dirent ent5 = *ent;
	printf("ent5: %s %lx\n", ent->d_name, (long) ent->d_off);

	/* Read position at the end of directory stream */
	long posx = telldir(dir);
	assert(posx >= 0);
	printf("posx: %lx\n", (long) posx);

	/* End of directory stream has been reached */
	ent = readdir(dir);
	assert(ent == NULL);

	/* Seek back to position just before the end of stream */
	seekdir(dir, posx);

	/* Function telldir returns the same position when asked again */
	assert(telldir(dir) == posx);
	assert(telldir(dir) == posx);
	assert(telldir(dir) == posx);

	/* Read end of stream again */
	ent = readdir(dir);
	assert(ent == NULL);

	/* Seek back to fifth file and read it again */
	seekdir(dir, pos5);
	assert(telldir(dir) == pos5);
	ent = readdir(dir);
	assert(ent != NULL);
	assert(strcmp(ent->d_name, ent5.d_name) == 0);

	/* Seek back to second file and read it again */
	seekdir(dir, pos2);
	assert(telldir(dir) == pos2);
	ent = readdir(dir);
	assert(ent != NULL);
	assert(strcmp(ent->d_name, ent2.d_name) == 0);

	/* Continue reading from the third file without a seek in between */
	assert(telldir(dir) == pos3);
	ent = readdir(dir);
	assert(ent != NULL);
	assert(strcmp(ent->d_name, ent3.d_name) == 0);

	/* Read fourth position again */
	assert(telldir(dir) == pos4);
	ent = readdir(dir);
	assert(ent != NULL);
	assert(strcmp(ent->d_name, ent4.d_name) == 0);

	/* Read fifth position again */
	assert(telldir(dir) == pos5);
	ent = readdir(dir);
	assert(ent != NULL);
	assert(strcmp(ent->d_name, ent5.d_name) == 0);

	/* Read end of stream again */
	assert(telldir(dir) == posx);
	ent = readdir(dir);
	assert(ent == NULL);
}

