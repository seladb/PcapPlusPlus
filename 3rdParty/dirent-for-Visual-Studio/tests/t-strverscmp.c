/*
 * Test program to make sure that strverscmp works correctly
 *
 * Copyright (C) 1998-2019 Toni Ronkko
 * This file is part of dirent.  Dirent may be freely distributed
 * under the MIT license.  For all details and documentation, see
 * https://github.com/tronkko/dirent
 */

/* Include prototype for strverscmp */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <dirent.h>
#include <ctype.h>

int
main(
	int argc, char *argv[])
{
	(void) argc;
	(void) argv;

	/* Strings without digits are compared as in strcmp() */
	assert(strverscmp("", "") == 0);
	assert(strverscmp("abc", "abc") == 0);
	assert(strverscmp("a", "b") < 0);
	assert(strverscmp("b", "a") > 0);

	/* Shorter string is smaller, other things being equal */
	assert(strverscmp("a", "aa") < 0);
	assert(strverscmp("aa", "a") > 0);
	assert(strverscmp("abcdef", "abcdefg") < 0);
	assert(strverscmp("abcdefg", "abcdef") > 0);

	/* Integers with equal length are compared as in strcmp() */
	assert(strverscmp("0", "0") == 0);
	assert(strverscmp("000", "000") == 0);
	assert(strverscmp("1", "2") < 0);
	assert(strverscmp("2", "1") > 0);
	assert(strverscmp("001", "100") < 0);
	assert(strverscmp("100", "001") > 0);
	assert(strverscmp("2020-07-01", "2020-07-02") < 0);
	assert(strverscmp("2020-07-02", "2020-07-01") > 0);
	assert(strverscmp("jan999", "jan999") == 0);

	/* Integers of different length are compared as numbers */
	assert(strverscmp("jan9", "jan10") < 0);
	assert(strverscmp("jan10", "jan9") > 0);
	assert(strverscmp("999", "1000") < 0);
	assert(strverscmp("1000", "999") > 0);
	assert(strverscmp("t12-1000", "t12-9999") < 0);
	assert(strverscmp("t12-9999", "t12-1000") > 0);
	assert(strverscmp("1000", "10001") < 0);
	assert(strverscmp("10001", "1000") > 0);
	assert(strverscmp("1000!", "10001") < 0);
	assert(strverscmp("10001", "1000!") > 0);
	assert(strverscmp("1000Z", "10001") < 0);
	assert(strverscmp("10001", "1000Z") > 0);

	/* If numbers starts with zero, then longer number is smaller */
	assert(strverscmp("00", "0") < 0);
	assert(strverscmp("0", "00") > 0);
	assert(strverscmp("a000", "a00") < 0);
	assert(strverscmp("a00", "a000") > 0);
	assert(strverscmp("0000", "000") < 0);
	assert(strverscmp("000", "0000") > 0);
	assert(strverscmp("0000", "000!") < 0);
	assert(strverscmp("000!", "0000") > 0);
	assert(strverscmp("0000", "000Z") < 0);
	assert(strverscmp("000Z", "0000") > 0);
	assert(strverscmp("0000", "000Z") < 0);
	assert(strverscmp("000Z", "0000") > 0);
	assert(strverscmp("1.01", "1.0") < 0);
	assert(strverscmp("1.0", "1.01") > 0);
	assert(strverscmp("1.01", "1.0!") < 0);
	assert(strverscmp("1.0!", "1.01") > 0);
	assert(strverscmp("1.01", "1.0~") < 0);
	assert(strverscmp("1.0~", "1.01") > 0);

	/* Number having more leading zeros is considered smaller */
	assert(strverscmp("item-0001", "item-001") < 0);
	assert(strverscmp("item-001", "item-0001") > 0);
	assert(strverscmp("item-001", "item-01") < 0);
	assert(strverscmp("item-01", "item-001") > 0);
	assert(strverscmp(".0001000", ".001") < 0);
	assert(strverscmp(".001", ".0001000") > 0);
	assert(strverscmp(".0001000", ".01") < 0);
	assert(strverscmp(".01", ".0001000") > 0);
	assert(strverscmp(".0001000", ".1") < 0);
	assert(strverscmp(".1", ".0001000") > 0);
	assert(strverscmp("1.0002", "1.0010000") < 0);
	assert(strverscmp("1.0010000", "1.0002") > 0);

	/* Number starting with zero is smaller than any number */
	assert(strverscmp("item-009", "item-1") < 0);
	assert(strverscmp("item-1", "item-009") > 0);
	assert(strverscmp("item-099", "item-2") < 0);
	assert(strverscmp("item-2", "item-099") > 0);

	/* Number vs alphabetical comparison */
	assert(strverscmp("1.001", "1.00!") < 0);
	assert(strverscmp("1.00!", "1.001") > 0);
	assert(strverscmp("1.001", "1.00x") < 0);
	assert(strverscmp("1.00x", "1.001") > 0);
	assert(strverscmp("1", "x") < 0);
	assert(strverscmp("x", "1") > 0);
	assert(strverscmp("1", "!") > 0);
	assert(strverscmp("!", "1") < 0);

	/* Handling the end of string */
	assert(strverscmp("01", "011") < 0);
	assert(strverscmp("011", "01") > 0);
	assert(strverscmp("0100", "01000") < 0);
	assert(strverscmp("01000", "0100") > 0);
	assert(strverscmp("1", "1!") < 0);
	assert(strverscmp("1!", "1") > 0);
	assert(strverscmp("1", "1z") < 0);
	assert(strverscmp("1z", "1") > 0);

	/* Ordering 000 < 00 < 01 < 010 < 09 < 0 < 1 < 9 < 10 */
	assert(strverscmp("000", "00") < 0);
	assert(strverscmp("000", "01") < 0);
	assert(strverscmp("000", "010") < 0);
	assert(strverscmp("000", "09") < 0);
	assert(strverscmp("000", "0") < 0);
	assert(strverscmp("000", "1") < 0);
	assert(strverscmp("000", "9") < 0);
	assert(strverscmp("000", "10") < 0);

	assert(strverscmp("00", "01") < 0);
	assert(strverscmp("00", "010") < 0);
	assert(strverscmp("00", "09") < 0);
	assert(strverscmp("00", "0") < 0);
	assert(strverscmp("00", "1") < 0);
	assert(strverscmp("00", "9") < 0);
	assert(strverscmp("00", "10") < 0);

	assert(strverscmp("01", "010") < 0);
	assert(strverscmp("01", "09") < 0);
	assert(strverscmp("01", "0") < 0);
	assert(strverscmp("01", "1") < 0);
	assert(strverscmp("01", "9") < 0);
	assert(strverscmp("01", "10") < 0);

	assert(strverscmp("010", "09") < 0);
	assert(strverscmp("010", "0") < 0);
	assert(strverscmp("010", "1") < 0);
	assert(strverscmp("010", "9") < 0);
	assert(strverscmp("010", "10") < 0);

	assert(strverscmp("09", "0") < 0);
	assert(strverscmp("09", "1") < 0);
	assert(strverscmp("09", "9") < 0);
	assert(strverscmp("09", "10") < 0);

	assert(strverscmp("0", "1") < 0);
	assert(strverscmp("0", "9") < 0);
	assert(strverscmp("0", "10") < 0);

	assert(strverscmp("1", "9") < 0);
	assert(strverscmp("1", "10") < 0);

	assert(strverscmp("9", "10") < 0);

	/* Compare speed */
	{
#define LENGTH 100
#define REPEAT 1000000
		char a[LENGTH+1];
		char b[LENGTH+1];
		size_t i;
		size_t j;
		char letters[] = "01234567890123456789abdefghjkpqrtwxyz-/.";
		size_t n = strlen(letters);

		/* Repeat test */
		for(i = 0; i < REPEAT; i++) {
			int diff1;
			int diff2;

			/* Generate two random strings of LENGTH characters */
			for(j = 0; j < LENGTH; j++) {
				a[j] = letters[rand() % n];
				b[j] = letters[rand() % n];
			}
			a[j] = '\0';
			b[j] = '\0';

			/* Compare strings in both directions */
			diff1 = strverscmp(a, b);
			diff2 = strverscmp(b, a);

			/* Must give identical result in both directions */
			assert((diff1 < 0 && diff2 > 0)
				|| (diff1 == 0 && diff2 == 0)
				|| (diff1 > 0 && diff2 < 0));
		}
	}

	printf("OK\n");
	return EXIT_SUCCESS;
}
