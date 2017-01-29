/*
 * Test program to make sure that dirent compiles cleanly.
 *
 * Attempt to compile this program using Visual Studio.  If dirent.h is
 * working properly, then this program compiles without errors.
 *
 * Copyright (C) 2006-2012 Toni Ronkko
 * This file is part of dirent.  Dirent may be freely distributed
 * under the MIT license.  For all details and documentation, see
 * https://github.com/tronkko/dirent
 */
#include <dirent.h>
#ifdef WIN32
#   include <winsock2.h>
#   include <ws2tcpip.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main(
    int argc, char *argv[]) 
{
    (void) argc;
    (void) argv;

    printf ("OK\n");
    return EXIT_SUCCESS;
}
