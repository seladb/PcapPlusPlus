/*
 * A test program for making sure that dirent works correctly.
 *
 * Compile this file with Visual Studio 2008 project vs2008.sln and run the
 * produced command in console using the project root as current working
 * directory.  If everything works out fine, the program outputs the word
 * OK and quits gracefully.
 *
 * Copyright (C) 2006-2012 Toni Ronkko
 * This file is part of dirent.  Dirent may be freely distributed
 * under the MIT license.  For all details and documentation, see
 * https://github.com/tronkko/dirent
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _MSC_VER
#   include <direct.h>
#   define chdir(x) _chdir(x)
#else
#   include <unistd.h>
#endif
#include <sys/stat.h>
#include <dirent.h>

#undef NDEBUG
#include <assert.h>


int
main(
    int argc, char *argv[]) 
{
    (void) argc;
    (void) argv;

    /* File type macros */
    {
        assert (DTTOIF(DT_REG) == S_IFREG);
        assert (DTTOIF(DT_DIR) == S_IFDIR);
        assert (DTTOIF(DT_FIFO) == S_IFIFO);
        assert (DTTOIF(DT_SOCK) == S_IFSOCK);
        assert (DTTOIF(DT_CHR) == S_IFCHR);
        assert (DTTOIF(DT_BLK) == S_IFBLK);

        assert (IFTODT(S_IFREG) == DT_REG);
        assert (IFTODT(S_IFDIR) == DT_DIR);
        assert (IFTODT(S_IFIFO) == DT_FIFO);
        assert (IFTODT(S_IFSOCK) == DT_SOCK);
        assert (IFTODT(S_IFCHR) == DT_CHR);
        assert (IFTODT(S_IFBLK) == DT_BLK);
    }

    /* Basic directory retrieval */
    {
        DIR *dir;
        struct dirent *ent;
        int found = 0;

        /* Open directory */
        dir = opendir ("tests/1");
        if (dir == NULL) {
            fprintf (stderr, "Directory tests/1 not found\n");
            abort ();
        }

        /* Read entries */
        while ((ent = readdir (dir)) != NULL) {

            /* Check each file */
            if (strcmp (ent->d_name, ".") == 0) {
                /* Directory itself */
#ifdef _DIRENT_HAVE_D_TYPE
                assert (ent->d_type == DT_DIR);
#endif
#ifdef _DIRENT_HAVE_D_NAMLEN
                assert (ent->d_namlen == 1);
#endif
#ifdef _D_EXACT_NAMLEN
                assert (_D_EXACT_NAMLEN(ent) == 1);
#endif
#ifdef _D_ALLOC_NAMLEN
                assert (_D_ALLOC_NAMLEN(ent) > 1);
#endif
                found += 1;

            } else if (strcmp (ent->d_name, "..") == 0) {
                /* Parent directory */
#ifdef _DIRENT_HAVE_D_TYPE
                assert (ent->d_type == DT_DIR);
#endif
#ifdef _DIRENT_HAVE_D_NAMLEN
                assert (ent->d_namlen == 2);
#endif
#ifdef _D_EXACT_NAMLEN
                assert (_D_EXACT_NAMLEN(ent) == 2);
#endif
#ifdef _D_ALLOC_NAMLEN
                assert (_D_ALLOC_NAMLEN(ent) > 2);
#endif
                found += 2;

            } else if (strcmp (ent->d_name, "file") == 0) {
                /* Regular file */
#ifdef _DIRENT_HAVE_D_TYPE
                assert (ent->d_type == DT_REG);
#endif
#ifdef _DIRENT_HAVE_D_NAMLEN
                assert (ent->d_namlen == 4);
#endif
#ifdef _D_EXACT_NAMLEN
                assert (_D_EXACT_NAMLEN(ent) == 4);
#endif
#ifdef _D_ALLOC_NAMLEN
                assert (_D_ALLOC_NAMLEN(ent) > 4);
#endif
                found += 4;

            } else if (strcmp (ent->d_name, "dir") == 0) {
                /* Just a directory */
#ifdef _DIRENT_HAVE_D_TYPE
                assert (ent->d_type == DT_DIR);
#endif
#ifdef _DIRENT_HAVE_D_NAMLEN
                assert (ent->d_namlen == 3);
#endif
#ifdef _D_EXACT_NAMLEN
                assert (_D_EXACT_NAMLEN(ent) == 3);
#endif
#ifdef _D_ALLOC_NAMLEN
                assert (_D_ALLOC_NAMLEN(ent) > 3);
#endif
                found += 8;

            } else {
                /* Other file */
                fprintf (stderr, "Unexpected file %s\n", ent->d_name);
                abort ();
            }

        }

        /* Make sure that all files were found */
        assert (found == 0xf);

        closedir (dir);
    }

    /* Rewind of directory stream */
    {
        DIR *dir;
        struct dirent *ent;
        int found = 0;

        /* Open directory */
        dir = opendir ("tests/1");
        assert (dir != NULL);

        /* Read entries */
        while ((ent = readdir (dir)) != NULL) {

            /* Check each file */
            if (strcmp (ent->d_name, ".") == 0) {
                /* Directory itself */
                found += 1;

            } else if (strcmp (ent->d_name, "..") == 0) {
                /* Parent directory */
                found += 2;

            } else if (strcmp (ent->d_name, "file") == 0) {
                /* Regular file */
                found += 4;

            } else if (strcmp (ent->d_name, "dir") == 0) {
                /* Just a directory */
                found += 8;

            } else {
                /* Other file */
                fprintf (stderr, "Unexpected file %s\n", ent->d_name);
                abort ();
            }

        }

        /* Make sure that all files were found */
        assert (found == 0xf);

        /* Rewind stream and read entries again */
        rewinddir (dir);
        found = 0;

        /* Read entries */
        while ((ent = readdir (dir)) != NULL) {

            /* Check each file */
            if (strcmp (ent->d_name, ".") == 0) {
                /* Directory itself */
                found += 1;

            } else if (strcmp (ent->d_name, "..") == 0) {
                /* Parent directory */
                found += 2;

            } else if (strcmp (ent->d_name, "file") == 0) {
                /* Regular file */
                found += 4;

            } else if (strcmp (ent->d_name, "dir") == 0) {
                /* Just a directory */
                found += 8;

            } else {
                /* Other file */
                fprintf (stderr, "Unexpected file %s\n", ent->d_name);
                abort ();
            }

        }

        /* Make sure that all files were found */
        assert (found == 0xf);

        closedir (dir);
    }

    /* Rewind with intervening change of working directory */
    {
        DIR *dir;
        struct dirent *ent;
        int found = 0;
        int errorcode;

        /* Open directory */
        dir = opendir ("tests/1");
        assert (dir != NULL);

        /* Read entries */
        while ((ent = readdir (dir)) != NULL) {

            /* Check each file */
            if (strcmp (ent->d_name, ".") == 0) {
                /* Directory itself */
                found += 1;

            } else if (strcmp (ent->d_name, "..") == 0) {
                /* Parent directory */
                found += 2;

            } else if (strcmp (ent->d_name, "file") == 0) {
                /* Regular file */
                found += 4;

            } else if (strcmp (ent->d_name, "dir") == 0) {
                /* Just a directory */
                found += 8;

            } else {
                /* Other file */
                fprintf (stderr, "Unexpected file %s\n", ent->d_name);
                abort ();
            }

        }

        /* Make sure that all files were found */
        assert (found == 0xf);

        /* Change working directory */
        errorcode = chdir ("tests");
        assert (errorcode == 0);

        /* Rewind stream and read entries again */
        rewinddir (dir);
        found = 0;

        /* Read entries */
        while ((ent = readdir (dir)) != NULL) {

            /* Check each file */
            if (strcmp (ent->d_name, ".") == 0) {
                /* Directory itself */
                found += 1;

            } else if (strcmp (ent->d_name, "..") == 0) {
                /* Parent directory */
                found += 2;

            } else if (strcmp (ent->d_name, "file") == 0) {
                /* Regular file */
                found += 4;

            } else if (strcmp (ent->d_name, "dir") == 0) {
                /* Just a directory */
                found += 8;

            } else {
                /* Other file */
                fprintf (stderr, "Unexpected file %s\n", ent->d_name);
                abort ();
            }

        }

        /* Make sure that all files were found */
        assert (found == 0xf);

        /* Restore working directory */
        errorcode = chdir ("..");
        assert (errorcode == 0);

        closedir (dir);
    }

    /* Long file name */
    {
        DIR *dir;
        struct dirent *ent;
        int found = 0;

        /* Open directory */
        dir = opendir ("tests/2");
        if (dir == NULL) {
            fprintf (stderr, "Directory tests/2 not found\n");
            abort ();
        }

        /* Read entries */
        while ((ent = readdir (dir)) != NULL) {

            /* Check each file */
            if (strcmp (ent->d_name, ".") == 0) {
                /* Directory itself */
                found += 1;

            } else if (strcmp (ent->d_name, "..") == 0) {
                /* Parent directory */
                found += 2;

            } else if (strcmp (ent->d_name, "file.txt") == 0) {
                /* Regular 8+3 filename */
#ifdef _DIRENT_HAVE_D_TYPE
                assert (ent->d_type == DT_REG);
#endif
#ifdef _DIRENT_HAVE_D_NAMLEN
                assert (ent->d_namlen == 8);
#endif
#ifdef _D_EXACT_NAMLEN
                assert (_D_EXACT_NAMLEN(ent) == 8);
#endif
#ifdef _D_ALLOC_NAMLEN
                assert (_D_ALLOC_NAMLEN(ent) > 8);
#endif
                found += 4;

            } else if (strcmp (ent->d_name, "Testfile-1.2.3.dat") == 0) {
                /* Long file name with multiple dots */
#ifdef _DIRENT_HAVE_D_TYPE
                assert (ent->d_type == DT_REG);
#endif
#ifdef _DIRENT_HAVE_D_NAMLEN
                assert (ent->d_namlen == 18);
#endif
#ifdef _D_EXACT_NAMLEN
                assert (_D_EXACT_NAMLEN(ent) == 18);
#endif
#ifdef _D_ALLOC_NAMLEN
                assert (_D_ALLOC_NAMLEN(ent) > 18);
#endif
                found += 8;

            } else {
                /* Other file */
                fprintf (stderr, "Unexpected file %s\n", ent->d_name);
                abort ();
            }

        }

        /* Make sure that all files were found */
        assert (found == 0xf);

        closedir (dir);
    }

    printf ("OK\n");
    return EXIT_SUCCESS;
}
