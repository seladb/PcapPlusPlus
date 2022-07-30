# Dirent

Dirent is a programming interface for retrieving information about files and
directories in C and C++ languages.  This project provides a Dirent interface
for Microsoft Visual Studio.


# Installation

Download the latest Dirent installation package from
[GitHub](https://github.com/tronkko/dirent/releases) and
unpack the installation file with 7-zip, for example.  The installation
package contains ``include/dirent.h`` file as well as a few example and test
programs.

To make Dirent available to all C/C++ projects in your machine, simply copy
``include/dirent.h`` file to the system include directory, e.g.
``C:\Program Files\Microsoft Visual Studio 9.0\VC\include``.  Everything you
need is included in the single ``dirent.h`` file, and you can start using
Dirent immediately -- there is no need to add files to your Visual Studio
project.

Alternatively, if you wish to distribute ``dirent.h`` alongside with your own
project, then copy ``include/dirent.h`` file to a new sub-directory within
your project and add that directory to include path on Windows while omitting
the directory under Linux/UNIX.  This allows your project to be compiled
against native ``dirent.h`` on Linux/UNIX while substituting the functionality
on Microsoft Windows.


# Example Programs

The installation package contains example programs:

Program  | Purpose
-------- | -----------------------------------------------------------------
ls       | List files in a directory, e.g. ls "c:\Program Files"
find     | Find files in subdirectories, e.g. find "c:\Program Files\CMake"
updatedb | Build database of files in a drive, e.g. updatedb c:\
locate   | Locate a file from database, e.g. locate notepad
scandir  | Printed sorted list of file names in a directory, e.g. scandir .
du       | Compute disk usage, e.g. du "C:\Program Files"
cat      | Print a text file to screen, e.g. cat include/dirent.h

In order to build the example programs, first install
[CMake](https://cmake.org/) to your machine.  Then, open command prompt and
create a temporary directory ``c:\temp\dirent`` for the build files as

```
c:\
mkdir temp
mkdir temp\dirent
cd temp\dirent
```

Generate build files as

```
cmake d:\dirent
```

where ``d:\dirent`` is the root directory of the Dirent package containing
this README.md file.

Once CMake is finished, open Visual Studio, load the generated ``dirent.sln``
file from the build directory and build the whole solution.

Once the build completes, open command prompt and cd to the Debug directory to
run the example programs.  For example:

```
cd c:\temp\dirent\Debug
.\ls .
```

Visual Studio project also contains a solution named ``check`` which can be
used to verify that Dirent API works as expected.  Just build the solution
from Visual Studio to run the test programs.


# UTF-8 Support

By default, file and directory names in the Dirent API are expressed in the
currently selected windows codepage.  If you wish to use UTF-8 character
encoding, then replace the main function with \_main function and convert
wide-character arguments to UTF-8 strings as demonstrated in the snippet
below.

```
/* This is your true main function */
static int
_main(int argc, wchar_t *argv[])
{
	/* ... */
}

/* Convert arguments to UTF-8 */
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
		mbargv[i] = (char*) malloc(n);
		if (!mbargv[i]) {
			puts("Out of memory");
			exit(3);
		}

		/* Convert ith argument to utf-8 */
		wcstombs_s(NULL, mbargv[i], n, argv[i], n);
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
```

For more information on UTF-8 support, please see setlocale in Visual Studio
[C runtime library reference](https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/setlocale-wsetlocale?view=msvc-160#utf-8-support).


# Contributing

We love to receive contributions from you.  See the
[CONTRIBUTING](CONTRIBUTING.md) file for details.


# Copying

Dirent may be freely distributed under the MIT license.  See the
[LICENSE](LICENSE) file for details.


# Alternatives to Dirent

I ported Dirent to Microsoft Windows in 1998 when only a few alternatives
were available.  However, the situation has changed since then and nowadays
both [Cygwin](http://www.cygwin.com) and [MingW](http://www.mingw.org)
allow you to compile a great number of UNIX programs in Microsoft Windows.
They both provide a full Dirent API as well as many other UNIX APIs.  MingW
can even be used for commercial applications!

