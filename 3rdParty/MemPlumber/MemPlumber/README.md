# MemPlumber

[![Build Status](https://travis-ci.org/seladb/MemPlumber.svg?branch=master)](https://travis-ci.org/seladb/MemPlumber)
[![Build status](https://ci.appveyor.com/api/projects/status/aw1jwoqa0sb2no45?svg=true)](https://ci.appveyor.com/project/seladb/memplumber)

MemPlumber is a C++ library that aims to help developers with debugging of memory allocations and detection of memory leaks in C++ applications. It is based on the [Debug_new](https://en.wikipedia.org/wiki/Debug_new) technique and provides a clean and easy-to-use interface.

It is multi platform and supported on Windows (MinGW and Visual Studio), Linux and MacOS.

It is different than tools like [Valgrind](http://www.valgrind.org/) in that it's not an external tool, but rather a library you link your code with. Once turned on from inside your code it will track all memory allocations and will help detecting memory leaks.

This library is very useful for testing and debugging, and in particular in unit-tests. Just link it to your test code and initiate a mem leak test. Once memory leaks are found, the library provides easy to use tools for debugging and locating the exact origin of the memory leak.

Please note it is not recommended to use this library in production since tracking memory allocations has a cost in both performance and memory.

## Table Of Contents

- [Getting Started](#getting-started)
- [Download](#download)
- [Feature Overview](#feature-overview)
- [Examples](#examples)
- [API Reference](#api-reference)
- [License](#license)

## Getting Started

Consider this piece of code:

```cpp
#include <stdio.h>

class MyClass {
    int x;
};

int main( int argc, const char* argv[]) {

    // init 2 objects
    int* num = new int(100);
    MyClass* myClass = new MyClass();

    // init 1 array of 10 objects
    MyClass* myClassArr = new MyClass[10];

    return 0;
}
```

You probably spotted the two leaked objects (one integer and one instance of `MyClass`) and the leaked array of 10 `MyClass` Objects. Let's add `MemPlumber` leak test now:

```cpp
#include "memplumber.h"
#include <stdio.h>

class MyClass {
    int x;
};

int main( int argc, const char* argv[]) {

    // start collecting mem allocations info
    MemPlumber::start();

    // init 2 objects
    int* num = new int(100);
    MyClass* myClass = new MyClass();

    // init 1 array of 10 objects
    MyClass* myClassArr = new MyClass[10];

    // run memory leak test in verbose mode
    size_t memLeakCount;
    uint64_t memLeakSize;
    MemPlumber::memLeakCheck(memLeakCount, memLeakSize, true);

    // print memory leak results
    printf("Number of leaked objects: %d\nTotal amount of memory leaked: %d[bytes]\n", (int)memLeakCount, (int)memLeakSize);

    return 0;
}
```

When running this code we get the following output:

```
Found leaked object at 0x001A6E90 (size 4[bytes]) allocated in: C:\MemPlumber\Examples\example1.cpp:14
Found leaked object at 0x001A6F10 (size 4[bytes]) allocated in: C:\MemPlumber\Examples\example1.cpp:15
Found leaked object at 0x001A7020 (size 40[bytes]) allocated in: C:\MemPlumber\Examples\example1.cpp:18
Number of leaked objects: 3
Total number of memory leaked: 48[bytes]
```

Please note that we ran the mem leak test in verbose mode, so in addition to the number of leaked objects and total memory leaked, we also got information about where each mem leak happened.

## Download

Downloading and building MemPlumber is very easy! First download the latest version from `master`:

```
git clone https://github.com/seladb/MemPlumber
```

MemPlumber uses `CMake` as its build system, so building it is very easy:

```
# Create the build directory
mkdir build
cd build

# Run CMake configuration. Add any relevant configuration flags
cmake ..

# Compile
make
```

There is currently only one configuration flag:

| Flag                        | Description  |
|-----------------------------|--------------|
| `-DCOLLECT_STATIC_VAR_DATA=ON` | Collect data on static variable memory allocation (default is OFF) |

## Feature Overview

- Start and stop collecting data about memory allocations. Before starting or after stopping no information is being collected
- Running in verbose mode which outputs for each allocation and de-allocation: where in the code memory was allocated or freed and how much memory was allocated
- Run a memory leak test that outputs the number of leaked objects as well as the amount of memory leaked
- Running the memory leak test in verbose mode also outputs where each leak happened in the code and how much memory was leaked
- Run a static memory test that outputs the number of objects and the amount of memory that is allocated as static objects. This feature is only available if library is compiled with the `-DCOLLECT_STATIC_VAR_DATA=ON` flag
- Write all output to either `stdout` or a file
- Manually free all currently allocated memory

## Examples

It's often easier to understand the usage through examples. That's why MemPlumber is shipped with a few examples that are highly documented and explain the basic usage and features of this library. You can find all of them in the [Examples](https://github.com/seladb/MemPlumber/tree/master/Examples) section. Here is a brief overview of those examples:

- [basic-example](https://github.com/seladb/MemPlumber/tree/master/Examples/basic-example.cpp) - provides a simple flow of starting MemPlumber, allocating some memory and then running a mem leak test

- [static-example](https://github.com/seladb/MemPlumber/tree/master/Examples/static-example.cpp) - provides a simple flow of allocating several static variables, and running a static mem check. Please note you have to run this example when you compile MemPlumber with the `-DCOLLECT_STATIC_VAR_DATA=ON` flag

- [dump-to-file-example](https://github.com/seladb/MemPlumber/tree/master/Examples/dump-to-file-example.cpp) - provides examples of how to dump verbose data to files, both data about memory allocations and de-allocations and data during mem leak test

## API Reference

### `start()`

Start collecting information about memory allocations. Note that before calling this method no information is collected

__Params__:

- `verbose` _[in]_ - A flag indicating whether to dump information on each memory allocation and deallocation. The default value is false
- `fileDumperName` _[in]_ - If the "verbose" flag is set to true, it is possible to dump the verbose information to a file. If this parameter is set to an empty string (which is also the default value), the verbose information will be dumped to stdout
- `append` _[in]_ - If the "verbose" flag is set to true and "fileDumperName" is a non-empty string and if this file already exists on disk this parameter indicates whether to append the verbose information to the existing file or start writing from scratch

### `stop()`

Stop collecting information about memory allocations

### `stopAndFreeAllMemory()`

Stop collecting information about memory allocations and also free all the memory that was already allocated and collected

### `memLeakCheck()`

Present information about memory allocations that were not yet freed

__Params:__

- `memLeakCount` _[out]_ - The number of memory allocations that were not yet freed
- `memLeakSize` _[out]_ - The total amount of memory that was allocated but not yet freed
- `verbose` _[in]_ - A flag indicating whether to dump information on all memory allocations that were not yet freed. The default value is false
- `fileDumperName` _[in]_ - If the "verbose" flag is set to true, it is possible to dump the verbose information to a file. If this parameter is set to an empty string (which is also the default value), the verbose information will be dumped to stdout
- `append` _[in]_ - If the "verbose" flag is set to true and "fileDumperName" is a non-empty string and if this file already exists on disk, this parameter indicates whether to append the verbose information to the existing file or start writing from scratch

### `staticMemCheck()`

Present information about memory allocations of static variables. This information is available only if the library was compiled with the `-DCOLLECT_STATIC_VAR_DATA` flag and if the main method of the application was renamed and replaced by calling `MEMPLUMBER_MAIN(<renamed_original_main_method>);`

__Params:__

- `memCount` _[out]_ - The number of static memory allocations
- `memSize` _[out]_ - The total amount of memory that was allocated in static variables
- `verbose` _[in]_ - A flag indicating whether to dump information on all static memory allocations. The default value is false
- `fileDumperName` _[in]_ - If the "verbose" flag is set to true, it is possible to dump the verbose information to a file. If this parameter is set to an empty string (which is also the default value), the verbose information will be dumped to stdout
- `append` _[in]_ - If the "verbose" flag is set to true and "fileDumperName" is a non-empty string and if this file already exists on disk, this parameter indicates whether to append the verbose information to the existing file or start writing from scratch

## License

MemPlumber is released under the [MIT license](https://choosealicense.com/licenses/mit/).
