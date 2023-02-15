#include "memplumber.h"
#include <stdio.h>

/**
 * This example is similar to "basic-example", the only difference is that it shows how to dump data to a file. It demonstrates the following flow:
 * - Start collecting memory allocation data and dump data to a file
 * - Allocate some memory (2 objects and 1 array)
 * - Run a mem leak test in verbose mode and dump data to a file. This will output all places in the code where memory was allocated and not yet freed.
 *   It will also summarize the total number of leaked objects as well as the amount of memory leaked
 * - Free some memory. This will also be dumped to the file
 * - Stop collecting memory allocation data and free remaining leaked memory. This will also be logged into the file
 *
 * The output should look something like this:
 *
 * 1st run. Number of leaked objects: 3
 * Total amount of memory leaked: 48[bytes]
 *
 * 2nd run. Number of leaked objects: 1
 * Total amount of memory leaked: 4[bytes]
 *
 * If you open `mem_allocations.log` you're expected to find the following data:
 *
 * Allocate: 4[bytes] in 0x00986EB0 in C:\MemPlumber\Examples\dump-to-file-example.cpp:50
 * Allocate: 4[bytes] in 0x00986F30 in C:\MemPlumber\Examples\dump-to-file-example.cpp:51
 * Allocate: 40[bytes] in 0x00987030 in C:\MemPlumber\Examples\dump-to-file-example.cpp:54
 * Free: 0x00986EB0 (size 4[bytes]) allocated in: C:\MemPlumber\Examples\dump-to-file-example.cpp:50
 * Free: 0x00987030 (size 40[bytes]) allocated in: C:\MemPlumber\Examples\dump-to-file-example.cpp:54
 * FreeAllMem: freeing 0x00986F30 (size 4[bytes]) allocated in C:\MemPlumber\Examples\dump-to-file-example.cpp:51
 *
 * If you open `mem_leak_test.log` you're expected to find the following data:
 *
 * Found leaked object at 0x00986EB0 (size 4[bytes]) allocated in: C:\Examples\dump-to-file-example.cpp:50
 * Found leaked object at 0x00986F30 (size 4[bytes]) allocated in: C:\Examples\dump-to-file-example.cpp:51
 * Found leaked object at 0x00987030 (size 40[bytes]) allocated in: C:\Examples\dump-to-file-example.cpp:54
 * Found leaked object at 0x00986F30 (size 4[bytes]) allocated in: C:\Examples\dump-to-file-example.cpp:51
 *
 */


class MyClass {
    int x;
};

int main( int argc, const char* argv[]) {

    // start collecting mem allocations info and dump info to "mem_allocations.log"
    MemPlumber::start(true, "mem_allocations.log");

    // init 2 objects
    int* num = new int(100);
    MyClass* myClass = new MyClass();

    // init 1 array of 10 objects
    MyClass* myClassArr = new MyClass[10];

    // run memory leak test in verbose mode and dump info to "mem_leak_test.log"
    size_t memLeakCount;
    uint64_t memLeakSize;
    MemPlumber::memLeakCheck(memLeakCount, memLeakSize, true, "mem_leak_test.log");

    // print memory leak results
    printf("1st run. Number of leaked objects: %d\nTotal amount of memory leaked: %d[bytes]\n", (int)memLeakCount, (int)memLeakSize);

    // free some memory (this will also be written to "mem_allocations.log")
    delete num;
    delete [] myClassArr;

    // run memory leak test again in verbose mode and dump info to the same file "mem_leak_test.log" but in append mode
    // this time we're expecting to find only 1 leaked object (myClass) since the other were already freed
    MemPlumber::memLeakCheck(memLeakCount, memLeakSize, true, "mem_leak_test.log", true);

    // print memory leak results
    printf("\n2nd run. Number of leaked objects: %d\nTotal amount of memory leaked: %d[bytes]\n", (int)memLeakCount, (int)memLeakSize);

    // stop collecting mem allocations info and clean the reminaing mem leaks. This will also be dumped to "mem_allocations.log"
    MemPlumber::stopAndFreeAllMemory();

    return 0;
}
