#include "memplumber.h"
#include <stdio.h>

/**
 * This example shows the basic usage of MemPlumber. It demonstrates the following flow:
 * - Start collecting memory allocation data
 * - Allocate some memory (2 objects and 1 array)
 * - Run a mem leak test in verbose mode. This will output all places in the code where memory was allocated and not yet freed.
 *   It will also summarize the total number of leaked objects as well as the amount of memory leaked
 * - Stop collection memory allocation data
 *
 * The output should look something like this:
 *
 * Found leaked object at 0x001A6E90 (size 4[bytes]) allocated in: C:\MemPlumber\Examples\example1.cpp:33
 * Found leaked object at 0x001A6F10 (size 4[bytes]) allocated in: C:\MemPlumber\Examples\example1.cpp:34
 * Found leaked object at 0x001A7020 (size 40[bytes]) allocated in: C:\MemPlumber\Examples\example1.cpp:37
 * Number of leaked objects: 3
 * Total number of memory leaked: 48[bytes]
 *
 */


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

    // stop collecting mem allocations info
    MemPlumber::stop();

    return 0;
}
