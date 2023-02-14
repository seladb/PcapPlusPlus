#ifdef COLLECT_STATIC_VAR_DATA
#include "memplumber.h"
#include <stdio.h>

/**
 * This example shows how to enable MemPlumber to collect information about allocation of static variables. It demonstrates the following flow:
 * - Allocate some static variables (1 static variable and 2 static members of a class)
 * - Run a static mem test in verbose mode. This will output all places in the code where static memory was allocated. It will also summarize
 *   the total number of static objects as well as the amount of memory in those objects
 * - When enabling static memory collection you should rename your `main` method and instead add the `MEMPLUMBER_MAIN` macro and give it your
 *   alternative (renamed) main method
 *
 * In order for this example to work please compile the MemPlumber library with the -DCOLLECT_STATIC_VAR_DATA=ON flag
 *
 * The output should look something like this:
 *
 * Static object allocated at 0x007F6E90 (size 4[bytes]) allocated in: C:\MemPlumber\Examples\static-example.cpp:27
 * Static object allocated at 0x007F6F10 (size 4[bytes]) allocated in: C:\MemPlumber\Examples\static-example.cpp:45
 * Static object allocated at 0x007F7028 (size 16[bytes]) allocated in: C:\MemPlumber\Examples\static-example.cpp:46
 * Number of static objects: 3
 * Total amount of memory allocated in static objects: 24[bytes]
 *
 */


// allocating a static int
static int* MyStaticInt = new int(100);

class MyClass1 {
    int x;
};

class MyClass2 {
    double x;
    double y;
};

// defining a class with 2 static members
class ClassWithStaticMembers {
    static MyClass1* m_StaticMember1;
    static MyClass2* m_StaticMember2;
};

// initiating the 2 static members
MyClass1* ClassWithStaticMembers::m_StaticMember1 = new MyClass1();
MyClass2* ClassWithStaticMembers::m_StaticMember2 = new MyClass2();

// in order to collect static memory allocation we need to rename our `main` method and add the `MEMPLUMBER_MAIN` with the alternative main
// method as a parameter
int app_main(int argc, char* argv[]) {

    // initiate a static memory check in verbose mode
    size_t staticMemCount;
    uint64_t staticMemSize;
    MemPlumber::staticMemCheck(staticMemCount, staticMemSize, true);

    // print memory check results
    printf("Number of static objects: %d\nTotal amount of memory allocated in static objects: %d[bytes]\n", (int)staticMemCount, (int)staticMemSize);

    return 0;
}

// add this macro here as an alternative to the `main` method
MEMPLUMBER_MAIN(app_main);

#else
#include <stdio.h>
int main() {
    printf("Please compile the library with -DCOLLECT_STATIC_VAR_DATA flag");
    return 1;
}
#endif
