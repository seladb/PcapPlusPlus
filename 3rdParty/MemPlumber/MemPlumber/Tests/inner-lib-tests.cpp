#include "test-macros.h"
#include "test-lib/test-lib.h"
#include "memplumber.h"

TEST_CASE(MultiLibTest) {

    START_TEST;

    LibClass* libClass = new LibClass();

    CHECK_MEM_LEAK(4, sizeof(LibClass) + sizeof(double) + LibClass::getSizeOfInternalClass());

    libClass->doSomething();

    CHECK_MEM_LEAK(44, sizeof(LibClass) + sizeof(double) + 21*LibClass::getSizeOfInternalClass());

    delete libClass;

    CHECK_MEM_LEAK(40, 20*libClass->getSizeOfInternalClass());

    STOP_TEST;
}

#ifdef COLLECT_STATIC_VAR_DATA
#define MAIN tests_main
#else
#define MAIN main
#endif

int MAIN(int argc, char* argv[]) {

    START_RUNNING_TESTS;

    #if !defined _MSC_VER || !defined _DEBUG
    RUN_TEST(MultiLibTest);
    #else
    SKIP_TEST(MultiLibTest, "Additional debug allocations made by VS make it difficult to track real memory allocations");
    #endif

    END_RUNNING_TESTS;
}

#ifdef COLLECT_STATIC_VAR_DATA
MEMPLUMBER_MAIN(tests_main);
#endif
