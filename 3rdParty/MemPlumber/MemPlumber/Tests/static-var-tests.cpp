#include <fstream>
#include "memplumber.h"
#include "test-macros.h"
#include <stdint.h>

static int StaticVar = 100;

class StaticClass {
    int x;
};

class StaticVarsTestClass {
    private:

    uint16_t m_PrivateMember1;
    uint8_t m_PrivateMember2;
    uint64_t* m_PrivatePtrMember;

    static StaticClass* m_StaticMember;

    public:

    StaticVarsTestClass() {
        m_PrivateMember1 = 1;
        m_PrivateMember2 = 2;
        m_PrivatePtrMember = new uint64_t(1000);
    }

    ~StaticVarsTestClass() {
        delete m_PrivatePtrMember;
    }

    static StaticClass* getStaticVar() {
        return m_StaticMember;
    }
};

StaticClass* StaticVarsTestClass::m_StaticMember = new StaticClass();

static int* static_int_ptr = new int(100);

static StaticVarsTestClass* static_class = new StaticVarsTestClass();


int countLinesInFile(const char* fileName) {
    int numberOfLines = 0;
    std::string line;
    std::ifstream file(fileName);

    while (std::getline(file, line))
        ++numberOfLines;

    return numberOfLines;
}


TEST_CASE(StaticVarTest) {

    START_TEST;

    StaticVarsTestClass* var1 = new StaticVarsTestClass();

    size_t staticMemCount;
    uint64_t staticMemSize;
    MemPlumber::staticMemCheck(staticMemCount, staticMemSize);
    TEST_ASSERT_EQUAL(staticMemCount, 4);
    TEST_ASSERT_EQUAL(staticMemSize, sizeof(StaticClass) + sizeof(int) + sizeof(StaticVarsTestClass) + sizeof(uint64_t));

    CHECK_MEM_LEAK(2, sizeof(StaticVarsTestClass) + sizeof(uint64_t));

    delete var1;

    CHECK_MEM_LEAK(0, 0);

    STOP_TEST;
}

TEST_CASE(StaticVarsDumpToFile) {

    size_t staticMemCount;
    uint64_t staticMemSize;
    MemPlumber::staticMemCheck(staticMemCount, staticMemSize, true, "staticvarsdump.log", false);

    TEST_ASSERT_EQUAL(countLinesInFile("staticvarsdump.log"), 4);

    MemPlumber::staticMemCheck(staticMemCount, staticMemSize, true, "staticvarsdump.log", true);

    TEST_ASSERT_EQUAL(countLinesInFile("staticvarsdump.log"), 8);

    MemPlumber::staticMemCheck(staticMemCount, staticMemSize, true, "staticvarsdump.log", false);

    TEST_ASSERT_EQUAL(countLinesInFile("staticvarsdump.log"), 4);
}

#ifdef COLLECT_STATIC_VAR_DATA
int tests_main(int argc, char* argv[]) {

    START_RUNNING_TESTS;

    RUN_TEST(StaticVarTest);
    RUN_TEST(StaticVarsDumpToFile);

    END_RUNNING_TESTS;
}

MEMPLUMBER_MAIN(tests_main);
#else
int main(int argc, char* argv[]) {
    START_RUNNING_TESTS;

    SKIP_TEST(StaticVarTest, "Library is not compiled with -DCOLLECT_STATIC_VAR_DATA flag");
    SKIP_TEST(StaticVarsDumpToFile, "Library is not compiled with -DCOLLECT_STATIC_VAR_DATA flag");

    END_RUNNING_TESTS;
}
#endif //COLLECT_STATIC_VAR_DATA
