#include "test-macros.h"
#include "test-lib/test-lib.h"
#include "memplumber.h"
#include <string.h>
#include <stdlib.h>

struct SimpleStruct {
    int x;
    int y;
};

class SimpleClass {
    private:

    double m_DoubleMember;

    public:

    SimpleClass() { m_DoubleMember = 1.1; }
};

class InheritedClass : public SimpleClass {
    private:

    int* m_IntPtr;

    public:

    InheritedClass() : SimpleClass() {
        m_IntPtr = new int(10000);
    }

    ~InheritedClass() {
        delete m_IntPtr;
    }
};

class ClassWithMemAllocations {
    private:

    int* m_IntPtr;
    char* m_String;
    float* m_FloatArr;

    public:

    ClassWithMemAllocations() {
        m_IntPtr = new int(1000);
        m_String = new char[12];
        m_FloatArr = new float[20];
        strcpy(m_String, "Hello World");
    }

    ~ClassWithMemAllocations() {
        delete m_IntPtr;
        delete [] m_String;
        delete [] m_FloatArr;
    }

};

class ComplexClass {
    private:

    SimpleStruct* m_MemberArr1;
    SimpleClass* m_MemberPtr2;
    ClassWithMemAllocations* m_MemberPtr3;
    LibClass* m_MemberPtr4;

    public:

    ComplexClass() {
        m_MemberArr1 = new SimpleStruct[10];
        m_MemberPtr2 = new SimpleClass();
        m_MemberPtr3 = new ClassWithMemAllocations();
        m_MemberPtr4 = new LibClass();
    }

    ~ComplexClass() {
        delete [] m_MemberArr1;
        delete m_MemberPtr2;
        delete m_MemberPtr3;
        delete m_MemberPtr4;
    }
};

#define NUM_OF_OBJECTS 10000

TEST_CASE(AllocateAllAndThenRelease) {

    START_TEST;

    size_t sizeOfSimpleStruct = sizeof(SimpleStruct);
    size_t sizeOfSimpleClass = sizeof(SimpleClass);
    size_t sizeOfInheritedClass = sizeof(InheritedClass) + sizeof(int);
    size_t sizeOfClassWithMemAllocations = sizeof(ClassWithMemAllocations) + sizeof(int) + 12*sizeof(char) + 20*sizeof(float);
    size_t sizeOfLibClass = sizeof(LibClass) + sizeof(double) + LibClass::getSizeOfInternalClass();
    size_t sizeOfComplexClass = sizeof(ComplexClass) + 10*sizeOfSimpleStruct + sizeOfSimpleClass + sizeOfClassWithMemAllocations + sizeOfLibClass;

    SimpleStruct* simpleStructArr[NUM_OF_OBJECTS];
    SimpleClass* simpleClassArr[NUM_OF_OBJECTS];
    InheritedClass* inheritedClassArr[NUM_OF_OBJECTS];
    ClassWithMemAllocations* classWithMemAllocationsArr[NUM_OF_OBJECTS];
    LibClass* libClassArr[NUM_OF_OBJECTS];
    ComplexClass* complexClassArr[NUM_OF_OBJECTS];

    for (int i=0; i < NUM_OF_OBJECTS; i++) {
        simpleStructArr[i] = new SimpleStruct();
        simpleClassArr[i] = new SimpleClass();
        inheritedClassArr[i] = new InheritedClass();
        classWithMemAllocationsArr[i] = new ClassWithMemAllocations();
        libClassArr[i] = new LibClass();
        complexClassArr[i] = new ComplexClass();
    }

    #if !defined _MSC_VER || !defined _DEBUG
    CHECK_MEM_LEAK(NUM_OF_OBJECTS*23, NUM_OF_OBJECTS*(
        sizeOfSimpleStruct +
        sizeOfSimpleClass +
        sizeOfInheritedClass +
        sizeOfClassWithMemAllocations +
        sizeOfLibClass +
        sizeOfComplexClass));
    #endif

    for (int i=0; i < NUM_OF_OBJECTS; i++) {
        delete simpleStructArr[i];
        delete simpleClassArr[i];
        delete inheritedClassArr[i];
        delete classWithMemAllocationsArr[i];
        delete libClassArr[i];
        delete complexClassArr[i];
    }

    CHECK_MEM_LEAK(0, 0);

    STOP_TEST;
}


TEST_CASE(AllocateSomeAndReleaseSome) {

    START_TEST;

    size_t sizeOfSimpleStruct = sizeof(SimpleStruct);
    size_t sizeOfSimpleClass = sizeof(SimpleClass);
    size_t sizeOfInheritedClass = sizeof(InheritedClass) + sizeof(int);
    size_t sizeOfClassWithMemAllocations = sizeof(ClassWithMemAllocations) + sizeof(int) + 12*sizeof(char) + 20*sizeof(float);
    size_t sizeOfLibClass = sizeof(LibClass) + sizeof(double) + LibClass::getSizeOfInternalClass();
    size_t sizeOfComplexClass = sizeof(ComplexClass) + 10*sizeOfSimpleStruct + sizeOfSimpleClass + sizeOfClassWithMemAllocations + sizeOfLibClass;

    SimpleStruct* simpleStructArr[NUM_OF_OBJECTS];
    SimpleClass* simpleClassArr[NUM_OF_OBJECTS];
    InheritedClass* inheritedClassArr[NUM_OF_OBJECTS];
    ClassWithMemAllocations* classWithMemAllocationsArr[NUM_OF_OBJECTS];
    LibClass* libClassArr[NUM_OF_OBJECTS];
    ComplexClass* complexClassArr[NUM_OF_OBJECTS];

    for (int i=0; i < NUM_OF_OBJECTS; i++) {
        simpleStructArr[i] = new SimpleStruct();
        simpleClassArr[i] = new SimpleClass();
        inheritedClassArr[i] = new InheritedClass();
        classWithMemAllocationsArr[i] = new ClassWithMemAllocations();
        libClassArr[i] = new LibClass();
        complexClassArr[i] = new ComplexClass();
    }

    #if !defined _MSC_VER || !defined _DEBUG
    CHECK_MEM_LEAK(NUM_OF_OBJECTS*23, NUM_OF_OBJECTS*(
        sizeOfSimpleStruct +
        sizeOfSimpleClass +
        sizeOfInheritedClass +
        sizeOfClassWithMemAllocations +
        sizeOfLibClass +
        sizeOfComplexClass));
    #endif

    for (int i=0; i < NUM_OF_OBJECTS; i++) {
        int index1 = rand() % NUM_OF_OBJECTS;
        int index2 = index1;
        while (index2 == index1) {
            index2 = rand() % NUM_OF_OBJECTS;
        }

        delete simpleStructArr[index1];
        delete simpleClassArr[index1];
        delete inheritedClassArr[index1];
        delete classWithMemAllocationsArr[index1];
        delete libClassArr[index1];
        delete complexClassArr[index1];

        delete simpleStructArr[index2];
        delete simpleClassArr[index2];
        delete inheritedClassArr[index2];
        delete classWithMemAllocationsArr[index2];
        delete libClassArr[index2];
        delete complexClassArr[index2];

        simpleStructArr[index2] = new SimpleStruct();
        simpleClassArr[index2] = new SimpleClass();
        inheritedClassArr[index2] = new InheritedClass();
        classWithMemAllocationsArr[index2] = new ClassWithMemAllocations();
        libClassArr[index2] = new LibClass();
        complexClassArr[index2] = new ComplexClass();

        simpleStructArr[index1] = new SimpleStruct();
        simpleClassArr[index1] = new SimpleClass();
        inheritedClassArr[index1] = new InheritedClass();
        classWithMemAllocationsArr[index1] = new ClassWithMemAllocations();
        libClassArr[index1] = new LibClass();
        complexClassArr[index1] = new ComplexClass();
    }

    #if !defined _MSC_VER || !defined _DEBUG
    CHECK_MEM_LEAK(NUM_OF_OBJECTS*23, NUM_OF_OBJECTS*(
        sizeOfSimpleStruct +
        sizeOfSimpleClass +
        sizeOfInheritedClass +
        sizeOfClassWithMemAllocations +
        sizeOfLibClass +
        sizeOfComplexClass));
    #endif

    for (int i=0; i < NUM_OF_OBJECTS; i++) {
        delete simpleStructArr[i];
        delete simpleClassArr[i];
        delete inheritedClassArr[i];
        delete classWithMemAllocationsArr[i];
        delete libClassArr[i];
        delete complexClassArr[i];
    }

    CHECK_MEM_LEAK(0, 0);

    STOP_TEST;

}

#ifdef COLLECT_STATIC_VAR_DATA
#define MAIN tests_main
#else
#define MAIN main
#endif

int MAIN(int argc, char* argv[]) {

    START_RUNNING_TESTS;

    RUN_TEST(AllocateAllAndThenRelease);
    RUN_TEST(AllocateSomeAndReleaseSome);

    END_RUNNING_TESTS;
}

#ifdef COLLECT_STATIC_VAR_DATA
MEMPLUMBER_MAIN(tests_main);
#endif
