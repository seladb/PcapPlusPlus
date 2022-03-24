#include "test-lib.h"

class LibInternalClass {
    private:

    double* m_DoubleMember;

    public:

    LibInternalClass() {
        m_DoubleMember = new double(999.888);
    }

    ~LibInternalClass() {
        delete m_DoubleMember;
    }
};

LibClass::LibClass() {
    m_Str = "TestClass2";
    m_Num = 1000;
    m_DoublePtr = new double(1.2345);
    m_InnerMember = new LibInternalClass();
}

LibClass::~LibClass() {
    delete m_DoublePtr;
    delete (LibInternalClass*)m_InnerMember;
}

void LibClass::doSomething() {
    for (int i = 0; i < 20; i++) {
        LibInternalClass* temp = new LibInternalClass();
    }
}

size_t LibClass::getSizeOfInternalClass() {
    return sizeof(LibInternalClass) + sizeof(double);
}
