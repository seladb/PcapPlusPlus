#pragma once

#include <vector>
#include <string>
#include <stdint.h>

class LibClass {
    private:

    std::string m_Str;
    int m_Num;
    std::vector<uint64_t*> m_Vec;
    double* m_DoublePtr;
    void* m_InnerMember;

    public:

    LibClass();
    ~LibClass();

    void doSomething();

    static size_t getSizeOfInternalClass();
};
