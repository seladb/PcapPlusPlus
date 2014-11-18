/*
 * debug_new.h  1.7 2003/07/03
 *
 * Header file for checking leakage by operator new
 *
 * By Wu Yongwei
 *
 */

#ifndef _DEBUG_NEW_H
#define _DEBUG_NEW_H

#include <new>

/* Prototypes */
void start_leak_check();
bool check_leaks();
void* operator new(size_t size, const char* file, int line);
void* operator new[](size_t size, const char* file, int line);
#ifndef NO_PLACEMENT_DELETE
void operator delete(void* pointer, const char* file, int line);
void operator delete[](void* pointer, const char* file, int line);
#endif // NO_PLACEMENT_DELETE
void operator delete[](void*);  // MSVC 6 requires this declaration

/* Macros */
#ifndef DEBUG_NEW_NO_NEW_REDEFINITION
#define new DEBUG_NEW
#define DEBUG_NEW new(__FILE__, __LINE__)
#define debug_new new
#else
#define debug_new new(__FILE__, __LINE__)
#endif // DEBUG_NEW_NO_NEW_REDEFINITION
#ifdef DEBUG_NEW_EMULATE_MALLOC
#include <stdlib.h>
#define malloc(s) ((void*)(debug_new char[s]))
#define free(p) delete[] (char*)(p)
#endif // DEBUG_NEW_EMULATE_MALLOC

/* Control flags */
extern bool new_verbose_flag;   // default to false: no verbose information
extern bool new_autocheck_flag; // default to true: call check_leaks() on exit

class debug_new_counter
{
    static int _S_count;
public:
    debug_new_counter()
	{
    	++_S_count;
	}

    ~debug_new_counter()
    {
        if (--_S_count == 0 && new_autocheck_flag)
            if (check_leaks())
            {
                new_verbose_flag = true;
    #if defined(__GNUC__) && __GNUC__ == 3
                if (!getenv("GLIBCPP_FORCE_NEW") && !getenv("GLIBCXX_FORCE_NEW"))
                    fprintf(new_output_fp,
    "*** WARNING:  GCC 3 is detected, please make sure the environment\n"
    "    variable GLIBCPP_FORCE_NEW (GCC 3.2 and 3.3) or GLIBCXX_FORCE_NEW\n"
    "    (GCC 3.4) is defined.  Check the README file for details.\n");
    #endif
            }
    }

};

int debug_new_counter::_S_count = 0;

/** Counting object for each file including debug_new.h. */
static debug_new_counter __debug_new_count;

#endif // _DEBUG_NEW_H
