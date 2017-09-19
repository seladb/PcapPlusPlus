/*
 * debug_new.cpp  1.11 2003/07/03
 *
 * Implementation of debug versions of new and delete to check leakage
 *
 * By Chen jiangbo
 *
 */

#include <new>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#ifndef _MSC_VER
#include <unistd.h>
#endif

#ifdef _MSC_VER
#pragma warning(disable: 4073)
#pragma init_seg(lib)
#include <process.h>
typedef int pid_t;
#define popen(cmd, mode) _popen(cmd, mode)
#define pclose(x) _pclose(x)
#define getpid() _getpid()
#include <intrin.h>
#define _DEBUG_NEW_CALLER_ADDRESS _ReturnAddress()
#else
#define _DEBUG_NEW_CALLER_ADDRESS __builtin_return_address(0)
#endif

#if defined(WIN32) && !defined(_MSC_VER)
#define alloca __builtin_alloca
#endif

#ifndef DEBUG_NEW_HASHTABLESIZE
#define DEBUG_NEW_HASHTABLESIZE 16384
#endif

#ifndef DEBUG_NEW_HASH
#define DEBUG_NEW_HASH(p) (((unsigned long)(p) >> 8) % DEBUG_NEW_HASHTABLESIZE)
#endif

// The default behaviour now is to copy the file name, because we found
// that the exit leakage check cannot access the address of the file
// name sometimes (in our case, a core dump will occur when trying to
// access the file name in a shared library after a SIGINT).
#ifndef DEBUG_NEW_FILENAME_LEN
#define DEBUG_NEW_FILENAME_LEN  32
#endif
#if DEBUG_NEW_FILENAME_LEN == 0 && !defined(DEBUG_NEW_NO_FILENAME_COPY)
#define DEBUG_NEW_NO_FILENAME_COPY
#endif
#ifndef DEBUG_NEW_NO_FILENAME_COPY
#include <string.h>
#endif

#define PATH_SIZE 128
#define ADDR2LINE_CMD "addr2line -e %s %08lx %s"
#define CMD_OPT "%s %08lx %s"

struct new_ptr_list_t
{
        new_ptr_list_t*         next;
#ifdef DEBUG_NEW_NO_FILENAME_COPY
        const char*                     file;
#else
        char                            file[DEBUG_NEW_FILENAME_LEN];
#endif
        int                                     line;
        size_t                          size;
        char							is_static;
};

typedef struct pmap_line {
    unsigned long vm_start;
    unsigned long vm_end;
    char perm[5];               /* permission */
    char path[PATH_SIZE];
    bool absolute;             /* Is the absoluted address*/
    struct pmap_line *next;
} pmap_line_t;

static unsigned  int total_size = 0;
static pmap_line_t *pmap_line_head=NULL;

static void free_pmap_line()
{
    pmap_line_t *line=NULL;
    while((line=pmap_line_head) != NULL)
    {
        pmap_line_head=pmap_line_head->next;
        free(line);
    }
}

static new_ptr_list_t* new_ptr_list[DEBUG_NEW_HASHTABLESIZE];

bool new_verbose_flag = false;
bool new_autocheck_flag = true;
bool new_start_check = false;
int	 static_alloc_counter = 0;

static void getpmaps(pid_t  pid)
{

    FILE *f;
    char buf[4096+100]={0};
    pmap_line_t *pmap_line_tail=NULL;
    pmap_line_t *line=NULL;
    char fname [50]={0};
    long int offset;
    int major;
    int minor;
    int inode;

    sprintf(fname, "/proc/%ld/maps", (long)pid);
    //sprintf(fname, "D:\\proc\\maps");
    f = fopen(fname, "r");
    if(!f) {
        printf("open file : %s failed \n", fname);
        return;
    }

    while(!feof(f))
    {
        /*get the line from the file*/
        if(fgets(buf, sizeof(buf), f) == 0) {
            break;
        }

        /*allocate the memory for storing the VMA information*/
            line=(pmap_line_t*)malloc(sizeof(pmap_line_t));
        if (!line) {
                printf("malloc failed\n");
                return;
        }

        /*init the allocated memory*/
           memset(line, 0, sizeof(pmap_line_t));

        /*parse the line */
            sscanf(buf, "%lx-%lx %4s %lx %02x:%02x %d %s",
            &line->vm_start, &line->vm_end, line->perm, &offset, &major, &minor, &inode, line->path);
            line->next=NULL;

        if (line->perm[2] != 'x' || strstr(buf, "/usr/lib") || strstr(buf, "/lib/")
            || 0 == inode || 0 != offset) {
                free(line);
                continue;
        }

        if (strstr(buf, ".so")) {
            line->absolute = false;
        } else {
            line->absolute = true;
        }
        if(!pmap_line_head)
        {
            pmap_line_head=line;
        }
        if(pmap_line_tail)
        {
            pmap_line_tail->next=line;
        }
        pmap_line_tail = line;
    }

        /*print the parsed result*/
    line=pmap_line_head;
    while(line)
    {
        printf("%08lx-%08lx %s %s\n",line->vm_start,line->vm_end, line->perm, line->path);
        line=line->next;
    }

        /*close the map file*/
    fclose(f);
}

static char* canReadAndEexcAddr(unsigned long addr, unsigned long *pStartAddr)
{
    pmap_line_t *line=pmap_line_head;

    if(!pmap_line_head)
    {
        return 0;
    }

    while(line)
    {
        if(line->perm[0] == 'r' && line->perm[2] == 'x' &&
                addr >= line->vm_start && addr <=line->vm_end)
        {
            if (line->absolute) {
                *pStartAddr = 0;
            } else {
                *pStartAddr = line->vm_start;
            }
            return line->path;
        }
        line=line->next;
    }

    printf("cannot read address %#08lx\n",addr);

    return NULL;

}

static long last_addr = 0;
static char last_info[256] = "";

static bool get_position_from_addr(char* programe,  const long addr)
{
    if (addr == last_addr)
    {
        if (last_info[0] == '\0')
            return false;
        return true;
    }
    if (programe)
    {
        const char addr2line_cmd[] = ADDR2LINE_CMD;
        char ignore_err[] = " 2>/dev/null";
        char *cmd;

        cmd = (char *)alloca(sizeof(addr2line_cmd) - sizeof(CMD_OPT) +
                            strlen(programe) - 1 +
                            8 +
                            sizeof(ignore_err));

        sprintf(cmd, addr2line_cmd, programe, addr, ignore_err);

        size_t len = strlen(cmd);

        //printf("CMD: %s \n", cmd);

        FILE* fp = popen(cmd, "r");
        if (fp)
        {
            char buffer[sizeof last_info] = "";
            len = 0;
            if (fgets(buffer, sizeof buffer, fp))
            {
                len = strlen(buffer);
                if (buffer[len - 1] == '\n')
                    buffer[--len] = '\0';
            }
            int res = pclose(fp);
            // Display the file/line information only if the command
            // is executed successfully and the output points to a
            // valid position, but the result will be cached if only
            // the command is executed successfully.
            if (res == 0 && len > 0)
            {
                last_addr = addr;
                if (buffer[len - 1] == '0' && buffer[len - 2] == ':') {
                    last_info[0] = '\0';
                    fprintf(stderr, "Can't locate the address at %lx\n", addr);
                }
                else
                {
                    strcpy(last_info, buffer);
                    return true;
                }
            }
        } else {
            fprintf(stderr, "popen failed!\n");
        }
    }
    return false;
}

bool locate_addr(char* file, int* line)
{
    unsigned long start_addr = 0;
    char* program_path = NULL;
    char* slash_index = NULL;
    char* colon_index = NULL;
    bool  result = false;

    if (!pmap_line_head) {
        getpmaps(getpid());
    }

    program_path = canReadAndEexcAddr(((long *)file)[0], &start_addr);

    if (program_path) {
        result = get_position_from_addr(program_path, ((long *)file)[0] - start_addr);
        if (result) {
            colon_index = strrchr(last_info, ':');
            if (!colon_index) {
                printf("ERR:last_info: %s\n", last_info);
                return false;
            }
            *line = atoi(colon_index + 1);
            *colon_index = '\0';
            slash_index = strrchr(last_info, '/');
            if (!slash_index) {
                printf("ERR:last_info: %s\n", last_info);
                return false;
            }
            strcpy(file, slash_index + 1);
            // restore the colon
            *colon_index = ':';
        } else {
            strcpy(file, "Unknown");
            *line = 0;
        }
    } else {
        return false;
    }
    return true;
}



void start_leak_check()
{
	new_start_check = true;
}



bool check_leaks()
{
        bool fLeaked = false;
    bool ret = false;

        for (int i = 0; i < DEBUG_NEW_HASHTABLESIZE; ++i)
        {
                new_ptr_list_t* ptr = new_ptr_list[i];
                if (ptr == NULL)
                        continue;

                if (ptr->is_static != 0)
                	continue;

                fLeaked = true;
                while (ptr)
                {
                    if (!ptr->line) {
                    	ret = locate_addr(ptr->file, &ptr->line);
                    }

                    if (ret) {
								printf("Leaked object at %p (size %d, %s:%d)\n",
												(char*)ptr + sizeof(new_ptr_list_t),
												(int)ptr->size,
												ptr->file,
												ptr->line);
								ptr = ptr->next;
					}
					else {
								printf("Leaked object at %p (size %d, %s:%d)\n",
												(char*)ptr + sizeof(new_ptr_list_t),
												(int)ptr->size,
												ptr->file,
												ptr->line);

								ptr = ptr->next;
					}
                }
        }
    free_pmap_line();

        if (fLeaked) {
                return true;
    } else {
                return false;
    }
}


void* operator new(size_t size, const char* file, int line)
{
    char file_name[PATH_SIZE];

        size_t s = size + sizeof(new_ptr_list_t);
        new_ptr_list_t* ptr = (new_ptr_list_t*)malloc(s);
        if (ptr == NULL)
        {
            if (0 == line) {
            // release memory for memory check program
                for (int i = 0; i < DEBUG_NEW_HASHTABLESIZE; ++i)
                {
                        new_ptr_list_t* ptr_tmp = new_ptr_list[i];
                        if (ptr_tmp == NULL) {
                                continue;
                } else if (ptr_tmp == ptr) {
                    continue;
                } else {
                    delete((char*)ptr_tmp + sizeof(new_ptr_list_t));
                }
            }
            memcpy(file_name, &file, 4); // address occupy 4 bytes
            locate_addr(file_name, &line);
        }

                fprintf(stderr, "new:  out of memory when allocating %d bytes at %s:%d\n",
                                (int)size,
                                file_name,
                                line);
                abort();
        }
    total_size = total_size + size;
        void* pointer = (char*)ptr + sizeof(new_ptr_list_t);
        size_t hash_index = DEBUG_NEW_HASH(pointer);
        ptr->next = new_ptr_list[hash_index];
#ifdef DEBUG_NEW_NO_FILENAME_COPY
        ptr->file = file;
#else
    if (0 == line) {
        memcpy(ptr->file, &file, sizeof(void *));
    } else {
        strncpy(ptr->file, file, DEBUG_NEW_FILENAME_LEN - 1);
        ptr->file[DEBUG_NEW_FILENAME_LEN - 1] = '\0';
    }
#endif
        ptr->line = line;
        ptr->size = size;
        if (new_start_check)
        	ptr->is_static = 0;
        else
        {
        	ptr->is_static = 1;
        	static_alloc_counter++;
        }
        new_ptr_list[hash_index] = ptr;
        if (new_verbose_flag) {
        printf("new:  allocated  %p (size %d)\n", pointer, (int)size);
    }
        return pointer;
}

void* operator new[](size_t size, const char* file, int line)
{
        return operator new(size, file, line);
}

void* operator new(size_t size)
{
        return operator new(size, (char *)_DEBUG_NEW_CALLER_ADDRESS, 0);
}

void* operator new[](size_t size)
{
        return operator new(size, (char *)_DEBUG_NEW_CALLER_ADDRESS, 0);
}

void* operator new(size_t size, const std::nothrow_t&) throw()
{
        return operator new(size, (char *)_DEBUG_NEW_CALLER_ADDRESS, 0);
}

void* operator new[](size_t size, const std::nothrow_t&) throw()
{
        return operator new[](size, (char *)_DEBUG_NEW_CALLER_ADDRESS, 0);
}

void operator delete(void* pointer)
{
        if (pointer == NULL)
                return;
        size_t hash_index = DEBUG_NEW_HASH(pointer);
        new_ptr_list_t* ptr = new_ptr_list[hash_index];
        new_ptr_list_t* ptr_last = NULL;
        while (ptr)
        {
                if ((char*)ptr + sizeof(new_ptr_list_t) == pointer)
                {
                    total_size = total_size - ptr->size;
                        if (new_verbose_flag && ptr->is_static == 0) {
                                printf("delete: freeing  %p (size %d)\n", pointer, (int)ptr->size);
						}
                        if (ptr->is_static != 0)
                        {
                        	static_alloc_counter--;
                        	if (static_alloc_counter == 0 && new_verbose_flag)
                        		printf("Memory leaks check: all STATIC variables were freed\n");
                        	else if (static_alloc_counter != 0 && new_verbose_flag)
                        		printf("static_alloc_counter = %d\n", static_alloc_counter);
                        }

                        if (ptr_last == NULL)
                                new_ptr_list[hash_index] = ptr->next;
                        else
                                ptr_last->next = ptr->next;
                        free(ptr);
                        return;
                } else if ((char*)ptr + sizeof(new_ptr_list_t) == (char *)pointer - 8) {
                    char file_name[PATH_SIZE];
            int  line = 0;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-aliasing"
            memcpy(file_name, &((long *)ptr->file)[0], 4);
#pragma GCC diagnostic pop
                    locate_addr(file_name, &line);
            printf("ERR: Maybe delete a array missing [] before the pointer at %s:%d\n", file_name, line);
        }
                ptr_last = ptr;
                ptr = ptr->next;
        }
        fprintf(stderr, "delete: invalid pointer %p\n", pointer);
}

void operator delete[](void* pointer)
{
        operator delete(pointer);
}

// Some older compilers like Borland C++ Compiler 5.5.1 and Digital Mars
// Compiler 8.29 do not support placement delete operators.
// NO_PLACEMENT_DELETE needs to be defined when using such compilers.
// Also note that in that case memory leakage will occur if an exception
// is thrown in the initialization (constructor) of a dynamically
// created object.
#ifndef NO_PLACEMENT_DELETE
void operator delete(void* pointer, const char* file, int line)
{
        if (new_verbose_flag)
                printf("info: exception thrown on initializing object at %p (%s:%d)\n",
                                pointer, file, line);
        operator delete(pointer);
}

void operator delete[](void* pointer, const char* file, int line)
{
        operator delete(pointer, file, line);
}

void operator delete(void* pointer, const std::nothrow_t&)
{
        operator delete(pointer);
}

void operator delete[](void* pointer, const std::nothrow_t&)
{
        operator delete(pointer, std::nothrow);
}

unsigned int PrintMemTotalSize()
{
    printf("\nNOW Allocate MEM SIZE ----   [0x%x]---\n", total_size);
    return total_size;
}

#endif // NO_PLACEMENT_DELETE

//// Proxy class to automatically call check_leaks if new_autocheck_flag is set
//class new_check_t
//{
//public:
//        new_check_t() {}
//        ~new_check_t()
//        {
//                if (new_autocheck_flag)
//                {
//                        // Check for leakage.
//                        // If any leaks are found, set new_verbose_flag so that any
//                        // delete operations in the destruction of global/static
//                        // objects will display information to compensate for
//                        // possible false leakage reports.
//                        if (check_leaks())
//                                new_verbose_flag = true;
//                }
//        }
//};
//static new_check_t new_check_object;

