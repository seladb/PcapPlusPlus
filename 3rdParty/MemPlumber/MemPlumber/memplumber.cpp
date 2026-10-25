#include <new>
#include <cstdlib>
#include <string>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <atomic>

#ifndef MEMPLUMBER_FILENAME_LEN
#define MEMPLUMBER_FILENAME_LEN  104
#endif

#ifndef _THROW_BAD_ALLOC
#define _THROW_BAD_ALLOC
#endif

#ifndef _NOEXCEPT
#define _NOEXCEPT noexcept
#endif

class MemPlumberInternal {
private:
	enum class MagicTrackState : uint32_t
	{
        // The allocation was made during active tracking.
		TRACKED = 0xBEEF,
        // The allocation was made before tracking started.
		UNTRACKED = 0xDEAD,
	};

    struct LinkedList;

    /// @brief Intrusive list node.
    ///
    /// Each node is initialized immedately before the allocation pointer, that is returned by the allocator.
    struct LinkedListNode
	{
		/// @brief Pointer to the linked list this elements belongs to.
        /// Allows O(1) access to the list.
		LinkedList* list = nullptr;
		/// @brief Pointer to the next element in the list.
		LinkedListNode* next = nullptr;
		/// @brief Pointer to the previous element in the list.
		LinkedListNode* prev = nullptr;
        int line = -1;
		MagicTrackState magic = MagicTrackState::UNTRACKED;
        size_t size = 0;
		char file[MEMPLUMBER_FILENAME_LEN] = {0};
    };

    struct LinkedList
	{
		LinkedListNode* head = nullptr;
		LinkedListNode* tail = nullptr;
    };

    LinkedList m_DynamicAllocations;
	LinkedList m_StaticAllocations;

    bool m_Started;
    int m_ProgramStarted;
    bool m_Verbose;
    FILE* m_Dumper;

    // PCPP Patch: C++11 thread safety
    // Atomic flag to ensure thread-safe access to the hashtables
    // Specifically using atomic_flag here to avoid potential issues with higher abstraction atomic types.
	std::atomic_flag m_Lock{};

    // private c'tor
    MemPlumberInternal() {
        m_Started = false;
        m_Verbose = false;

        #ifdef COLLECT_STATIC_VAR_DATA
        m_ProgramStarted = 0;
        #else
        m_ProgramStarted = -1;
        #endif //COLLECT_STATIC_VAR_DATA
    }

    FILE* openFile(const char* fileName, bool append) {
        if (strncmp(fileName, "", 1000) == 0) { // dump to stdout
            return stdout;
        }
        else { // dump to file
            FILE* file = NULL;
            if (!append) { // override the file
                file = fopen(fileName, "wt");
            }
            else { // append the file
                file = fopen(fileName, "at"); // try append
                if (!file) { // if append failed, create a new file
                    file = fopen(fileName, "wt");
                }
            }

            if (!file) {
                fprintf(stderr, "WARNING: couldn't open file `%s`\n", fileName);
            }

            return file;
        }
    }

    void closeFile(FILE* file) {
        if (file) {
            fflush(file);
            if (file != stdout) {
                fclose(file);
            }
        }
    }

    bool isVerbose() {
        return m_Verbose && m_Dumper != NULL;
    }

public:

    static MemPlumberInternal& getInstance() {
        static MemPlumberInternal instance;
        return instance;
    }

    // PCPP Patch: C++11 thread safety
    struct SpinLockGuard
	{
		std::atomic_flag& lock;
		SpinLockGuard(std::atomic_flag& lock) noexcept : lock(lock)
		{
			while (lock.test_and_set(std::memory_order_acquire))
			{
				// spin until the lock is released
			}
		}
		~SpinLockGuard() noexcept
		{
			lock.clear(std::memory_order_release);
		}
	};
    // PCPP Patch End: C++11 thread safety

    void* allocateMemory(std::size_t size, const char* file, int line) {

        SpinLockGuard guard(m_Lock);  // PCPP Patch: C++11 thread safety

        // Always allocate memory for the metadata + element.
        // This ensures that free can always be called on a pointer and performs the same,
		// no matter if the pointer was allocated before or after tracking started.
        size_t totalSizeToAllocate = size + sizeof(LinkedListNode);
		LinkedListNode* node = (LinkedListNode*)malloc(totalSizeToAllocate);

        // Return null on allocation failure
		if (node == NULL)
			return node;

        // Avoid placement new because it might be overriden.
		*node = LinkedListNode();

		void* userPointer = (char*)node + sizeof(LinkedListNode);

        // Fill in the metadata record with the allocation information
        // Mark as untracked initially, as it is not part of the lists yet.
		node->magic = MagicTrackState::UNTRACKED;
		node->line = line;
		node->size = size;
		strncpy(node->file, file, MEMPLUMBER_FILENAME_LEN - 1);
		node->file[MEMPLUMBER_FILENAME_LEN - 1] = '\0';

        // if not started, do not add the allocation into the hashtable.
        if (m_ProgramStarted != 0 && !m_Started) {
            if (isVerbose()) {
                fprintf(m_Dumper, "Allocate untracked: %d[bytes] in 0x%p in %s:%d\n", (int)size, userPointer, file, line);
            }
            return userPointer;
        }

        // Get the linked list for the current allocation type (static or dynamic)
        LinkedList& list = (m_ProgramStarted == 0 ? m_StaticAllocations : m_DynamicAllocations);

        // mark this allocation as tracked
        node->magic = MagicTrackState::TRACKED;

        // chain this metadata to the linked list of the specific bucket
		node->list = &list;
        node->next = list.head;
        node->prev = nullptr;
		if (node->next != nullptr)
		{
            node->next->prev = node;
        }

        // put this metadata in the head of the list
        list.head = node;

        if (isVerbose()) {
            if (m_ProgramStarted == 0) {
                fprintf(m_Dumper, "Allocate static variable: %d[bytes] in 0x%p in %s:%d\n", (int)size, userPointer, file, line);
            } else {
                fprintf(m_Dumper, "Allocate: %d[bytes] in 0x%p in %s:%d\n", (int)size, userPointer, file, line);
            }
        }

        return userPointer;
    }

    void freeMemory(void* pointer, const char* file, int line) {

        if (pointer == NULL) {
            return;
        }

        SpinLockGuard guard(m_Lock);  // PCPP Patch: C++11 thread safety

        LinkedListNode* node = (LinkedListNode*)((char*)pointer - sizeof(LinkedListNode));

        // Record was allocated before tracking started
        if(node->magic == MagicTrackState::UNTRACKED)
        {
			if (isVerbose())
			{
				fprintf(m_Dumper, "Free Untracked: 0x%p (size %d[bytes]) allocated in: %s:%d\n", pointer,
				        (int)node->size, node->file, node->line);
			}

			free(node);
            return;
        }

        if (node->magic != MagicTrackState::TRACKED)
		{
			fprintf(stderr, "ERROR: Memory corruption detected when freeing pointer 0x%p allocated in %s:%d\n", pointer,
			        node->file, node->line);
			fprintf(m_Dumper, "ERROR: Memory corruption detected when freeing pointer 0x%p allocated in %s:%d\n", pointer,
			        node->file, node->line);
			return;
		}

        // Unlink the metadata record from the linked list
        LinkedList* list = node->list;
        if(list->head == node)
        {
			list->head = node->next;
        }
        if(list->tail == node)
        {
			list->tail = node->prev;
        }

        // Unlink the node from adjacent nodes in the linked list
        if (node->prev != nullptr)
        {
			node->prev->next = node->next;
        }
        if (node->next != nullptr)
        {
			node->next->prev = node->prev;
        }

        // if got to here it means memory was allocated before monitoring started. Simply free the memory and return
        if (isVerbose()) {
            fprintf(m_Dumper, "Pointer 0x%p wasn't found\n", pointer);
        }

        free(node);
    }

    void programStarted() {
        m_ProgramStarted = 1;
    }

    void start(bool verbose, const char* fileDumperName, bool append) {
        m_Started = true;
        m_Verbose = verbose;
        m_Dumper = openFile(fileDumperName, append);
    }

    void stop(bool closeDumper = true) {
        m_Started = false;
        if (closeDumper) {
            closeFile(m_Dumper);
            m_Dumper = NULL;
        }
    }

    void checkLeaks(size_t& memLeakCount, uint64_t& memLeakSize, bool verbose, const char* fileDumperName, bool append) {

        memLeakCount = 0;
        memLeakSize = 0;

        FILE* dumper = NULL;
        if (verbose) {
            dumper = openFile(fileDumperName, append);
        }

        // go over all buckets in the hashmap
        for(auto* node = m_DynamicAllocations.head; node != nullptr; node = node->next)
        {
			memLeakCount++;
			memLeakSize += (uint64_t)node->size;

            if(verbose)
            {
				fprintf(dumper, "Found leaked object at 0x%p (size %d[bytes]) allocated in: %s:%d\n",
				        (char*)node + sizeof(LinkedListNode),
				        (int)node->size, node->file,
				        node->line);
            }
        }

        closeFile(dumper);
    }

    void staticMemAllocation(size_t& memCount, uint64_t& memSize, bool verbose, const char* fileDumperName, bool append) {
        memCount = 0;
        memSize = 0;

        FILE* dumper = NULL;
        if (verbose) {
            dumper = openFile(fileDumperName, append);
        }

        for (auto* node = m_StaticAllocations.head; node != nullptr; node = node->next)
		{
			memCount++;
			memSize += (uint64_t)node->size;

            if (verbose)
			{
				fprintf(dumper, "Static object allocated at 0x%p (size %d[bytes]) allocated in: %s:%d\n",
				        (char*)node + sizeof(LinkedListNode),
				        (int)node->size, node->file,
				        node->line);
			}
		}

        closeFile(dumper);
    }

    void freeAllMemory() {
        for(auto* node = m_DynamicAllocations.head; node != nullptr;)
        {
			if (isVerbose())
			{
				fprintf(m_Dumper, "FreeAllMem: freeing 0x%p (size %d[bytes]) allocated in %s:%d\n",
				        (char*)node + sizeof(LinkedListNode), (int)node->size,
				        node->file, node->line);
			}

            // Save the next node before freeing the current one
            auto* nextNode = node->next;
			free(node);
            node = nextNode;
        }
		m_DynamicAllocations.head = nullptr;
		m_DynamicAllocations.tail = nullptr;

        closeFile(m_Dumper);
        m_Dumper = NULL;
    }
};


#if defined _MSC_VER || defined _WIN32 || defined __ANDROID__ || defined MUSL || defined DISABLE_BACKTRACE
// TODO: backtrace() is not supported on Windows and Android.
// On Windows we can use dbghelp but it's not supported on MinGW. Need to figure out a way to solve it on all platforms
const char* getCaller() {
    return "Unknown";
}
#else
#include <execinfo.h>
const char* getCaller() {
    void* backtraceArr[3];
    size_t backtraceArrSize;

    // get void*'s for all entries on the stack
    backtraceArrSize = backtrace(backtraceArr, 3);

    if (backtraceArrSize < 3) {
        return "Unknown";
    }

    // get the symbols
    char** backtraceSymbols = backtrace_symbols(backtraceArr, backtraceArrSize);

    // the caller is second in the backtrace
    return backtraceSymbols[2];
}
#endif

void* operator new(std::size_t size, const char* file, int line) noexcept(false) { // PCPP Patch
    return MemPlumberInternal::getInstance().allocateMemory(size, file, line);
}

void* operator new[](std::size_t size, const char* file, int line) noexcept(false) { // PCPP Patch
    return operator new(size, file, line);
}

void* operator new[](size_t size) noexcept(false) { // PCPP Patch
	return operator new(size, getCaller(), 0);
}

void* operator new(size_t size) noexcept(false) { // PCPP Patch
	return operator new(size, getCaller(), 0);
}

void* operator new(size_t size, const std::nothrow_t&) noexcept { // PCPP Patch
	return operator new(size, getCaller(), 0);
}

void* operator new[](size_t size, const std::nothrow_t&) noexcept { // PCPP Patch
	return operator new[](size, getCaller(), 0);
}

void operator delete(void* pointer, const char* file, int line) {
    MemPlumberInternal::getInstance().freeMemory(pointer, file, line);
}

void operator delete(void* pointer) noexcept { // PCPP Patch
    operator delete(pointer, __FILE__, __LINE__);
}

void operator delete(void* pointer, std::size_t size) noexcept { // PCPP Patch
    operator delete(pointer, __FILE__, __LINE__);
}

void operator delete[](void* pointer) noexcept { // PCPP Patch
    operator delete(pointer, __FILE__, __LINE__);
}

void operator delete[](void* pointer, std::size_t size) noexcept { // PCPP Patch
    operator delete(pointer, __FILE__, __LINE__);
}


void operator delete[](void* pointer, const char* file, int line) noexcept { // PCPP Patch
    operator delete(pointer, file, line);
}

void operator delete(void* pointer, const std::nothrow_t&) noexcept { // PCPP Patch
	operator delete(pointer);
}

void operator delete[](void* pointer, const std::nothrow_t&) noexcept { // PCPP Patch
	operator delete(pointer, std::nothrow);
}

void __mem_leak_check(size_t& memLeakCount, uint64_t& memLeakSize, bool verbose, const char* fileDumperName, bool append) {
    MemPlumberInternal::getInstance().checkLeaks(memLeakCount, memLeakSize, verbose, fileDumperName, append);
}

void __static_mem_check(size_t&  memCount, uint64_t& memSize, bool verbose, const char* fileDumperName, bool append) {
    MemPlumberInternal::getInstance().staticMemAllocation(memCount, memSize, verbose, fileDumperName, append);
}

void __start(bool verbose, const char* fileDumperName, bool append) {
    MemPlumberInternal::getInstance().start(verbose, fileDumperName, append);
}

void __stop() {
    MemPlumberInternal::getInstance().stop();
}

void __stop_and_free_all_mem() {
    MemPlumberInternal::getInstance().stop(false);
    MemPlumberInternal::getInstance().freeAllMemory();
}

void __program_started() {
    MemPlumberInternal::getInstance().programStarted();
}
