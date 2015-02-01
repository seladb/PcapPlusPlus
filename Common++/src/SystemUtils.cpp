#include <SystemUtils.h>
#include <unistd.h>

const SystemCore SystemCores::Core0 = { 0x01, 0 };
const SystemCore SystemCores::Core1 = { 0x02, 1 };
const SystemCore SystemCores::Core2 = { 0x04, 2 };
const SystemCore SystemCores::Core3 = { 0x08, 3 };
const SystemCore SystemCores::Core4 = { 0x10, 4 };
const SystemCore SystemCores::Core5 = { 0x20, 5 };
const SystemCore SystemCores::Core6 = { 0x40, 6 };
const SystemCore SystemCores::Core7 = { 0x80, 7 };
const SystemCore SystemCores::Core8 = { 0x100, 8 };
const SystemCore SystemCores::Core9 = { 0x200, 9 };
const SystemCore SystemCores::Core10 = { 0x400, 10 };
const SystemCore SystemCores::Core11 = { 0x800, 11 };
const SystemCore SystemCores::Core12 = { 0x1000, 12 };
const SystemCore SystemCores::Core13 = { 0x2000, 13 };
const SystemCore SystemCores::Core14 = { 0x4000, 14 };
const SystemCore SystemCores::Core15 = { 0x8000, 15 };
const SystemCore SystemCores::Core16 = { 0x10000, 16 };
const SystemCore SystemCores::Core17 = { 0x20000, 17 };
const SystemCore SystemCores::Core18 = { 0x40000, 18 };
const SystemCore SystemCores::Core19 = { 0x80000, 19 };
const SystemCore SystemCores::Core20 = { 0x100000, 20 };
const SystemCore SystemCores::Core21 = { 0x200000, 21 };
const SystemCore SystemCores::Core22 = { 0x400000, 22 };
const SystemCore SystemCores::Core23 = { 0x800000, 23 };
const SystemCore SystemCores::Core24 = { 0x1000000, 24 };
const SystemCore SystemCores::Core25 = { 0x2000000, 25 };
const SystemCore SystemCores::Core26 = { 0x4000000, 26 };
const SystemCore SystemCores::Core27 = { 0x8000000, 27 };
const SystemCore SystemCores::Core28 = { 0x10000000, 28 };
const SystemCore SystemCores::Core29 = { 0x20000000, 29 };
const SystemCore SystemCores::Core30 = { 0x40000000, 30 };
const SystemCore SystemCores::Core31 = { 0x80000000, 31 };

const SystemCore SystemCores::IdToSystemCore[MAX_NUM_OF_CORES] =
{
	SystemCores::Core0,
	SystemCores::Core1,
	SystemCores::Core2,
	SystemCores::Core3,
	SystemCores::Core4,
	SystemCores::Core5,
	SystemCores::Core6,
	SystemCores::Core7,
	SystemCores::Core8,
	SystemCores::Core9,
	SystemCores::Core10,
	SystemCores::Core11,
	SystemCores::Core12,
	SystemCores::Core13,
	SystemCores::Core14,
	SystemCores::Core15,
	SystemCores::Core16,
	SystemCores::Core17,
	SystemCores::Core18,
	SystemCores::Core19,
	SystemCores::Core20,
	SystemCores::Core21,
	SystemCores::Core22,
	SystemCores::Core23,
	SystemCores::Core24,
	SystemCores::Core25,
	SystemCores::Core26,
	SystemCores::Core27,
	SystemCores::Core28,
	SystemCores::Core29,
	SystemCores::Core30,
	SystemCores::Core31
};


int getNumOfCores()
{
#ifdef WIN32
	SYSTEM_INFO sysinfo;
	GetSystemInfo( &sysinfo );
	return sysinfo.dwNumberOfProcessors;
#else
	return sysconf(_SC_NPROCESSORS_ONLN);
}
#endif

