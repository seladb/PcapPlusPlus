#ifndef PCAPPP_SYSTEM_UTILS
#define PCAPPP_SYSTEM_UTILS

#include <stdint.h>

#define MAX_NUM_OF_CORES 32

struct SystemCore
{
	uint32_t Mask;
	uint8_t Id;
};

struct SystemCores
{
	static const SystemCore Core0;
	static const SystemCore Core1;
	static const SystemCore Core2;
	static const SystemCore Core3;
	static const SystemCore Core4;
	static const SystemCore Core5;
	static const SystemCore Core6;
	static const SystemCore Core7;
	static const SystemCore Core8;
	static const SystemCore Core9;
	static const SystemCore Core10;
	static const SystemCore Core11;
	static const SystemCore Core12;
	static const SystemCore Core13;
	static const SystemCore Core14;
	static const SystemCore Core15;
	static const SystemCore Core16;
	static const SystemCore Core17;
	static const SystemCore Core18;
	static const SystemCore Core19;
	static const SystemCore Core20;
	static const SystemCore Core21;
	static const SystemCore Core22;
	static const SystemCore Core23;
	static const SystemCore Core24;
	static const SystemCore Core25;
	static const SystemCore Core26;
	static const SystemCore Core27;
	static const SystemCore Core28;
	static const SystemCore Core29;
	static const SystemCore Core30;
	static const SystemCore Core31;

	static const SystemCore IdToSystemCore[MAX_NUM_OF_CORES];
};

typedef uint32_t CoreMask;

int getNumOfCores();

#endif /* PCAPPP_SYSTEM_UTILS */
