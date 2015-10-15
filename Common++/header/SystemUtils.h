#ifndef PCAPPP_SYSTEM_UTILS
#define PCAPPP_SYSTEM_UTILS

#include <stdint.h>
#include <string>
#include <vector>

/// @file

#define MAX_NUM_OF_CORES 32

/**
 * @struct SystemCore
 * Represents data of 1 CPU core. Current implementation supports up to 32 cores
 */
struct SystemCore
{
	/**
	 * Core position in a 32-bit mask. For each core this attribute holds a 4B integer where only 1 bit is set, according to the core ID.
	 * For example: in core #0 the right-most bit will be set (meaning the number 0x01);
	 * 				in core #5 the 5th right-most bit will be set (meaning the number 0x20)...
	 */
	uint32_t Mask;

	/**
	 * Core ID - a value between 0 and 31
	 */
	uint8_t Id;

	/**
	* Overload of the comparison operator
	* @return true if 2 addresses are equal. False otherwise
	*/
	bool operator==(const SystemCore& other) const { return Id == other.Id; }
};

/**
 * @struct SystemCores
 * Contains static representation to all 32 cores and a static array to map core ID (integer) to a SystemCore struct
 */
struct SystemCores
{
	/**
	 * Static representation of core #0
	 */
	static const SystemCore Core0;
	/**
	 * Static representation of core #1
	 */
	static const SystemCore Core1;
	/**
	 * Static representation of core #2
	 */
	static const SystemCore Core2;
	/**
	 * Static representation of core #3
	 */
	static const SystemCore Core3;
	/**
	 * Static representation of core #4
	 */
	static const SystemCore Core4;
	/**
	 * Static representation of core #5
	 */
	static const SystemCore Core5;
	/**
	 * Static representation of core #6
	 */
	static const SystemCore Core6;
	/**
	 * Static representation of core #7
	 */
	static const SystemCore Core7;
	/**
	 * Static representation of core #8
	 */
	static const SystemCore Core8;
	/**
	 * Static representation of core #9
	 */
	static const SystemCore Core9;
	/**
	 * Static representation of core #10
	 */
	static const SystemCore Core10;
	/**
	 * Static representation of core #11
	 */
	static const SystemCore Core11;
	/**
	 * Static representation of core #12
	 */
	static const SystemCore Core12;
	/**
	 * Static representation of core #13
	 */
	static const SystemCore Core13;
	/**
	 * Static representation of core #14
	 */
	static const SystemCore Core14;
	/**
	 * Static representation of core #15
	 */
	static const SystemCore Core15;
	/**
	 * Static representation of core #16
	 */
	static const SystemCore Core16;
	/**
	 * Static representation of core #17
	 */
	static const SystemCore Core17;
	/**
	 * Static representation of core #18
	 */
	static const SystemCore Core18;
	/**
	 * Static representation of core #19
	 */
	static const SystemCore Core19;
	/**
	 * Static representation of core #20
	 */
	static const SystemCore Core20;
	/**
	 * Static representation of core #21
	 */
	static const SystemCore Core21;
	/**
	 * Static representation of core #22
	 */
	static const SystemCore Core22;
	/**
	 * Static representation of core #23
	 */
	static const SystemCore Core23;
	/**
	 * Static representation of core #24
	 */
	static const SystemCore Core24;
	/**
	 * Static representation of core #25
	 */
	static const SystemCore Core25;
	/**
	 * Static representation of core #26
	 */
	static const SystemCore Core26;
	/**
	 * Static representation of core #27
	 */
	static const SystemCore Core27;
	/**
	 * Static representation of core #28
	 */
	static const SystemCore Core28;
	/**
	 * Static representation of core #29
	 */
	static const SystemCore Core29;
	/**
	 * Static representation of core #30
	 */
	static const SystemCore Core30;
	/**
	 * Static representation of core #31
	 */
	static const SystemCore Core31;

	/**
	 * A static array for mapping core ID (integer) to the corresponding static SystemCore representation
	 */
	static const SystemCore IdToSystemCore[MAX_NUM_OF_CORES];
};

typedef uint32_t CoreMask;

/**
 * Get total number of cores on device
 * @return Total number of CPU cores on device
 */
int getNumOfCores();

/**
 * Create a core mask for all cores available on machine
 * @return A core mask for all cores available on machine
 */
CoreMask getCoreMaskForAllMachineCores();


/**
 * Create a core mask from a vector of system cores
 * @param[in] cores A vector of SystemCore instances
 * @return A core mask representing these cores
 */
CoreMask createCoreMaskFromCoreVector(std::vector<SystemCore> cores);


/**
 * Create a core mask from a vector of core IDs
 * @param[in] cores A vector of core IDs
 * @return A core mask representing these cores
 */
CoreMask createCoreMaskFromCoreIds(std::vector<int> coreIds);


/**
 * Covert a core mask into a vector of its appropriate system cores
 * @param[in] coreMask The input core mask
 * @param[out] resultVec The vector that will contain the system cores
 */
void createCoreVectorFromCoreMask(CoreMask coreMask, std::vector<SystemCore>& resultVec);

/**
 * Execute a shell command and return its output
 * @param[in] command The command to run
 * @return The output of the command (both stdout and stderr)
 */
std::string executeShellCommand(const std::string command);

#endif /* PCAPPP_SYSTEM_UTILS */
