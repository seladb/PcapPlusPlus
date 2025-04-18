#pragma once

#include "DeprecationUtils.h"

#include <cstdint>
#include <string>
#include <vector>

/// @file

// @todo Change to constexpr when C++17 is minimum supported version
enum : uint8_t
{
	MAX_NUM_OF_CORES = 32
};

#ifdef _MSC_VER
int gettimeofday(struct timeval* tp, struct timezone* tzp);
#endif

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{

	/// @struct SystemCore
	/// Represents data of 1 CPU core. Current implementation supports up to 32 cores
	struct SystemCore
	{

		/// Core position in a 32-bit mask. For each core this attribute holds a 4B integer where only 1 bit is set,
		/// according to the core ID. For example:
		/// - In core #0 the right-most bit will be set (meaning the number 0x01);
		/// - in core #5 the 5th right-most bit will be set (meaning the number 0x20)
		uint32_t Mask;

		/// Core ID - a value between 0 and 31
		uint8_t Id;

		/// Overload of the comparison operator
		/// @return true if 2 addresses are equal. False otherwise
		bool operator==(const SystemCore& other) const
		{
			return Id == other.Id;
		}
	};

	/// @struct SystemCores
	/// Contains static representation to all 32 cores and a static array to map core ID (integer) to a SystemCore
	/// struct
	struct SystemCores
	{
		/// Static representation of core #0
		static const SystemCore Core0;
		/// Static representation of core #1
		static const SystemCore Core1;
		/// Static representation of core #2
		static const SystemCore Core2;
		/// Static representation of core #3
		static const SystemCore Core3;
		/// Static representation of core #4
		static const SystemCore Core4;
		/// Static representation of core #5
		static const SystemCore Core5;
		/// Static representation of core #6
		static const SystemCore Core6;
		/// Static representation of core #7
		static const SystemCore Core7;
		/// Static representation of core #8
		static const SystemCore Core8;
		/// Static representation of core #9
		static const SystemCore Core9;
		/// Static representation of core #10
		static const SystemCore Core10;
		/// Static representation of core #11
		static const SystemCore Core11;
		/// Static representation of core #12
		static const SystemCore Core12;
		/// Static representation of core #13
		static const SystemCore Core13;
		/// Static representation of core #14
		static const SystemCore Core14;
		/// Static representation of core #15
		static const SystemCore Core15;
		/// Static representation of core #16
		static const SystemCore Core16;
		/// Static representation of core #17
		static const SystemCore Core17;
		/// Static representation of core #18
		static const SystemCore Core18;
		/// Static representation of core #19
		static const SystemCore Core19;
		/// Static representation of core #20
		static const SystemCore Core20;
		/// Static representation of core #21
		static const SystemCore Core21;
		/// Static representation of core #22
		static const SystemCore Core22;
		/// Static representation of core #23
		static const SystemCore Core23;
		/// Static representation of core #24
		static const SystemCore Core24;
		/// Static representation of core #25
		static const SystemCore Core25;
		/// Static representation of core #26
		static const SystemCore Core26;
		/// Static representation of core #27
		static const SystemCore Core27;
		/// Static representation of core #28
		static const SystemCore Core28;
		/// Static representation of core #29
		static const SystemCore Core29;
		/// Static representation of core #30
		static const SystemCore Core30;
		/// Static representation of core #31
		static const SystemCore Core31;
		/// A static array for mapping core ID (integer) to the corresponding static SystemCore representation
		static const SystemCore IdToSystemCore[MAX_NUM_OF_CORES];
	};

	using CoreMask = uint32_t;

	/// Get total number of cores on device
	/// @return Total number of CPU cores on device
	int getNumOfCores();

	/// Create a core mask for all cores available on machine
	/// @return A core mask for all cores available on machine
	CoreMask getCoreMaskForAllMachineCores();

	/// Create a core mask from a vector of system cores
	/// @param[in] cores A vector of SystemCore instances
	/// @return A core mask representing these cores
	CoreMask createCoreMaskFromCoreVector(const std::vector<SystemCore>& cores);

	/// Create a core mask from a vector of core IDs
	/// @param[in] coreIds A vector of core IDs
	/// @return A core mask representing these cores
	CoreMask createCoreMaskFromCoreIds(const std::vector<int>& coreIds);

	/// Convert a core mask into a vector of its appropriate system cores
	/// @param[in] coreMask The input core mask
	/// @param[out] resultVec The vector that will contain the system cores
	void createCoreVectorFromCoreMask(CoreMask coreMask, std::vector<SystemCore>& resultVec);

	/// Execute a shell command and return its output
	/// @param[in] command The command to run
	/// @return The output of the command (both stdout and stderr)
	/// @throws std::runtime_error Error executing the command.
	std::string executeShellCommand(const std::string& command);

	/// Check if a directory exists
	/// @param[in] dirPath Full path of the directory to search
	/// @return True if directory exists, false otherwise
	bool directoryExists(const std::string& dirPath);

	/// Retrieve a system-wide real-time accurate clock. It's actually a multi-platform version of clock_gettime() which
	/// is fully supported only on Linux
	/// @param[out] sec The second portion of the time
	/// @param[out] nsec The nanosecond portion of the time
	/// @return 0 for success, or -1 for failure
	int clockGetTime(long& sec, long& nsec);

	/// A multi-platform version of the popular sleep method. This method simply runs the right sleep method, according
	/// to the platform it is running on.
	/// @param[in] seconds Number of seconds to sleep
	/// @deprecated Please use std::this_thread::sleep_for(). It is a standard C++ (since C++11) method which is already
	/// cross-platform
	PCPP_DEPRECATED("Please use std::this_thread::sleep_for(std::chrono::seconds(seconds)) instead")
	void multiPlatformSleep(uint32_t seconds);

	/// A multi-platform version of sleep in milliseconds resolution. This method simply runs the right sleep method,
	/// according to the platform it is running on.
	/// @param[in] milliseconds Number of milliseconds to sleep
	/// @deprecated Please use std::this_thread::sleep_for(). It is a standard C++ (since C++11) method which is already
	/// cross-platform
	PCPP_DEPRECATED("Please use std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds)) instead")
	void multiPlatformMSleep(uint32_t milliseconds);

	/// A multi-platform version of `htons` which convert host to network byte order
	/// @param[in] host Value in host byte order
	/// @return Value in network byte order
	uint16_t hostToNet16(uint16_t host);

	/// A multi-platform version of `ntohs` which convert network to host byte order
	/// @param[in] net Value in network byte order
	/// @return Value in host byte order
	uint16_t netToHost16(uint16_t net);

	/// A multi-platform version of `htonl` which convert host to network byte order
	/// @param[in] host Value in host byte order
	/// @return Value in network byte order
	uint32_t hostToNet32(uint32_t host);

	/// A multi-platform version of `ntohl` which convert network to host byte order
	/// @param[in] net Value in network byte order
	/// @return Value in host byte order
	uint32_t netToHost32(uint32_t net);

	/// @class AppName
	/// This class extracts the application name from the current running executable and stores it for usage of the
	/// application throughout its runtime. This class should be initialized once in the beginning of the main() method
	/// using AppName#init() and from then on the app name could be retrieved using AppName#get()
	class AppName
	{
	private:
		static std::string m_AppName;

	public:
		/// Static init method which should be called once at the beginning of the main method.
		/// @param[in] argc The argc param from main()
		/// @param[in] argv The argv param from main()
		// cppcheck-suppress constParameter
		static void init(int argc, char* argv[])
		{
			if (argc == 0)
			{
				m_AppName.clear();
				return;
			}

			m_AppName = argv[0];

			// remove Linux/Unix path
			size_t lastPos = m_AppName.rfind('/');
			if (lastPos != std::string::npos)
			{
				m_AppName = m_AppName.substr(lastPos + 1);
			}

			// remove Windows path
			lastPos = m_AppName.rfind('\\');
			if (lastPos != std::string::npos)
			{
				m_AppName = m_AppName.substr(lastPos + 1);
			}

			// remove file extension
			lastPos = m_AppName.rfind('.');
			if (lastPos != std::string::npos)
			{
				m_AppName.resize(lastPos);
			}
		}

		/// @return The app name as extracted from the current running executable
		static const std::string& get()
		{
			return m_AppName;
		}
	};

	/// @class ApplicationEventHandler
	/// A singleton class that provides callbacks for events that occur during application life-cycle such as ctrl+c
	/// pressed, application closed, killed, etc.
	class ApplicationEventHandler
	{
	public:
		/// @typedef EventHandlerCallback
		/// The callback to be invoked when the event occurs
		/// @param[in] cookie A pointer the the cookie provided by the user in ApplicationEventHandler c'tor
		using EventHandlerCallback = void (*)(void*);

		/// As ApplicationEventHandler is a singleton, this is the static getter to retrieve its instance
		/// @return The singleton instance of ApplicationEventHandler
		static ApplicationEventHandler& getInstance()
		{
			static ApplicationEventHandler instance;
			return instance;
		}

		/// Register for an application-interrupted event, meaning ctrl+c was pressed
		/// @param[in] handler The callback to be activated when the event occurs
		/// @param[in] cookie A pointer to a user provided object. This object will be transferred to the
		/// EventHandlerCallback callback. This cookie is very useful for transferring objects that give context to the
		/// event callback
		void onApplicationInterrupted(EventHandlerCallback handler, void* cookie);

	private:
		EventHandlerCallback m_ApplicationInterruptedHandler;
		void* m_ApplicationInterruptedCookie;

		// private c'tor
		ApplicationEventHandler();

#if defined(_WIN32)
		static int handlerRoutine(unsigned long fdwCtrlType);
#else
		static void handlerRoutine(int signum);
#endif
	};

}  // namespace pcpp
