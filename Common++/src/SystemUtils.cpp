#include "SystemUtils.h"
#include "EndianPortable.h"

#ifndef _MSC_VER
#	include <unistd.h>
#endif
#include <stdexcept>
#include <memory>
#include <array>
#include <iostream>
#include <mutex>
#include <cstring>
#include <csignal>
#include <sys/stat.h>
#include <thread>
#if defined(__APPLE__)
#	include <mach/clock.h>
#	include <mach/mach.h>
#endif

#if defined(_WIN32)
#	include <Windows.h>
#	define POPEN _popen
#	define PCLOSE _pclose
#else
#	define POPEN popen
#	define PCLOSE pclose
#endif

#ifdef _MSC_VER
#	include <chrono>
int gettimeofday(struct timeval* tp, struct timezone* tzp)
{

	auto now = std::chrono::system_clock::now();
	auto duration = now.time_since_epoch();

	auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration);
	auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(duration - seconds);

	tp->tv_sec = static_cast<long>(seconds.count());
	tp->tv_usec = static_cast<long>(microseconds.count());
	return 0;
}
#endif

/// @cond PCPP_INTERNAL

namespace
{

	/// @class PcloseDeleter
	/// A deleter that cleans up a FILE handle using pclose.
	struct PcloseDeleter
	{
		void operator()(FILE* ptr) const noexcept
		{
			PCLOSE(ptr);
		}
	};
}  // namespace

/// @endcond

namespace pcpp
{

	const SystemCore SystemCores::Core0(0);
	const SystemCore SystemCores::Core1(1);
	const SystemCore SystemCores::Core2(2);
	const SystemCore SystemCores::Core3(3);
	const SystemCore SystemCores::Core4(4);
	const SystemCore SystemCores::Core5(5);
	const SystemCore SystemCores::Core6(6);
	const SystemCore SystemCores::Core7(7);
	const SystemCore SystemCores::Core8(8);
	const SystemCore SystemCores::Core9(9);
	const SystemCore SystemCores::Core10(10);
	const SystemCore SystemCores::Core11(11);
	const SystemCore SystemCores::Core12(12);
	const SystemCore SystemCores::Core13(13);
	const SystemCore SystemCores::Core14(14);
	const SystemCore SystemCores::Core15(15);
	const SystemCore SystemCores::Core16(16);
	const SystemCore SystemCores::Core17(17);
	const SystemCore SystemCores::Core18(18);
	const SystemCore SystemCores::Core19(19);
	const SystemCore SystemCores::Core20(20);
	const SystemCore SystemCores::Core21(21);
	const SystemCore SystemCores::Core22(22);
	const SystemCore SystemCores::Core23(23);
	const SystemCore SystemCores::Core24(24);
	const SystemCore SystemCores::Core25(25);
	const SystemCore SystemCores::Core26(26);
	const SystemCore SystemCores::Core27(27);
	const SystemCore SystemCores::Core28(28);
	const SystemCore SystemCores::Core29(29);
	const SystemCore SystemCores::Core30(30);
	const SystemCore SystemCores::Core31(31);

	const SystemCore SystemCores::IdToSystemCore[MAX_NUM_OF_CORES] = {
		SystemCores::Core0,  SystemCores::Core1,  SystemCores::Core2,  SystemCores::Core3,  SystemCores::Core4,
		SystemCores::Core5,  SystemCores::Core6,  SystemCores::Core7,  SystemCores::Core8,  SystemCores::Core9,
		SystemCores::Core10, SystemCores::Core11, SystemCores::Core12, SystemCores::Core13, SystemCores::Core14,
		SystemCores::Core15, SystemCores::Core16, SystemCores::Core17, SystemCores::Core18, SystemCores::Core19,
		SystemCores::Core20, SystemCores::Core21, SystemCores::Core22, SystemCores::Core23, SystemCores::Core24,
		SystemCores::Core25, SystemCores::Core26, SystemCores::Core27, SystemCores::Core28, SystemCores::Core29,
		SystemCores::Core30, SystemCores::Core31
	};

	LongCoreMask::LongCoreMask(SystemCore core)
	{
		if (core.Id < 0 || core.Id >= MaxCoreCount)
		{
			throw std::out_of_range("Core ID is out of range");
		}

		Mask.set(core.Id);
	}

	LongCoreMask::LongCoreMask(std::vector<SystemCore> const& cores)
	{
		for (auto const& core : cores)
		{
			if (core.Id < 0 || core.Id >= MaxCoreCount)
			{
				throw std::out_of_range("Core ID is out of range");
			}

			Mask.set(core.Id);
		}
	}

	LongCoreMask LongCoreMask::fromAllCores()
	{
		const int numOfCores = getNumOfCores() < MaxCoreCount ? getNumOfCores() : MaxCoreCount;
		
		LongCoreMask mask;
		for (int i = 0; i < numOfCores; i++)
		{
			mask.Mask.set(i);
		}
		return mask;
	}

	std::vector<SystemCore> LongCoreMask::toCoreVector() const
	{
		static_assert(static_cast<size_t>((std::numeric_limits<decltype(SystemCore::Id)>::max)()) + 1 >= MaxCoreCount,
		              "SystemCore::Id type is too small to represent all cores in LongCoreMask");

		std::vector<SystemCore> result;
		for (size_t i = 0; i < MaxCoreCount; ++i)
		{
			if (Mask.test(i))
			{
				result.push_back(SystemCore(static_cast<uint8_t>(i)));
			}
		}
		return result;
	}

	int getNumOfCores()
	{
#if defined(_WIN32)
		SYSTEM_INFO sysinfo;
		GetSystemInfo(&sysinfo);
		return sysinfo.dwNumberOfProcessors;
#else
		return static_cast<int>(sysconf(_SC_NPROCESSORS_ONLN));
#endif
	}

	namespace
	{
		void checkCoreIdRangeForCoreMask(int coreId)
		{
			if (coreId >= 32 || coreId < 0)
			{
				throw std::out_of_range(
				    "Core ID is out of range for CoreMask. Use LongCoreMask for more than 32 cores.");
			}
		}
	}

	CoreMask getCoreMaskForAllMachineCores()
	{
		const int numOfCores = getNumOfCores() < 32 ? getNumOfCores() : 32;
		CoreMask result = 0;
		for (int i = 0; i < numOfCores; i++)
		{
			result = result | SystemCore(i).getShortCoreMask();
		}

		return result;
	}

	CoreMask createCoreMaskFromCoreVector(const std::vector<SystemCore>& cores)
	{
		CoreMask result = 0;
		for (const auto& core : cores)
		{
			checkCoreIdRangeForCoreMask(core.Id);
			// cppcheck-suppress useStlAlgorithm
			result |= core.getShortCoreMask();
		}

		return result;
	}

	CoreMask createCoreMaskFromCoreIds(const std::vector<int>& coreIds)
	{
		CoreMask result = 0;
		for (const auto& coreId : coreIds)
		{
			checkCoreIdRangeForCoreMask(coreId);

			// cppcheck-suppress useStlAlgorithm
			result |= SystemCore(coreId).getShortCoreMask();
		}

		return result;
	}

	void createCoreVectorFromCoreMask(CoreMask coreMask, std::vector<SystemCore>& resultVec)
	{
		int idx = 0;
		while (coreMask != 0)
		{
			if ((1 & coreMask) != 0U)
			{
				resultVec.push_back(SystemCore(idx));
			}

			coreMask = coreMask >> 1;
			++idx;
		}
	}

	std::vector<SystemCore> createCoreVectorFromCoreMask(CoreMask coreMask)
	{
		std::vector<SystemCore> resultVec;
		createCoreVectorFromCoreMask(coreMask, resultVec);
		return resultVec;
	}

	std::string executeShellCommand(const std::string& command)
	{
		const std::unique_ptr<FILE, PcloseDeleter> pipe =
		    std::unique_ptr<FILE, PcloseDeleter>(POPEN(command.c_str(), "r"));
		if (!pipe)
		{
			throw std::runtime_error("Error executing command: " + command);
		}

		std::array<char, 128> buffer{};
		std::string result;
		while (feof(pipe.get()) == 0)
		{
			if (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr)
			{
				result += buffer.data();  // Using the C-string overload of string append.
			}
		}
		return result;
	}

	bool directoryExists(const std::string& dirPath)
	{
		struct stat info{};

		if (stat(dirPath.c_str(), &info) != 0)
		{
			return false;
		}
		return (info.st_mode & S_IFDIR) != 0;
	}

	int clockGetTime(long& sec, long& nsec)
	{
		using namespace std::chrono;

		auto now = system_clock::now();
		auto duration = now.time_since_epoch();

		auto secondsDuration = duration_cast<seconds>(duration);
		auto nanosecondsDuration = duration_cast<nanoseconds>(duration - secondsDuration);

		sec = static_cast<long>(secondsDuration.count());
		nsec = static_cast<long>(nanosecondsDuration.count());

		return 0;
	}

	time_t mkUtcTime(std::tm& time)
	{
#if defined(_WIN32)
		return _mkgmtime(&time);
#else
		return timegm(&time);
#endif
	}

	void multiPlatformSleep(uint32_t seconds)
	{
		std::this_thread::sleep_for(std::chrono::seconds(seconds));
	}

	void multiPlatformMSleep(uint32_t milliseconds)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
	}

	uint16_t hostToNet16(uint16_t host)
	{
		return htobe16(host);
	}

	uint16_t netToHost16(uint16_t net)
	{
		return be16toh(net);
	}

	uint32_t hostToNet32(uint32_t host)
	{
		return htobe32(host);
	}

	uint32_t netToHost32(uint32_t net)
	{
		return be32toh(net);
	}

	std::string AppName::m_AppName;

#if defined(_WIN32)
	int ApplicationEventHandler::handlerRoutine(unsigned long fdwCtrlType)
	{
		switch (fdwCtrlType)
		{
		case CTRL_C_EVENT:
		case CTRL_BREAK_EVENT:
		{
			if (ApplicationEventHandler::getInstance().m_ApplicationInterruptedHandler != nullptr)
				ApplicationEventHandler::getInstance().m_ApplicationInterruptedHandler(
				    ApplicationEventHandler::getInstance().m_ApplicationInterruptedCookie);
			return TRUE;
		}

		default:
			return FALSE;
		}
	}
#else

	static std::mutex UnixLinuxHandlerRoutineMutex;

	void ApplicationEventHandler::handlerRoutine(int signum)
	{
		switch (signum)
		{
		case SIGINT:
		{
			// Most calls are unsafe in a signal handler, and this includes printf(). In particular,
			// if the signal is caught while inside printf() it may be called twice at the same time which might not be
			// a good idea The way to make sure the signal is called only once is using this lock and putting nullptr in
			// m_ApplicationInterruptedHandler
			const std::lock_guard<std::mutex> lock(UnixLinuxHandlerRoutineMutex);

			if (ApplicationEventHandler::getInstance().m_ApplicationInterruptedHandler != nullptr)
			{
				ApplicationEventHandler::getInstance().m_ApplicationInterruptedHandler(
				    ApplicationEventHandler::getInstance().m_ApplicationInterruptedCookie);
			}

			ApplicationEventHandler::getInstance().m_ApplicationInterruptedHandler = nullptr;

			return;
		}
		default:
		{
			return;
		}
		}
	}
#endif

	ApplicationEventHandler::ApplicationEventHandler()
	    : m_ApplicationInterruptedHandler(nullptr), m_ApplicationInterruptedCookie(nullptr)
	{}

	void ApplicationEventHandler::onApplicationInterrupted(EventHandlerCallback handler, void* cookie)
	{
		m_ApplicationInterruptedHandler = handler;
		m_ApplicationInterruptedCookie = cookie;

#if defined(_WIN32)
		SetConsoleCtrlHandler(reinterpret_cast<PHANDLER_ROUTINE>(handlerRoutine), TRUE);
#else
		struct sigaction action{};
		memset(&action, 0, sizeof(struct sigaction));
		action.sa_handler = handlerRoutine;
		sigemptyset(&action.sa_mask);
		sigaction(SIGINT, &action, nullptr);
#endif
	}

}  // namespace pcpp
