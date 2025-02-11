#define LOG_MODULE PacketLogModuleArpLayer
#include "../TestDefinition.h"
#include <algorithm>
#include <cctype>
#include <random>
#include <string>
#include <thread>

#include "Logger.h"
#include "SystemUtils.h"

namespace pcpp
{
	void invokeDebugLog()
	{
		PCPP_LOG_DEBUG("debug log");
	}

	void invokeErrorLog(const std::string& message = "")
	{
		PCPP_LOG_ERROR("error log" << message);
	}
}  // namespace pcpp

class LogPrinter
{
public:
	static int lastLogLevelSeen;
	static std::string* lastLogMessageSeen;
	static std::string* lastFilenameSeen;
	static std::string* lastMethodSeen;
	static int lastLineSeen;

	static void logPrinter(pcpp::Logger::LogLevel logLevel, const std::string& logMessage, const std::string& fileName,
	                       const std::string& method, const int line)
	{
		LogPrinter::clean();
		LogPrinter::lastLogLevelSeen = (int)logLevel;
		LogPrinter::lastLogMessageSeen = new std::string(logMessage);
		LogPrinter::lastFilenameSeen = new std::string(fileName);
		LogPrinter::lastMethodSeen = new std::string(method);
		LogPrinter::lastLineSeen = line;
	}

	static void clean()
	{
		LogPrinter::lastLogLevelSeen = 999;
		LogPrinter::lastLineSeen = 99999;
		if (LogPrinter::lastLogMessageSeen != nullptr)
		{
			delete LogPrinter::lastLogMessageSeen;
			LogPrinter::lastLogMessageSeen = nullptr;
		}
		if (LogPrinter::lastFilenameSeen != nullptr)
		{
			delete LogPrinter::lastFilenameSeen;
			LogPrinter::lastFilenameSeen = nullptr;
		}

		if (LogPrinter::lastMethodSeen != nullptr)
		{
			delete LogPrinter::lastMethodSeen;
			LogPrinter::lastMethodSeen = nullptr;
		}
	}
};

int LogPrinter::lastLogLevelSeen = 999;
std::string* LogPrinter::lastLogMessageSeen = nullptr;
std::string* LogPrinter::lastFilenameSeen = nullptr;
std::string* LogPrinter::lastMethodSeen = nullptr;
int LogPrinter::lastLineSeen = 99999;

class MultiThreadLogCounter
{
public:
	static const int ThreadCount = 5;
	static int logMessageThreadCount[ThreadCount];
	static void logPrinter(pcpp::Logger::LogLevel logLevel, const std::string& logMessage, const std::string& fileName,
	                       const std::string& method, const int line)
	{
		int threadId = logMessage[logMessage.length() - 1] - '0';
		MultiThreadLogCounter::logMessageThreadCount[threadId]++;
	}
};

int MultiThreadLogCounter::logMessageThreadCount[MultiThreadLogCounter::ThreadCount] = { 0, 0, 0, 0, 0 };

// clang-format off
#if defined(_WIN32)
#define SEPARATOR '\\'
#else
#define SEPARATOR '/'
#endif
// clang-format on

std::string getLFileName(const std::string& path)
{
	std::string result = path;
	// check the "/" separator
	size_t i = result.rfind('/', result.length());
	if (i != std::string::npos)
	{
		result = result.substr(i + 1, result.length() - i);
	}
	// check the "\\" separator
	i = result.rfind('\\', result.length());
	if (i != std::string::npos)
	{
		result = result.substr(i + 1, result.length() - i);
	}
	return result;
}

std::string getLowerCaseFileName(const std::string& path)
{
	std::string result = getLFileName(path);
	std::transform(result.begin(), result.end(), result.begin(), ::tolower);
	return result;
}

std::string getMethodWithoutNamespace(const std::string& method)
{
	std::string result = method;
	size_t i = result.rfind(':', result.length());
	if (i != std::string::npos)
	{
		result = result.substr(i + 1, result.length() - i);
	}
	return result;
}

class LoggerCleaner
{
public:
	~LoggerCleaner()
	{
		pcpp::Logger::getInstance().enableLogs();
		pcpp::Logger::getInstance().setAllModulesToLogLevel(pcpp::LogLevel::Info);
		pcpp::Logger::getInstance().resetLogPrinter();
		std::cout.clear();
		LogPrinter::clean();
	}
};

void printLogThread(int threadId)
{
	std::random_device rd;
	std::mt19937 simpleRand(rd());
	std::uniform_int_distribution<int> dist(1, 5);
	std::ostringstream sstream;
	sstream << threadId;
	std::string threadIdAsString = sstream.str();
	for (int i = 0; i < 1000; i++)
	{
		pcpp::invokeErrorLog(threadIdAsString);
		int sleepTime = dist(simpleRand);
		std::this_thread::sleep_for(std::chrono::milliseconds(sleepTime));
	}
}

PTF_TEST_CASE(TestLoggerMultiThread)
{
	// cppcheck-suppress unusedVariable
	LoggerCleaner loggerCleaner;

	std::thread threads[MultiThreadLogCounter::ThreadCount];

	pcpp::Logger::getInstance().setLogPrinter(&MultiThreadLogCounter::logPrinter);

	for (int i = 0; i < MultiThreadLogCounter::ThreadCount; i++)
	{
		threads[i] = std::thread(printLogThread, i);
	}

	for (auto& thread : threads)
	{
		thread.join();
	}

	int totalLogMessages = 0;
	for (int logMessagesCount : MultiThreadLogCounter::logMessageThreadCount)
	{
		// cppcheck-suppress useStlAlgorithm
		totalLogMessages += logMessagesCount;
	}

	PTF_ASSERT_EQUAL(totalLogMessages, 5000);
}  // TestLoggerMultiThread

PTF_TEST_CASE(TestLogger)
{
	using pcpp::Logger;
	using pcpp::LogLevel;
	using pcpp::LogModule;

	auto& logger = Logger::getInstance();

	// cppcheck-suppress unusedVariable
	LoggerCleaner loggerCleaner;

	// verify all modules are on info log level
	for (int moduleInt = 1; moduleInt < LogModule::NumOfLogModules; moduleInt++)
	{
		const LogModule moduleEnum = static_cast<LogModule>(moduleInt);

		PTF_ASSERT_EQUAL(logger.getLogLevel(moduleEnum), LogLevel::Info, enum);
		PTF_ASSERT_FALSE(logger.isDebugEnabled(moduleEnum));

		PTF_ASSERT_TRUE(logger.shouldLog(LogLevel::Error, moduleEnum));
		PTF_ASSERT_TRUE(logger.shouldLog(LogLevel::Info, moduleEnum));
		PTF_ASSERT_FALSE(logger.shouldLog(LogLevel::Debug, moduleEnum));
		PTF_ASSERT_FALSE(logger.shouldLog(LogLevel::Off, moduleEnum));
	}

	// invoke debug and error logs - expect to see only the error log
	logger.setLogPrinter(&LogPrinter::logPrinter);

	pcpp::invokeDebugLog();
	PTF_ASSERT_EQUAL(LogPrinter::lastLogLevelSeen, 999);
	PTF_ASSERT_EQUAL(LogPrinter::lastLineSeen, 99999);
	PTF_ASSERT_NULL(LogPrinter::lastLogMessageSeen);
	PTF_ASSERT_NULL(LogPrinter::lastFilenameSeen);
	PTF_ASSERT_NULL(LogPrinter::lastMethodSeen);

	pcpp::invokeErrorLog();
	PTF_ASSERT_EQUAL(LogPrinter::lastLogLevelSeen, (int)pcpp::Logger::Error);
	PTF_ASSERT_EQUAL(*LogPrinter::lastLogMessageSeen, "error log");
	PTF_ASSERT_EQUAL(getLowerCaseFileName(*LogPrinter::lastFilenameSeen), "loggertests.cpp");
	PTF_ASSERT_EQUAL(getMethodWithoutNamespace(*LogPrinter::lastMethodSeen), "invokeErrorLog");
	PTF_ASSERT_EQUAL(LogPrinter::lastLineSeen, 21);

	// change one module log level
	logger.setLogLevel(pcpp::PacketLogModuleArpLayer, pcpp::Logger::Debug);
	PTF_ASSERT_EQUAL(logger.getLogLevel(pcpp::PacketLogModuleArpLayer), pcpp::LogLevel::Debug, enum);
	PTF_ASSERT_TRUE(logger.isDebugEnabled(pcpp::PacketLogModuleArpLayer));

	// invoke debug and error logs - expect to see both
	pcpp::invokeDebugLog();
	PTF_ASSERT_EQUAL(LogPrinter::lastLogLevelSeen, (int)pcpp::Logger::Debug);
	PTF_ASSERT_EQUAL(*LogPrinter::lastLogMessageSeen, "debug log");
	PTF_ASSERT_EQUAL(getLowerCaseFileName(*LogPrinter::lastFilenameSeen), "loggertests.cpp");
	PTF_ASSERT_EQUAL(getMethodWithoutNamespace(*LogPrinter::lastMethodSeen), "invokeDebugLog");
	PTF_ASSERT_EQUAL(LogPrinter::lastLineSeen, 16);

	pcpp::invokeErrorLog();
	PTF_ASSERT_EQUAL(LogPrinter::lastLogLevelSeen, (int)pcpp::Logger::Error);
	PTF_ASSERT_EQUAL(*LogPrinter::lastLogMessageSeen, "error log");
	PTF_ASSERT_EQUAL(getLowerCaseFileName(*LogPrinter::lastFilenameSeen), "loggertests.cpp");
	PTF_ASSERT_EQUAL(getMethodWithoutNamespace(*LogPrinter::lastMethodSeen), "invokeErrorLog");
	PTF_ASSERT_EQUAL(LogPrinter::lastLineSeen, 21);

	// verify the last error message
	PTF_ASSERT_EQUAL(logger.getLastError(), "error log");

	// change all modules log level
	logger.setAllModulesToLogLevel(LogLevel::Debug);
	for (int moduleInt = 1; moduleInt < LogModule::NumOfLogModules; moduleInt++)
	{
		auto const moduleEnum = static_cast<LogModule>(moduleInt);

		PTF_ASSERT_EQUAL(logger.getLogLevel(static_cast<LogModule>(moduleEnum)), pcpp::LogLevel::Debug, enum);
		PTF_ASSERT_TRUE(logger.isDebugEnabled(static_cast<LogModule>(moduleEnum)));

		PTF_ASSERT_TRUE(logger.shouldLog(LogLevel::Error, moduleEnum));
		PTF_ASSERT_TRUE(logger.shouldLog(LogLevel::Info, moduleEnum));
		PTF_ASSERT_TRUE(logger.shouldLog(LogLevel::Debug, moduleEnum));
		PTF_ASSERT_FALSE(logger.shouldLog(LogLevel::Off, moduleEnum));
	}

	// invoke debug log - expect to see it
	pcpp::invokeDebugLog();
	PTF_ASSERT_EQUAL(LogPrinter::lastLogLevelSeen, (int)pcpp::Logger::Debug);
	PTF_ASSERT_EQUAL(*LogPrinter::lastLogMessageSeen, "debug log");
	PTF_ASSERT_EQUAL(getLowerCaseFileName(*LogPrinter::lastFilenameSeen), "loggertests.cpp");
	PTF_ASSERT_EQUAL(getMethodWithoutNamespace(*LogPrinter::lastMethodSeen), "invokeDebugLog");
	PTF_ASSERT_EQUAL(LogPrinter::lastLineSeen, 16);

	// suppress logs
	PTF_ASSERT_TRUE(logger.logsEnabled())
	logger.suppressLogs();
	PTF_ASSERT_FALSE(logger.logsEnabled())

	// reset LogPrinter
	LogPrinter::clean();

	// invoke debug and error logs - expect to see none
	pcpp::invokeDebugLog();
	pcpp::invokeErrorLog();
	PTF_ASSERT_EQUAL(LogPrinter::lastLogLevelSeen, 999);
	PTF_ASSERT_NULL(LogPrinter::lastLogMessageSeen);

	// invoke another error log - expect to see it as the last error message although logs are suppressed
	pcpp::invokeErrorLog("2");
	PTF_ASSERT_EQUAL(logger.getLastError(), "error log2");

	// re-enable logs
	logger.enableLogs();
	PTF_ASSERT_TRUE(logger.logsEnabled())

	// invoke error log - expect to see it
	pcpp::invokeErrorLog();
	PTF_ASSERT_EQUAL(LogPrinter::lastLogLevelSeen, static_cast<int>(pcpp::LogLevel::Error));
	PTF_ASSERT_EQUAL(*LogPrinter::lastLogMessageSeen, "error log");
	PTF_ASSERT_EQUAL(getLowerCaseFileName(*LogPrinter::lastFilenameSeen), "loggertests.cpp");
	PTF_ASSERT_EQUAL(getMethodWithoutNamespace(*LogPrinter::lastMethodSeen), "invokeErrorLog");
	PTF_ASSERT_EQUAL(logger.getLastError(), "error log");
	PTF_ASSERT_EQUAL(LogPrinter::lastLineSeen, 21);

	// reset LogPrinter
	LogPrinter::clean();

	// reset the log printer
	logger.resetLogPrinter();

	// disable std::cout for a bit
	std::cout.setstate(std::ios_base::failbit);

	// set debug log for a module, don't expect to see it in the custom log printer
	logger.setLogLevel(pcpp::PacketLogModuleArpLayer, pcpp::LogLevel::Debug);
	pcpp::invokeDebugLog();
	pcpp::invokeErrorLog();
	PTF_ASSERT_EQUAL(LogPrinter::lastLogLevelSeen, 999);
	PTF_ASSERT_NULL(LogPrinter::lastLogMessageSeen);
}  // TestLogger
