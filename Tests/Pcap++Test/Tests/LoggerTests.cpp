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
#define PCPP_TEST_EXPECTED_DEBUG_LOG_LINE 20
#define PCPP_TEST_EXPECTED_WARN_LOG_LINE 25
#define PCPP_TEST_EXPECTED_ERROR_LOG_LINE 30

	void invokeDebugLog()
	{
		PCPP_LOG_DEBUG("debug log");
	}

	void invokeWarnLog(const std::string& message = "")
	{
		PCPP_LOG_WARN("warn log" << message);
	}

	void invokeErrorLog(const std::string& message = "")
	{
		PCPP_LOG_ERROR("error log" << message);
	}
}  // namespace pcpp

class LogPrinter
{
public:
	struct LogInfo
	{
		int logLevel;
		std::string message;
		std::string filename;
		std::string method;
		int line;
	};

	LogPrinter()
	{
		// Huge reservation to avoid reallocations.
		lastLog.message.reserve(1000);
		lastLog.filename.reserve(1000);
		lastLog.method.reserve(1000);
	}

	void onLogMessage(pcpp::Logger::LogLevel logLevel, const std::string& logMessage, const std::string& fileName,
	                  const std::string& method, const int line)
	{
		std::lock_guard<std::mutex> lock(LogPrinter::logPrinterMutex);

		lastLogValid = true;
		lastLog.logLevel = (int)logLevel;
		lastLog.message = logMessage;
		lastLog.filename = fileName;
		lastLog.method = method;
		lastLog.line = line;
	}

	void clean()
	{
		std::lock_guard<std::mutex> lock(logPrinterMutex);
		lastLogValid = false;
	}

	LogInfo const* getLastLog() const
	{
		if (lastLogValid)
		{
			return &lastLog;
		}
		return nullptr;
	}

private:
	bool lastLogValid = false;
	LogInfo lastLog;
	std::mutex logPrinterMutex;
};

class MultiThreadLogCounter
{
public:
	// alignas(64) to avoid false sharing between threads when updating the logMessagesCount variable
	struct alignas(64) ThreadLogCounter
	{
		int logMessagesCount = 0;
	};

	std::vector<ThreadLogCounter> counters;

	MultiThreadLogCounter(size_t numThreads)
	{
		counters.resize(numThreads);
	}

	void onLogMessage(pcpp::Logger::LogLevel logLevel, const std::string& logMessage, const std::string& fileName,
	                  const std::string& method, const int line)
	{
		if (logMessage.empty())
			return;

		int threadId = logMessage.back() - '0';
		if (threadId < 0 || threadId >= counters.size())
			return;

		counters[threadId].logMessagesCount++;
	}
};

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
	}
};

void printLogThread(int threadId, int numMessages)
{
	std::random_device rd;
	std::mt19937 simpleRand(rd());
	std::uniform_int_distribution<int> dist(1, 5);
	std::ostringstream sstream;
	sstream << threadId;
	std::string threadIdAsString = sstream.str();

	for (int i = 0; i < numMessages; i++)
	{
		pcpp::invokeErrorLog(threadIdAsString);
		int sleepTime = dist(simpleRand);
		std::this_thread::sleep_for(std::chrono::milliseconds(sleepTime));
	}
}

PTF_TEST_CASE(TestLoggerMultiThread)
{
	constexpr int threadCount = 5;
	MultiThreadLogCounter logCounter(threadCount);

	// cppcheck-suppress unusedVariable
	LoggerCleaner loggerCleaner;

	std::thread threads[threadCount];

	// clang-format off
	pcpp::Logger::getInstance().setLogPrinter([&](pcpp::Logger::LogLevel logLevel, const std::string& logMessage,
	                                              const std::string& fileName, const std::string& method, const int line) {
		logCounter.onLogMessage(logLevel, logMessage, fileName, method, line);
	});
	// clang-format on

	constexpr int messagesPerThread = 1000;
	const int expectedTotalMessages = messagesPerThread * threadCount;

	for (int i = 0; i < threadCount; i++)
	{
		threads[i] = std::thread(printLogThread, i, messagesPerThread);
	}

	for (auto& thread : threads)
	{
		thread.join();
	}

	int totalLogMessages = 0;
	for (auto const& count : logCounter.counters)
	{
		// cppcheck-suppress useStlAlgorithm
		totalLogMessages += count.logMessagesCount;
	}

	PTF_ASSERT_EQUAL(totalLogMessages, expectedTotalMessages);
}  // TestLoggerMultiThread

PTF_TEST_CASE(TestLogger)
{
	using pcpp::Logger;
	using pcpp::LogLevel;
	using pcpp::LogModule;

	auto& logger = Logger::getInstance();

	LogPrinter logPrinter;

	// cppcheck-suppress unusedVariable
	LoggerCleaner loggerCleaner;

	// verify all modules are on info log level
	for (int moduleInt = 1; moduleInt < LogModule::NumOfLogModules; moduleInt++)
	{
		const LogModule moduleEnum = static_cast<LogModule>(moduleInt);

		PTF_ASSERT_EQUAL(logger.getLogLevel(moduleEnum), LogLevel::Info, enum);
		PTF_ASSERT_FALSE(logger.isDebugEnabled(moduleEnum));

		PTF_ASSERT_TRUE(logger.shouldLog(LogLevel::Error, moduleEnum));
		PTF_ASSERT_TRUE(logger.shouldLog(LogLevel::Warn, moduleEnum));
		PTF_ASSERT_TRUE(logger.shouldLog(LogLevel::Info, moduleEnum));
		PTF_ASSERT_FALSE(logger.shouldLog(LogLevel::Debug, moduleEnum));
		PTF_ASSERT_FALSE(logger.shouldLog(LogLevel::Off, moduleEnum));
	}

	// invoke debug and error logs - expect to see only the error log
	logger.setLogPrinter([&](pcpp::Logger::LogLevel logLevel, const std::string& logMessage,
	                         const std::string& fileName, const std::string& method, const int line) {
		logPrinter.onLogMessage(logLevel, logMessage, fileName, method, line);
	});

	LogPrinter::LogInfo const* lastLog;

	pcpp::invokeDebugLog();
	lastLog = logPrinter.getLastLog();
	PTF_ASSERT_NULL(lastLog);

	pcpp::invokeErrorLog();

	lastLog = logPrinter.getLastLog();
	PTF_ASSERT_NOT_NULL(lastLog);
	PTF_ASSERT_EQUAL(lastLog->logLevel, (int)LogLevel::Error);
	PTF_ASSERT_EQUAL(lastLog->message, "error log");
	PTF_ASSERT_EQUAL(getLowerCaseFileName(lastLog->filename), "loggertests.cpp");
	PTF_ASSERT_EQUAL(getMethodWithoutNamespace(lastLog->method), "invokeErrorLog");
	PTF_ASSERT_EQUAL(lastLog->line, PCPP_TEST_EXPECTED_ERROR_LOG_LINE);

	// change one module log level
	logger.setLogLevel(pcpp::PacketLogModuleArpLayer, LogLevel::Debug);
	PTF_ASSERT_EQUAL(logger.getLogLevel(pcpp::PacketLogModuleArpLayer), pcpp::LogLevel::Debug, enum);
	PTF_ASSERT_TRUE(logger.isDebugEnabled(pcpp::PacketLogModuleArpLayer));

	// invoke debug, warn and error logs - expect to see all
	pcpp::invokeDebugLog();
	lastLog = logPrinter.getLastLog();
	PTF_ASSERT_NOT_NULL(lastLog);
	PTF_ASSERT_EQUAL(lastLog->logLevel, (int)LogLevel::Debug);
	PTF_ASSERT_EQUAL(lastLog->message, "debug log");
	PTF_ASSERT_EQUAL(getLowerCaseFileName(lastLog->filename), "loggertests.cpp");
	PTF_ASSERT_EQUAL(getMethodWithoutNamespace(lastLog->method), "invokeDebugLog");
	PTF_ASSERT_EQUAL(lastLog->line, PCPP_TEST_EXPECTED_DEBUG_LOG_LINE);

	pcpp::invokeWarnLog();
	lastLog = logPrinter.getLastLog();
	PTF_ASSERT_NOT_NULL(lastLog);
	PTF_ASSERT_EQUAL(lastLog->logLevel, (int)LogLevel::Warn);
	PTF_ASSERT_EQUAL(lastLog->message, "warn log");
	PTF_ASSERT_EQUAL(getLowerCaseFileName(lastLog->filename), "loggertests.cpp");
	PTF_ASSERT_EQUAL(getMethodWithoutNamespace(lastLog->method), "invokeWarnLog");
	PTF_ASSERT_EQUAL(lastLog->line, PCPP_TEST_EXPECTED_WARN_LOG_LINE);

	pcpp::invokeErrorLog();
	lastLog = logPrinter.getLastLog();
	PTF_ASSERT_NOT_NULL(lastLog);
	PTF_ASSERT_EQUAL(lastLog->logLevel, (int)LogLevel::Error);
	PTF_ASSERT_EQUAL(lastLog->message, "error log");
	PTF_ASSERT_EQUAL(getLowerCaseFileName(lastLog->filename), "loggertests.cpp");
	PTF_ASSERT_EQUAL(getMethodWithoutNamespace(lastLog->method), "invokeErrorLog");
	PTF_ASSERT_EQUAL(lastLog->line, PCPP_TEST_EXPECTED_ERROR_LOG_LINE);

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
		PTF_ASSERT_TRUE(logger.shouldLog(LogLevel::Warn, moduleEnum));
		PTF_ASSERT_TRUE(logger.shouldLog(LogLevel::Info, moduleEnum));
		PTF_ASSERT_TRUE(logger.shouldLog(LogLevel::Debug, moduleEnum));
		PTF_ASSERT_FALSE(logger.shouldLog(LogLevel::Off, moduleEnum));
	}

	// invoke debug log - expect to see it
	pcpp::invokeDebugLog();
	lastLog = logPrinter.getLastLog();
	PTF_ASSERT_NOT_NULL(lastLog);
	PTF_ASSERT_EQUAL(lastLog->logLevel, (int)pcpp::LogLevel::Debug);
	PTF_ASSERT_EQUAL(lastLog->message, "debug log");
	PTF_ASSERT_EQUAL(getLowerCaseFileName(lastLog->filename), "loggertests.cpp");
	PTF_ASSERT_EQUAL(getMethodWithoutNamespace(lastLog->method), "invokeDebugLog");
	PTF_ASSERT_EQUAL(lastLog->line, PCPP_TEST_EXPECTED_DEBUG_LOG_LINE);

	// suppress logs
	PTF_ASSERT_TRUE(logger.logsEnabled())
	logger.suppressLogs();
	PTF_ASSERT_FALSE(logger.logsEnabled())

	// reset LogPrinter
	logPrinter.clean();

	// invoke debug and error logs - expect to see none
	pcpp::invokeDebugLog();
	pcpp::invokeErrorLog();

	lastLog = logPrinter.getLastLog();
	PTF_ASSERT_NULL(lastLog);

	// invoke another error log - expect to see it as the last error message although logs are suppressed
	pcpp::invokeErrorLog("2");
	PTF_ASSERT_EQUAL(logger.getLastError(), "error log2");

	// re-enable logs
	logger.enableLogs();
	PTF_ASSERT_TRUE(logger.logsEnabled())

	// invoke error log - expect to see it
	pcpp::invokeErrorLog();

	lastLog = logPrinter.getLastLog();
	PTF_ASSERT_NOT_NULL(lastLog);
	PTF_ASSERT_EQUAL(lastLog->logLevel, static_cast<int>(pcpp::LogLevel::Error));
	PTF_ASSERT_EQUAL(lastLog->message, "error log");
	PTF_ASSERT_EQUAL(getLowerCaseFileName(lastLog->filename), "loggertests.cpp");
	PTF_ASSERT_EQUAL(getMethodWithoutNamespace(lastLog->method), "invokeErrorLog");
	PTF_ASSERT_EQUAL(logger.getLastError(), "error log");
	PTF_ASSERT_EQUAL(lastLog->line, PCPP_TEST_EXPECTED_ERROR_LOG_LINE);

	// reset LogPrinter
	logPrinter.clean();

	// reset the log printer
	logger.resetLogPrinter();

	// disable std::cout for a bit
	std::cout.setstate(std::ios_base::failbit);

	// set debug log for a module, don't expect to see it in the custom log printer
	logger.setLogLevel(pcpp::PacketLogModuleArpLayer, pcpp::LogLevel::Debug);
	pcpp::invokeDebugLog();
	pcpp::invokeErrorLog();

	lastLog = logPrinter.getLastLog();
	PTF_ASSERT_NULL(lastLog);
}  // TestLogger
