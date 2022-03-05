#define LOG_MODULE PacketLogModuleArpLayer
#include "../TestDefinition.h"
#include "Logger.h"
#include <string>
#include <algorithm>
#include <cctype>


namespace pcpp
{
	void invokeDebugLog()
	{
		PCPP_LOG_DEBUG("debug log");
	}

	void invokeErrorLog()
	{
		PCPP_LOG_ERROR("error log" << 1);
	}

	void invokeErrorLog2()
	{
		PCPP_LOG_ERROR("error log" << 2);
	}
}


class LogPrinter
{
	public:
		static int lastLogLevelSeen;
		static std::string* lastLogMessageSeen;
		static std::string* lastFilenameSeen;
		static std::string* lastMethodSeen;
		static int lastLineSeen;

		static void logPrinter(pcpp::Logger::LogLevel logLevel, const std::string& logMessage, const std::string& fileName, const std::string& method, const int line)
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
			if (LogPrinter::lastLogMessageSeen != NULL)
			{
				delete LogPrinter::lastLogMessageSeen;
				LogPrinter::lastLogMessageSeen = NULL;
			}
			if (LogPrinter::lastFilenameSeen != NULL)
			{
				delete LogPrinter::lastFilenameSeen;
				LogPrinter::lastFilenameSeen = NULL;
			}

			if (LogPrinter::lastMethodSeen != NULL)
			{
				delete LogPrinter::lastMethodSeen;
				LogPrinter::lastMethodSeen = NULL;
			}
		}
};

int LogPrinter::lastLogLevelSeen = 999;
std::string* LogPrinter::lastLogMessageSeen = NULL;
std::string* LogPrinter::lastFilenameSeen = NULL;
std::string* LogPrinter::lastMethodSeen = NULL;
int LogPrinter::lastLineSeen = 99999;


#if defined(_WIN32)
#define SEPARATOR '\\'
#else
#define SEPARATOR '/'
#endif


std::string getLFileName(const std::string& path)
{
	std::string result = path;
	// check the "/" separator
	size_t i = result.rfind('/', result.length());
	if (i != std::string::npos)
	{
		result = result.substr(i+1, result.length() - i);
	}
	// check the "\\" separator
	i = result.rfind('\\', result.length());
	if (i != std::string::npos)
	{
		result = result.substr(i+1, result.length() - i);
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
		result = result.substr(i+1, result.length() - i);
	}
	return result;
}


class LoggerCleaner
{
	public:
		~LoggerCleaner()
		{
			pcpp::Logger::getInstance().enableLogs();
			pcpp::Logger::getInstance().setAllModlesToLogLevel(pcpp::Logger::Info);
			pcpp::Logger::getInstance().resetLogPrinter();
			std::cout.clear();
			LogPrinter::clean();
		}
};


PTF_TEST_CASE(TestLogger)
{
	LoggerCleaner loggerCleaner;

	// verify all modules are on info log level
	for (int module = 1; module < pcpp::NumOfLogModules; module++)
	{
		PTF_ASSERT_EQUAL(pcpp::Logger::getInstance().getLogLevel((pcpp::LogModule)module), pcpp::Logger::Info, enum);
		PTF_ASSERT_FALSE(pcpp::Logger::getInstance().isDebugEnabled((pcpp::LogModule)module));
	}

	// invoke debug and error logs - expect to see only the error log
	pcpp::Logger::getInstance().setLogPrinter(&LogPrinter::logPrinter);
	pcpp::invokeDebugLog();
	PTF_ASSERT_EQUAL(LogPrinter::lastLogLevelSeen, 999);
	PTF_ASSERT_EQUAL(LogPrinter::lastLineSeen, 99999);
	PTF_ASSERT_NULL(LogPrinter::lastLogMessageSeen);
	PTF_ASSERT_NULL(LogPrinter::lastFilenameSeen);
	PTF_ASSERT_NULL(LogPrinter::lastMethodSeen);
	pcpp::invokeErrorLog();
	PTF_ASSERT_EQUAL(LogPrinter::lastLogLevelSeen, (int)pcpp::Logger::Error);
	PTF_ASSERT_EQUAL(*LogPrinter::lastLogMessageSeen, "error log1");
	PTF_ASSERT_EQUAL(getLowerCaseFileName(*LogPrinter::lastFilenameSeen), "loggertests.cpp");
	PTF_ASSERT_EQUAL(getMethodWithoutNamespace(*LogPrinter::lastMethodSeen), "invokeErrorLog");
	PTF_ASSERT_EQUAL(LogPrinter::lastLineSeen, 18);

	// change one module log level
	pcpp::Logger::getInstance().setLogLevel(pcpp::PacketLogModuleArpLayer, pcpp::Logger::Debug);
	PTF_ASSERT_EQUAL(pcpp::Logger::getInstance().getLogLevel(pcpp::PacketLogModuleArpLayer), pcpp::Logger::Debug, enum);
	PTF_ASSERT_TRUE(pcpp::Logger::getInstance().isDebugEnabled(pcpp::PacketLogModuleArpLayer));

	// invoke debug and error logs - expect to see both
	pcpp::invokeDebugLog();
	PTF_ASSERT_EQUAL(LogPrinter::lastLogLevelSeen, (int)pcpp::Logger::Debug);
	PTF_ASSERT_EQUAL(*LogPrinter::lastLogMessageSeen, "debug log");
	PTF_ASSERT_EQUAL(getLowerCaseFileName(*LogPrinter::lastFilenameSeen), "loggertests.cpp");
	PTF_ASSERT_EQUAL(getMethodWithoutNamespace(*LogPrinter::lastMethodSeen), "invokeDebugLog");
	PTF_ASSERT_EQUAL(LogPrinter::lastLineSeen, 13);

	pcpp::invokeErrorLog();
	PTF_ASSERT_EQUAL(LogPrinter::lastLogLevelSeen, (int)pcpp::Logger::Error);
	PTF_ASSERT_EQUAL(*LogPrinter::lastLogMessageSeen, "error log1");
	PTF_ASSERT_EQUAL(getLowerCaseFileName(*LogPrinter::lastFilenameSeen), "loggertests.cpp");
	PTF_ASSERT_EQUAL(getMethodWithoutNamespace(*LogPrinter::lastMethodSeen), "invokeErrorLog");
	PTF_ASSERT_EQUAL(LogPrinter::lastLineSeen, 18);

	// verify the last error message
	PTF_ASSERT_EQUAL(pcpp::Logger::getInstance().getLastError(), "error log1");

	// change all modules log level
	pcpp::Logger::getInstance().setAllModlesToLogLevel(pcpp::Logger::Debug);
	for (int module = 1; module < pcpp::NumOfLogModules; module++)
	{
		PTF_ASSERT_EQUAL(pcpp::Logger::getInstance().getLogLevel((pcpp::LogModule)module), pcpp::Logger::Debug, enum);
		PTF_ASSERT_TRUE(pcpp::Logger::getInstance().isDebugEnabled((pcpp::LogModule)module));
	}

	// invoke debug log - expect to see it
	pcpp::invokeDebugLog();
	PTF_ASSERT_EQUAL(LogPrinter::lastLogLevelSeen, (int)pcpp::Logger::Debug);
	PTF_ASSERT_EQUAL(*LogPrinter::lastLogMessageSeen, "debug log");
	PTF_ASSERT_EQUAL(getLowerCaseFileName(*LogPrinter::lastFilenameSeen), "loggertests.cpp");
	PTF_ASSERT_EQUAL(getMethodWithoutNamespace(*LogPrinter::lastMethodSeen), "invokeDebugLog");
	PTF_ASSERT_EQUAL(LogPrinter::lastLineSeen, 13);

	// suppress logs
	PTF_ASSERT_TRUE(pcpp::Logger::getInstance().logsEnabled())
	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_FALSE(pcpp::Logger::getInstance().logsEnabled())

	// reset LogPrinter
	LogPrinter::clean();

	// invoke debug and error logs - expect to see none
	pcpp::invokeDebugLog();
	pcpp::invokeErrorLog();
	PTF_ASSERT_EQUAL(LogPrinter::lastLogLevelSeen, 999);
	PTF_ASSERT_NULL(LogPrinter::lastLogMessageSeen);

	// invoke another error log - expect to see it as the last error message although logs are suppressed
	pcpp::invokeErrorLog2();
	PTF_ASSERT_EQUAL(pcpp::Logger::getInstance().getLastError(), "error log2");

	// re-enable logs
	pcpp::Logger::getInstance().enableLogs();
	PTF_ASSERT_TRUE(pcpp::Logger::getInstance().logsEnabled())

	// invoke error log - expect to see it
	pcpp::invokeErrorLog();
	PTF_ASSERT_EQUAL(LogPrinter::lastLogLevelSeen, (int)pcpp::Logger::Error);
	PTF_ASSERT_EQUAL(*LogPrinter::lastLogMessageSeen, "error log1");
	PTF_ASSERT_EQUAL(getLowerCaseFileName(*LogPrinter::lastFilenameSeen), "loggertests.cpp");
	PTF_ASSERT_EQUAL(getMethodWithoutNamespace(*LogPrinter::lastMethodSeen), "invokeErrorLog");
	PTF_ASSERT_EQUAL(pcpp::Logger::getInstance().getLastError(), "error log1");
	PTF_ASSERT_EQUAL(LogPrinter::lastLineSeen, 18);

	// reset LogPrinter
	LogPrinter::clean();

	// reset the log printer
	pcpp::Logger::getInstance().resetLogPrinter();

	// disable std::cout for a bit
	std::cout.setstate(std::ios_base::failbit);

	// set debug log for a module, don't expect to see it in the custom log printer
	pcpp::Logger::getInstance().setLogLevel(pcpp::PacketLogModuleArpLayer, pcpp::Logger::Debug);
	pcpp::invokeDebugLog();
	pcpp::invokeErrorLog();
	PTF_ASSERT_EQUAL(LogPrinter::lastLogLevelSeen, 999);
	PTF_ASSERT_NULL(LogPrinter::lastLogMessageSeen);
} // TestLogger
