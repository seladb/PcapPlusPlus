#define LOG_MODULE PacketLogModuleArpLayer
#include "../TestDefinition.h"
#include "Logger.h"


class LoggerCleaner
{
	public:
		~LoggerCleaner()
		{
			pcpp::Logger::getInstance().enableLogs();
			pcpp::Logger::getInstance().setAllModlesToLogLevel(pcpp::Logger::Info);
			pcpp::Logger::getInstance().resetLogPrinter();
			std::cout.clear();
		}
};


namespace pcpp
{
	void invokeDebugLog()
	{
		LOG_DEBUG("debug log");
	}

	void invokeErrorLog()
	{
		LOG_ERROR("error log");
	}

	void invokeErrorLog2()
	{
		LOG_ERROR("error log2");
	}
}


class LogPrinter
{
	public:
		static int lastLogLevelSeen;
		static std::string lastLogMessageSeen;
		static void logPrinter(pcpp::Logger::LogLevel logLevel, const std::string& logMessage, const std::string& file, const std::string& method, const int line)
		{
			LogPrinter::lastLogLevelSeen = (int)logLevel;
			LogPrinter::lastLogMessageSeen = logMessage;
		}
};

int LogPrinter::lastLogLevelSeen = 999;
std::string LogPrinter::lastLogMessageSeen = std::string();


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
	PTF_ASSERT_EQUAL(LogPrinter::lastLogMessageSeen, "");
	pcpp::invokeErrorLog();
	PTF_ASSERT_EQUAL(LogPrinter::lastLogLevelSeen, (int)pcpp::Logger::Error);
	PTF_ASSERT_EQUAL(LogPrinter::lastLogMessageSeen, "error log");

	// change one module log level
	pcpp::Logger::getInstance().setLogLevel(pcpp::PacketLogModuleArpLayer, pcpp::Logger::Debug);
	PTF_ASSERT_EQUAL(pcpp::Logger::getInstance().getLogLevel(pcpp::PacketLogModuleArpLayer), pcpp::Logger::Debug, enum);
	PTF_ASSERT_TRUE(pcpp::Logger::getInstance().isDebugEnabled(pcpp::PacketLogModuleArpLayer));

	// invoke debug and error logs - expect to see both
	pcpp::invokeDebugLog();
	PTF_ASSERT_EQUAL(LogPrinter::lastLogLevelSeen, (int)pcpp::Logger::Debug);
	PTF_ASSERT_EQUAL(LogPrinter::lastLogMessageSeen, "debug log");
	pcpp::invokeErrorLog();
	PTF_ASSERT_EQUAL(LogPrinter::lastLogLevelSeen, (int)pcpp::Logger::Error);
	PTF_ASSERT_EQUAL(LogPrinter::lastLogMessageSeen, "error log");

	// verify the last error message
	PTF_ASSERT_EQUAL(pcpp::Logger::getInstance().getLastError(), "error log");

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
	PTF_ASSERT_EQUAL(LogPrinter::lastLogMessageSeen, "debug log");

	// suppress logs
	PTF_ASSERT_TRUE(pcpp::Logger::getInstance().logsEnabled())
	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_FALSE(pcpp::Logger::getInstance().logsEnabled())

	// reset LogPrinter
	LogPrinter::lastLogLevelSeen = 999;
	LogPrinter::lastLogMessageSeen = "";

	// invoke debug and error logs - expect to see none
	pcpp::invokeDebugLog();
	pcpp::invokeErrorLog();
	PTF_ASSERT_EQUAL(LogPrinter::lastLogLevelSeen, 999);
	PTF_ASSERT_EQUAL(LogPrinter::lastLogMessageSeen, "");

	// invoke another error log - expect to see it as the last error message although logs are suppressed
	pcpp::invokeErrorLog2();
	PTF_ASSERT_EQUAL(pcpp::Logger::getInstance().getLastError(), "error log2");

	// re-enable logs
	pcpp::Logger::getInstance().enableLogs();
	PTF_ASSERT_TRUE(pcpp::Logger::getInstance().logsEnabled())

	// invoke error log - expect to see it
	pcpp::invokeErrorLog();
	PTF_ASSERT_EQUAL(LogPrinter::lastLogLevelSeen, (int)pcpp::Logger::Error);
	PTF_ASSERT_EQUAL(LogPrinter::lastLogMessageSeen, "error log");
	PTF_ASSERT_EQUAL(pcpp::Logger::getInstance().getLastError(), "error log");

	// reset LogPrinter
	LogPrinter::lastLogLevelSeen = 999;
	LogPrinter::lastLogMessageSeen = "";

	// reset the log printer
	pcpp::Logger::getInstance().resetLogPrinter();
	
	// disable std::cout for a bit
	std::cout.setstate(std::ios_base::failbit);

	// set debug log for a module, don't expect to see it in the custom log printer
	pcpp::Logger::getInstance().setLogLevel(pcpp::PacketLogModuleArpLayer, pcpp::Logger::Debug);
	pcpp::invokeDebugLog();
	pcpp::invokeErrorLog();
	PTF_ASSERT_EQUAL(LogPrinter::lastLogLevelSeen, 999);
	PTF_ASSERT_EQUAL(LogPrinter::lastLogMessageSeen, "");

	// re-enable std::cout
	std::cout.clear();
} // TestLogger