#include "pch.h"

#include <string>

#include "Logger.h"

namespace pcpp
{
	constexpr char getPathSeparator()
	{
#ifdef _WIN32
		return '\\';
#else
		return '/';
#endif  // _WIN32
	}

	class LogCallbackMock
	{
	public:
		MOCK_METHOD(void, call,
		            (pcpp::Logger::LogLevel logLevel, const std::string& logMessage, const std::string& fileName,
		             const std::string& method, const int line),
		            (const));

		// Redirects the call to the mock method
		void operator()(pcpp::Logger::LogLevel logLevel, const std::string& logMessage, const std::string& fileName,
		                const std::string& method, const int line) const
		{
			call(logLevel, logMessage, fileName, method, line);
		}
	};

	class LoggerTest : public ::testing::Test
	{
		using Base = ::testing::Test;

	public:
		LoggerTest() : m_Logger(Logger::getInstance())
		{}

		void SetUp() override
		{
			Base::SetUp();

			// Setup log callback trampoline
			m_Logger.setLogPrinter(&LoggerTest::logPrinterTrampoline);

			// Enable all logs and set them to Info level by default
			m_Logger.enableLogs();
			m_Logger.setAllModulesToLogLevel(Logger::Info);

			// Setup log callback mock
			m_LogCallbackMock = std::unique_ptr<LogCallbackMock>(new LogCallbackMock());
		}

		void TearDown() override
		{
			// Reset log callback trampoline
			m_Logger.enableLogs();
			m_Logger.setAllModulesToLogLevel(Logger::Info);
			m_Logger.resetLogPrinter();

			// Reset log callback mock
			m_LogCallbackMock.reset();

			Base::TearDown();
		}

	protected:
// Spoofing the log module for testing purposes
#pragma push_macro("LOG_MODULE")
#undef LOG_MODULE
#define LOG_MODULE ::pcpp::LogModule::PacketLogModuleArpLayer

		void invokeDebugLog(std::string const& msg)
		{
			PCPP_LOG_DEBUG(msg);
		}

		void invokeErrorLog(std::string const& msg)
		{
			PCPP_LOG_ERROR(msg);
		}

		static const LogModule SpoofedLogModule = LOG_MODULE;

#pragma pop_macro("LOG_MODULE")

		static void logPrinterTrampoline(Logger::LogLevel logLevel, const std::string& logMessage,
		                                 const std::string& fileName, const std::string& method, const int line)
		{
			if (m_LogCallbackMock != nullptr)
			{
				// Dereference the pointer and call the mock with the parameters.
				(*m_LogCallbackMock)(logLevel, logMessage, fileName, method, line);
			}
			else
			{
				throw std::runtime_error("Log Trampoline Error: Log callback not set");
			}
		}

		static std::unique_ptr<LogCallbackMock> m_LogCallbackMock;
		Logger& m_Logger;
	};

	std::unique_ptr<LogCallbackMock> LoggerTest::m_LogCallbackMock = nullptr;

	TEST_F(LoggerTest, LogLevelAsString)
	{
		EXPECT_EQ(Logger::logLevelAsString(Logger::Error), "ERROR");
		EXPECT_EQ(Logger::logLevelAsString(Logger::Info), "INFO");
		EXPECT_EQ(Logger::logLevelAsString(Logger::Debug), "DEBUG");
	}

	TEST_F(LoggerTest, GetSetLogLevel)
	{
		EXPECT_EQ(m_Logger.getLogLevel(SpoofedLogModule), Logger::Info)
		    << "Initial setup should have initialized all modules to Info";

		m_Logger.setLogLevel(SpoofedLogModule, Logger::Debug);
		EXPECT_EQ(m_Logger.getLogLevel(SpoofedLogModule), Logger::Debug);
		EXPECT_TRUE(m_Logger.isDebugEnabled(SpoofedLogModule));
	}

	TEST_F(LoggerTest, SetAllModulesMethod)
	{
		for (int module = 1; module < NumOfLogModules; module++)
		{
			ASSERT_EQ(m_Logger.getLogLevel(static_cast<LogModule>(module)), Logger::Info);
		}

		m_Logger.setAllModulesToLogLevel(Logger::Debug);

		for (int module = 1; module < NumOfLogModules; module++)
		{
			EXPECT_EQ(m_Logger.getLogLevel(static_cast<LogModule>(module)), Logger::Debug);
		}
	}

	TEST_F(LoggerTest, LogError)
	{
		using testing::_;

		ASSERT_EQ(m_Logger.getLogLevel(SpoofedLogModule), Logger::Info)
		    << "Initial setup should have initialized all modules to Info";

		// Expect a call to the log callback mock
		EXPECT_CALL(*m_LogCallbackMock,
		            call(Logger::Error, "Error Log Message", _ /* Filename */, _ /* method */, _ /* line number */))
		    .Times(1);

		invokeErrorLog("Error Log Message");
	}

	TEST_F(LoggerTest, LogDebug)
	{
		using testing::_;

		m_Logger.setLogLevel(SpoofedLogModule, Logger::Debug);
		ASSERT_EQ(m_Logger.getLogLevel(SpoofedLogModule), Logger::Debug);

		// Expect a call to the log callback mock
		EXPECT_CALL(*m_LogCallbackMock,
		            call(Logger::Debug, "Debug Log Message", _ /* Filename */, _ /* method */, _ /* line number */))
		    .Times(1);

		invokeDebugLog("Debug Log Message");
	}

	TEST_F(LoggerTest, GlobalLogSuppression)
	{
		using testing::_;

		m_Logger.suppressLogs();
		EXPECT_FALSE(m_Logger.logsEnabled());

		// Expect no calls to the log callback mock
		EXPECT_CALL(*m_LogCallbackMock, call(Logger::Debug, "Global Log Suppression Error", _ /* Filename */,
		                                     _ /* method */, _ /* line number */))
		    .Times(0);

		invokeErrorLog("Global Log Suppression Error");

		// Verifies that all expectations on the mock have been met and clears them.
		::testing::Mock::VerifyAndClearExpectations(m_LogCallbackMock.get());

		m_Logger.enableLogs();
		EXPECT_TRUE(m_Logger.logsEnabled());

		EXPECT_CALL(*m_LogCallbackMock, call(Logger::Error, "Global Log Suppression Error", _ /* Filename */,
		                                     _ /* method */, _ /* line number */))
		    .Times(1);

		invokeErrorLog("Global Log Suppression Error");
	}

	TEST_F(LoggerTest, ModuleLevelLogSuppression)
	{
		using ::testing::_;

		m_Logger.setLogLevel(SpoofedLogModule, Logger::Error);

		EXPECT_CALL(*m_LogCallbackMock, call(Logger::Debug, "Module Level Log Suppression Debug", _ /* Filename */,
		                                     _ /* method */, _ /* line number */))
		    .Times(0);
		EXPECT_CALL(*m_LogCallbackMock, call(Logger::Error, "Module Level Log Suppression Error", _ /* Filename */,
		                                     _ /* method */, _ /* line number */))
		    .Times(1);

		invokeDebugLog("Module Level Log Suppression Debug");
		invokeErrorLog("Module Level Log Suppression Error");

		// Verifies that all expectations on the mock have been met and clears them.
		::testing::Mock::VerifyAndClearExpectations(m_LogCallbackMock.get());

		m_Logger.setLogLevel(SpoofedLogModule, Logger::Debug);

		EXPECT_CALL(*m_LogCallbackMock, call(Logger::Debug, "Module Level Log Suppression Debug", _ /* Filename */,
		                                     _ /* method */, _ /* line number */))
		    .Times(1);
		EXPECT_CALL(*m_LogCallbackMock, call(Logger::Error, "Module Level Log Suppression Error", _ /* Filename */,
		                                     _ /* method */, _ /* line number */))
		    .Times(1);

		invokeDebugLog("Module Level Log Suppression Debug");
		invokeErrorLog("Module Level Log Suppression Error");
	}
}  // namespace pcpp
