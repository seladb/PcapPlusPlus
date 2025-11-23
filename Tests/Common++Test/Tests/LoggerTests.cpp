#include "pch.h"

#include <string>
#include <functional>
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
		            (pcpp::LogLevel logLevel, const std::string& logMessage, const std::string& fileName,
		             const std::string& method, const int line),
		            (const));

		// Redirects the call to the mock method
		void operator()(pcpp::LogLevel logLevel, const std::string& logMessage, const std::string& fileName,
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

			// Setup log callback mock
			m_LogCallbackMock = std::make_unique<LogCallbackMock>();

			// Setup log callback to the mock
			m_Logger.setLogPrinter(std::cref(*m_LogCallbackMock));

			// Enable all logs and set them to Info level by default
			m_Logger.enableLogs();
			m_Logger.setAllModulesToLogLevel(LogLevel::Info);
		}

		void TearDown() override
		{
			// Reset log callback
			m_Logger.enableLogs();
			m_Logger.setAllModulesToLogLevel(LogLevel::Info);
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

		Logger& m_Logger;
		std::unique_ptr<LogCallbackMock> m_LogCallbackMock;
	};

	TEST_F(LoggerTest, LogLevelAsString)
	{
		EXPECT_EQ(Logger::logLevelAsString(LogLevel::Error), "ERROR");
		EXPECT_EQ(Logger::logLevelAsString(LogLevel::Info), "INFO");
		EXPECT_EQ(Logger::logLevelAsString(LogLevel::Debug), "DEBUG");
	}

	TEST_F(LoggerTest, GetSetLogLevel)
	{
		EXPECT_EQ(m_Logger.getLogLevel(SpoofedLogModule), LogLevel::Info)
		    << "Initial setup should have initialized all modules to Info";

		m_Logger.setLogLevel(SpoofedLogModule, Logger::Debug);
		EXPECT_EQ(m_Logger.getLogLevel(SpoofedLogModule), LogLevel::Debug);
		EXPECT_TRUE(m_Logger.isDebugEnabled(SpoofedLogModule));
	}

	TEST_F(LoggerTest, SetAllModulesMethod)
	{
		for (int module = 1; module < NumOfLogModules; module++)
		{
			ASSERT_EQ(m_Logger.getLogLevel(static_cast<LogModule>(module)), LogLevel::Info);
		}

		m_Logger.setAllModulesToLogLevel(LogLevel::Debug);

		for (int module = 1; module < NumOfLogModules; module++)
		{
			EXPECT_EQ(m_Logger.getLogLevel(static_cast<LogModule>(module)), LogLevel::Debug);
		}
	}

	TEST_F(LoggerTest, LogError)
	{
		using testing::_;

		ASSERT_EQ(m_Logger.getLogLevel(SpoofedLogModule), LogLevel::Info)
		    << "Initial setup should have initialized all modules to Info";

		// Expect a call to the log callback mock
		EXPECT_CALL(*m_LogCallbackMock,
		            call(LogLevel::Error, "Error Log Message", _ /* Filename */, _ /* method */, _ /* line number */))
		    .Times(1);

		invokeErrorLog("Error Log Message");
	}

	TEST_F(LoggerTest, LogDebug)
	{
		using testing::_;

		m_Logger.setLogLevel(SpoofedLogModule, LogLevel::Debug);
		ASSERT_EQ(m_Logger.getLogLevel(SpoofedLogModule), LogLevel::Debug);

		// Expect a call to the log callback mock
		EXPECT_CALL(*m_LogCallbackMock,
		            call(LogLevel::Debug, "Debug Log Message", _ /* Filename */, _ /* method */, _ /* line number */))
		    .Times(1);

		invokeDebugLog("Debug Log Message");
	}

	TEST_F(LoggerTest, GlobalLogSuppression)
	{
		using testing::_;

		m_Logger.suppressLogs();
		EXPECT_FALSE(m_Logger.logsEnabled());

		// Expect no calls to the log callback mock
		EXPECT_CALL(*m_LogCallbackMock, call(LogLevel::Debug, "Global Log Suppression Error", _ /* Filename */,
		                                     _ /* method */, _ /* line number */))
		    .Times(0);

		invokeErrorLog("Global Log Suppression Error");

		// Verifies that all expectations on the mock have been met and clears them.
		::testing::Mock::VerifyAndClearExpectations(m_LogCallbackMock.get());

		m_Logger.enableLogs();
		EXPECT_TRUE(m_Logger.logsEnabled());

		EXPECT_CALL(*m_LogCallbackMock, call(LogLevel::Error, "Global Log Suppression Error", _ /* Filename */,
		                                     _ /* method */, _ /* line number */))
		    .Times(1);

		invokeErrorLog("Global Log Suppression Error");
	}

	TEST_F(LoggerTest, ModuleLevelLogSuppression)
	{
		using ::testing::_;

		m_Logger.setLogLevel(SpoofedLogModule, LogLevel::Error);

		EXPECT_CALL(*m_LogCallbackMock, call(LogLevel::Debug, "Module Level Log Suppression Debug", _ /* Filename */,
		                                     _ /* method */, _ /* line number */))
		    .Times(0);
		EXPECT_CALL(*m_LogCallbackMock, call(LogLevel::Error, "Module Level Log Suppression Error", _ /* Filename */,
		                                     _ /* method */, _ /* line number */))
		    .Times(1);

		invokeDebugLog("Module Level Log Suppression Debug");
		invokeErrorLog("Module Level Log Suppression Error");

		// Verifies that all expectations on the mock have been met and clears them.
		::testing::Mock::VerifyAndClearExpectations(m_LogCallbackMock.get());

		m_Logger.setLogLevel(SpoofedLogModule, LogLevel::Debug);

		EXPECT_CALL(*m_LogCallbackMock, call(LogLevel::Debug, "Module Level Log Suppression Debug", _ /* Filename */,
		                                     _ /* method */, _ /* line number */))
		    .Times(1);
		EXPECT_CALL(*m_LogCallbackMock, call(LogLevel::Error, "Module Level Log Suppression Error", _ /* Filename */,
		                                     _ /* method */, _ /* line number */))
		    .Times(1);

		invokeDebugLog("Module Level Log Suppression Debug");
		invokeErrorLog("Module Level Log Suppression Error");
	}
}  // namespace pcpp
