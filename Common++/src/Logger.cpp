#include <stdexcept>
#include <sstream>
#include "Logger.h"

namespace pcpp
{
	Logger::Logger() : m_LogsEnabled(true), m_LogPrinter(&defaultLogPrinter)
	{
		m_LastError.reserve(200);
		for (int i = 0; i < NumOfLogModules; i++)
			m_LogModulesArray[i] = LogLevel::Info;
	}

	std::string Logger::logLevelAsString(LogLevel logLevel)
	{
		switch (logLevel)
		{
		case LogLevel::Off:
			return "OFF";
		case LogLevel::Error:
			return "ERROR";
		case LogLevel::Info:
			return "INFO";
		case LogLevel::Debug:
			return "DEBUG";
		default:
			return "UNKNOWN";
		}
	}

	std::unique_ptr<internal::LogContext> Logger::createLogContext()
	{
		return createLogContext(LogLevel::Info, {});  // call the other createLogContext method
	}
	std::unique_ptr<internal::LogContext> Logger::createLogContext(LogLevel level, LogSource const& source)
	{
#ifdef PCPP_LOG_USE_OBJECT_POOL
		auto ctx = m_LogContextPool.acquireObject();
		ctx->init(level, source);
		return ctx;
#else
		return std::unique_ptr<internal::LogContext>(new internal::LogContext(level, source));
#endif  // PCPP_LOG_USE_OBJECT_POOL
	}

	void Logger::emit(std::unique_ptr<internal::LogContext> message)
	{
		emit(message->m_Source, message->level, message->m_Stream.str());
#ifdef PCPP_LOG_USE_OBJECT_POOL
		m_LogContextPool.releaseObject(std::move(message));
#endif  // PCPP_LOG_USE_OBJECT_POOL
	}

	void Logger::emit(LogSource const& source, LogLevel logLevel, std::string const& message)
	{
		if (logLevel == LogLevel::Error)
		{
			m_LastError = message;
		}
		if (m_LogsEnabled)
		{
			m_LogPrinter(logLevel, message, source.file, source.function, source.line);
		}
	}

	void Logger::log(std::unique_ptr<internal::LogContext> message)
	{
		if (shouldLog(message->level, message->m_Source.logModule))
		{
			emit(std::move(message));
		}
	}

	void Logger::defaultLogPrinter(LogLevel logLevel, const std::string& logMessage, const std::string& file,
	                               const std::string& method, const int line)
	{
		std::ostringstream sstream;
		sstream << file << ": " << method << ":" << line;
		std::cerr << std::left << "[" << std::setw(5) << Logger::logLevelAsString(logLevel) << ": " << std::setw(45)
		          << sstream.str() << "] " << logMessage << std::endl;
	}
}  // namespace pcpp
