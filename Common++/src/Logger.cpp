#include "Logger.h"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <mutex>

namespace pcpp
{

	// Alpine Linux incorrectly declares strerror_r
	// https://stackoverflow.com/questions/41953104/strerror-r-is-incorrectly-declared-on-alpine-linux
	char* checkError(int /*unused*/, char* buffer, int /*unused*/)
	{
		return buffer;
	}

	char* checkError(char* result, const char* /*unused*/, int /*unused*/)
	{
		return result;
	}

	std::string getErrorString(int errnum)
	{
		std::array<char, BUFSIZ> buffer{};
#if defined(_WIN32)
		strerror_s(buffer.data(), buffer.size(), errnum);
		return buffer.data();
#else
		return checkError(strerror_r(errnum, buffer.data(), BUFSIZ), buffer.data(), errnum);
#endif
	}

	Logger::Logger() : m_LogsEnabled(true), m_LogPrinter(&defaultLogPrinter)
	{
		m_LastError.reserve(200);
		m_LogModulesArray.fill(LogLevel::Info);
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
		if (m_UseContextPooling)
		{
			auto ctx = m_LogContextPool.acquireObject();
			ctx->init(level, source);
			return ctx;
		}
		return std::make_unique<internal::LogContext>(level, source);
	}

	void Logger::emit(std::unique_ptr<internal::LogContext> message)
	{
		emit(message->m_Source, message->m_Level, message->m_Stream.str());
		// Pushes the message back to the pool if pooling is enabled. Otherwise, the message is deleted.
		if (m_UseContextPooling)
		{
			m_LogContextPool.releaseObject(std::move(message));
		}
	}

	void Logger::emit(LogSource const& source, LogLevel logLevel, std::string const& message)
	{
		// If the log level is an error, save the error to the last error message variable.
		if (logLevel == LogLevel::Error)
		{
			std::lock_guard<std::mutex> lock(m_LastErrorMtx);
			m_LastError = message;
		}
		if (m_LogsEnabled)
		{
			m_LogPrinter(logLevel, message, source.file, source.function, source.line);
		}
	}

	void Logger::defaultLogPrinter(LogLevel logLevel, const std::string& logMessage, const std::string& file,
	                               const std::string& method, const int line)
	{
		// This mutex is used to prevent multiple threads from writing to the console at the same time.
		static std::mutex logMutex;

		std::ostringstream sstream;
		sstream << file << ": " << method << ":" << line;

		std::unique_lock<std::mutex> lock(logMutex);
		std::cerr << std::left << "[" << std::setw(5) << Logger::logLevelAsString(logLevel) << ": " << std::setw(45)
		          << sstream.str() << "] " << logMessage << std::endl;
	}
}  // namespace pcpp
