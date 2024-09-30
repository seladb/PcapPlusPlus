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
		case LogLevel::Error:
			return "ERROR";
		case LogLevel::Info:
			return "INFO";
		default:
			return "DEBUG";
		}
	}

	void Logger::printLogMessage(LogSource source, LogLevel logLevel, std::string const& message)
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

	void Logger::defaultLogPrinter(LogLevel logLevel, const std::string& logMessage, const std::string& file,
	                               const std::string& method, const int line)
	{
		std::ostringstream sstream;
		sstream << file << ": " << method << ":" << line;
		std::cerr << std::left << "[" << std::setw(5) << Logger::logLevelAsString(logLevel) << ": " << std::setw(45)
		          << sstream.str() << "] " << logMessage << std::endl;
	}
}  // namespace pcpp
