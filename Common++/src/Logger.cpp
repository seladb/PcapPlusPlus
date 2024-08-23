#include <sstream>
#include "Logger.h"

namespace pcpp
{

	Logger::Logger() : m_LogsEnabled(true), m_LogPrinter(&defaultLogPrinter)
	{
		m_LastError.reserve(200);
		for (int i = 0; i < NumOfLogModules; i++)
			m_LogModulesArray[i] = Info;
	}

	std::string Logger::logLevelAsString(LogLevel logLevel)
	{
		switch (logLevel)
		{
		case Logger::Error:
			return "ERROR";
		case Logger::Info:
			return "INFO";
		default:
			return "DEBUG";
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

	std::ostringstream* Logger::internalCreateLogStream()
	{
		return new std::ostringstream();
	}

	void Logger::internalPrintLogMessage(std::ostringstream* logStream, Logger::LogLevel logLevel, const char* file,
	                                     const char* method, int line)
	{
		std::string logMessage = logStream->str();
		delete logStream;
		if (logLevel == Logger::Error)
		{
			m_LastError = logMessage;
		}
		if (m_LogsEnabled)
		{
			m_LogPrinter(logLevel, logMessage, file, method, line);
		}
	}

}  // namespace pcpp
