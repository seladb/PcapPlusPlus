#include <algorithm>
#include <cstring>
#include <sstream>
#include "Logger.h"

namespace pcpp
{
	
	// Alpine Linux incorrectly declares strerror_r
	// https://stackoverflow.com/questions/41953104/strerror-r-is-incorrectly-declared-on-alpine-linux
	char *checkError(int /*unused*/, char *buffer, int /*unused*/) { return buffer; }
	char *checkError(char *result, const char * /*unused*/, int /*unused*/) { return result; }

	std::string getErrnoString(int errnum)
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
		std::fill(m_LogModulesArray, m_LogModulesArray + NumOfLogModules, Info);
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
		          << sstream.str() << "] " << logMessage << '\n';
	}

	std::ostringstream* Logger::internalCreateLogStream()
	{
		return new std::ostringstream();
	}

	void Logger::internalPrintLogMessage(std::ostringstream* logStream, Logger::LogLevel logLevel, const char* file,
	                                     const char* method, int line)
	{
		const std::string logMessage = logStream->str();
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
