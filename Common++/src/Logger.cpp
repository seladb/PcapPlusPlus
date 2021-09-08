#include <sstream>
#include "Logger.h"

namespace pcpp
{

Logger::Logger() : m_LogsEnabled(true), m_LogPrinter(&defaultLogPrinter)
{
	for (int i = 0; i<NumOfLogModules; i++)
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

void Logger::defaultLogPrinter(LogLevel logLevel, const std::string& logMessage, const std::string& file, const std::string& method, const int line)
{
	std::ostringstream sstream;
	sstream << file << ": " << method << ":" << line;
	std::cout << std::left
		<< "["
		<< std::setw(5) << Logger::logLevelAsString(logLevel) << ": "
		<< std::setw(45) << sstream.str()
		<< "] "
		<< logMessage << std::endl;
}

} // namespace pcpp
