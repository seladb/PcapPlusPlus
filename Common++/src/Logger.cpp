#include <sstream>
#include "Logger.h"

namespace pcpp
{

LoggerPP::LoggerPP() : m_LogsEnabled(true), m_LogPrinter(&defaultLogPrinter)
{
	for (int i = 0; i<NumOfLogModules; i++)
		m_LogModulesArray[i] = Info;
}

std::string LoggerPP::logLevelAsString(LogLevel logLevel)
{
	switch (logLevel)
	{
	case LoggerPP::Error:
		return "ERROR";
	case LoggerPP::Info:
		return "INFO";
	default:
		return "DEBUG";
	}
}

void LoggerPP::defaultLogPrinter(LogLevel logLevel, const std::string& logMessage, const std::string& file, const std::string& method, const int line)
{
	std::ostringstream sstream;
	sstream << file << ": " << method << ":" << line;
	std::cout << std::left
		<< "["
		<< std::setw(5) << LoggerPP::logLevelAsString(logLevel) << ": "
		<< std::setw(45) << sstream.str()
		<< "] "
		<< logMessage << std::endl;
}

} // namespace pcpp
