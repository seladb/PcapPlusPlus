#include "Logger.h"

namespace pcpp
{

LoggerPP::LoggerPP() : m_ErrorString(NULL), m_ErrorStringLen(0), m_SuppressErrors(false)
{
	for (int i = 0; i<NumOfLogModules; i++)
		m_LogModulesArray[i] = Normal;
}
} // namespace pcpp
