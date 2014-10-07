#ifndef COMMONPP_LOGGER
#define COMMONPP_LOGGER

#include <stdio.h>
#include <stdint.h>

#ifndef LOG_MODULE
#define LOG_MODULE UndefinedLogModule
#endif

enum LogModule
{
	UndefinedLogModule,
	CommonLogModuleIpUtils,
	PacketLogModuleUndefined,
	PacketLogModuleIpUtils,
	PacketLogModuleRawPacket,
	PacketLogModulePacket,
	PacketLogModuleLayer,
	PacketLogModuleArpLayer,
	PacketLogModuleEthLayer,
	PacketLogModuleIPv4Layer,
	PacketLogModuleIPv6Layer,
	PacketLogModulePayloadLayer,
	PacketLogModuleTcpLayer,
	PacketLogModuleUdpLayer,
	PacketLogModuleVlanLayer,
	PacketLogModuleNumOfModules,
	PcapLogModuleWinPcapLiveDevice,
	PcapLogModuleRemoteDevice,
	PcapLogModuleLiveDevice,
	PcapLogModuleFileDevice,
	NumOfLogModules
};

class LoggerPP
{
public:
	enum LogLevel
	{
		Normal,
		Debug
	};

	void setLogLevel(LogModule module, LogLevel level) { m_LogModulesArray[module] = level; }
	void setAllModlesToLogLevel(LogLevel level) { for (int i=1; i<NumOfLogModules; i++) m_LogModulesArray[i] = level; }
	inline bool isDebugEnabled(LogModule module) { return m_LogModulesArray[module] == Debug; }
	inline LogLevel* getLogModulesArr() { return m_LogModulesArray; }

	inline bool isErrorStringSet() { return m_ErrorString != NULL; }
	inline char* getErrorString() { return m_ErrorString; }
	void setErrorString(char* errString, int len) { m_ErrorString = errString; m_ErrorStringLen = len; }
	inline int getErrorStringLength() { return m_ErrorStringLen; }

	void supressErrors() { m_SuppressErrors = true; }
	void enableErrors() { m_SuppressErrors = false; }
	inline bool isSupressErrors() { return m_SuppressErrors; }

	//TODO: make this singleton thread-safe
	static inline LoggerPP& getInstance()
	{
		static LoggerPP instance;
		return instance;
	}
private:
	char* m_ErrorString;
	int m_ErrorStringLen;
	bool m_SuppressErrors;
	LoggerPP::LogLevel m_LogModulesArray[NumOfLogModules];
	LoggerPP();
};

#define LOG_DEBUG(format, ...) do { \
		if(LoggerPP::getInstance().isDebugEnabled(LOG_MODULE)) { \
			printf("[%-35s: %-25s: line:%-4d] " format "\n", __FILE__, __FUNCTION__, __LINE__, ## __VA_ARGS__); \
		} \
} while(0)

#define LOG_ERROR(format, ...) do { \
		if (!LoggerPP::getInstance().isSupressErrors()) {\
			if(LoggerPP::getInstance().isErrorStringSet()) \
				snprintf(LoggerPP::getInstance().getErrorString(), LoggerPP::getInstance().getErrorStringLength(), format "\n", ## __VA_ARGS__); \
			else \
				fprintf(stderr, format "\n", ## __VA_ARGS__); \
		} \
    } while (0)

#endif /* COMMONPP_LOGGER */
