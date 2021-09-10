#ifndef PCAPPP_LOGGER
#define PCAPPP_LOGGER

#include <stdio.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <stdint.h>

#ifndef LOG_MODULE
#define LOG_MODULE UndefinedLogModule
#endif

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * An enum representing all PcapPlusPlus modules
	 */
	enum LogModule
	{
		UndefinedLogModule,
		CommonLogModuleIpUtils, ///< IP Utils module (Common++)
		CommonLogModuleTablePrinter, ///< Table printer module (Common++)
		CommonLogModuleGenericUtils, ///< Generic Utils (Common++)
		PacketLogModuleRawPacket, ///< RawPacket module (Packet++)
		PacketLogModulePacket, ///< Packet module (Packet++)
		PacketLogModuleLayer, ///< Layer module (Packet++)
		PacketLogModuleArpLayer, ///< ArpLayer module (Packet++)
		PacketLogModuleEthLayer, ///< EthLayer module (Packet++)
		PacketLogModuleIPv4Layer, ///< IPv4Layer module (Packet++)
		PacketLogModuleIPv6Layer, ///< IPv6Layer module (Packet++)
		PacketLogModulePayloadLayer, ///< PayloadLayer module (Packet++)
		PacketLogModuleTcpLayer, ///< TcpLayer module (Packet++)
		PacketLogModuleUdpLayer, ///< UdpLayer module (Packet++)
		PacketLogModuleVlanLayer, ///< VlanLayer module (Packet++)
		PacketLogModuleHttpLayer, ///< HttpLayer module (Packet++)
		PacketLogModulePPPoELayer, ///< PPPoELayer module (Packet++)
		PacketLogModuleDnsLayer, ///< DnsLayer module (Packet++)
		PacketLogModuleMplsLayer, ///< MplsLayer module (Packet++)
		PacketLogModuleIcmpLayer, ///< IcmpLayer module (Packet++)
		PacketLogModuleGreLayer, ///< GreLayer module (Packet++)
		PacketLogModuleSSLLayer, ///< SSLLayer module (Packet++)
		PacketLogModuleSllLayer, ///< SllLayer module (Packet++)
		PacketLogModuleDhcpLayer, ///< DhcpLayer module (Packet++)
		PacketLogModuleIgmpLayer, ///< IgmpLayer module (Packet++)
		PacketLogModuleSipLayer, ///< SipLayer module (Packet++)
		PacketLogModuleSdpLayer, ///< SdpLayer module (Packet++)
		PacketLogModuleRadiusLayer, ///< RadiusLayer module (Packet++)
		PacketLogModuleGtpLayer, ///< GtpLayer module (Packet++)
		PacketLogModuleBgpLayer, ///< GtpLayer module (Packet++)
		PacketLogModuleSSHLayer, ///< SSHLayer module (Packet++)
		PacketLogModuleTcpReassembly, ///< TcpReassembly module (Packet++)
		PacketLogModuleIPReassembly, ///< IPReassembly module (Packet++)
		PacketLogModuleIPSecLayer, ///< IPSecLayers module (Packet++)
		PcapLogModuleWinPcapLiveDevice, ///< WinPcapLiveDevice module (Pcap++)
		PcapLogModuleRemoteDevice, ///< WinPcapRemoteDevice module (Pcap++)
		PcapLogModuleLiveDevice, ///< PcapLiveDevice module (Pcap++)
		PcapLogModuleFileDevice, ///< FileDevice module (Pcap++)
		PcapLogModulePfRingDevice, ///< PfRingDevice module (Pcap++)
		PcapLogModuleMBufRawPacket, ///< MBufRawPacket module (Pcap++)
		PcapLogModuleDpdkDevice, ///< DpdkDevice module (Pcap++)
		PcapLogModuleKniDevice, ///< KniDevice module (Pcap++)
		NetworkUtils, ///< NetworkUtils module (Pcap++)
		NumOfLogModules
	};

	/**
	 * @class Logger
	 * The PcapPlusPlus log manager class.
	 * PcapPlusPlus uses this logger to output both error and debug logs.
	 *
	 * Debug logs: PcapPlusPlus is divided into modules (described in LogModule enum). The user can set each module or all modules to output or suppress debug messages. The default is suppressing debug messages.
	 * Changing debug log level for modules can be done dynamically while application is running.
	 *
	 * Error logs: errors are printed by default to stderr. The user can change this behavior in several manners:
	 * 1. Suppress errors - no errors will be printed (for all modules)
	 * 2. Print error logs to a string provided by the user instead of stderr
	 *
	 * PcapPlusPlus logger is a singleton which can be reached from anywhere in the code *
	 */
	class Logger
	{
	public:

		/**
		 * An enum representing the log level. Currently 3 log levels are supported: Error, Info and Debug. Info is the default log level
		 */
		enum LogLevel
		{
			Error, ///< Error log level
			Info, ///< Info log level
			Debug ///< Debug log level
		};

		typedef void (*LogPrinter)(LogLevel logLevel, const std::string& logMessage, const std::string& file, const std::string& method, const int line);

		static std::string logLevelAsString(LogLevel logLevel);

		/**
		 * Set the log level for a certain PcapPlusPlus module
		 * @param[in] module PcapPlusPlus module
		 * @param[in] level The log level to set the module to
		 */
		void setLogLevel(LogModule module, LogLevel level) { m_LogModulesArray[module] = level; }

		/**
		 * Set all PcapPlusPlus modules to a certain log level
		 * @param[in] level The log level to set all modules to
		 */
		void setAllModlesToLogLevel(LogLevel level) { for (int i=1; i<NumOfLogModules; i++) m_LogModulesArray[i] = level; }

		/**
		 * Check whether a certain module is set to debug log level
		 * @param[in] module PcapPlusPlus module
		 * @return True if this module log level is "debug". False otherwise
		 */
		bool isDebugEnabled(LogModule module) const { return m_LogModulesArray[module] == Debug; }

		/**
		 * Get an array that contains log level information for all modules. User can access this array with a certain PcapPlusPlus module
		 * and get the log level this module is currently in. For example:
		 * LogLevel* myLogLevelArr = getLogModulesArr();
		 * if (myLogLevelArr[PacketLogModuleUdpLayer] == LogLevel::Debug) ....
		 * @return A pointer to the LogLevel array
		 */
		const LogLevel* getLogModulesArr() const { return m_LogModulesArray; }

		void setLogPrinter(LogPrinter printer) { m_LogPrinter = printer; }

		std::string getLastError() { return m_LastError; }

		/**
		 * Suppress logs in all PcapPlusPlus modules
		 */
		void suppressLogs() { m_LogsEnabled = false; }

		/**
		 * Enable logs in all PcapPlusPlus modules
		 */
		void enableLogs() { m_LogsEnabled = true; }

		/**
		 * Get an indication if logs are currently suppressed
		 * @return True if logs are currently suppressed, false otherwise
		 */
		bool logsEnabled() const { return m_LogsEnabled; }

		inline void printLogMessage(LogLevel logLevel, const std::string& logMessage, const std::string& file, const std::string& method, const int line);

		/**
		 * Get access to Logger singleton
		 * @todo: make this singleton thread-safe/
		 * @return a pointer to the Logger singleton
		**/
		static Logger& getInstance()
		{
			static Logger instance;
			return instance;
		}
	private:
		bool m_LogsEnabled;
		Logger::LogLevel m_LogModulesArray[NumOfLogModules];
		LogPrinter m_LogPrinter;
		std::string m_LastError;

		Logger();

		static void defaultLogPrinter(LogLevel logLevel, const std::string& logMessage, const std::string& file, const std::string& method, const int line);
	};

#define LOG_DEBUG(message) do { \
		if (pcpp::Logger::getInstance().logsEnabled() && pcpp::Logger::getInstance().isDebugEnabled(LOG_MODULE)) { \
			std::ostringstream logStream; \
			logStream << message; \
			pcpp::Logger::getInstance().printLogMessage(pcpp::Logger::Debug, logStream.str(), __FILE__, __FUNCTION__, __LINE__); \
		} \
	} while(0)

#define LOG_ERROR(message) do { \
			if (pcpp::Logger::getInstance().logsEnabled()) {\
				std::ostringstream logStream; \
				logStream << message; \
				pcpp::Logger::getInstance().printLogMessage(pcpp::Logger::Error, logStream.str(), __FILE__, __FUNCTION__, __LINE__); \
			} \
		} while (0)

#define IS_DEBUG pcpp::Logger::getInstance().isDebugEnabled(LOG_MODULE)

void Logger::printLogMessage(LogLevel logLevel, const std::string& logMessage, const std::string& file, const std::string& method, const int line)
{
	if (logLevel == Logger::Error)
	{
		m_LastError = logMessage;
	}
	m_LogPrinter(logLevel, logMessage, file, method, line);
}

} // namespace pcpp

#endif /* PCAPPP_LOGGER */
