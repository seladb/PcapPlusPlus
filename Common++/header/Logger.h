#ifndef PCAPPP_LOGGER
#define PCAPPP_LOGGER

#include <stdio.h>
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
		PacketLogModuleTcpReassembly, ///< TcpReassembly module (Packet++)
		PacketLogModuleIPReassembly, ///< IPReassembly module (Packet++)
		PcapLogModuleWinPcapLiveDevice, ///< WinPcapLiveDevice module (Pcap++)
		PcapLogModuleRemoteDevice, ///< WinPcapRemoteDevice module (Pcap++)
		PcapLogModuleLiveDevice, ///< PcapLiveDevice module (Pcap++)
		PcapLogModuleFileDevice, ///< FileDevice module (Pcap++)
		PcapLogModulePfRingDevice, ///< PfRingDevice module (Pcap++)
		PcapLogModuleDpdkDevice, ///< DpdkDevice module (Pcap++)
		NetworkUtils, ///< NetworkUtils module (Pcap++)
		NumOfLogModules
	};

	/**
	 * @class LoggerPP
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
	class LoggerPP
	{
	public:
		/**
		 * An enum representing the log level. Currently 2 log level are supported: Normal and Debug. Normal is the default log level
		 */
		enum LogLevel
		{
			Normal, ///< Normal log level
			Debug ///< Debug log level
		};

		/**
		 * Set the log level for a certain PcapPlusPlus module
		 * @param[in] module PcapPlusPlus module
		 * @param[in] level The log level to set the module to
		 */
		void setLogLevel(LogModule module, LogLevel level) { m_LogModulesArray[module] = level; }

		/**
		 * Set all PcapPlusPlus modules to a certain log leve
		 * @param[in] level The log level to set all modules to
		 */
		void setAllModlesToLogLevel(LogLevel level) { for (int i=1; i<NumOfLogModules; i++) m_LogModulesArray[i] = level; }

		/**
		 * Check whether a certain module is set to debug log level
		 * @param[in] module PcapPlusPlus module
		 * @return True if this module log level is "debug". False otherwise
		 */
		inline bool isDebugEnabled(LogModule module) { return m_LogModulesArray[module] == Debug; }

		/**
		 * Get an array that contains log level information for all modules. User can access this array with a certain PcapPlusPlus module
		 * and get the log level this module is currently in. For example:
		 * LogLevel* myLogLevelArr = getLogModulesArr();
		 * if (myLogLevelArr[PacketLogModuleUdpLayer] == LogLevel::Debug) ....
		 * @return A pointer to the LogLevel array
		 */
		inline LogLevel* getLogModulesArr() { return m_LogModulesArray; }

		/**
		 * Check whether error string was already set
		 * @return true if error string was already set, false otherwise
		 */
		inline bool isErrorStringSet() { return m_ErrorString != NULL; }

		/**
		 * Get the pointer to the error string set by the user. If no such pointer was provided by the user, NULL will be returned
		 * @return A pointer to the string
		 */
		inline char* getErrorString() { return m_ErrorString; }

		/**
		 * Set the error string to a string pointer provided by the user. By default all errors are printed to stderr.
		 * Using this method will cause PcapPlusPlus to output errors to the user string instead
		 * @param[in] errString A string pointer provided by the user which all error messages will be print to from now on
		 * @param[in] len The length of errString array. If
		 */
		void setErrorString(char* errString, int len) { m_ErrorString = errString; m_ErrorStringLen = len; }

		/**
		 * Get the user-defined error string length. If no such pointer was provided by the user, 0 will be returned
		 * @return The user-defined error string length
		 **/
		inline int getErrorStringLength() { return m_ErrorStringLen; }

		/**
		 * Suppress all errors in all PcapPlusPlusModules
		 */
		void supressErrors() { m_SuppressErrors = true; }

		/**
		 * Enable all errors in all PcapPlusPlusModules
		 */
		void enableErrors() { m_SuppressErrors = false; }

		/**
		 * Get an indication if errors are currently suppressed
		 * @return True if errors are currently suppressed, false otherwise
		 */
		inline bool isSupressErrors() { return m_SuppressErrors; }

		/**
		 * Get access to LoggerPP singleton
		 * @todo: make this singleton thread-safe/
		 * @return a pointer to the LoggerPP singleton
		**/
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
			if(pcpp::LoggerPP::getInstance().isDebugEnabled(LOG_MODULE)) { \
				printf("[%-35s: %-25s: line:%-4d] " format "\n", __FILE__, __FUNCTION__, __LINE__, ## __VA_ARGS__); \
			} \
	} while(0)

#define LOG_ERROR(format, ...) do { \
			if (!pcpp::LoggerPP::getInstance().isSupressErrors()) {\
				if(pcpp::LoggerPP::getInstance().isErrorStringSet()) \
					snprintf(pcpp::LoggerPP::getInstance().getErrorString(), pcpp::LoggerPP::getInstance().getErrorStringLength(), format "\n", ## __VA_ARGS__); \
				else \
					fprintf(stderr, format "\n", ## __VA_ARGS__); \
			} \
		} while (0)

#define IS_DEBUG pcpp::LoggerPP::getInstance().isDebugEnabled(LOG_MODULE)

} // namespace pcpp

#endif /* PCAPPP_LOGGER */
