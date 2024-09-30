#pragma once

#include <stdio.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <stdint.h>
#include "DeprecationUtils.h"

#ifndef LOG_MODULE
#	define LOG_MODULE UndefinedLogModule
#endif

// Use __FILE_NAME__ to avoid leaking complete full path
#ifdef __FILE_NAME__
#	define PCAPPP_FILENAME __FILE_NAME__
#else
#	define PCAPPP_FILENAME __FILE__
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
		CommonLogModuleIpUtils,          ///< IP Utils module (Common++)
		CommonLogModuleTablePrinter,     ///< Table printer module (Common++)
		CommonLogModuleGenericUtils,     ///< Generic Utils (Common++)
		PacketLogModuleRawPacket,        ///< RawPacket module (Packet++)
		PacketLogModulePacket,           ///< Packet module (Packet++)
		PacketLogModuleLayer,            ///< Layer module (Packet++)
		PacketLogModuleAsn1Codec,        ///< Asn1Codec module (Packet++)
		PacketLogModuleArpLayer,         ///< ArpLayer module (Packet++)
		PacketLogModuleEthLayer,         ///< EthLayer module (Packet++)
		PacketLogModuleIPv4Layer,        ///< IPv4Layer module (Packet++)
		PacketLogModuleIPv6Layer,        ///< IPv6Layer module (Packet++)
		PacketLogModulePayloadLayer,     ///< PayloadLayer module (Packet++)
		PacketLogModuleTcpLayer,         ///< TcpLayer module (Packet++)
		PacketLogModuleUdpLayer,         ///< UdpLayer module (Packet++)
		PacketLogModuleVlanLayer,        ///< VlanLayer module (Packet++)
		PacketLogModuleHttpLayer,        ///< HttpLayer module (Packet++)
		PacketLogModulePPPoELayer,       ///< PPPoELayer module (Packet++)
		PacketLogModuleDnsLayer,         ///< DnsLayer module (Packet++)
		PacketLogModuleMplsLayer,        ///< MplsLayer module (Packet++)
		PacketLogModuleIcmpLayer,        ///< IcmpLayer module (Packet++)
		PacketLogModuleIcmpV6Layer,      ///< IcmpV6Layer module (Packet++)
		PacketLogModuleGreLayer,         ///< GreLayer module (Packet++)
		PacketLogModuleSSLLayer,         ///< SSLLayer module (Packet++)
		PacketLogModuleSllLayer,         ///< SllLayer module (Packet++)
		PacketLogModuleSll2Layer,        ///< Sll2Layer module (Packet++)
		PacketLogModuleNflogLayer,       ///< NflogLayer module (Packet++)
		PacketLogModuleDhcpLayer,        ///< DhcpLayer module (Packet++)
		PacketLogModuleDhcpV6Layer,      ///< DhcpV6Layer module (Packet++)
		PacketLogModuleIgmpLayer,        ///< IgmpLayer module (Packet++)
		PacketLogModuleSipLayer,         ///< SipLayer module (Packet++)
		PacketLogModuleSdpLayer,         ///< SdpLayer module (Packet++)
		PacketLogModuleRadiusLayer,      ///< RadiusLayer module (Packet++)
		PacketLogModuleGtpLayer,         ///< GtpLayer module (Packet++)
		PacketLogModuleBgpLayer,         ///< GtpLayer module (Packet++)
		PacketLogModuleSSHLayer,         ///< SSHLayer module (Packet++)
		PacketLogModuleVrrpLayer,        ///< Vrrp Record module (Packet++)
		PacketLogModuleTcpReassembly,    ///< TcpReassembly module (Packet++)
		PacketLogModuleIPReassembly,     ///< IPReassembly module (Packet++)
		PacketLogModuleIPSecLayer,       ///< IPSecLayers module (Packet++)
		PacketLogModuleNtpLayer,         ///< NtpLayer module (Packet++)
		PacketLogModuleTelnetLayer,      ///< TelnetLayer module (Packet++)
		PacketLogModuleStpLayer,         ///< StpLayer module (Packet++)
		PacketLogModuleLLCLayer,         ///< LLCLayer module (Packet++)
		PacketLogModuleNdpLayer,         ///< NdpLayer module (Packet++)
		PacketLogModuleFtpLayer,         ///< FtpLayer module (Packet++)
		PacketLogModuleSomeIpLayer,      ///< SomeIpLayer module (Packet++)
		PacketLogModuleSomeIpSdLayer,    ///< SomeIpSdLayer module (Packet++)
		PacketLogModuleWakeOnLanLayer,   ///< WakeOnLanLayer module (Packet++)
		PacketLogModuleSmtpLayer,        ///< SmtpLayer module (Packet++)
		PcapLogModuleWinPcapLiveDevice,  ///< WinPcapLiveDevice module (Pcap++)
		PcapLogModuleRemoteDevice,       ///< WinPcapRemoteDevice module (Pcap++)
		PcapLogModuleLiveDevice,         ///< PcapLiveDevice module (Pcap++)
		PcapLogModuleFileDevice,         ///< FileDevice module (Pcap++)
		PcapLogModulePfRingDevice,       ///< PfRingDevice module (Pcap++)
		PcapLogModuleMBufRawPacket,      ///< MBufRawPacket module (Pcap++)
		PcapLogModuleDpdkDevice,         ///< DpdkDevice module (Pcap++)
		PcapLogModuleKniDevice,          ///< KniDevice module (Pcap++)
		PcapLogModuleXdpDevice,          ///< XdpDevice module (Pcap++)
		PcapLogModuleNetworkUtils,       ///< Network Utils module (Pcap++)
		NumOfLogModules
	};

	struct LogSource
	{
		constexpr LogSource() = default;
		constexpr LogSource(LogModule logModule) : logModule(logModule)
		{}
		constexpr LogSource(LogModule logModule, const char* file, const char* function, int line)
		    : file(file), function(function), line(line), logModule(logModule)
		{}

		const char* file = nullptr;
		const char* function = nullptr;
		int line = 0;
		LogModule logModule = UndefinedLogModule;
	};

	/**
	 * An enum representing the log level. Currently 3 log levels are supported: Error, Info and Debug. Info is the
	 * default log level
	 */
	enum class LogLevel
	{
		Off,    ///< No log messages are emitted.
		Error,  ///< Error level logs are emitted.
		Info,   ///< Info level logs and above are emitted.
		Debug   ///< Debug level logs and above are emitted.
	};

	inline std::ostream& operator<<(std::ostream& s, LogLevel v)
	{
		return s << static_cast<std::underlying_type<LogLevel>::type>(v);
	}

	// Forward declaration
	template <class T> void log(LogSource source, LogLevel level, T const& message);
	template <> void log(LogSource source, LogLevel level, std::string const& message);
	template <> void log(LogSource source, LogLevel level, const char* const& message);

	/**
	 * @class Logger
	 * PcapPlusPlus logger manager.
	 * PcapPlusPlus uses this logger to output both error and debug logs.
	 * There are currently 3 log levels: Logger#Error, Logger#Info and Logger#Debug.
	 *
	 * PcapPlusPlus is divided into modules (described in #LogModule enum). The user can set the log level got each
	 * module or to all modules at once. The default is Logger#Info which outputs only error messages. Changing log
	 * level for modules can be done dynamically while the application is running.
	 *
	 * The logger also exposes a method to retrieve the last error log message.
	 *
	 * Logs are printed to console by default in a certain format. The user can set a different print function to change
	 * the format or to print to other media (such as files, etc.).
	 *
	 * PcapPlusPlus logger is a singleton which can be reached from anywhere in the code.
	 *
	 * Note: Logger#Info level logs are currently only used in DPDK devices to set DPDK log level to RTE_LOG_NOTICE.
	 */
	class Logger
	{
	public:
		/**
		 * An enum representing the log level. Currently 3 log levels are supported: Error, Info and Debug. Info is the
		 * default log level
		 */
		/* enum LogLevel
		{
		    Error,  ///< Error log level
		    Info,   ///< Info log level
		    Debug   ///< Debug log level
		};*/

		// Deprecated, Use the LogLevel in the pcpp namespace instead.
		using LogLevel = pcpp::LogLevel;
		PCPP_DEPRECATED("Use the LogLevel in the pcpp namespace instead.")
		static const LogLevel Error = LogLevel::Error;
		PCPP_DEPRECATED("Use the LogLevel in the pcpp namespace instead.")
		static const LogLevel Info = LogLevel::Info;
		PCPP_DEPRECATED("Use the LogLevel in the pcpp namespace instead.")
		static const LogLevel Debug = LogLevel::Debug;

		/**
		 * @typedef LogPrinter
		 * Log printer callback. Used for printing the logs in a custom way.
		 * @param[in] logLevel The log level for this log message
		 * @param[in] logMessage The log message
		 * @param[in] file The source file in PcapPlusPlus code the log message is coming from
		 * @param[in] method The method in PcapPlusPlus code the log message is coming from
		 * @param[in] line The line in PcapPlusPlus code the log message is coming from
		 */
		typedef void (*LogPrinter)(LogLevel logLevel, const std::string& logMessage, const std::string& file,
		                           const std::string& method, const int line);

		/**
		 * A static method for converting the log level enum to a string.
		 * @param[in] logLevel A log level enum
		 * @return The log level as a string
		 */
		static std::string logLevelAsString(LogLevel logLevel);

		/**
		 * Get the log level for a certain module
		 * @param[in] module PcapPlusPlus module
		 * @return The log level set for this module
		 */
		LogLevel getLogLevel(LogModule module)
		{
			return m_LogModulesArray[module];
		}

		/**
		 * Set the log level for a certain PcapPlusPlus module
		 * @param[in] module PcapPlusPlus module
		 * @param[in] level The log level to set the module to
		 */
		void setLogLevel(LogModule module, LogLevel level)
		{
			m_LogModulesArray[module] = level;
		}

		/**
		 * Check whether a certain module is set to debug log level
		 * @param[in] module PcapPlusPlus module
		 * @return True if this module log level is "debug". False otherwise
		 */
		bool isDebugEnabled(LogModule module) const
		{
			return m_LogModulesArray[module] == LogLevel::Debug;
		}

		/**
		 * @brief Check whether a log level should be emitted by the logger.
		 * @param level The level of the log message.
		 * @param module PcapPlusPlus module
		 * @return True if the message should be emitted. False otherwise.
		 */
		bool shouldLog(LogLevel level, LogModule module) const
		{
			return level != LogLevel::Off && m_LogModulesArray[module] >= level;
		}

		/**
		 * Set all PcapPlusPlus modules to a certain log level
		 * @param[in] level The log level to set all modules to
		 */
		void setAllModulesToLogLevel(LogLevel level)
		{
			for (int i = 1; i < NumOfLogModules; i++)
				m_LogModulesArray[i] = level;
		}

		/**
		 * Set a custom log printer.
		 * @param[in] printer A log printer function that will be called for every log message
		 */
		void setLogPrinter(LogPrinter printer)
		{
			m_LogPrinter = printer;
		}

		/**
		 * Set the log printer back to the default printer
		 */
		void resetLogPrinter()
		{
			m_LogPrinter = &defaultLogPrinter;
		}

		/**
		 * @return Get the last error message
		 */
		std::string getLastError()
		{
			return m_LastError;
		}

		/**
		 * Suppress logs in all PcapPlusPlus modules
		 */
		void suppressLogs()
		{
			m_LogsEnabled = false;
		}

		/**
		 * Enable logs in all PcapPlusPlus modules
		 */
		void enableLogs()
		{
			m_LogsEnabled = true;
		}

		/**
		 * Get an indication if logs are currently enabled.
		 * @return True if logs are currently enabled, false otherwise
		 */
		bool logsEnabled() const
		{
			return m_LogsEnabled;
		}

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

		template <class T> friend void pcpp::log(LogSource source, LogLevel level, T const& message);

	private:
		bool m_LogsEnabled;
		LogLevel m_LogModulesArray[NumOfLogModules];
		LogPrinter m_LogPrinter;
		std::string m_LastError;

		// private c'tor - this class is a singleton
		Logger();

		void printLogMessage(LogSource source, LogLevel logLevel, std::string const& message);
		static void defaultLogPrinter(LogLevel logLevel, const std::string& logMessage, const std::string& file,
		                              const std::string& method, const int line);
	};

	template <class T> inline void log(LogSource source, LogLevel level, T const& message)
	{
		auto& logger = Logger::getInstance();
		if (logger.shouldLog(level, source.module))
		{
			std::ostringstream sstream;
			sstream << message;
			logger.printLogMessage(source, level, sstream);
		}
	};

	// Specialization for string to skip the stringstream
	template <> inline void log(LogSource source, LogLevel level, std::string const& message)
	{
		auto& logger = Logger::getInstance();
		if (logger.shouldLog(level, source.logModule))
		{
			logger.printLogMessage(source, level, message);
		}
	};

	// Specialization for const char* to skip the stringstream
	template <> inline void log(LogSource source, LogLevel level, const char* const& message)
	{
		auto& logger = Logger::getInstance();
		if (logger.shouldLog(level, source.logModule))
		{
			logger.printLogMessage(source, level, message);
		}
	};

	template <class T> inline void logError(LogSource source, T const& message)
	{
		log(source, LogLevel::Error, message);
	};

	template <class T> inline void logInfo(LogSource source, T const& message)
	{
		log(source, LogLevel::Info, message);
	};

	template <class T> inline void logDebug(LogSource source, T const& message)
	{
		log(source, LogLevel::Debug, message);
	};
}  // namespace pcpp

#define PCPP_LOG(level, message)                                                                                       \
	do                                                                                                                 \
	{                                                                                                                  \
		if (pcpp::Logger::getInstance().shouldLog(level, LOG_MODULE))                                                  \
		{                                                                                                              \
			std::ostringstream sstream;                                                                                \
			sstream << message;                                                                                        \
			pcpp::log(pcpp::LogSource(LOG_MODULE, PCAPPP_FILENAME, __FUNCTION__, __LINE__), level, sstream.str());     \
		}                                                                                                              \
	} while (0)

#define PCPP_LOG_DEBUG(message) PCPP_LOG(pcpp::LogLevel::Debug, message)

#define PCPP_LOG_INFO(message) PCPP_LOG(pcpp::LogLevel::Info, message)

#define PCPP_LOG_ERROR(message) PCPP_LOG(pcpp::LogLevel::Error, message)
