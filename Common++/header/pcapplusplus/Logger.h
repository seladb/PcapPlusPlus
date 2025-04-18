#pragma once

#include <cstdio>
#include <cstdint>
#include <memory>
#include <array>
#include <mutex>
#include <ostream>
#include <sstream>
#include "DeprecationUtils.h"
#include "ObjectPool.h"

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

// Compile time log levels.
// Allows for conditional removal of unwanted log calls at compile time.
#define PCPP_LOG_LEVEL_OFF 0
#define PCPP_LOG_LEVEL_ERROR 1
#define PCPP_LOG_LEVEL_INFO 2
#define PCPP_LOG_LEVEL_DEBUG 3

// All log messages built via a PCPP_LOG_* macro below the PCPP_ACTIVE_LOG_LEVEL will be removed at compile time.
// Uses the PCPP_ACTIVE_LOG_LEVEL if it is defined, otherwise defaults to PCAP_LOG_LEVEL_DEBUG
#ifndef PCPP_ACTIVE_LOG_LEVEL
#	define PCPP_ACTIVE_LOG_LEVEL PCPP_LOG_LEVEL_DEBUG
#endif  // !PCPP_ACTIVE_LOG_LEVEL

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	/// Cross-platform and thread-safe version of strerror
	/// @param errnum Value of errno
	/// @return String representation of the error number
	std::string getErrorString(int errnum);

	/// An enum representing all PcapPlusPlus modules
	enum LogModule : uint8_t
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
		PacketLogModuleWireGuardLayer,   ///< WireGuardLayer module (Packet++)
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

	/// @struct LogSource
	/// Represents the source of a log message.
	/// Contains information about the source file, function, line number, and the log module.
	struct LogSource
	{
		/// Default constructor for LogSource.
		constexpr LogSource() = default;

		/// Constructor for LogSource with only the log module.
		/// @param logModule The log module.
		explicit constexpr LogSource(LogModule logModule) : logModule(logModule)
		{}

		/// Constructor for LogSource with all parameters.
		/// @param logModule The log module.
		/// @param file The source file.
		/// @param function The source function.
		/// @param line The line number.
		constexpr LogSource(LogModule logModule, const char* file, const char* function, int line)
		    : file(file), function(function), line(line), logModule(logModule)
		{}

		const char* file = nullptr;               /**< The source file. */
		const char* function = nullptr;           /**< The source function. */
		int line = 0;                             /**< The line number. */
		LogModule logModule = UndefinedLogModule; /**< The log module. */
	};

	/// An enum representing the log level. Currently 4 log levels are supported: Off, Error, Info and Debug. Info is
	/// the default log level
	enum class LogLevel
	{
		Off = PCPP_LOG_LEVEL_OFF,      ///< No log messages are emitted.
		Error = PCPP_LOG_LEVEL_ERROR,  ///< Error level logs are emitted.
		Info = PCPP_LOG_LEVEL_INFO,    ///< Info level logs and above are emitted.
		Debug = PCPP_LOG_LEVEL_DEBUG   ///< Debug level logs and above are emitted.
	};

	inline std::ostream& operator<<(std::ostream& s, LogLevel v)
	{
		return s << static_cast<std::underlying_type<LogLevel>::type>(v);
	}

	// Forward declaration
	class Logger;

	namespace internal
	{
		/// @class LogContext
		/// @brief A context encapsulating the details of a single log message to be passed to the Logger.
		class LogContext
		{
		public:
			friend class pcpp::Logger;

			/// @brief Creates a context with an empty message with Info level and no source.
			LogContext() = default;

			/// @brief Creates a context with an empty message with the given level and source.
			/// @param level The log level for this message.
			/// @param source The log source.
			explicit LogContext(LogLevel level, LogSource const& source = {}) : m_Source(source), m_Level(level)
			{}

			/// @brief Initializes the context with an empty message and the given level and source.
			/// @param level The log level for this message.
			/// @param source The log source.
			void init(LogLevel level, LogSource const& source)
			{
				m_Source = source;
				m_Level = level;
				m_Stream.clear();
				m_Stream.str({});
			}

			/// @brief Appends to the message.
			/// @param value The value to append.
			/// @return A reference to this context.
			template <class T> inline LogContext& operator<<(T const& value)
			{
				m_Stream << value;
				return *this;
			}

		private:
			std::ostringstream m_Stream;
			LogSource m_Source;
			LogLevel m_Level = LogLevel::Info;
		};
	}  // namespace internal

	/// @class Logger
	/// PcapPlusPlus logger manager.
	/// PcapPlusPlus uses this logger to output both error and debug logs.
	/// There are currently 3 log levels: Logger#Error, Logger#Info and Logger#Debug.
	///
	/// PcapPlusPlus is divided into modules (described in #LogModule enum). The user can set the log level got each
	/// module or to all modules at once. The default is Logger#Info which outputs only error messages. Changing log
	/// level for modules can be done dynamically while the application is running.
	///
	/// The logger also exposes a method to retrieve the last error log message.
	///
	/// Logs are printed to console by default in a certain format. The user can set a different print function to
	/// change the format or to print to other media (such as files, etc.).
	///
	/// PcapPlusPlus logger is a singleton which can be reached from anywhere in the code.
	///
	/// Note: Logger#Info level logs are currently only used in DPDK devices to set DPDK log level to RTE_LOG_NOTICE.
	class Logger
	{
	public:
		Logger(const Logger&) = delete;
		Logger& operator=(const Logger&) = delete;

		// Deprecated, Use the LogLevel in the pcpp namespace instead.
		using LogLevel = pcpp::LogLevel;
		PCPP_DEPRECATED("Use the LogLevel in the pcpp namespace instead.")
		static const LogLevel Error = LogLevel::Error;
		PCPP_DEPRECATED("Use the LogLevel in the pcpp namespace instead.")
		static const LogLevel Info = LogLevel::Info;
		PCPP_DEPRECATED("Use the LogLevel in the pcpp namespace instead.")
		static const LogLevel Debug = LogLevel::Debug;

		/// @typedef LogPrinter
		/// Log printer callback. Used for printing the logs in a custom way.
		/// @param[in] logLevel The log level for this log message
		/// @param[in] logMessage The log message
		/// @param[in] file The source file in PcapPlusPlus code the log message is coming from
		/// @param[in] method The method in PcapPlusPlus code the log message is coming from
		/// @param[in] line The line in PcapPlusPlus code the log message is coming from
		/// @remarks The printer callback should support being called from multiple threads simultaneously.
		using LogPrinter =
		    std::add_pointer<void(LogLevel logLevel, const std::string& logMessage, const std::string& file,
		                          const std::string& method, const int line)>::type;

		/// A static method for converting the log level enum to a string.
		/// @param[in] logLevel A log level enum
		/// @return The log level as a string
		static std::string logLevelAsString(LogLevel logLevel);

		/// Get the log level for a certain module
		/// @param[in] module PcapPlusPlus module
		/// @return The log level set for this module
		LogLevel getLogLevel(LogModule module)
		{
			return m_LogModulesArray[module];
		}

		/// Set the log level for a certain PcapPlusPlus module
		/// @param[in] module PcapPlusPlus module
		/// @param[in] level The log level to set the module to
		void setLogLevel(LogModule module, LogLevel level)
		{
			m_LogModulesArray[module] = level;
		}

		/// Check whether a certain module is set to debug log level
		/// @param[in] module PcapPlusPlus module
		/// @return True if this module log level is "debug". False otherwise
		bool isDebugEnabled(LogModule module) const
		{
			return m_LogModulesArray[module] == LogLevel::Debug;
		}

		/// @brief Check whether a log level should be emitted by the logger.
		/// @param level The level of the log message.
		/// @param module PcapPlusPlus module
		/// @return True if the message should be emitted. False otherwise.
		bool shouldLog(LogLevel level, LogModule module) const
		{
			return level != LogLevel::Off && m_LogModulesArray[module] >= level;
		}

		/// Set all PcapPlusPlus modules to a certain log level
		/// @param[in] level The log level to set all modules to
		void setAllModulesToLogLevel(LogLevel level)
		{
			for (int i = 1; i < NumOfLogModules; i++)
			{
				m_LogModulesArray[i] = level;
			}
		}

		/// Set a custom log printer.
		/// @param[in] printer A log printer function that will be called for every log message
		void setLogPrinter(LogPrinter printer)
		{
			m_LogPrinter = printer;
		}

		/// Set the log printer back to the default printer
		void resetLogPrinter()
		{
			m_LogPrinter = &defaultLogPrinter;
		}

		/// @return Get the last error message
		std::string getLastError() const
		{
			std::lock_guard<std::mutex> lock(m_LastErrorMtx);
			return m_LastError;
		}

		/// Suppress logs in all PcapPlusPlus modules
		void suppressLogs()
		{
			m_LogsEnabled = false;
		}

		/// Enable logs in all PcapPlusPlus modules
		void enableLogs()
		{
			m_LogsEnabled = true;
		}

		/// Get an indication if logs are currently enabled.
		/// @return True if logs are currently enabled, false otherwise
		bool logsEnabled() const
		{
			return m_LogsEnabled;
		}

		/// @brief Controls if the logger should use a pool of LogContext objects.
		///
		/// If enabled is set to false, preallocate and maxPoolSize are ignored.
		/// @param enabled True to enable context pooling, false to disable.
		/// @param preallocate The number of LogContext objects to preallocate in the pool.
		/// @param maxPoolSize The maximum number of LogContext objects to keep in the pool.
		/// @remarks Disabling the pooling clears the pool.
		void useContextPooling(bool enabled, std::size_t preallocate = 2, std::size_t maxPoolSize = 10)
		{
			m_UseContextPooling = enabled;

			if (m_UseContextPooling)
			{
				m_LogContextPool.setMaxSize(maxPoolSize);

				if (preallocate > 0)
				{
					m_LogContextPool.preallocate(preallocate);
				}
			}
			else
			{
				// Clear the pool if we're disabling pooling.
				m_LogContextPool.clear();
			}
		}

		/// Get access to Logger singleton
		/// @todo: make this singleton thread-safe/
		/// @return a pointer to the Logger singleton
		static Logger& getInstance()
		{
			static Logger instance;
			return instance;
		}

		/// @brief Creates a new LogContext with Info level and no source.
		/// @return A new LogContext.
		std::unique_ptr<internal::LogContext> createLogContext();

		/// @brief Creates a new LogContext with the given level and source.
		/// @param level The log level for this message.
		/// @param source The log source.
		/// @return A new LogContext.
		std::unique_ptr<internal::LogContext> createLogContext(LogLevel level, LogSource const& source = {});

		/// @brief Directly emits a log message bypassing all level checks.
		/// @param source The log source.
		/// @param level The log level for this message. This is only used for the log printer.
		/// @param message The log message.
		void emit(LogSource const& source, LogLevel level, std::string const& message);

		/// @brief Directly emits a log message bypassing all level checks.
		/// @param message The log message.
		void emit(std::unique_ptr<internal::LogContext> message);

	private:
		bool m_LogsEnabled;
		std::array<LogLevel, NumOfLogModules> m_LogModulesArray;
		LogPrinter m_LogPrinter;

		mutable std::mutex m_LastErrorMtx;
		std::string m_LastError;

		bool m_UseContextPooling = true;
		// Keep a maximum of 10 LogContext objects in the pool.
		internal::DynamicObjectPool<internal::LogContext> m_LogContextPool{ 10, 2 };

		// private c'tor - this class is a singleton
		Logger();

		static void defaultLogPrinter(LogLevel logLevel, const std::string& logMessage, const std::string& file,
		                              const std::string& method, int line);
	};

}  // namespace pcpp

#define PCPP_LOG(level, message)                                                                                       \
	do                                                                                                                 \
	{                                                                                                                  \
		auto& logger = pcpp::Logger::getInstance();                                                                    \
		if (logger.shouldLog(level, LOG_MODULE))                                                                       \
		{                                                                                                              \
			auto ctx =                                                                                                 \
			    logger.createLogContext(level, pcpp::LogSource(LOG_MODULE, PCAPPP_FILENAME, __FUNCTION__, __LINE__));  \
			(*ctx) << message;                                                                                         \
			logger.emit(std::move(ctx));                                                                               \
		}                                                                                                              \
	} while (0)

#if PCPP_ACTIVE_LOG_LEVEL >= PCPP_LOG_LEVEL_DEBUG
#	define PCPP_LOG_DEBUG(message) PCPP_LOG(pcpp::LogLevel::Debug, message)
#else
#	define PCPP_LOG_DEBUG(message) (void)0
#endif

#if PCPP_ACTIVE_LOG_LEVEL >= PCPP_LOG_LEVEL_INFO
#	define PCPP_LOG_INFO(message) PCPP_LOG(pcpp::LogLevel::Info, message)
#else
#	define PCPP_LOG_INFO(message) (void)0
#endif

#if PCPP_ACTIVE_LOG_LEVEL >= PCPP_LOG_LEVEL_ERROR
#	define PCPP_LOG_ERROR(message) PCPP_LOG(pcpp::LogLevel::Error, message)
#else
#	define PCPP_LOG_ERROR(message) (void)0
#endif
