#pragma once

#include <functional>
#include <tuple>
#include <unordered_map>
#include <atomic>
#include "Device.h"

/// @file
/// @brief WinDivert-based device (Windows-only) for capturing and sending packets at the network layer.
///
/// This header exposes a device wrapper around the WinDivert driver that lets applications:
/// - Open a WinDivert handle with a filter
/// - Capture inbound/outbound IPv4/IPv6 packets in batches or via a callback
/// - Send batches of raw packets
/// - Inspect and configure queue parameters (length, time, size)
/// - Query WinDivert runtime version and available network interfaces
///
/// For filter syntax and semantics please refer to the WinDivert documentation.
///
/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus library
namespace pcpp
{
	namespace internal
	{
		/// @brief Opaque handle wrapper for an opened WinDivert driver instance.
		///
		/// Implementations encapsulate the native WinDivert handle and its lifetime.
		class IWinDivertHandle
		{
		public:
			virtual ~IWinDivertHandle() = default;
		};

		/// @brief Abstract helper that wraps Windows OVERLAPPED I/O used by WinDivert operations.
		///
		/// Implementations provide waiting/resetting primitives and a way to fetch
		/// the result of an asynchronous I/O tied to a specific WinDivert handle.
		class IOverlappedWrapper
		{
		public:
			/// @brief Result of waiting on an OVERLAPPED I/O operation.
			///
			/// Indicates whether the asynchronous operation completed, timed out or failed,
			/// and carries an optional Windows error code.
			struct WaitResult
			{
				/// @enum Status
				/// @brief Status codes for wait result.
				enum class Status
				{
					Completed,  ///< The wait completed successfully
					Timeout,    ///< The wait timed out before completion
					Failed      ///< The wait failed; see errorCode
				};
				
				Status status;       ///< Final wait status
				uint32_t errorCode = 0; ///< Windows error code (when relevant)
			};

			/// @brief Result of completing an OVERLAPPED I/O operation.
			///
			/// Contains the final status, the number of bytes/packet length produced by the
			/// operation (when applicable), and a Windows error code on failure.
			struct OverlappedResult
			{
				/// @enum Status
				/// @brief Status codes for overlapped result.
				enum class Status
				{
					Success, ///< Operation completed successfully
					Failed   ///< Operation failed; see errorCode
				};
				
				Status status;           ///< Completion status
				uint32_t packetLen = 0;  ///< Number of bytes read/written (when applicable)
				uint32_t errorCode = 0;  ///< Windows error code (when relevant)
			};

			virtual WaitResult wait(uint32_t timeout) = 0;
			virtual void reset() = 0;
			virtual OverlappedResult getOverlappedResult(const IWinDivertHandle* handle) = 0;
			virtual ~IOverlappedWrapper() = default;
		};

		/// @brief Minimal address/metadata returned by WinDivert for a captured packet.
		///
		/// This structure mirrors the subset of fields PcapPlusPlus needs from WinDivert's
		/// WINDIVERT_ADDRESS: whether the packet is IPv6, the Windows interface index and
		/// the original WinDivert timestamp.
		struct WinDivertAddress
		{
			bool isIPv6;             ///< True if the packet is IPv6, false for IPv4
			uint32_t interfaceIndex; ///< Windows network interface index
			uint64_t timestamp;      ///< WinDivert timestamp associated with the packet
		};

		/// @brief Abstraction over the concrete WinDivert API used by WinDivertDevice.
		///
		/// This interface allows providing different backends (e.g., real WinDivert DLL
		/// or a test double) while keeping the device logic independent from the API.
		class IWinDivertImplementation
		{
		public:
			/// @brief WinDivert runtime parameters that can be queried or configured.
			enum class WinDivertParam
			{
				QueueLength = 0, ///< Maximum number of packets in the queue
				QueueTime   = 1, ///< Maximum time (ms) a packet may stay in the queue
				QueueSize   = 2, ///< Maximum total queue size (bytes)
				VersionMajor= 3, ///< WinDivert major version
				VersionMinor= 4  ///< WinDivert minor version
			};

			/// @brief Information about a Windows network interface as reported by WinDivert.
			struct NetworkInterface
			{
				uint32_t index;           ///< Interface index
				std::wstring name;        ///< Interface GUID or system name
				std::wstring description; ///< Human-readable description
				bool isLoopback;          ///< True if the interface is loopback
				bool isUp;                ///< True if the interface is up/running
			};

			static constexpr uint32_t SuccessResult = 0;
			static constexpr uint32_t ErrorIoPending = 997;

			virtual ~IWinDivertImplementation() = default;

			virtual std::unique_ptr<IWinDivertHandle> open(const std::string& filter, int layer, int16_t priority,
			                                               uint64_t flags) = 0;
			virtual uint32_t close(const IWinDivertHandle* handle) = 0;
			virtual uint32_t recvEx(const IWinDivertHandle* handle, uint8_t* buffer, uint32_t bufferLen,
			                        size_t addressesSize, IOverlappedWrapper* overlapped) = 0;
			virtual std::vector<WinDivertAddress> recvExComplete() = 0;
			virtual uint32_t sendEx(const IWinDivertHandle* handle, uint8_t* buffer, uint32_t bufferLen,
			                        size_t addressesSize) = 0;
			virtual std::unique_ptr<IOverlappedWrapper> createOverlapped() = 0;
			virtual bool getParam(const IWinDivertHandle* handle, WinDivertParam param, uint64_t& value) = 0;
			virtual bool setParam(const IWinDivertHandle* handle, WinDivertParam param, uint64_t value) = 0;
			virtual std::vector<NetworkInterface> getNetworkInterfaces() const = 0;
		};
	}  // namespace internal

	/// @class WinDivertRawPacket
	/// @brief A RawPacket specialization used by WinDivertDevice.
	///
	/// In addition to the base RawPacket data (raw buffer, timestamp and link-layer type),
	/// WinDivert also provides the Windows network interface index and the original
	/// WinDivert timestamp. These can be retrieved with getInterfaceIndex() and
	/// getWinDivertTimestamp() respectively.
	class WinDivertRawPacket : public RawPacket
	{
	public:
		WinDivertRawPacket(const uint8_t* pRawData, int rawDataLen, timespec timestamp, bool deleteRawDataAtDestructor,
		                   LinkLayerType layerType, uint32_t interfaceIndex, uint64_t winDivertTimestamp)
		    : RawPacket(pRawData, rawDataLen, timestamp, deleteRawDataAtDestructor, layerType),
		      m_InterfaceIndex(interfaceIndex), m_WinDivertTimestamp(winDivertTimestamp)
		{}

		/// @brief Get the Windows interface index the packet was captured on.
		/// @return The interface index as reported by WinDivert.
		uint32_t getInterfaceIndex() const
		{
			return m_InterfaceIndex;
		}

		/// @brief Get the original WinDivert timestamp captured for this packet.
		/// @return A 64-bit timestamp value as returned by WinDivert (see WinDivert docs for units and origin).
		uint64_t getWinDivertTimestamp() const
		{
			return m_WinDivertTimestamp;
		}

	private:
		uint32_t m_InterfaceIndex;
		uint64_t m_WinDivertTimestamp;
	};

	/// @class WinDivertDevice
	/// @brief A device wrapper around the WinDivert driver for Windows.
	///
	/// WinDivert is a kernel driver for packet interception and injection on Windows.
	/// WinDivertDevice opens a WinDivert handle on the WINDIVERT_LAYER_NETWORK layer using a filter
	/// and provides methods to receive and send packets in batches, query/set queue parameters,
	/// retrieve the WinDivert runtime version, and enumerate Windows network interfaces.
	///
	/// Notes:
	/// - The default open() uses the filter "inbound or outbound", capturing both directions.
	/// - The device is opened in sniffing mode and supports fragmented packets.
	/// - Receive can be done into a user-provided vector or via a callback loop that can be stopped with stopReceive().
	/// - Send batches multiple packets at once for efficiency.
	/// - Queue parameters map to WinDivert queue configuration (length in packets, time in milliseconds, size in
	/// bytes).
	///
	/// For WinDivert filter syntax, layer semantics, timestamps and error codes please refer to the WinDivert
	/// documentation.
	class WinDivertDevice : public IDevice
	{
	public:
		/// @struct ReceiveResult
		/// @brief Result object returned by receive operations.
		struct ReceiveResult
		{
			/// @enum Status
			/// @brief Status codes for receive operations.
			enum class Status
			{
				Completed,  ///< Receive completed successfully
				Timeout,    ///< Receive timed out before completing the requested operation
				Failed      ///< Receive failed due to an error (see error and errorCode)
			};

			Status status;           ///< Operation status (Completed/Timeout/Failed)
			std::string error;       ///< Error message when status is Failed; empty otherwise
			uint32_t errorCode = 0;  ///< Platform-specific error code associated with the failure (0 if none)
		};

		/// @struct SendResult
		/// @brief Result object returned by send operations.
		struct SendResult
		{
			/// @enum Status
			/// @brief Status codes for send operations.
			enum class Status
			{
				Completed,  ///< Send operation completed successfully
				Failed      ///< Send operation failed (see error and errorCode)
			};

			Status status;           ///< Operation status (Completed/Failed)
			size_t packetsSent;      ///< Number of packets successfully sent when status is Completed
			std::string error;       ///< Error message when status is Failed; empty otherwise
			uint32_t errorCode = 0;  ///< Platform-specific error code associated with the failure (0 if none)
		};

		/// @struct WinDivertVersion
		/// @brief The WinDivert runtime version as reported by the driver.
		struct WinDivertVersion
		{
			uint64_t major;  ///< Major version number reported by WinDivert
			uint64_t minor;  ///< Minor version number reported by WinDivert

			/// @brief Convert to "major.minor" string representation.
			std::string toString() const
			{
				return std::to_string(major) + "." + std::to_string(minor);
			}
		};

		/// @struct NetworkInterface
		/// @brief A Windows network interface entry returned by getNetworkInterfaces().
		struct NetworkInterface
		{
			uint32_t index;
			std::wstring name;
			std::wstring description;
			bool isLoopback;
			bool isUp;
		};

		/// @enum QueueParam
		/// @brief Queue tuning parameters supported by WinDivert.
		///
		/// These map to WinDivert queue configuration parameters:
		/// - QueueLength – maximum number of packets in the internal queue (packets)
		/// - QueueTime – maximum time packets may sit in the internal queue (milliseconds)
		/// - QueueSize – maximum memory size for the internal queue (bytes)
		enum class QueueParam
		{
			QueueLength,  ///< Maximum number of packets in the packet queue (packets)
			QueueTime,    ///< Maximum residence time of packets in the queue (milliseconds)
			QueueSize     ///< Maximum memory allocated for the queue (bytes)
		};

		/// @typedef WinDivertRawPacketVector
		/// @brief Convenience alias for a vector of WinDivertRawPacket pointers with ownership semantics.
		using WinDivertRawPacketVector = PointerVector<WinDivertRawPacket>;
		/// @typedef ReceivePacketCallback
		/// @brief Callback invoked with a batch of received packets when using the callback receive API.
		/// The callback is called from the receiving loop until stopReceive() is invoked or an error/timeout occurs.
		using ReceivePacketCallback = std::function<void(const WinDivertRawPacketVector& packetVec)>;
		/// @typedef QueueParams
		/// @brief A map of QueueParam keys to their values. Units are per QueueParam description above.
		using QueueParams = std::unordered_map<QueueParam, uint64_t>;

		/// @brief Construct a WinDivertDevice with the default WinDivert implementation.
		WinDivertDevice();

		/// @brief Open the device with a default filter capturing both directions.
		/// @return true on success, false on failure (see logs for details).
		/// @note This calls open("inbound or outbound") on WINDIVERT_LAYER_NETWORK with sniffing/fragments flags.
		bool open() override;

		/// @brief Open the device with a custom WinDivert filter.
		/// @param[in] filter A WinDivert filter string (e.g. "ip and tcp.DstPort == 80").
		/// @return true on success, false on failure (see logs for details).
		/// @note The device is opened on WINDIVERT_LAYER_NETWORK with sniffing and fragment support.
		bool open(const std::string& filter);

		/// @brief Close the device and release the underlying WinDivert handle.
		void close() override;

		/// @brief Receive packets into a vector owned by the caller.
		///
		/// This method receives up to maxPackets packets (0 means unlimited) in batches of batchSize.
		/// It returns when either enough packets were captured or timeout milliseconds elapsed without completion.
		///
		/// @param[out] packetVec Destination vector for received packets. Each entry is a WinDivertRawPacket that owns
		/// its data.
		/// @param[in] timeout Receive timeout in milliseconds. Use 0 with a positive maxPackets to wait until quota is
		/// reached.
		/// @param[in] maxPackets Maximum packets to receive before returning. Use 0 for no limit (subject to timeout).
		/// @param[in] batchSize Number of packets to read per WinDivert call (must be > 0). Default is 64.
		/// @return A ReceiveResult describing the outcome. On failure, see error and errorCode.
		ReceiveResult receivePackets(WinDivertRawPacketVector& packetVec, uint32_t timeout = 5000,
		                             uint32_t maxPackets = 0, uint8_t batchSize = 64);

		/// @brief Receive packets using a callback invoked for each received batch.
		///
		/// The method runs a receive loop and invokes callback with each batch. The loop ends when stopReceive()
		/// is called from another thread, on timeout, or if an error occurs. Packet memory is valid during the callback
		/// and is released when the callback returns.
		///
		/// @param[in] callback A callback receiving a vector view of the current batch.
		/// @param[in] timeout Receive timeout in milliseconds per wait cycle. Default is 5000ms.
		/// @param[in] batchSize Number of packets to read per WinDivert call (must be > 0). Default is 64.
		/// @return A ReceiveResult describing the final outcome.
		ReceiveResult receivePackets(const ReceivePacketCallback& callback, uint32_t timeout = 5000,
		                             uint8_t batchSize = 64);

		/// @brief Request to stop an ongoing receivePackets(callback, ...) loop.
		/// @note This is thread-safe and can be called from a thread other than the receiving thread.
		void stopReceive();

		/// @brief Send a vector of raw packets in batches.
		///
		/// The method copies packet data into an internal buffer and calls WinDivert send in batches of batchSize.
		///
		/// @param[in] packetVec A vector of raw packets to send.
		/// @param[in] batchSize Number of packets to send per WinDivert call (must be > 0). Default is 64.
		/// @return A SendResult describing the outcome and number of packets sent.
		SendResult sendPackets(const RawPacketVector& packetVec, uint8_t batchSize = 64) const;

		/// @brief Get the current WinDivert queue parameters.
		/// @return A map from QueueParam to the configured value.
		QueueParams getPacketQueueParams() const;

		/// @brief Set WinDivert queue parameters.
		/// @param[in] params A map of queue parameters to set. Absent keys are left unchanged.
		/// @note Values units are: length (packets), time (milliseconds), size (bytes).
		void setPacketQueueParams(const QueueParams& params) const;

		/// @brief Get the WinDivert runtime version loaded on the system.
		/// @return A WinDivertVersion with major and minor components.
		WinDivertVersion getVersion() const;

		/// @brief Get a pointer to a specific Windows network interface by index.
		/// @param[in] interfaceIndex The Windows interface index.
		/// @return A pointer to an internal NetworkInterface entry or nullptr if not found.
		/// @warning The returned pointer may become invalid after subsequent calls that refresh interfaces.
		const NetworkInterface* getNetworkInterface(uint32_t interfaceIndex) const;

		/// @brief Enumerate Windows network interfaces.
		/// @return A vector of NetworkInterface entries.
		std::vector<NetworkInterface> getNetworkInterfaces() const;

		/// @brief Replace the underlying implementation (intended for testing/mocking).
		/// @param[in] implementation An implementation of the WinDivert backend APIs.
		void setImplementation(std::unique_ptr<internal::IWinDivertImplementation> implementation);

	private:
		std::unique_ptr<internal::IWinDivertImplementation> m_Impl;
		std::unique_ptr<internal::IWinDivertHandle> m_Handle;
		std::atomic<bool> m_IsReceiving{ false };
		mutable std::unordered_map<uint32_t, NetworkInterface> m_NetworkInterfaces;
		mutable bool m_NetworkInterfacesInitialized = false;

		struct ReceiveResultInternal : ReceiveResult
		{
			uint32_t capturedDataLength = 0;
			std::vector<internal::WinDivertAddress> addresses;

			ReceiveResultInternal(Status status, const std::string& error = "", uint32_t errorCode = 0)
			    : ReceiveResult{ status, error, errorCode }
			{}

			ReceiveResultInternal(uint32_t capturedDataLength, const std::vector<internal::WinDivertAddress>& addresses)
			    : ReceiveResult{ Status::Completed, "", 0 }, capturedDataLength(capturedDataLength),
			      addresses(addresses)
			{}
		};

		ReceiveResultInternal receivePacketsInternal(uint32_t timeout, uint8_t batchSize, std::vector<uint8_t>& buffer,
		                                             internal::IOverlappedWrapper* overlapped);
		static std::tuple<LinkLayerType, uint16_t, timespec> getPacketInfo(uint8_t* buffer, uint32_t bufferLen,
		                                                                   const internal::WinDivertAddress& address);
		void setNetworkInterfaces() const;
		static std::string getErrorString(uint32_t errorCode);
	};
}  // namespace pcpp
