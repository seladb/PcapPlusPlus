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

				Status status;           ///< Final wait status
				uint32_t errorCode = 0;  ///< Windows error code (when relevant)
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
					Success,  ///< Operation completed successfully
					Failed    ///< Operation failed; see errorCode
				};

				Status status;           ///< Completion status
				uint32_t packetLen = 0;  ///< Number of bytes read/written (when applicable)
				uint32_t errorCode = 0;  ///< Windows error code (when relevant)
			};

			virtual WaitResult wait(uint32_t timeout) = 0;
			virtual void reset() = 0;
			virtual OverlappedResult getOverlappedResult() = 0;
			virtual ~IOverlappedWrapper() = default;
		};

		/// @brief Minimal address/metadata returned by WinDivert for a captured packet.
		///
		/// This structure mirrors the subset of fields PcapPlusPlus needs from WinDivert's
		/// WINDIVERT_ADDRESS: whether the packet is IPv6, the Windows interface index and
		/// the original WinDivert timestamp.
		struct WinDivertAddress
		{
			bool isIPv6;              ///< True if the packet is IPv6, false for IPv4
			uint32_t interfaceIndex;  ///< Windows network interface index
			uint64_t timestamp;       ///< WinDivert timestamp associated with the packet
		};

		/// @class IWinDivertHandle
		/// @brief An abstract handle for interacting with the WinDivert device.
		///
		/// This interface represents an opened WinDivert handle and provides the minimal
		/// set of operations used by WinDivertDevice: asynchronous receive, batched send,
		/// querying/setting queue parameters and handle closure. Concrete implementations
		/// wrap the corresponding WinDivert C APIs and Windows OVERLAPPED I/O.
		class IWinDivertHandle
		{
		public:
			/// @brief WinDivert runtime parameters that can be queried or configured.
			enum class WinDivertParam
			{
				QueueLength = 0,   ///< Maximum number of packets in the queue
				QueueTime = 1,     ///< Maximum time (ms) a packet may stay in the queue
				QueueSize = 2,     ///< Maximum total queue size (bytes)
				VersionMajor = 3,  ///< WinDivert major version
				VersionMinor = 4   ///< WinDivert minor version
			};

			/// @brief Generic success code returned by most operations.
			static constexpr uint32_t SuccessResult = 0;
			/// @brief Windows ERROR_IO_PENDING (997) reported when an async operation is in flight.
			static constexpr uint32_t ErrorIoPending = 997;

			virtual ~IWinDivertHandle() = default;

			/// @brief Close the underlying WinDivert handle.
			/// @return Windows error code-style result. 0 indicates success.
			virtual uint32_t close() = 0;

			/// @brief Begin or perform an overlapped receive of raw packet data.
			///
			/// If an overlapped object is provided, the call initiates an asynchronous read
			/// and typically returns ErrorIoPending. Completion status and size should be
			/// obtained via the provided IOverlappedWrapper.
			///
			/// @param[in] buffer          Destination buffer for packet data.
			/// @param[in] bufferLen       Size of the destination buffer in bytes.
			/// @param[in] addressesSize   Number of address entries the implementation may capture for a batch.
			/// @param[in] overlapped      Wrapper around Windows OVERLAPPED used for async I/O. Must not be null for
			/// async.
			/// @return 0 on success, ErrorIoPending if async operation started, or a Windows error code on failure.
			virtual uint32_t recvEx(uint8_t* buffer, uint32_t bufferLen, size_t addressesSize,
			                        IOverlappedWrapper* overlapped) = 0;

			/// @brief Finalize a previous overlapped receive and fetch per-packet address metadata.
			/// @return A vector of WinDivertAddress entries, one per packet captured in the last receive.
			virtual std::vector<WinDivertAddress> recvExComplete() = 0;

			/// @brief Send a batch of raw packets.
			/// @param[in] buffer        Buffer containing one or more consecutive packets.
			/// @param[in] bufferLen     Total size in bytes of the packets contained in buffer.
			/// @param[in] addressesSize Number of address entries accompanying the send batch.
			/// @return 0 on success, otherwise a Windows error code.
			virtual uint32_t sendEx(uint8_t* buffer, uint32_t bufferLen, size_t addressesSize) = 0;

			/// @brief Create a new overlapped wrapper bound to this handle.
			/// @return A unique_ptr to a fresh IOverlappedWrapper for async operations.
			virtual std::unique_ptr<IOverlappedWrapper> createOverlapped() = 0;

			/// @brief Query a WinDivert runtime/queue parameter.
			/// @param[in]  param The parameter to query.
			/// @param[out] value The retrieved value.
			/// @return True on success, false on failure.
			virtual bool getParam(WinDivertParam param, uint64_t& value) = 0;

			/// @brief Set a WinDivert runtime/queue parameter.
			/// @param[in] param The parameter to set.
			/// @param[in] value The value to set.
			/// @return True on success, false on failure.
			virtual bool setParam(WinDivertParam param, uint64_t value) = 0;
		};

		/// @class IWinDivertDriver
		/// @brief Factory and system-query abstraction used by WinDivertDevice.
		///
		/// The sole responsibilities of this interface are:
		/// - Creating IWinDivertHandle instances (which expose the WinDivert API surface).
		/// - Enumerating relevant Windows network interfaces.
		/// Keeping these responsibilities here keeps WinDivertDevice decoupled from concrete
		/// system/driver calls and enables unit testing and alternative implementations.
		class IWinDivertDriver
		{
		public:
			/// @brief Information about a Windows network interface as reported by WinDivert/Windows APIs.
			struct NetworkInterface
			{
				uint32_t index;            ///< Interface index as provided by Windows
				std::wstring name;         ///< Interface name (GUID or friendly/system name)
				std::wstring description;  ///< Human-readable description from the OS
				bool isLoopback;           ///< True if the interface type is software loopback
				bool isUp;                 ///< True when the interface operational status is up
			};

			/// @brief Open a WinDivert handle with the given filter and settings.
			/// @param[in] filter   WinDivert filter string (see WinDivert documentation).
			/// @param[in] layer    WinDivert layer value (typically WINDIVERT_LAYER_NETWORK).
			/// @param[in] priority Injection/capture priority (lower is higher priority).
			/// @param[in] flags    WinDivert open flags (sniff mode, fragments, etc.).
			/// @return A unique_ptr to an IWinDivertHandle on success, or nullptr on failure.
			virtual std::unique_ptr<IWinDivertHandle> open(const std::string& filter, int layer, int16_t priority,
			                                               uint64_t flags) = 0;

			/// @brief Enumerate Windows network interfaces relevant to WinDivert.
			/// @return A vector of NetworkInterface objects with index, name, description and status.
			virtual std::vector<NetworkInterface> getNetworkInterfaces() const = 0;

			virtual ~IWinDivertDriver() = default;
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

		~WinDivertRawPacket() override = default;

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
	/// - The default open() uses the filter "true", capturing both directions.
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
			uint32_t index;            ///< Interface index as provided by Windows
			std::wstring name;         ///< Interface name (GUID or friendly/system name)
			std::wstring description;  ///< Human-readable description from the OS
			bool isLoopback;           ///< True if the interface type is software loopback
			bool isUp;                 ///< True when the interface operational status is up
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

		/// @struct WinDivertReceiveCallbackContext
		/// @brief Context object passed to ReceivePacketCallback.
		struct WinDivertReceiveCallbackContext
		{
			WinDivertDevice* device = nullptr;  ///< The device that owns the receive loop (may be null)
		};

		/// @brief Callback invoked with a batch of received packets when using the callback receive API.
		/// The callback is called from the receiving loop until stopReceive() is invoked or an error/timeout occurs.
		///
		/// @param[in] packetVec A list of the currently received batch of WinDivertRawPacket objects.
		/// @param[in] context   A context object providing the calling device and, potentially, other metadata.
		using ReceivePacketCallback = std::function<void(const WinDivertRawPacketVector& packetVec,
		                                                 const WinDivertReceiveCallbackContext& context)>;
		/// @typedef QueueParams
		/// @brief A map of QueueParam keys to their values. Units are per QueueParam description above.
		using QueueParams = std::unordered_map<QueueParam, uint64_t>;

		/// @brief Construct a WinDivertDevice.
		///
		/// @param[in] driver Optional WinDivert driver implementation.
		/// Ownership is transferred to WinDivertDevice. Pass nullptr (the default)
		/// to use the built-in default driver implementation.
		WinDivertDevice(std::unique_ptr<internal::IWinDivertDriver> driver = nullptr);

		/// @brief Open the device with a default filter capturing both directions.
		/// @return true on success, false on failure (see logs for details).
		/// @note This calls open("true") on WINDIVERT_LAYER_NETWORK with sniffing/fragments flags.
		bool open() override;

		/// @brief Open the device with a custom WinDivert filter.
		/// @param[in] filter A WinDivert filter string (e.g. "ip and tcp.DstPort == 80").
		/// @return true on success, false on failure (see logs for details).
		/// @note The device is opened on WINDIVERT_LAYER_NETWORK with sniffing and fragment support.
		bool open(const std::string& filter);

		/// @brief Close the device and release the underlying WinDivert handle.
		void close() override;

		bool isOpened() const override
		{
			return m_DeviceOpened;
		}

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

	private:
		std::unique_ptr<internal::IWinDivertDriver> m_Driver;
		std::unique_ptr<internal::IWinDivertHandle> m_Handle;
		std::atomic<bool> m_IsReceiving{ false };
		mutable std::unordered_map<uint32_t, NetworkInterface> m_NetworkInterfaces;
		mutable bool m_NetworkInterfacesInitialized = false;
		bool m_DeviceOpened = false;

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
