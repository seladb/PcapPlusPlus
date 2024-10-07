#pragma once

#include "IpAddress.h"
#include "Layer.h"
#include "MacAddress.h"
#include "SystemUtils.h"
#include <iostream>

/**
 * @file GvcpLayer.h
 * @author An-Chi Liu (phy.tiger@gmail.com)
 */

/**
 * @namespace pcpp
 * @brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
	namespace internal
	{
		static constexpr size_t kGvcpMagicNumber = 0x42;
		static constexpr size_t kGvcpRequestHeaderLength = 8;
		static constexpr size_t kGvcpAckHeaderLength = 8;
		static constexpr size_t kGvcpDiscoveryBodyLength = 248;
		static constexpr size_t kGvcpForceIpBodyLength = 56;
	}  // namespace internal

	using GvcpFlag = uint8_t;  // flag bits are specified by each command

	/// @brief Gvcp command
	/// See spec "18 Command and Acknowledge Values"
	enum class GvcpCommand : uint16_t
	{
		// Discovery Protocol Control
		DiscoveredCmd = 0x0002,
		DiscoveredAck = 0x0003,
		ForceIpCmd = 0x0004,
		ForceIpAck = 0x0005,

		// Streaming Protocol Control
		PacketResendCmd = 0x0040,
		PacketResendAck = 0x0041,  // Resent packet must be on the stream channel

		// Device Memory Access
		ReadRegCmd = 0x0080,
		ReadRegAck = 0x0081,
		WriteRegCmd = 0x0082,
		WriteRegAck = 0x0083,
		ReadMemCmd = 0x0084,
		ReadMemAck = 0x0085,
		WriteMemCmd = 0x0086,
		WriteMemAck = 0x0087,
		PendingAck = 0x0089,

		// Asynchronous Events
		EventCmd = 0x00C0,
		EventAck = 0x00C1,
		EventDataCmd = 0x00C2,
		EventDataAck = 0x00C3,

		// Miscellaneous
		ActionCmd = 0x0100,
		ActionAck = 0x0101,
		Unknown = 0xFFFF
	};

	std::ostream& operator<<(std::ostream& os, GvcpCommand command);

	/// @brief Gvcp response status
	/// See spec "Table 19-1: List of Standard Status Codes"
	enum class GvcpResponseStatus : uint16_t
	{
		Success = 0x0000,
		PacketResend = 0x0100,
		NotImplemented = 0x8001,
		InvalidParameter = 0x8002,
		InvalidAddress = 0x8003,
		WriteProtect = 0x8004,
		BadAlignment = 0x8005,
		AccessDenied = 0x8006,
		Busy = 0x8007,
		LocalProblem = 0x8008,     // deprecated
		MsgMismatch = 0x8009,      // deprecated
		InvalidProtocol = 0x800A,  // deprecated
		NoMsg = 0x800B,            // deprecated
		PacketUnavailable = 0x800C,
		DataOverrun = 0x800D,
		InvalidHeader = 0x800E,
		WrongConfig = 0x800F,  // deprecated
		PacketNotYetAvailable = 0x8010,
		PacketAndPrevRemovedFromMemory = 0x8011,
		PacketRemovedFromMemory = 0x8012,
		NoRefTime = 0x8013,                     // GEV 2.0
		PacketTemporarilyUnavailable = 0x8014,  // GEV 2.0
		Overflow = 0x8015,                      // GEV 2.0
		ActionLate = 0x8016,                    // GEV 2.0
		LeaderTrailerOverflow = 0x8017,         // GEV 2.1
		Error = 0x8FFF,
		Unknown = 0xFFFF
	};

	std::ostream& operator<<(std::ostream& os, GvcpResponseStatus status);

#pragma pack(push, 1)
	/// @brief Gvcp request header
	/// @note refer to the spec "15.1 Request Header". The data is stored as big-endian.
	struct GvcpRequestHeader
	{
		friend class GvcpRequestLayer;

	protected:
		uint8_t magicNumber = internal::kGvcpMagicNumber;  // always fixed
		uint8_t flag = 0;  // 0-3 bits are specified by each command, 4-6 bits are reserved, 7 bit is acknowledge
		uint16_t command = 0;
		uint16_t dataSize = 0;
		uint16_t requestId = 0;

	public:
		// ------------- methods --------------
		GvcpRequestHeader() = default;

		GvcpRequestHeader(GvcpFlag flag, GvcpCommand command, uint16_t dataSize, uint16_t requestId)
		    : flag(flag), command(hostToNet16(static_cast<uint16_t>(command))), dataSize(hostToNet16(dataSize)),
		      requestId(hostToNet16(requestId))
		{}

		GvcpCommand getCommand() const
		{
			return static_cast<GvcpCommand>(netToHost16(command));
		}
	};
	static_assert(sizeof(GvcpRequestHeader) == internal::kGvcpRequestHeaderLength,
	              "Gvcp request header size should be 8 bytes");

	/// @brief Gvcp discovery request
	struct GvcpDiscoveryRequest : public GvcpRequestHeader
	{
		// no addition fields

		// ------------- methods --------------

		/**
		 * @brief Check if the broadcast is allowed
		 * @return true The broadcast acknowledge is allowed
		 */
		bool hasAllowBroadcastFlag() const
		{
			constexpr GvcpFlag kAllowBroadcastFlag = 0b0001000;
			return (flag & kAllowBroadcastFlag) == kAllowBroadcastFlag;
		}
	};

	/// @brief Gvcp acknowledge header
	/// @note refer to the spec "15.2 Acknowledge Header". The data is stored as big-endian.
	struct GvcpAckHeader
	{
		friend class GvcpAcknowledgeLayer;

	protected:
		uint16_t status = 0;
		uint16_t command = 0;
		uint16_t dataSize = 0;
		uint16_t ackId = 0;

	public:
		// ------------- methods --------------
		GvcpAckHeader() = default;

		GvcpAckHeader(GvcpResponseStatus status, GvcpCommand command, uint16_t dataSize, uint16_t ackId)
		    : status(hostToNet16(static_cast<uint16_t>(status))), command(hostToNet16(static_cast<uint16_t>(command))),
		      dataSize(hostToNet16(dataSize)), ackId(hostToNet16(ackId))
		{}

		GvcpCommand getCommand() const
		{
			return static_cast<GvcpCommand>(netToHost16(command));
		}
	};
	static_assert(sizeof(GvcpAckHeader) == internal::kGvcpAckHeaderLength, "Gvcp ack header size should be 8 bytes");

	/// @brief Gvcp discovery acknowledge body
	/// @note refer to the spec "16.1.2 DISCOVERY_ACK". The data is stored as big-endian.
	struct GvcpDiscoveryBody
	{
		uint16_t versionMajor = 0;
		uint16_t versionMinor = 0;
		uint32_t deviceMode = 0;
		uint16_t reserved = 0;
		uint8_t macAddress[6] = { 0 };
		uint32_t supportedIpConfigOptions = 0;
		uint32_t ipConfigCurrent = 0;
		uint8_t reserved2[12] = { 0 };
		uint32_t ipAddress = 0;
		uint8_t reserved3[12];
		uint32_t subnetMask = 0;
		uint8_t reserved4[12] = { 0 };
		uint32_t defaultGateway = 0;
		char manufacturerName[32] = { 0 };
		char modelName[32] = { 0 };
		char deviceVersion[32] = { 0 };
		char manufacturerSpecificInformation[48] = { 0 };
		char serialNumber[16] = { 0 };
		char userDefinedName[16] = { 0 };
	};
	static_assert(sizeof(GvcpDiscoveryBody) == internal::kGvcpDiscoveryBodyLength,
	              "Gvcp ack body size should be 248 bytes");

	/// @brief GVCP force IP command body
	/// @note refer to the spec "16.2 FORCEIP". The data is stored as big-endian.
	struct GvcpForceIpBody
	{
		char padding1[2] = { 0 };
		char macAddress[6] = { 0 };
		char padding2[12] = { 0 };
		uint32_t ipAddress = 0;
		char padding3[12] = { 0 };
		uint32_t subnetMask = 0;
		char padding4[12] = { 0 };
		uint32_t gateway = 0;
	};
	static_assert(sizeof(GvcpForceIpBody) == internal::kGvcpForceIpBodyLength,
	              "GVCP force IP command body size should be 56 bytes");
#pragma pack(pop)

	/**
	 * @class GvcpLayer
	 * A class representing the GigE Vision protocol(GVCP).
	 * The class is implemented according to the GigE Vision specification 2.0.
	 * @see https://en.wikipedia.org/wiki/GigE_Vision
	 * @note The class cannot be instantiated directly.
	 */
	class GvcpLayer : public Layer
	{
	public:
		/**
		 * A static method that checks whether the port is considered as GVCP
		 * @param[in] port The port number to be checked
		 */
		static bool isGvcpPort(uint16_t port)
		{
			return port == 3956;
		}

		/**
		 * @brief Get the magic number
		 * @return uint8_t The magic number
		 */
		static bool verifyRequest(const uint8_t* data)
		{
			return data[0] == internal::kGvcpMagicNumber;
		};

		/**
		 * @brief Construct a new GvcpLayer object
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 * @return GvcpLayer* A pointer to the constructed GvcpLayer object
		 */
		static GvcpLayer* parseGvcpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

	protected:
		GvcpLayer() = default;

		/**
		 * @brief Construct a new GvcpLayer object
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		GvcpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		// implement Layer's abstract methods
		void parseNextLayer() override
		{}

		// implement Layer's abstract methods
		void computeCalculateFields() override
		{}

		// implement Layer's abstract methods
		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelLayer::OsiModelApplicationLayer;
		}
	};

	/// @brief Gvcp request layer
	class GvcpRequestLayer : public GvcpLayer
	{
	public:
		/**
		 * @brief Construct a new GvcpLayer object
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		GvcpRequestLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/**
		 * @brief Construct a new GvcpRequestLayer object
		 * @param[in] data A pointer to the data including the header and the payload
		 * @param[in] dataSize The size of the data in bytes
		 */
		GvcpRequestLayer(const uint8_t* data, size_t dataSize);

		/**
		 * @brief Construct a new GvcpRequestLayer object
		 * @param[in] command The command
		 * @param[in] payloadData A pointer to the payload data, optional
		 * @param[in] payloadDataSize The size of the payload data in bytes, optional
		 * @param[in] flag The flag, optional
		 * @param[in] requestId The request ID, it should be always larger than 1, optional
		 * @note all the parameters will be converted to the network byte order
		 */
		explicit GvcpRequestLayer(GvcpCommand command, const uint8_t* payloadData = nullptr,
		                          uint16_t payloadDataSize = 0, GvcpFlag flag = 0, uint16_t requestId = 1);

		/**
		 * @brief Get the header object
		 * @return GvcpRequestHeader* A pointer to the header object
		 */
		GvcpRequestHeader* getGvcpHeader() const
		{
			return reinterpret_cast<GvcpRequestHeader*>(m_Data);  // the header is at the beginning of the data
		}

		/**
		 * @brief Get the flag from the header
		 */
		GvcpFlag getFlag() const
		{
			return getGvcpHeader()->flag;
		}

		/**
		 * @brief Get the data size from the header
		 */
		uint16_t getDataSize() const
		{
			return netToHost16(getGvcpHeader()->dataSize);
		}

		/**
		 * @brief Get the request ID from the header
		 */
		uint16_t getRequestId() const
		{
			return netToHost16(getGvcpHeader()->requestId);
		}

		/**
		 * @brief Get the command from the header
		 */
		GvcpCommand getCommand() const
		{
			return static_cast<GvcpCommand>(netToHost16(getGvcpHeader()->command));
		}

		/**
		 * @brief Verify the magic number in the header
		 * @return true The magic number is valid
		 */
		bool verifyMagicNumber() const
		{
			return getGvcpHeader()->magicNumber == internal::kGvcpMagicNumber;
		}

		/**
		 * @brief Check if the acknowledge is required from the header
		 * @return true The acknowledge is required
		 */
		bool hasAcknowledgeFlag() const
		{
			constexpr GvcpFlag kAcknowledgeFlag = 0b0000001;
			return (getGvcpHeader()->flag & kAcknowledgeFlag) == kAcknowledgeFlag;
		}

		// implement Layer's abstract methods
		std::string toString() const override;

		// implement Layer's abstract methods
		size_t getHeaderLen() const override
		{
			return sizeof(GvcpRequestHeader);
		}
	};

	/// @brief Gvcp acknowledge layer
	class GvcpAcknowledgeLayer : public GvcpLayer
	{
	public:
		/**
		 * @brief Construct a new GvcpLayer object
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		GvcpAcknowledgeLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/**
		 * @brief Construct a new GvcpRequestLayer object
		 * @param[in] data A pointer to the data including the header and the payload
		 * @param[in] dataSize The size of the data in bytes
		 */
		GvcpAcknowledgeLayer(const uint8_t* data, size_t dataSize);

		/**
		 * @brief Construct a new GvcpAcknowledgeLayer object
		 * @param[in] status The response status
		 * @param[in] command The command
		 * @param[in] payloadData A pointer to the payload data, optional
		 * @param[in] payloadDataSize The size of the payload data in bytes, optional
		 * @param[in] ackId The acknowledge ID, optional
		 * @note all the parameters will be converted to the network byte order
		 */
		GvcpAcknowledgeLayer(GvcpResponseStatus status, GvcpCommand command, const uint8_t* payloadData = nullptr,
		                     uint16_t payloadDataSize = 0, uint16_t ackId = 0);

		/**
		 * @brief Get the header object
		 * @return GvcpAckHeader* A pointer to the header object
		 */
		GvcpAckHeader* getGvcpHeader() const
		{
			return reinterpret_cast<GvcpAckHeader*>(m_Data);  // the header is at the beginning of the data
		}

		/**
		 * @return the response status from the header
		 */
		GvcpResponseStatus getStatus() const
		{
			return static_cast<GvcpResponseStatus>((netToHost16(getGvcpHeader()->status)));
		}

		/**
		 * @return the response command type from the header
		 */
		GvcpCommand getCommand() const
		{
			return static_cast<GvcpCommand>(netToHost16(getGvcpHeader()->command));
		}

		/**
		 * @return the size of the data in bytes from the header
		 */
		uint16_t getDataSize() const
		{
			return netToHost16(getGvcpHeader()->dataSize);
		}

		/**
		 * @return uint16_t The acknowledge ID from the header
		 */
		uint16_t getAckId() const
		{
			return netToHost16(getGvcpHeader()->ackId);
		}

		// implement Layer's abstract methods
		std::string toString() const override;

		// implement Layer's abstract methods
		size_t getHeaderLen() const override
		{
			return sizeof(GvcpAckHeader);
		}
	};

	// ---------------------------------------- Special Layer ----------------------------------------

	/// @brief Gvcp discovery request layer
	class GvcpDiscoveryRequestLayer : public GvcpRequestLayer
	{
	public:
		/**
		 * @brief Construct a new GvcpLayer object
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		GvcpDiscoveryRequestLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : GvcpRequestLayer(data, dataLen, prevLayer, packet) {};

		/**
		 * @brief Construct a new GvcpRequestLayer object
		 * @param[in] data A pointer to the data including the header and the payload
		 * @param[in] dataSize The size of the data in bytes
		 */
		explicit GvcpDiscoveryRequestLayer(const uint8_t* data, size_t dataSize) : GvcpRequestLayer(data, dataSize) {};

		/**
		 * @brief Construct a new GvcpRequestLayer object
		 * @param[in] payloadData A pointer to the payload data, optional
		 * @param[in] payloadDataSize The size of the payload data in bytes, optional
		 * @param[in] flag The flag, optional
		 * @param[in] requestId The request ID, it should be always larger than 1, optional
		 * @note all the parameters will be converted to the network byte order
		 */
		explicit GvcpDiscoveryRequestLayer(const uint8_t* payloadData = nullptr, uint16_t payloadDataSize = 0,
		                                   GvcpFlag flag = 0, uint16_t requestId = 1)
		    : GvcpRequestLayer(GvcpCommand::DiscoveredCmd, payloadData, payloadDataSize, flag, requestId) {};
	};

	/// @brief Gvcp discovery acknowledge layer
	class GvcpDiscoveryAcknowledgeLayer : public GvcpAcknowledgeLayer
	{
	public:
		/**
		 * @brief Construct a new GvcpLayer object
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		GvcpDiscoveryAcknowledgeLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : GvcpAcknowledgeLayer(data, dataLen, prevLayer, packet) {};

		/**
		 * @brief Construct a new GvcpRequestLayer object
		 * @param[in] data A pointer to the data including the header and the payload
		 * @param[in] dataSize The size of the data in bytes
		 */
		GvcpDiscoveryAcknowledgeLayer(const uint8_t* data, uint16_t dataSize) : GvcpAcknowledgeLayer(data, dataSize) {};

		/**
		 * @brief Construct a new GvcpAcknowledgeLayer object
		 * @param[in] status The response status
		 * @param[in] payloadData A pointer to the payload data, optional
		 * @param[in] payloadDataSize The size of the payload data in bytes, optional
		 * @param[in] ackId The acknowledge ID, optional
		 * @note all the parameters will be converted to the network byte order
		 */
		explicit GvcpDiscoveryAcknowledgeLayer(GvcpResponseStatus status, const uint8_t* payloadData = nullptr,
		                                       uint16_t payloadDataSize = 0, uint16_t ackId = 0)
		    : GvcpAcknowledgeLayer(status, GvcpCommand::DiscoveredAck, payloadData, payloadDataSize, ackId) {};

		/**
		 * @brief Get the version
		 * @return std::pair<uint16_t, uint16_t> The version major and minor
		 */
		std::pair<uint16_t, uint16_t> getVersion() const
		{
			auto body = this->getGvcpDiscoveryBody();
			return { body->versionMajor, body->versionMinor };
		}

		/**
		 * @brief Get the IP address
		 * @return pcpp::IPAddress The IP address. Throw if the IP address is invalid.
		 */
		pcpp::MacAddress getMacAddress() const
		{
			auto body = this->getGvcpDiscoveryBody();
			return pcpp::MacAddress(body->macAddress);
		}

		/**
		 * @brief Get the IP address
		 * @return pcpp::IPAddress The IP address. Throw if the IP address is invalid.
		 */
		pcpp::IPv4Address getIpAddress() const
		{
			auto body = this->getGvcpDiscoveryBody();
			return pcpp::IPv4Address(body->ipAddress);
		}

		/**
		 * @brief Get the subnet mask
		 * @return pcpp::IPAddress The subnet mask. Throw if the subnet mask is invalid.
		 */
		pcpp::IPv4Address getSubnetMask() const
		{
			auto body = this->getGvcpDiscoveryBody();
			return pcpp::IPv4Address(body->subnetMask);
		}

		/**
		 * @brief Get the gateway IP address
		 * @return pcpp::IPAddress The gateway IP address. Throw if the gateway IP address is invalid.
		 */
		pcpp::IPv4Address getGatewayIpAddress() const
		{
			auto body = this->getGvcpDiscoveryBody();
			return pcpp::IPv4Address(body->defaultGateway);
		}

		/**
		 * @brief Get the manufacturer name
		 * @return std::string The manufacturer name
		 */
		std::string getManufacturerName() const
		{
			auto body = this->getGvcpDiscoveryBody();
			return std::string(body->manufacturerName);
		}

		/**
		 * @brief Get the model name
		 * @return std::string The model name
		 */
		std::string getModelName() const
		{
			auto body = this->getGvcpDiscoveryBody();
			return std::string(body->modelName);
		}

		/**
		 * @brief Get the device version
		 * @return std::string The device version
		 */
		std::string getDeviceVersion() const
		{
			auto body = this->getGvcpDiscoveryBody();
			return std::string(body->deviceVersion);
		}

		/**
		 * @brief Get the manufacturer specific information
		 * @return std::string The manufacturer specific information
		 */
		std::string getManufacturerSpecificInformation() const
		{
			auto body = this->getGvcpDiscoveryBody();
			return std::string(body->manufacturerSpecificInformation);
		}

		/**
		 * @brief Get the serial number
		 * @return std::string The serial number
		 */
		std::string getSerialNumber() const
		{
			auto body = this->getGvcpDiscoveryBody();
			return std::string(body->serialNumber);
		}

		/**
		 * @brief Get the user defined name
		 * @return std::string The user defined name
		 */
		std::string getUserDefinedName() const
		{
			auto body = this->getGvcpDiscoveryBody();
			return std::string(body->userDefinedName);
		}

	private:
		GvcpDiscoveryBody* getGvcpDiscoveryBody() const
		{
			return reinterpret_cast<GvcpDiscoveryBody*>(m_Data + getHeaderLen());
		}
	};

	/// @brief Gvcp force IP request layer
	class GvcpForceIpRequestLayer : public GvcpRequestLayer
	{
	public:
		/**
		 * @brief Construct a new GvcpLayer object
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		GvcpForceIpRequestLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : GvcpRequestLayer(data, dataLen, prevLayer, packet) {};

		/**
		 * @brief Construct a new GvcpRequestLayer object
		 * @param[in] data A pointer to the data including the header and the payload
		 * @param[in] dataSize The size of the data in bytes
		 */
		explicit GvcpForceIpRequestLayer(const uint8_t* data, size_t dataSize) : GvcpRequestLayer(data, dataSize) {};

		/**
		 * @brief Construct a new GvcpRequestLayer object
		 * @param[in] payloadData A pointer to the payload data, optional
		 * @param[in] payloadDataSize The size of the payload data in bytes, optional
		 * @param[in] flag The flag, optional
		 * @param[in] requestId The request ID, it should be always larger than 1, optional
		 * @note all the parameters will be converted to the network byte order
		 */
		explicit GvcpForceIpRequestLayer(const uint8_t* payloadData = nullptr, uint16_t payloadDataSize = 0,
		                                 GvcpFlag flag = 0, uint16_t requestId = 1)
		    : GvcpRequestLayer(GvcpCommand::ForceIpCmd, payloadData, payloadDataSize, flag, requestId) {};

		/**
		 * @brief Get the IP address
		 * @return pcpp::IPAddress The IP address. Throw if the IP address is invalid.
		 */
		pcpp::MacAddress getMacAddress() const
		{
			auto body = this->getGvcpForceIpBody();
			return pcpp::MacAddress(reinterpret_cast<const uint8_t*>(body->macAddress));
		}

		/**
		 * @brief Get the IP address
		 * @return pcpp::IPAddress The IP address. Throw if the IP address is invalid.
		 */
		pcpp::IPv4Address getIpAddress() const
		{
			auto body = this->getGvcpForceIpBody();
			return pcpp::IPv4Address(body->ipAddress);
		}

		/**
		 * @brief Get the subnet mask
		 * @return pcpp::IPAddress The subnet mask. Throw if the subnet mask is invalid.
		 */
		pcpp::IPv4Address getSubnetMask() const
		{
			auto body = this->getGvcpForceIpBody();
			return pcpp::IPv4Address(body->subnetMask);
		}

		/**
		 * @brief Get the gateway IP address
		 * @return pcpp::IPAddress The gateway IP address. Throw if the gateway IP address is invalid.
		 */
		pcpp::IPv4Address getGatewayIpAddress() const
		{
			auto body = this->getGvcpForceIpBody();
			return pcpp::IPv4Address(body->gateway);
		}

	private:
		GvcpForceIpBody* getGvcpForceIpBody() const
		{
			return reinterpret_cast<GvcpForceIpBody*>(m_Data + getHeaderLen());
		}
	};

	/// @brief Gvcp force IP acknowledge layer
	class GvcpForceIpAcknowledgeLayer : public GvcpAcknowledgeLayer
	{
	public:
		/**
		 * @brief Construct a new GvcpLayer object
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		GvcpForceIpAcknowledgeLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : GvcpAcknowledgeLayer(data, dataLen, prevLayer, packet) {};

		/**
		 * @brief Construct a new GvcpRequestLayer object
		 * @param[in] data A pointer to the data including the header and the payload
		 * @param[in] dataSize The size of the data in bytes
		 */
		GvcpForceIpAcknowledgeLayer(const uint8_t* data, size_t dataSize) : GvcpAcknowledgeLayer(data, dataSize) {};

		/**
		 * @brief Construct a new GvcpAcknowledgeLayer object
		 * @param[in] status The response status
		 * @param[in] payloadData A pointer to the payload data, optional
		 * @param[in] payloadDataSize The size of the payload data in bytes, optional
		 * @param[in] ackId The acknowledge ID, optional
		 * @note all the parameters will be converted to the network byte order
		 */
		explicit GvcpForceIpAcknowledgeLayer(GvcpResponseStatus status, const uint8_t* payloadData = nullptr,
		                                     uint16_t payloadDataSize = 0, uint16_t ackId = 0)
		    : GvcpAcknowledgeLayer(status, GvcpCommand::ForceIpAck, payloadData, payloadDataSize, ackId) {};
	};
}  // namespace pcpp
