#pragma once

#include "IpAddress.h"
#include "Layer.h"
#include "MacAddress.h"
#include <iostream>

/// @file

/// This GVCP implementation is based on GigE Vision ® Specification version 2.0

/**
 * @namespace pcpp
 * The main namespace for the PcapPlusPlus lib
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

	/**
	 * GVCP command defines the command values and the corresponding acknowledge values
	 * See more in the spec "18 Command and Acknowledge Values"
	 */
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

	/// output operator for GvcpCommand
	std::ostream& operator<<(std::ostream& os, GvcpCommand command);

	/**
	 * GVCP response status can be returned in an acknowledge message or a GVSP header.
	 * See more in the spec "Table 19-1: List of Standard Status Codes"
	 */
	enum class GvcpResponseStatus : uint16_t
	{
		Success = 0x0000,         ///< Command executed successfully
		PacketResend = 0x0100,    ///< Only applies to packet being resent
		NotImplemented = 0x8001,  ///< Command is not supported by the device
		InvalidParameter =
		    0x8002,  ///< At least one parameter provided in the command is invalid (or out of range) for the device
		InvalidAddress = 0x8003,  ///< An attempt was made to access a non-existent address space location.
		WriteProtect = 0x8004,    ///< The addressed register cannot be written to
		BadAlignment = 0x8005,    ///< A badly aligned address offset or data size was specified.
		AccessDenied =
		    0x8006,  ///< An attempt was made to access an address location which is currently/momentary not accessible
		Busy = 0x8007,  ///< A required resource to service the request is not currently available. The request may be
		                ///< retried at a later time
		LocalProblem = 0x8008,       ///< deprecated
		MsgMismatch = 0x8009,        ///< deprecated
		InvalidProtocol = 0x800A,    ///< deprecated
		NoMsg = 0x800B,              ///< deprecated
		PacketUnavailable = 0x800C,  ///< The requested packet is not available anymore
		DataOverrun = 0x800D,        ///< Internal memory of GVSP transmitter overrun (typically for image acquisition)
		InvalidHeader = 0x800E,  ///< The message header is not valid. Some of its fields do not match the specification
		WrongConfig = 0x800F,    ///< deprecated
		PacketNotYetAvailable = 0x8010,  ///< The requested packet has not yet been acquired. Can be used for linescan
		                                 ///< cameras device when line trigger rate is slower than application timeout
		PacketAndPrevRemovedFromMemory = 0x8011,  ///< The requested packet and all previous ones are not available
		                                          ///< anymore and have been discarded from the GVSP transmitter memory
		PacketRemovedFromMemory = 0x8012,  ///< The requested packet is not available anymore and has been discarded
		                                   ///< from the GVSP transmitter memory
		NoRefTime = 0x8013,  ///< The device is not synchronized to a master clock to be used as time reference
		PacketTemporarilyUnavailable = 0x8014,  ///< The packet cannot be resent at the moment due to temporary
		                                        ///< bandwidth issues and should be requested again in the future
		Overflow = 0x8015,                      ///< A device queue or packet data has overflowed
		ActionLate = 0x8016,  ///< The requested scheduled action command was requested at a time that is already past
		LeaderTrailerOverflow = 0x8017,  // GEV 2.1
		Error = 0x8FFF,                  ///< Generic error
		Unknown = 0xFFFF                 ///< Unknown status
	};

	std::ostream& operator<<(std::ostream& os, GvcpResponseStatus status);

	namespace internal
	{

#pragma pack(push, 1)
		/**
		 * GVCP request header
		 * refer to the spec "15.1 Request Header". The data is stored as big-endian.
		 */
		struct gvcp_request_header
		{
			uint8_t magicNumber = internal::kGvcpMagicNumber;  ///< Magic number
			uint8_t flag =
			    0;  ///< GVCP flag. 0-3 bits are specified by each command, 4-6 bits are reserved, 7 bit is acknowledge
			uint16_t command = 0;    ///< Command
			uint16_t dataSize = 0;   ///< Data size
			uint16_t requestId = 0;  ///< Request ID

			// ------------- methods --------------
			gvcp_request_header() = default;

			gvcp_request_header(GvcpFlag flag, GvcpCommand command, uint16_t dataSize, uint16_t requestId);

			GvcpCommand getCommand() const;
		};
		static_assert(sizeof(gvcp_request_header) == internal::kGvcpRequestHeaderLength,
		              "GVCP request header size should be 8 bytes");

		/**
		 * GVCP acknowledge header
		 * refer to the spec "15.2 Acknowledge Header". The data is stored as big-endian.
		 */
		struct gvcp_ack_header
		{
			uint16_t status = 0;    ///< Response status
			uint16_t command = 0;   ///< Command
			uint16_t dataSize = 0;  ///< Data size
			uint16_t ackId = 0;     ///< Acknowledge ID

			// ------------- methods --------------
			gvcp_ack_header() = default;

			gvcp_ack_header(GvcpResponseStatus status, GvcpCommand command, uint16_t dataSize, uint16_t ackId);

			GvcpCommand getCommand() const;
		};
		static_assert(sizeof(gvcp_ack_header) == internal::kGvcpAckHeaderLength,
		              "GVCP ack header size should be 8 bytes");

		/**
		 * GVCP discovery acknowledge body
		 * refer to the spec "16.1.2 DISCOVERY_ACK". The data is stored as big-endian.
		 */
		struct gvcp_discovery_body
		{
			uint16_t versionMajor = 0;                         ///< GigE Vision version major number
			uint16_t versionMinor = 0;                         ///< GigE Vision version minor number
			uint32_t deviceMode = 0;                           ///< Device mode
			uint16_t reserved = 0;                             ///< Reserved
			uint8_t macAddress[6] = { 0 };                     ///< MAC address
			uint32_t supportedIpConfigOptions = 0;             ///< Supported IP configuration options
			uint32_t ipConfigCurrent = 0;                      ///< Current IP configuration
			uint8_t reserved2[12] = { 0 };                     ///< Reserved
			uint32_t ipAddress = 0;                            ///< IP address
			uint8_t reserved3[12];                             ///< Reserved
			uint32_t subnetMask = 0;                           ///< Subnet mask
			uint8_t reserved4[12] = { 0 };                     ///< Reserved
			uint32_t defaultGateway = 0;                       ///< Default gateway
			char manufacturerName[32] = { 0 };                 ///< Manufacturer name
			char modelName[32] = { 0 };                        ///< Model name
			char deviceVersion[32] = { 0 };                    ///< Device version
			char manufacturerSpecificInformation[48] = { 0 };  ///< Manufacturer specific information
			char serialNumber[16] = { 0 };                     ///< Serial number
			char userDefinedName[16] = { 0 };                  ///< User defined name
		};
		static_assert(sizeof(gvcp_discovery_body) == internal::kGvcpDiscoveryBodyLength,
		              "GVCP ack body size should be 248 bytes");

		/**
		 * GVCP force IP command body
		 * refer to the spec "16.2 FORCEIP". The data is stored as big-endian.
		 */
		struct gvcp_forceip_body
		{
			char padding1[2] = { 0 };    ///< Padding
			char macAddress[6] = { 0 };  ///< MAC address
			char padding2[12] = { 0 };   ///< Padding
			uint32_t ipAddress = 0;      ///< IP address
			char padding3[12] = { 0 };   ///< Padding
			uint32_t subnetMask = 0;     ///< Subnet mask
			char padding4[12] = { 0 };   ///< Padding
			uint32_t gateway = 0;        ///< Gateway
		};
		static_assert(sizeof(gvcp_forceip_body) == internal::kGvcpForceIpBodyLength,
		              "GVCP force IP command body size should be 56 bytes");
#pragma pack(pop)
	}  // namespace internal

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
		 * Get the magic number
		 * @return uint8_t The magic number
		 */
		static bool verifyRequest(const uint8_t* data)
		{
			return data[0] == internal::kGvcpMagicNumber;
		};

		/**
		 * Construct a new GvcpLayer object
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 * @return GvcpLayer* A pointer to the constructed GvcpLayer object
		 */
		static GvcpLayer* parseGvcpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

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

	protected:
		GvcpLayer() = default;

		/**
		 * Construct a new GvcpLayer object
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		GvcpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);
	};

	/**
	 * GVCP request layer
	 */
	class GvcpRequestLayer : public GvcpLayer
	{
	public:
		/**
		 * Construct a new GvcpLayer object
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		GvcpRequestLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/**
		 * Construct a new GvcpRequestLayer object
		 * @param[in] data A pointer to the data including the header and the payload
		 * @param[in] dataSize The size of the data in bytes
		 */
		GvcpRequestLayer(const uint8_t* data, size_t dataSize);

		/**
		 * Construct a new GvcpRequestLayer object
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
		 * Get the flag from the header
		 */
		GvcpFlag getFlag() const
		{
			return getGvcpHeader()->flag;
		}

		/**
		 * Get the data size from the header
		 */
		uint16_t getDataSize() const;

		/**
		 * Get the request ID from the header
		 */
		uint16_t getRequestId() const;

		/**
		 * Get the command from the header
		 */
		GvcpCommand getCommand() const;

		/**
		 * Verify the magic number in the header
		 * @return true The magic number is valid
		 */
		bool verifyMagicNumber() const
		{
			return getGvcpHeader()->magicNumber == internal::kGvcpMagicNumber;
		}

		/**
		 * Check if the acknowledge is required from the header
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
			return sizeof(internal::gvcp_request_header);
		}

	private:
		/**
		 * Get the header object
		 * @return internal::gvcp_request_header* A pointer to the header object
		 */
		internal::gvcp_request_header* getGvcpHeader() const
		{
			return reinterpret_cast<internal::gvcp_request_header*>(
			    m_Data);  // the header is at the beginning of the data
		}
	};

	/**
	 * GVCP acknowledge layer
	 */
	class GvcpAcknowledgeLayer : public GvcpLayer
	{
	public:
		/**
		 * Construct a new GvcpLayer object
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		GvcpAcknowledgeLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/**
		 * Construct a new GvcpRequestLayer object
		 * @param[in] data A pointer to the data including the header and the payload
		 * @param[in] dataSize The size of the data in bytes
		 */
		GvcpAcknowledgeLayer(const uint8_t* data, size_t dataSize);

		/**
		 * Construct a new GvcpAcknowledgeLayer object
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
		 * @return the response status from the header
		 */
		GvcpResponseStatus getStatus() const;

		/**
		 * @return the response command type from the header
		 */
		GvcpCommand getCommand() const;

		/**
		 * @return the size of the data in bytes from the header
		 */
		uint16_t getDataSize() const;

		/**
		 * @return uint16_t The acknowledge ID from the header
		 */
		uint16_t getAckId() const;

		// implement Layer's abstract methods
		std::string toString() const override;

		// implement Layer's abstract methods
		size_t getHeaderLen() const override
		{
			return sizeof(internal::gvcp_ack_header);
		}

	private:
		/**
		 * Get the header object
		 * @return gvcp_ack_header* A pointer to the header object
		 */
		internal::gvcp_ack_header* getGvcpHeader() const
		{
			return reinterpret_cast<internal::gvcp_ack_header*>(m_Data);  // the header is at the beginning of the data
		}
	};

	// ---------------------------------------- Special Layer ----------------------------------------

	/**
	 * GVCP discovery request layer
	 */
	class GvcpDiscoveryRequestLayer : public GvcpRequestLayer
	{
	public:
		/**
		 * Construct a new GvcpLayer object
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		GvcpDiscoveryRequestLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : GvcpRequestLayer(data, dataLen, prevLayer, packet) {};

		/**
		 * Construct a new GvcpRequestLayer object
		 * @param[in] data A pointer to the data including the header and the payload
		 * @param[in] dataSize The size of the data in bytes
		 */
		explicit GvcpDiscoveryRequestLayer(const uint8_t* data, size_t dataSize) : GvcpRequestLayer(data, dataSize) {};

		/**
		 * Construct a new GvcpRequestLayer object
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

	/**
	 * GVCP discovery acknowledge layer
	 */
	class GvcpDiscoveryAcknowledgeLayer : public GvcpAcknowledgeLayer
	{
	public:
		/**
		 * Construct a new GvcpLayer object
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		GvcpDiscoveryAcknowledgeLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : GvcpAcknowledgeLayer(data, dataLen, prevLayer, packet) {};

		/**
		 * Construct a new GvcpRequestLayer object
		 * @param[in] data A pointer to the data including the header and the payload
		 * @param[in] dataSize The size of the data in bytes
		 */
		GvcpDiscoveryAcknowledgeLayer(const uint8_t* data, uint16_t dataSize) : GvcpAcknowledgeLayer(data, dataSize) {};

		/**
		 * Construct a new GvcpAcknowledgeLayer object
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
		 * Get the version
		 * @return std::pair<uint16_t, uint16_t> The version major and minor
		 */
		std::pair<uint16_t, uint16_t> getVersion() const
		{
			auto body = this->getGvcpDiscoveryBody();
			return { body->versionMajor, body->versionMinor };
		}

		/**
		 * Get the IP address
		 * @return pcpp::IPAddress The IP address. Throw if the IP address is invalid.
		 */
		pcpp::MacAddress getMacAddress() const
		{
			auto body = this->getGvcpDiscoveryBody();
			return pcpp::MacAddress(body->macAddress);
		}

		/**
		 * Get the IP address
		 * @return pcpp::IPAddress The IP address. Throw if the IP address is invalid.
		 */
		pcpp::IPv4Address getIpAddress() const
		{
			auto body = this->getGvcpDiscoveryBody();
			return pcpp::IPv4Address(body->ipAddress);
		}

		/**
		 * Get the subnet mask
		 * @return pcpp::IPAddress The subnet mask. Throw if the subnet mask is invalid.
		 */
		pcpp::IPv4Address getSubnetMask() const
		{
			auto body = this->getGvcpDiscoveryBody();
			return pcpp::IPv4Address(body->subnetMask);
		}

		/**
		 * Get the gateway IP address
		 * @return pcpp::IPAddress The gateway IP address. Throw if the gateway IP address is invalid.
		 */
		pcpp::IPv4Address getGatewayIpAddress() const
		{
			auto body = this->getGvcpDiscoveryBody();
			return pcpp::IPv4Address(body->defaultGateway);
		}

		/**
		 * Get the manufacturer name
		 * @return std::string The manufacturer name
		 */
		std::string getManufacturerName() const
		{
			auto body = this->getGvcpDiscoveryBody();
			return std::string(body->manufacturerName);
		}

		/**
		 * Get the model name
		 * @return std::string The model name
		 */
		std::string getModelName() const
		{
			auto body = this->getGvcpDiscoveryBody();
			return std::string(body->modelName);
		}

		/**
		 * Get the device version
		 * @return std::string The device version
		 */
		std::string getDeviceVersion() const
		{
			auto body = this->getGvcpDiscoveryBody();
			return std::string(body->deviceVersion);
		}

		/**
		 * Get the manufacturer specific information
		 * @return std::string The manufacturer specific information
		 */
		std::string getManufacturerSpecificInformation() const
		{
			auto body = this->getGvcpDiscoveryBody();
			return std::string(body->manufacturerSpecificInformation);
		}

		/**
		 * Get the serial number
		 * @return std::string The serial number
		 */
		std::string getSerialNumber() const
		{
			auto body = this->getGvcpDiscoveryBody();
			return std::string(body->serialNumber);
		}

		/**
		 * Get the user defined name
		 * @return std::string The user defined name
		 */
		std::string getUserDefinedName() const
		{
			auto body = this->getGvcpDiscoveryBody();
			return std::string(body->userDefinedName);
		}

	private:
		internal::gvcp_discovery_body* getGvcpDiscoveryBody() const
		{
			return reinterpret_cast<internal::gvcp_discovery_body*>(m_Data + getHeaderLen());
		}
	};

	/**
	 * GVCP force IP request layer
	 */
	class GvcpForceIpRequestLayer : public GvcpRequestLayer
	{
	public:
		/**
		 * Construct a new GvcpLayer object
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		GvcpForceIpRequestLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : GvcpRequestLayer(data, dataLen, prevLayer, packet) {};

		/**
		 * Construct a new GvcpRequestLayer object
		 * @param[in] data A pointer to the data including the header and the payload
		 * @param[in] dataSize The size of the data in bytes
		 */
		explicit GvcpForceIpRequestLayer(const uint8_t* data, size_t dataSize) : GvcpRequestLayer(data, dataSize) {};

		/**
		 * Construct a new GvcpRequestLayer object
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
		 * Get the IP address
		 * @return pcpp::IPAddress The IP address. Throw if the IP address is invalid.
		 */
		pcpp::MacAddress getMacAddress() const
		{
			auto body = this->getGvcpForceIpBody();
			return pcpp::MacAddress(reinterpret_cast<const uint8_t*>(body->macAddress));
		}

		/**
		 * Get the IP address
		 * @return pcpp::IPAddress The IP address. Throw if the IP address is invalid.
		 */
		pcpp::IPv4Address getIpAddress() const
		{
			auto body = this->getGvcpForceIpBody();
			return pcpp::IPv4Address(body->ipAddress);
		}

		/**
		 * Get the subnet mask
		 * @return pcpp::IPAddress The subnet mask. Throw if the subnet mask is invalid.
		 */
		pcpp::IPv4Address getSubnetMask() const
		{
			auto body = this->getGvcpForceIpBody();
			return pcpp::IPv4Address(body->subnetMask);
		}

		/**
		 * Get the gateway IP address
		 * @return pcpp::IPAddress The gateway IP address. Throw if the gateway IP address is invalid.
		 */
		pcpp::IPv4Address getGatewayIpAddress() const
		{
			auto body = this->getGvcpForceIpBody();
			return pcpp::IPv4Address(body->gateway);
		}

	private:
		internal::gvcp_forceip_body* getGvcpForceIpBody() const
		{
			return reinterpret_cast<internal::gvcp_forceip_body*>(m_Data + getHeaderLen());
		}
	};

	/**
	 * GVCP force IP acknowledge layer
	 */
	class GvcpForceIpAcknowledgeLayer : public GvcpAcknowledgeLayer
	{
	public:
		/**
		 * Construct a new GvcpLayer object
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		GvcpForceIpAcknowledgeLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : GvcpAcknowledgeLayer(data, dataLen, prevLayer, packet) {};

		/**
		 * Construct a new GvcpRequestLayer object
		 * @param[in] data A pointer to the data including the header and the payload
		 * @param[in] dataSize The size of the data in bytes
		 */
		GvcpForceIpAcknowledgeLayer(const uint8_t* data, size_t dataSize) : GvcpAcknowledgeLayer(data, dataSize) {};

		/**
		 * Construct a new GvcpAcknowledgeLayer object
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
