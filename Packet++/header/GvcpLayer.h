#pragma once

#include "IpAddress.h"
#include "Layer.h"
#include "MacAddress.h"
#include <ostream>
#include <string>
#include <utility>

/// @file
/// This file contains classes for parsing, creating and editing GVCP (GigE Vision Control Protocol) packets.
/// The implementation is based on the GigE Vision (R) Specification version 2.0

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	/// GVCP flag. The meaning of bits 0-3 is specified by each command, bits 4-6 are reserved and bit 7 (the least
	/// significant bit) is the acknowledge-required bit
	using GvcpFlag = uint8_t;

	/// GVCP command defines the command values and the corresponding acknowledge values.
	/// See more in the spec "18 Command and Acknowledge Values"
	enum class GvcpCommand : uint16_t
	{
		/// Discovery command (Discovery Protocol Control)
		DiscoveredCmd = 0x0002,
		/// Discovery acknowledge (Discovery Protocol Control)
		DiscoveredAck = 0x0003,
		/// Force IP command (Discovery Protocol Control)
		ForceIpCmd = 0x0004,
		/// Force IP acknowledge (Discovery Protocol Control)
		ForceIpAck = 0x0005,

		/// Packet resend command (Streaming Protocol Control)
		PacketResendCmd = 0x0040,
		/// Packet resend acknowledge (Streaming Protocol Control). The resent packet must be on the stream channel
		PacketResendAck = 0x0041,

		/// Read register command (Device Memory Access)
		ReadRegCmd = 0x0080,
		/// Read register acknowledge (Device Memory Access)
		ReadRegAck = 0x0081,
		/// Write register command (Device Memory Access)
		WriteRegCmd = 0x0082,
		/// Write register acknowledge (Device Memory Access)
		WriteRegAck = 0x0083,
		/// Read memory command (Device Memory Access)
		ReadMemCmd = 0x0084,
		/// Read memory acknowledge (Device Memory Access)
		ReadMemAck = 0x0085,
		/// Write memory command (Device Memory Access)
		WriteMemCmd = 0x0086,
		/// Write memory acknowledge (Device Memory Access)
		WriteMemAck = 0x0087,
		/// Pending acknowledge (Device Memory Access)
		PendingAck = 0x0089,

		/// Event command (Asynchronous Events)
		EventCmd = 0x00C0,
		/// Event acknowledge (Asynchronous Events)
		EventAck = 0x00C1,
		/// Event data command (Asynchronous Events)
		EventDataCmd = 0x00C2,
		/// Event data acknowledge (Asynchronous Events)
		EventDataAck = 0x00C3,

		/// Action command (Miscellaneous)
		ActionCmd = 0x0100,
		/// Action acknowledge (Miscellaneous)
		ActionAck = 0x0101,

		/// Unknown command
		Unknown = 0xFFFF
	};

	/// Output operator for GvcpCommand, prints the command value in hex
	std::ostream& operator<<(std::ostream& os, GvcpCommand command);

	/// GVCP response status can be returned in an acknowledge message or a GVSP header.
	/// See more in the spec "Table 19-1: List of Standard Status Codes"
	enum class GvcpResponseStatus : uint16_t
	{
		/// Command executed successfully
		Success = 0x0000,
		/// Only applies to packet being resent
		PacketResend = 0x0100,
		/// Command is not supported by the device
		NotImplemented = 0x8001,
		/// At least one parameter provided in the command is invalid (or out of range) for the device
		InvalidParameter = 0x8002,
		/// An attempt was made to access a non-existent address space location
		InvalidAddress = 0x8003,
		/// The addressed register cannot be written to
		WriteProtect = 0x8004,
		/// A badly aligned address offset or data size was specified
		BadAlignment = 0x8005,
		/// An attempt was made to access an address location which is currently/momentary not accessible
		AccessDenied = 0x8006,
		/// A required resource to service the request is not currently available. The request may be retried at a
		/// later time
		Busy = 0x8007,
		/// Deprecated
		LocalProblem = 0x8008,
		/// Deprecated
		MsgMismatch = 0x8009,
		/// Deprecated
		InvalidProtocol = 0x800A,
		/// Deprecated
		NoMsg = 0x800B,
		/// The requested packet is not available anymore
		PacketUnavailable = 0x800C,
		/// Internal memory of GVSP transmitter overrun (typically for image acquisition)
		DataOverrun = 0x800D,
		/// The message header is not valid. Some of its fields do not match the specification
		InvalidHeader = 0x800E,
		/// Deprecated
		WrongConfig = 0x800F,
		/// The requested packet has not yet been acquired. Can be used for linescan cameras device when line trigger
		/// rate is slower than application timeout
		PacketNotYetAvailable = 0x8010,
		/// The requested packet and all previous ones are not available anymore and have been discarded from the GVSP
		/// transmitter memory
		PacketAndPrevRemovedFromMemory = 0x8011,
		/// The requested packet is not available anymore and has been discarded from the GVSP transmitter memory
		PacketRemovedFromMemory = 0x8012,
		/// The device is not synchronized to a master clock to be used as time reference
		NoRefTime = 0x8013,
		/// The packet cannot be resent at the moment due to temporary bandwidth issues and should be requested again
		/// in the future
		PacketTemporarilyUnavailable = 0x8014,
		/// A device queue or packet data has overflowed
		Overflow = 0x8015,
		/// The requested scheduled action command was requested at a time that is already past
		ActionLate = 0x8016,
		/// Leader or trailer overflow (GEV 2.1)
		LeaderTrailerOverflow = 0x8017,
		/// Generic error
		Error = 0x8FFF,
		/// Unknown status
		Unknown = 0xFFFF
	};

	/// Output operator for GvcpResponseStatus, prints the status value in hex
	std::ostream& operator<<(std::ostream& os, GvcpResponseStatus status);

	namespace internal
	{
#pragma pack(push, 1)
		/// @struct gvcp_request_header
		/// GVCP request header, see the spec "15.1 Request Header". The data is stored as big-endian.
		struct gvcp_request_header
		{
			/// Magic number, always 0x42
			uint8_t magicNumber;
			/// GVCP flag
			uint8_t flag;
			/// Command
			uint16_t command;
			/// Data size (the size of the message without the header)
			uint16_t dataSize;
			/// Request ID
			uint16_t requestId;
		};
		static_assert(sizeof(gvcp_request_header) == 8, "gvcp_request_header size is not 8 bytes");

		/// @struct gvcp_ack_header
		/// GVCP acknowledge header, see the spec "15.2 Acknowledge Header". The data is stored as big-endian.
		struct gvcp_ack_header
		{
			/// Response status
			uint16_t status;
			/// Command
			uint16_t command;
			/// Data size (the size of the message without the header)
			uint16_t dataSize;
			/// Acknowledge ID
			uint16_t ackId;
		};
		static_assert(sizeof(gvcp_ack_header) == 8, "gvcp_ack_header size is not 8 bytes");

		/// @struct gvcp_discovery_body
		/// GVCP discovery acknowledge body, see the spec "16.1.2 DISCOVERY_ACK". The data is stored as big-endian.
		struct gvcp_discovery_body
		{
			/// GigE Vision version major number
			uint16_t versionMajor;
			/// GigE Vision version minor number
			uint16_t versionMinor;
			/// Device mode
			uint32_t deviceMode;
			/// Reserved
			uint16_t reserved;
			/// MAC address
			uint8_t macAddress[6];
			/// Supported IP configuration options
			uint32_t supportedIpConfigOptions;
			/// Current IP configuration
			uint32_t ipConfigCurrent;
			/// Reserved
			uint8_t reserved2[12];
			/// IP address
			uint32_t ipAddress;
			/// Reserved
			uint8_t reserved3[12];
			/// Subnet mask
			uint32_t subnetMask;
			/// Reserved
			uint8_t reserved4[12];
			/// Default gateway
			uint32_t defaultGateway;
			/// Manufacturer name
			char manufacturerName[32];
			/// Model name
			char modelName[32];
			/// Device version
			char deviceVersion[32];
			/// Manufacturer specific information
			char manufacturerSpecificInformation[48];
			/// Serial number
			char serialNumber[16];
			/// User defined name
			char userDefinedName[16];
		};
		static_assert(sizeof(gvcp_discovery_body) == 248, "gvcp_discovery_body size is not 248 bytes");

		/// @struct gvcp_forceip_body
		/// GVCP force IP command body, see the spec "16.2 FORCEIP". The data is stored as big-endian.
		struct gvcp_forceip_body
		{
			/// Reserved
			uint8_t reserved[2];
			/// MAC address
			uint8_t macAddress[6];
			/// Reserved
			uint8_t reserved2[12];
			/// IP address
			uint32_t ipAddress;
			/// Reserved
			uint8_t reserved3[12];
			/// Subnet mask
			uint32_t subnetMask;
			/// Reserved
			uint8_t reserved4[12];
			/// Default gateway
			uint32_t gateway;
		};
		static_assert(sizeof(gvcp_forceip_body) == 56, "gvcp_forceip_body size is not 56 bytes");
#pragma pack(pop)
	}  // namespace internal

	/// @class GvcpLayer
	/// An abstract class representing the GigE Vision Control Protocol (GVCP).
	/// The class is implemented according to the GigE Vision specification 2.0.
	/// @see https://en.wikipedia.org/wiki/GigE_Vision
	/// @note The class cannot be instantiated directly, use GvcpRequestLayer, GvcpAcknowledgeLayer or their derived
	/// classes
	class GvcpLayer : public Layer
	{
	public:
		/// A static method that checks whether the port is considered as GVCP
		/// @param[in] port The port number to be checked
		/// @return True if the port is the GVCP port (3956), false otherwise
		static bool isGvcpPort(uint16_t port)
		{
			return port == 3956;
		}

		/// A static method that parses the raw data and creates the matching GVCP layer: a request layer if the data
		/// begins with the GVCP magic number, otherwise an acknowledge layer. Discovery and Force IP messages are
		/// created as their specific layers, unless they are too short to hold the fields of these messages
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		/// @return A pointer to the newly created GVCP layer, or nullptr if the data isn't a valid GVCP message
		static GvcpLayer* parseGvcpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/// @return The command (or acknowledge) value of this message, GvcpCommand::Unknown if the value isn't
		/// defined by the spec
		virtual GvcpCommand getCommand() const = 0;

		/// @return The data size field from the header, meaning the size of the message without the GVCP header
		virtual uint16_t getDataSize() const = 0;

		/// @return A pointer to the message data that follows the GVCP header, or nullptr if the message has no data
		uint8_t* getPayloadData() const;

		/// @return The size in bytes of the message data that follows the GVCP header
		size_t getPayloadDataLen() const;

		// Overridden methods

		/// Does nothing for this layer (GvcpLayer is always last)
		void parseNextLayer() override
		{}

		/// @return The size of the entire GVCP message (GVCP header and data)
		size_t getHeaderLen() const override
		{
			return m_DataLen;
		}

		/// @return The OSI Model layer this protocol belongs to
		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelApplicationLayer;
		}

	protected:
		GvcpLayer() = default;

		GvcpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, GVCP)
		{}
	};

	/// @class GvcpRequestLayer
	/// Represents a GVCP request (command) message. Commands which don't have a specific layer class are
	/// represented by this class
	class GvcpRequestLayer : public GvcpLayer
	{
	public:
		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		GvcpRequestLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : GvcpLayer(data, dataLen, prevLayer, packet)
		{}

		/// A constructor that creates a new GVCP request
		/// @param[in] command The command
		/// @param[in] payloadData A pointer to the message data that follows the header, optional
		/// @param[in] payloadDataSize The size of the message data in bytes, optional
		/// @param[in] flag The flag, optional
		/// @param[in] requestId The request ID, should be different than 0, optional
		explicit GvcpRequestLayer(GvcpCommand command, const uint8_t* payloadData = nullptr,
		                          uint16_t payloadDataSize = 0, GvcpFlag flag = 0, uint16_t requestId = 1);

		/// A static method that checks whether the data is a valid GVCP request: it should be large enough to hold a
		/// GVCP request header and begin with the GVCP magic number
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @return True if the data is a valid GVCP request, false otherwise
		static bool isDataValid(const uint8_t* data, size_t dataLen);

		/// @return The flag from the header
		GvcpFlag getFlag() const;

		/// Set the flag in the header
		/// @param[in] flag The flag to set
		void setFlag(GvcpFlag flag);

		/// @return True if the acknowledge-required bit is set in the flag, false otherwise
		bool hasAcknowledgeFlag() const;

		/// @return The request ID from the header
		uint16_t getRequestId() const;

		/// Set the request ID in the header
		/// @param[in] requestId The request ID to set
		void setRequestId(uint16_t requestId);

		// Overridden methods

		/// @return The command from the header, GvcpCommand::Unknown if the value isn't defined by the spec
		GvcpCommand getCommand() const override;

		/// @return The data size from the header
		uint16_t getDataSize() const override;

		/// Calculate the data size field in the header according to the size of the message data
		void computeCalculateFields() override;

		/// @return A string representation of the layer most important data
		std::string toString() const override;

	protected:
		GvcpRequestLayer() = default;

		/// Allocate the layer data (a header followed by dataSize zeroed bytes) and set the header fields
		void initLayer(GvcpCommand command, uint16_t dataSize, GvcpFlag flag, uint16_t requestId);

	private:
		internal::gvcp_request_header* getGvcpHeader() const
		{
			return reinterpret_cast<internal::gvcp_request_header*>(m_Data);
		}
	};

	/// @class GvcpAcknowledgeLayer
	/// Represents a GVCP acknowledge message. Acknowledges which don't have a specific layer class are
	/// represented by this class
	class GvcpAcknowledgeLayer : public GvcpLayer
	{
	public:
		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		GvcpAcknowledgeLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : GvcpLayer(data, dataLen, prevLayer, packet)
		{}

		/// A constructor that creates a new GVCP acknowledge
		/// @param[in] status The response status
		/// @param[in] command The acknowledge value
		/// @param[in] payloadData A pointer to the message data that follows the header, optional
		/// @param[in] payloadDataSize The size of the message data in bytes, optional
		/// @param[in] ackId The acknowledge ID, optional
		GvcpAcknowledgeLayer(GvcpResponseStatus status, GvcpCommand command, const uint8_t* payloadData = nullptr,
		                     uint16_t payloadDataSize = 0, uint16_t ackId = 0);

		/// A static method that checks whether the data is large enough to hold a GVCP acknowledge header
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @return True if the data can be parsed as a GVCP acknowledge, false otherwise
		static bool isDataValid(const uint8_t* data, size_t dataLen);

		/// @return The response status from the header, GvcpResponseStatus::Unknown if the value isn't defined by the
		/// spec
		GvcpResponseStatus getStatus() const;

		/// Set the response status in the header
		/// @param[in] status The response status to set
		void setStatus(GvcpResponseStatus status);

		/// @return The acknowledge ID from the header
		uint16_t getAckId() const;

		/// Set the acknowledge ID in the header
		/// @param[in] ackId The acknowledge ID to set
		void setAckId(uint16_t ackId);

		// Overridden methods

		/// @return The acknowledge value from the header, GvcpCommand::Unknown if the value isn't defined by the spec
		GvcpCommand getCommand() const override;

		/// @return The data size from the header
		uint16_t getDataSize() const override;

		/// Calculate the data size field in the header according to the size of the message data
		void computeCalculateFields() override;

		/// @return A string representation of the layer most important data
		std::string toString() const override;

	protected:
		GvcpAcknowledgeLayer() = default;

		/// Allocate the layer data (a header followed by dataSize zeroed bytes) and set the header fields
		void initLayer(GvcpResponseStatus status, GvcpCommand command, uint16_t dataSize, uint16_t ackId);

	private:
		internal::gvcp_ack_header* getGvcpHeader() const
		{
			return reinterpret_cast<internal::gvcp_ack_header*>(m_Data);
		}
	};

	/// @class GvcpDiscoveryRequestLayer
	/// Represents a GVCP discovery command (DISCOVERY_CMD)
	class GvcpDiscoveryRequestLayer : public GvcpRequestLayer
	{
	public:
		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		GvcpDiscoveryRequestLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : GvcpRequestLayer(data, dataLen, prevLayer, packet)
		{}

		/// A constructor that creates a new GVCP discovery command
		/// @param[in] flag The flag, optional
		/// @param[in] requestId The request ID, should be different than 0, optional
		explicit GvcpDiscoveryRequestLayer(GvcpFlag flag = 0, uint16_t requestId = 1)
		    : GvcpRequestLayer(GvcpCommand::DiscoveredCmd, nullptr, 0, flag, requestId)
		{}
	};

	/// @class GvcpDiscoveryAcknowledgeLayer
	/// Represents a GVCP discovery acknowledge (DISCOVERY_ACK)
	class GvcpDiscoveryAcknowledgeLayer : public GvcpAcknowledgeLayer
	{
	public:
		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		GvcpDiscoveryAcknowledgeLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : GvcpAcknowledgeLayer(data, dataLen, prevLayer, packet)
		{}

		/// A constructor that creates a new GVCP discovery acknowledge. All of the discovery fields are set to zero
		/// and can be set using the setters of this class
		/// @param[in] status The response status, optional
		/// @param[in] ackId The acknowledge ID, optional
		explicit GvcpDiscoveryAcknowledgeLayer(GvcpResponseStatus status = GvcpResponseStatus::Success,
		                                       uint16_t ackId = 0);

		/// @return The GigE Vision spec version supported by the device as a pair of {major, minor}
		std::pair<uint16_t, uint16_t> getVersion() const;

		/// Set the GigE Vision spec version supported by the device
		/// @param[in] major The version major number
		/// @param[in] minor The version minor number
		void setVersion(uint16_t major, uint16_t minor);

		/// @return The device MAC address
		MacAddress getMacAddress() const;

		/// Set the device MAC address
		/// @param[in] macAddress The MAC address to set
		void setMacAddress(const MacAddress& macAddress);

		/// @return The device IP address
		IPv4Address getIpAddress() const;

		/// Set the device IP address
		/// @param[in] ipAddress The IP address to set
		void setIpAddress(const IPv4Address& ipAddress);

		/// @return The device subnet mask
		IPv4Address getSubnetMask() const;

		/// Set the device subnet mask
		/// @param[in] subnetMask The subnet mask to set
		void setSubnetMask(const IPv4Address& subnetMask);

		/// @return The device default gateway IP address
		IPv4Address getGatewayIpAddress() const;

		/// Set the device default gateway IP address
		/// @param[in] gatewayIpAddress The default gateway IP address to set
		void setGatewayIpAddress(const IPv4Address& gatewayIpAddress);

		/// @return The manufacturer name
		std::string getManufacturerName() const;

		/// Set the manufacturer name
		/// @param[in] manufacturerName The manufacturer name to set, truncated if longer than 31 characters
		void setManufacturerName(const std::string& manufacturerName);

		/// @return The model name
		std::string getModelName() const;

		/// Set the model name
		/// @param[in] modelName The model name to set, truncated if longer than 31 characters
		void setModelName(const std::string& modelName);

		/// @return The device version
		std::string getDeviceVersion() const;

		/// Set the device version
		/// @param[in] deviceVersion The device version to set, truncated if longer than 31 characters
		void setDeviceVersion(const std::string& deviceVersion);

		/// @return The manufacturer specific information
		std::string getManufacturerSpecificInformation() const;

		/// Set the manufacturer specific information
		/// @param[in] info The manufacturer specific information to set, truncated if longer than 47 characters
		void setManufacturerSpecificInformation(const std::string& info);

		/// @return The serial number
		std::string getSerialNumber() const;

		/// Set the serial number
		/// @param[in] serialNumber The serial number to set, truncated if longer than 15 characters
		void setSerialNumber(const std::string& serialNumber);

		/// @return The user defined name
		std::string getUserDefinedName() const;

		/// Set the user defined name
		/// @param[in] userDefinedName The user defined name to set, truncated if longer than 15 characters
		void setUserDefinedName(const std::string& userDefinedName);

	private:
		internal::gvcp_discovery_body* getGvcpDiscoveryBody() const
		{
			return reinterpret_cast<internal::gvcp_discovery_body*>(m_Data + sizeof(internal::gvcp_ack_header));
		}
	};

	/// @class GvcpForceIpRequestLayer
	/// Represents a GVCP force IP command (FORCEIP_CMD)
	class GvcpForceIpRequestLayer : public GvcpRequestLayer
	{
	public:
		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		GvcpForceIpRequestLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : GvcpRequestLayer(data, dataLen, prevLayer, packet)
		{}

		/// A constructor that creates a new GVCP force IP command
		/// @param[in] macAddress The MAC address of the device to configure
		/// @param[in] ipAddress The IP address to force on the device
		/// @param[in] subnetMask The subnet mask to force on the device
		/// @param[in] gatewayIpAddress The default gateway to force on the device
		/// @param[in] flag The flag, optional
		/// @param[in] requestId The request ID, should be different than 0, optional
		GvcpForceIpRequestLayer(const MacAddress& macAddress, const IPv4Address& ipAddress,
		                        const IPv4Address& subnetMask, const IPv4Address& gatewayIpAddress, GvcpFlag flag = 0,
		                        uint16_t requestId = 1);

		/// @return The MAC address of the device to configure
		MacAddress getMacAddress() const;

		/// Set the MAC address of the device to configure
		/// @param[in] macAddress The MAC address to set
		void setMacAddress(const MacAddress& macAddress);

		/// @return The IP address to force on the device
		IPv4Address getIpAddress() const;

		/// Set the IP address to force on the device
		/// @param[in] ipAddress The IP address to set
		void setIpAddress(const IPv4Address& ipAddress);

		/// @return The subnet mask to force on the device
		IPv4Address getSubnetMask() const;

		/// Set the subnet mask to force on the device
		/// @param[in] subnetMask The subnet mask to set
		void setSubnetMask(const IPv4Address& subnetMask);

		/// @return The default gateway IP address to force on the device
		IPv4Address getGatewayIpAddress() const;

		/// Set the default gateway IP address to force on the device
		/// @param[in] gatewayIpAddress The default gateway IP address to set
		void setGatewayIpAddress(const IPv4Address& gatewayIpAddress);

	private:
		internal::gvcp_forceip_body* getGvcpForceIpBody() const
		{
			return reinterpret_cast<internal::gvcp_forceip_body*>(m_Data + sizeof(internal::gvcp_request_header));
		}
	};

	/// @class GvcpForceIpAcknowledgeLayer
	/// Represents a GVCP force IP acknowledge (FORCEIP_ACK)
	class GvcpForceIpAcknowledgeLayer : public GvcpAcknowledgeLayer
	{
	public:
		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		GvcpForceIpAcknowledgeLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : GvcpAcknowledgeLayer(data, dataLen, prevLayer, packet)
		{}

		/// A constructor that creates a new GVCP force IP acknowledge
		/// @param[in] status The response status, optional
		/// @param[in] ackId The acknowledge ID, optional
		explicit GvcpForceIpAcknowledgeLayer(GvcpResponseStatus status = GvcpResponseStatus::Success,
		                                     uint16_t ackId = 0)
		    : GvcpAcknowledgeLayer(status, GvcpCommand::ForceIpAck, nullptr, 0, ackId)
		{}
	};
}  // namespace pcpp
