#pragma once

#include <vector>
#include <cstring>
#include "Layer.h"
#include "Logger.h"
#include "EndianPortable.h"

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
/// @struct doiphdr
/// Represents an DoIP protocol header
#pragma pack(push, 1)
	struct doiphdr
	{
		/// DoIP version (DOIPV)
		uint8_t protocolVersion;
		/// DoIP invert version (DOIPIV). Inverse of protocol version
		uint8_t invertProtocolVersion;
		/// DoIP payload type (DOIPT)
		uint16_t payloadType;
		/// DoIP content payload length (DOIPL)
		uint32_t payloadLength;
	};
#pragma pack(pop)
	static_assert(sizeof(doiphdr) == 8, "DoIP header must be exactly 8 bytes.");

	namespace DoIpConstants
	{
		/// @brief Length of doip header
		static constexpr size_t DOIP_HEADER_LEN = sizeof(doiphdr);

		/// @brief Length of the Equiepement Identifier (EID) field.
		static constexpr size_t DOIP_EID_LEN = 6;

		/// @brief Length of the Group Identifier (GID) field.
		static constexpr size_t DOIP_GID_LEN = 6;

		/// @brief Length of the Vehicle Identification Number (VIN) field.
		static constexpr size_t DOIP_VIN_LEN = 17;

		/// @brief Length of the Reserved ISO field.
		static constexpr size_t DOIP_RESERVED_ISO_LEN = 4;

		/// @brief Length of the Reserved OEM field.
		static constexpr size_t DOIP_RESERVED_OEM_LEN = 4;

		/// @brief Length of the source address
		static constexpr size_t DOIP_SOURCE_ADDRESS_LEN = 2;

		/// @brief Length of the target address
		static constexpr size_t DOIP_TARGET_ADDRESS_LEN = 2;
	}  // namespace DoIpConstants

	/// @brief Enum representing DoIP routing activation types.
	/// These values specify the type of routing activation used in DoIP(Diagnostic over IP).
	enum class DoIpActivationTypes : uint8_t
	{
		/// Default routing activation type.
		/// Used when no specific type is required.
		DEFAULT = 0x00U,

		/// WWH-OBD (Worldwide Harmonized On-Board Diagnostics) routing activation type.
		/// Used for vehicle diagnostics in compliance with WWH-OBD standards.
		WWH_OBD = 0x01U,

		/// Central security routing activation type.
		/// Used for secure communications involving a central security system.
		CENTRAL_SECURITY = 0xE0U,
	};

	/// @brief Enum representing DoIP Generic Header NACK codes (ISO 13400).
	/// These codes are used to indicate specific errors in the DoIP Generic Header.
	enum class DoIpGenericHeaderNackCodes : uint8_t
	{
		/// Incorrect pattern detected in the header.
		/// Indicates that the header does not follow the expected pattern.
		INCORRECT_PATTERN = 0x00U,

		/// Unknown payload type.
		/// The payload type in the message is not recognized.
		UNKNOWN_PAYLOAD_TYPE = 0x01U,

		/// Message too large.
		/// The message size exceeds the allowed limit.
		MESSAGE_TOO_LARGE = 0x02U,

		/// Out of memory.
		/// There is insufficient memory available to process the message.
		OUT_OF_MEMORY = 0x03U,

		/// Invalid payload length.
		/// The payload length specified in the header is invalid.
		INVALID_PAYLOAD_LENGTH = 0x04U,
	};

	/// @brief Enum representing DoIP action codes for DoIP announcement messages (ISO 13400).
	/// These action codes specify the next steps required after receiving a DoIP announcement message.
	/// Some codes are reserved for future use by ISO standards.
	enum class DoIpActionCodes : uint8_t
	{
		/// No further action required.
		/// Indicates that no additional steps are needed after the announcement.
		NO_FURTHER_ACTION_REQUIRED = 0x00U,

		/// Reserved for ISO (0x01).
		/// Reserved for future use as per ISO standards.
		RESERVED_ISO_0x01 = 0x01U,

		/// Reserved for ISO (0x02).
		/// Reserved for future use as per ISO standards.
		RESERVED_ISO_0x02 = 0x02U,

		/// Reserved for ISO (0x03).
		/// Reserved for future use as per ISO standards.
		RESERVED_ISO_0x03 = 0x03U,

		/// Reserved for ISO (0x04).
		/// Reserved for future use as per ISO standards.
		RESERVED_ISO_0x04 = 0x04U,

		/// Reserved for ISO (0x05).
		/// Reserved for future use as per ISO standards.
		RESERVED_ISO_0x05 = 0x05U,

		/// Reserved for ISO (0x06).
		/// Reserved for future use as per ISO standards.
		RESERVED_ISO_0x06 = 0x06U,

		/// Reserved for ISO (0x07).
		/// Reserved for future use as per ISO standards.
		RESERVED_ISO_0x07 = 0x07U,

		/// Reserved for ISO (0x08).
		/// Reserved for future use as per ISO standards.
		RESERVED_ISO_0x08 = 0x08U,

		/// Reserved for ISO (0x09).
		/// Reserved for future use as per ISO standards.
		RESERVED_ISO_0x09 = 0x09U,

		/// Reserved for ISO (0x0A).
		/// Reserved for future use as per ISO standards.
		RESERVED_ISO_0x0A = 0x0AU,

		/// Reserved for ISO (0x0B).
		/// Reserved for future use as per ISO standards.
		RESERVED_ISO_0x0B = 0x0BU,

		/// Reserved for ISO (0x0C).
		/// Reserved for future use as per ISO standards.
		RESERVED_ISO_0x0C = 0x0CU,

		/// Reserved for ISO (0x0D).
		/// Reserved for future use as per ISO standards.
		RESERVED_ISO_0x0D = 0x0DU,

		/// Reserved for ISO (0x0E).
		/// Reserved for future use as per ISO standards.
		RESERVED_ISO_0x0E = 0x0EU,

		/// Reserved for ISO (0x0F).
		/// Reserved for future use as per ISO standards.
		RESERVED_ISO_0x0F = 0x0FU,

		/// Routing activation required.
		/// Indicates that routing activation is needed after the announcement message.
		ROUTING_ACTIVATION_REQUIRED = 0x10U,
	};

	/// @brief Enum representing DoIP routing activation response codes (ISO 13400).
	/// These codes are used in response to routing activation requests, providing status
	/// or error information related to the request.
	enum class DoIpRoutingResponseCodes : uint8_t
	{
		/// Unknown source address.
		/// The source address provided in the request is not recognized.
		UNKNOWN_SOURCE_ADDRESS = 0x00U,

		/// No free socket.
		/// There are no available sockets to establish the connection.
		NO_FREE_SOCKET = 0x01U,

		/// Wrong source address.
		/// The source address provided in the request is invalid.
		WRONG_SOURCE_ADDRESS = 0x02U,

		/// Source address already registered.
		/// The provided source address has already been activated.
		SOURCE_ADDRESS_ALREADY_REGISTERED = 0x03U,

		/// Missing authentication.
		/// The request is missing required authentication credentials.
		MISSING_AUTHENTICATION = 0x04U,

		/// Rejected confirmation.
		/// The confirmation of routing activation was rejected.
		REJECTED_CONFIRMATION = 0x05U,

		/// Unsupported activation type.
		/// The requested routing activation type is not supported.

		UNSUPPORTED_ACTIVATION_TYPE = 0x06U,

		/// Encrypted connection required(TLS).
		/// Indicates that the routing activation requires a secure TLS connection.
		ENCRYPTED_CONNECTION_TLS = 0x07U,

		/// Reserved for ISO (0x08).
		/// Reserved for future use as per ISO standards.
		RESERVED_ISO_0x08 = 0x08U,

		/// Reserved for ISO (0x09).
		/// Reserved for future use as per ISO standards.
		RESERVED_ISO_0x09 = 0x09U,

		/// Reserved for ISO (0x0A).
		/// Reserved for future use as per ISO standards.
		RESERVED_ISO_0x0A = 0x0AU,

		/// Reserved for ISO (0x0B).
		/// Reserved for future use as per ISO standards.
		RESERVED_ISO_0x0B = 0x0BU,

		/// Reserved for ISO (0x0C).
		/// Reserved for future use as per ISO standards.
		RESERVED_ISO_0x0C = 0x0CU,

		/// Reserved for ISO (0x0D).
		/// Reserved for future use as per ISO standards.
		RESERVED_ISO_0x0D = 0x0DU,

		/// Reserved for ISO (0x0E).
		/// Reserved for future use as per ISO standards.
		RESERVED_ISO_0x0E = 0x0EU,

		/// Reserved for ISO (0x0F).
		/// Reserved for future use as per ISO standards.
		RESERVED_ISO_0x0F = 0x0FU,

		/// Routing successfully activated.
		/// The routing activation request was processed successfully.
		ROUTING_SUCCESSFULLY_ACTIVATED = 0x10U,

		/// Confirmation required.
		/// Additional confirmation is required to complete the routing activation.
		CONFIRMATION_REQUIRED = 0x11U,
	};

	/// @brief Enum representing DoIP diagnostic message NACK codes (ISO 13400).
	/// These codes indicate reasons for rejecting or failing to process a diagnostic message
	/// in the DoIP protocol.
	enum class DoIpDiagnosticMessageNackCodes : uint8_t
	{
		/// Reserved for ISO (0x00).
		/// Reserved for future use as per ISO standards.
		RESERVED_ISO_0x00 = 0x00U,

		/// Reserved for ISO (0x01).
		/// Reserved for future use as per ISO standards.
		RESERVED_ISO_0x01 = 0x01U,

		/// Invalid source address.
		/// The source address specified in the message is invalid.
		INVALID_SOURCE_ADDRESS = 0x02U,

		/// Invalid target address.
		/// The target address specified in the message is invalid.
		INVALID_TARGET_ADDRESS = 0x03U,

		/// Message too large.
		/// The size of the message exceeds the maximum allowed limit.
		MESSAGE_TOO_LARGE = 0x04U,

		/// Out of memory.
		/// There is insufficient memory available to process the message.
		OUT_OF_MEMORY = 0x05U,

		/// Target unreachable.
		/// The specified target address cannot be reached.
		TARGET_UNREACHABLE = 0x06U,

		/// Unknown network.
		/// The message references a network that is not recognized or supported.
		UNKNOWN_NETWORK = 0x07U,

		/// Transport protocol error.
		/// An error occurred at the transport protocol level, preventing the message from being processed.
		TRANSPORT_PROTOCOL_ERROR = 0x08U,
	};

	/// @brief Enum representing DoIP diagnostic power mode codes (ISO 13400).
	/// These codes indicate the diagnostic power mode status of a DoIP entity,
	/// providing information about its readiness for diagnostic operations.
	enum class DoIpDiagnosticPowerModeCodes : uint8_t
	{
		/// Not ready.
		/// The DoIP entity is not ready to perform diagnostic operations.
		NOT_READY = 0x00U,

		/// Ready.
		/// The DoIP entity is ready to perform diagnostic operations.
		READY = 0x01U,

		/// Not supported.
		/// The DoIP entity does not support diagnostic power mode reporting.
		NOT_SUPPORTED = 0x02U
	};

	/// @brief Enum representing DoIP diagnostic acknowledgment codes (ISO 13400).
	/// These codes are used to acknowledge the receipt or processing of diagnostic messages
	/// in the DoIP protocol.
	enum class DoIpDiagnosticAckCodes : uint8_t
	{
		/// Acknowledgment.
		/// Indicates successful receipt or acknowledgment of a diagnostic message.
		ACK = 0x00U
	};

	/// @brief Enum representing DoIP entity status response codes (ISO 13400).
	/// These codes are used to indicate the role or type of a DoIP entity in the network.
	enum class DoIpEntityStatusResponseCode : uint8_t
	{
		/// Gateway.
		/// The entity functions as a gateway,
		/// facilitating communication between networks.
		GATEWAY = 0x00U,

		/// Node.
		/// The entity functions as an individual node within the DoIP network.
		NODE = 0x01U
	};

	/// @brief Enum representing DoIP sync status (ISO 13400).
	/// These codes are used to indicate whether GID and VIN are synchronized or not.
	enum class DoIpSyncStatus : uint8_t
	{
		/// VIN and or GID are synchronized.
		VIN_AND_OR_GID_ARE_SINCHRONIZED = 0x00,

		/// Reserved for ISO (0x01).
		/// Reserved for future use as per ISO standards.
		RESERVED_ISO_0x01 = 0x01U,

		/// Reserved for ISO (0x02).
		/// Reserved for future use as per ISO standards.
		RESERVED_ISO_0x02 = 0x02U,

		/// Reserved for ISO (0x03).
		/// Reserved for future use as per ISO standards.
		RESERVED_ISO_0x03 = 0x03U,

		/// Reserved for ISO (0x04).
		/// Reserved for future use as per ISO standards.
		RESERVED_ISO_0x04 = 0x04U,

		/// Reserved for ISO (0x05).
		/// Reserved for future use as per ISO standards.
		RESERVED_ISO_0x05 = 0x05U,

		/// Reserved for ISO (0x06).
		/// Reserved for future use as per ISO standards.
		RESERVED_ISO_0x06 = 0x06U,

		/// Reserved for ISO (0x07).
		/// Reserved for future use as per ISO standards.
		RESERVED_ISO_0x07 = 0x07U,

		/// Reserved for ISO (0x08).
		/// Reserved for future use as per ISO standards.
		RESERVED_ISO_0x08 = 0x08U,

		/// Reserved for ISO (0x09).
		/// Reserved for future use as per ISO standards.
		RESERVED_ISO_0x09 = 0x09U,

		/// Reserved for ISO (0x0A).
		/// Reserved for future use as per ISO standards.
		RESERVED_ISO_0x0A = 0x0AU,

		/// Reserved for ISO (0x0B).
		/// Reserved for future use as per ISO standards.
		RESERVED_ISO_0x0B = 0x0BU,

		/// Reserved for ISO (0x0C).
		/// Reserved for future use as per ISO standards.
		RESERVED_ISO_0x0C = 0x0CU,

		/// Reserved for ISO (0x0D).
		/// Reserved for future use as per ISO standards.
		RESERVED_ISO_0x0D = 0x0DU,

		/// Reserved for ISO (0x0E).
		/// Reserved for future use as per ISO standards.
		RESERVED_ISO_0x0E = 0x0EU,

		/// Reserved for ISO (0x08).
		/// Reserved for future use as per ISO standards.
		RESERVED_ISO_0x0F = 0x0FU,

		/// VIN and or GID are not synchronized.
		VIN_AND_OR_GID_ARE_NOT_SINCHRONIZED = 0x10U,
	};

	/// @brief Represents the DoIP (Diagnostics over IP) protocol versions.
	enum class DoIpProtocolVersion : uint8_t
	{
		/// @brief Reserved protocol version.
		/// This value is used when the version is not specified.
		ReservedVersion = 0x00U,

		/// @brief Protocol version 1, based on ISO 2010 specification.
		Version01Iso2010 = 0x01U,

		/// @brief Protocol version 2, based on ISO 2012 specification.
		Version02Iso2012 = 0x02U,

		/// @brief Protocol version 3, based on ISO 2019 specification.
		Version03Iso2019 = 0x03U,

		/// @brief Protocol version 4, based on ISO 2019 AMD1 (Amendment 1) specification.
		Version04Iso2019_AMD1 = 0x04U,

		/// @brief Default protocol version.
		/// Used for broadcast Vehicle Identification Request Messages.
		DefaultVersion = 0xFFU,

		/// Represents an unknown or unsupported protocol version (not specified by ISO).
		/// Used to indicate an unsupported or unknown protocol version for internal usage.
		UnknownVersion = 0xEF
	};

	/// @brief Enum representing DoIP payload types.
	/// These payload types are defined as part of theDoIP(Diagnostic over IP) protocol
	/// and specify the type of message being transmitted.
	enum class DoIpPayloadTypes : uint16_t
	{
		/// Generic header negative acknowledgment.
		/// Indicates a failure or error in processing the generic header.
		GENERIC_HEADER_NEG_ACK = 0x0000U,

		/// Vehicle identification request.
		/// Used to request identification details of a vehicle.
		VEHICLE_IDENTIFICATION_REQUEST = 0x0001U,

		/// Vehicle identification request with EID.
		/// Requests identification using an external identifier(EID).
		VEHICLE_IDENTIFICATION_REQUEST_WITH_EID = 0x0002U,

		/// Vehicle identification request with VIN.
		/// Requests identification using the vehicle's VIN (Vehicle Identification Number).
		VEHICLE_IDENTIFICATION_REQUEST_WITH_VIN = 0x0003U,

		/// Announcement message.
		/// Sent to announce the availability of a DoIP entity.
		ANNOUNCEMENT_MESSAGE = 0x0004U,

		/// Routing activation request.
		/// Initiates a routing activation procedure.
		ROUTING_ACTIVATION_REQUEST = 0x0005U,

		/// Routing activation response.
		/// Response to a routing activation request.
		ROUTING_ACTIVATION_RESPONSE = 0x0006U,

		/// Alive check request.
		/// Sent to verify that a DoIP entity is still operational.
		ALIVE_CHECK_REQUEST = 0x0007U,

		/// Alive check response.
		/// Response to an alive check request.
		ALIVE_CHECK_RESPONSE = 0x0008U,

		/// Entity status request.
		/// Used to request the status of a DoIP entity.
		ENTITY_STATUS_REQUEST = 0x4001U,

		/// Entity status response.
		/// Response to an entity status request.
		ENTITY_STATUS_RESPONSE = 0x4002U,

		/// Diagnostic power mode request.
		/// Requests the current power mode of a DoIP entity.
		DIAGNOSTIC_POWER_MODE_REQUEST = 0x4003U,

		/// Diagnostic power mode response.
		/// Response to a diagnostic power mode request.
		DIAGNOSTIC_POWER_MODE_RESPONSE = 0x4004U,

		/// Diagnostic message type.
		/// Represents a generic diagnostic message.
		DIAGNOSTIC_MESSAGE_TYPE = 0x8001U,

		/// Diagnostic message positive acknowledgment.
		/// Indicates successful processing of a diagnostic message.
		DIAGNOSTIC_MESSAGE_POS_ACK = 0x8002U,

		/// Diagnostic message negative acknowledgment.
		/// Indicates an error in processing a diagnostic message.
		DIAGNOSTIC_MESSAGE_NEG_ACK = 0x8003U
	};

	/// @brief Enum representing DoIP diagnostic ports (ISO 13400).
	/// These ports are used for communication in the DoIP protocol over different transport layers.
	enum class DoIpPorts : uint16_t
	{

		/// TCP and UDP doip Ports.
		/// The standard port for DoIP communication.
		TCP_UDP_PORT = 13400U,

		/// TLS Port.
		/// The standard port for DoIP communication over a secure TLS connection.
		TLS_PORT = 3496U
	};

	using namespace DoIpConstants;

	/// @class DoIpLayer
	/// Represents an DoIP protocol layer. Currently only IPv4 DoIP messages are supported
	class DoIpLayer : public Layer
	{
	public:
		/// Get the doip payload type
		/// @return DoIpPayloadTypes presenting the message doip payload type
		virtual DoIpPayloadTypes getPayloadType() const = 0;

		/// Get the doip payload type as string
		/// @return uint16_t presenting the message doip payload type as string
		std::string getPayloadTypeAsStr() const;

		/// Get the version of DOIP protocol
		/// @return DoIpProtocolVersion presenting the used protocol version (DOIPV)
		DoIpProtocolVersion getProtocolVersion() const;

		/// Get the version of DOIP protocol
		/// @return string presentation the used protocol version (DOIPV)
		std::string getProtocolVersionAsStr() const;

		/// Set the version of DOIP protocol
		/// @param[in] version the version of DOIP protocol to set, restricted to existent doip version
		void setProtocolVersion(DoIpProtocolVersion version);

		/// Additional setter for raw protocol version (for testing/fuzzing/debugging)
		/// @param[in] rawVersion the raw version of DOIP protocol to set
		void setProtocolVersion(uint8_t rawVersion);

		/// Get the invert version of DOIP protocol
		/// @return A uint8_t presenting the used protocol invert version (DOIPV)
		uint8_t getInvertProtocolVersion() const;

		/// Set the invert protocol version of DOIP protocol
		/// @param[in] iVersion the invert version of DOIP protocol to set
		void setInvertProtocolVersion(uint8_t iVersion);

		/// Get the doip payload length
		/// @return uint32_t presenting the length of doip paylad not including the header
		uint32_t getPayloadLength() const;

		/// Set the doip payload length
		/// @param[in] length the doip payload length to set
		void setPayloadLength(uint32_t length);

		/// A method that creates a DoIP layer from packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored
		/// @return A newly allocated DoIP layer of one of the declared types (according to the message type)
		static DoIpLayer* parseDoIpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/// A static method that checks whether a port is considered as a DOIP port
		/// @param[in] port The port number to check
		/// @return True if this is a DOIP port number, false otherwise
		static inline bool isDoIpPort(uint16_t port);

		/// A static method that validates the input data
		/// @param[in] data The pointer to the beginning of a byte stream of an DOIP layer
		/// @param[in] dataLen The length of the byte stream
		/// @return True if the data is valid and can represent an DOIP layer
		static inline bool isDataValid(uint8_t* data, size_t dataLen);

		// implement abstract methods

		/// parse UDS layer
		void parseNextLayer() override;

		/// @return The size of @ref doiphdr + attached fields length
		size_t getHeaderLen() const override
		{
			return m_DataLen;
		}

		std::string toString() const override;

		void computeCalculateFields() override
		{}

		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelTransportLayer;
		}

	private:
		void setPayloadType(DoIpPayloadTypes payloadType);

		static inline bool isPayloadTypeValid(uint16_t type);

		static inline bool isProtocolVersionValid(uint8_t version, uint8_t inVersion, DoIpPayloadTypes type);

		static inline bool isPayloadLengthValid(uint32_t payloadLength, size_t dataLen);

	protected:
		// protected c'tors, this class cannot be instantiated by users
		DoIpLayer();

		DoIpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		doiphdr* getDoIpHeader() const
		{
			return reinterpret_cast<doiphdr*>(m_Data);
		}

		void setHeaderFields(DoIpProtocolVersion version, DoIpPayloadTypes type, uint32_t length);
	};

	// inline methods definition
	inline bool DoIpLayer::isDoIpPort(uint16_t port)
	{
		auto portAsEnum = static_cast<DoIpPorts>(port);
		return (portAsEnum == DoIpPorts::TCP_UDP_PORT || portAsEnum == DoIpPorts::TLS_PORT);
	}

	inline bool DoIpLayer::isDataValid(uint8_t* data, size_t dataLen)
	{
		if (data == nullptr || dataLen < DOIP_HEADER_LEN)
			return false;

		auto* doipHeader = reinterpret_cast<doiphdr*>(data);
		const uint8_t version = doipHeader->protocolVersion;
		const uint8_t inVersion = doipHeader->invertProtocolVersion;
		const uint16_t payloadRaw = doipHeader->payloadType;
		const uint32_t lengthRaw = doipHeader->payloadLength;

		const uint32_t payloadLen = htobe32(lengthRaw);

		if (!isPayloadTypeValid(payloadRaw))
			return false;
		// if payload type is validated, we ensure passing a valid type to isProtocolVersionValid()
		const DoIpPayloadTypes payloadType = static_cast<DoIpPayloadTypes>(htobe16(payloadRaw));
		if (!isProtocolVersionValid(version, inVersion, payloadType))
			return false;

		if (!isPayloadLengthValid(payloadLen, dataLen))
			return false;

		return true;
	}

	inline bool DoIpLayer::isProtocolVersionValid(uint8_t version, uint8_t inVersion, DoIpPayloadTypes type)
	{
		const DoIpProtocolVersion parsedVersion = static_cast<DoIpProtocolVersion>(version);

		switch (parsedVersion)
		{
		case DoIpProtocolVersion::ReservedVersion:
		{
			PCPP_LOG_DEBUG("[Malformed doip packet]: Reserved ISO DoIP protocol version detected: 0x"
			               << std::hex << static_cast<int>(version));
			return false;
		}
		case DoIpProtocolVersion::DefaultVersion:
			if (type != DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST_WITH_VIN &&
			    type != DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST_WITH_EID &&
			    type != DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST)
			{
				PCPP_LOG_DEBUG("[Malformed doip packet]: Invalid/unsupported DoIP version!");
				return false;
			}
		case DoIpProtocolVersion::Version01Iso2010:
		case DoIpProtocolVersion::Version02Iso2012:
		case DoIpProtocolVersion::Version03Iso2019:
		case DoIpProtocolVersion::Version04Iso2019_AMD1:
		{
			if (version != static_cast<uint8_t>(~inVersion))
			{
				PCPP_LOG_DEBUG("[Malformed doip packet]: Protocol version and inverse version mismatch! Version: 0x"
				               << std::hex << static_cast<int>(version) << ", Inverted: 0x"
				               << static_cast<int>(inVersion));
				return false;
			}
			return true;
		}
		default:
			PCPP_LOG_DEBUG("[Malformed doip packet]: Unknown DoIP protocol version: 0x" << std::hex
			                                                                            << static_cast<int>(version));
			return false;
		}
	}

	inline bool DoIpLayer::isPayloadTypeValid(uint16_t type)
	{
		const DoIpPayloadTypes payloadType = static_cast<DoIpPayloadTypes>(htobe16(type));

		switch (payloadType)
		{
		case DoIpPayloadTypes::ALIVE_CHECK_REQUEST:
		case DoIpPayloadTypes::ALIVE_CHECK_RESPONSE:
		case DoIpPayloadTypes::ANNOUNCEMENT_MESSAGE:
		case DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_NEG_ACK:
		case DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_POS_ACK:
		case DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_TYPE:
		case DoIpPayloadTypes::DIAGNOSTIC_POWER_MODE_REQUEST:
		case DoIpPayloadTypes::DIAGNOSTIC_POWER_MODE_RESPONSE:
		case DoIpPayloadTypes::ENTITY_STATUS_REQUEST:
		case DoIpPayloadTypes::ENTITY_STATUS_RESPONSE:
		case DoIpPayloadTypes::GENERIC_HEADER_NEG_ACK:
		case DoIpPayloadTypes::ROUTING_ACTIVATION_REQUEST:
		case DoIpPayloadTypes::ROUTING_ACTIVATION_RESPONSE:
		case DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST:
		case DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST_WITH_EID:
		case DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST_WITH_VIN:
			return true;

		default:
			PCPP_LOG_DEBUG("[Malformed doip packet]: Invalid DoIP payload type: 0x" << std::hex << type);
			return false;
		}
	}

	inline bool DoIpLayer::isPayloadLengthValid(uint32_t payloadLength, size_t dataLen)
	{
		const size_t actualPayloadLen = dataLen - DOIP_HEADER_LEN;

		if (payloadLength != actualPayloadLen)
		{
			PCPP_LOG_DEBUG("[Malformed doip packet]: Payload length mismatch: expected "
			               << payloadLength << " bytes, but got " << actualPayloadLen << " bytes.");
			return false;
		}

		return true;
	}

	//~~~~~~~~~~~~~~~~~~~~~~~~~|
	// RoutingActivationRequest|
	//~~~~~~~~~~~~~~~~~~~~~~~~~|

	/// @class DoIpRoutingActivationRequest
	/// @brief Represents a DoIP Routing Activation Request message.
	///
	/// Provides parsing and construction for Routing Activation Request messages
	/// as defined by the DoIP protocol.
	class DoIpRoutingActivationRequest : public DoIpLayer
	{
	public:
		/// @brief Constructs the layer from raw DoIP packet data.
		/// @param[in] data Pointer to raw packet data.
		/// @param[in] dataLen Length of the raw data.
		/// @param[in] prevLayer Pointer to the previous layer.
		/// @param[in] packet Pointer to the parent packet instance.
		DoIpRoutingActivationRequest(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/// @brief Constructs the message from field values.
		/// @param[in] sourceAddress Source address of the tester.
		/// @param[in] activationType Type of routing activation.
		DoIpRoutingActivationRequest(uint16_t sourceAddress, DoIpActivationTypes activationType);

		/// @brief Returns the source address.
		uint16_t getSourceAddress() const;

		/// @brief Sets the source address.
		void setSourceAddress(uint16_t value);

		/// @brief Returns the activation type.
		DoIpActivationTypes getActivationType() const;

		/// @brief Sets the activation type.
		void setActivationType(DoIpActivationTypes activationType);

		/// @brief Gets the reserved ISO bytes.
		std::array<uint8_t, DOIP_RESERVED_ISO_LEN> getReservedIso() const;

		/// @brief Sets the reserved ISO bytes.
		void setReservedIso(const std::array<uint8_t, DOIP_RESERVED_ISO_LEN>& reservedIso);

		/// @brief Gets pointer to reserved OEM bytes if present.
		const uint8_t* getReservedOem() const;

		/// @brief Sets the reserved OEM bytes.
		void setReservedOem(const std::array<uint8_t, DOIP_RESERVED_OEM_LEN>& reservedOem);

		/// @brief Checks if OEM reserved bytes are present.
		bool hasReservedOem() const;

		/// @brief Clears the OEM reserved bytes.
		void clearReservedOem();

		/// @brief Returns a human-readable summary of the message.
		std::string getSummary() const;

		/// @brief Returns the DoIP payload type for this message.
		DoIpPayloadTypes getPayloadType() const override
		{
			return DoIpPayloadTypes::ROUTING_ACTIVATION_REQUEST;
		}

		/// @brief Checks if the routing activation request data length is valid.
		/// @param[in] dataLen The length of the data.
		/// @return true if the data is valid, false otherwise.
		static inline bool isDataLenValid(size_t dataLen)
		{
			return (dataLen == FIXED_LEN || dataLen == OPT_LEN);
		}

	private:
#pragma pack(push, 1)
		struct routing_activation_request : doiphdr
		{
			uint16_t sourceAddress;

			uint8_t activationType;

			std::array<uint8_t, DOIP_RESERVED_ISO_LEN> reservedIso;
		};
#pragma pack(pop)

		routing_activation_request* getRoutingRequest() const
		{
			return reinterpret_cast<routing_activation_request*>(m_Data);
		}
		static constexpr size_t FIXED_LEN = sizeof(routing_activation_request);
		static constexpr size_t OPT_LEN = FIXED_LEN + DOIP_RESERVED_OEM_LEN;
	};

	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	// DoIpRoutingActivationResponse|
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|

	/// @class DoIpRoutingActivationResponse
	/// @brief Represents a DoIP Routing Activation Response message.
	///
	/// Provides parsing and construction for Routing Activation Response messages
	/// as defined by the DoIP protocol.
	class DoIpRoutingActivationResponse : public DoIpLayer
	{
	public:
		/// @brief Constructs the layer from raw DoIP packet data.
		/// @param[in] data Pointer to raw packet data.
		/// @param[in] dataLen Length of the raw data.
		/// @param[in] prevLayer Pointer to the previous layer.
		/// @param[in] packet Pointer to the parent packet instance.
		DoIpRoutingActivationResponse(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/// @brief Constructs the message from field values.
		/// @param[in] logicalAddressExternalTester Logical address of the external tester.
		/// @param[in] sourceAddress ECU source address.
		/// @param[in] responseCode The routing response code.
		DoIpRoutingActivationResponse(uint16_t logicalAddressExternalTester, uint16_t sourceAddress,
		                              DoIpRoutingResponseCodes responseCode);

		/// @brief Gets the logical address of the external tester.
		uint16_t getLogicalAddressExternalTester() const;

		/// @brief Sets the logical address of the external tester.
		void setLogicalAddressExternalTester(uint16_t addr);

		/// @brief Gets the source address.
		uint16_t getSourceAddress() const;

		/// @brief Sets the source address.
		void setSourceAddress(uint16_t addr);

		/// @brief Gets the routing response code.
		DoIpRoutingResponseCodes getResponseCode() const;

		/// @brief Sets the routing response code.
		void setResponseCode(DoIpRoutingResponseCodes code);

		/// @brief Gets the reserved ISO bytes.
		std::array<uint8_t, DOIP_RESERVED_ISO_LEN> getReservedIso() const;

		/// @brief Sets the reserved ISO bytes.
		void setReservedIso(const std::array<uint8_t, DOIP_RESERVED_ISO_LEN>& reservedIso);

		/// @brief Gets pointer to reserved OEM bytes if present.
		const uint8_t* getReservedOem() const;

		/// @brief Sets the reserved OEM bytes.
		void setReservedOem(const std::array<uint8_t, DOIP_RESERVED_OEM_LEN>& reservedOem);

		/// @brief Checks if OEM reserved bytes are present.
		bool hasReservedOem() const;

		/// @brief Clears the OEM reserved bytes.
		void clearReservedOem();

		/// @brief Returns a human-readable summary of the message.
		std::string getSummary() const;

		/// @brief Returns the DoIP payload type for this message.
		DoIpPayloadTypes getPayloadType() const override
		{
			return DoIpPayloadTypes::ROUTING_ACTIVATION_RESPONSE;
		}

		/// @brief Checks if the routing activation response data length is valid.
		/// @param[in] dataLen The length of the data.
		/// @return true if the data is valid, false otherwise.
		static inline bool isDataLenValid(size_t dataLen)
		{
			return (dataLen == FIXED_LEN || dataLen == OPT_LEN);
		}

	private:
#pragma pack(push, 1)
		struct routing_activation_response : doiphdr
		{
			uint16_t logicalAddressExternalTester;

			uint16_t sourceAddress;

			uint8_t responseCode;

			std::array<uint8_t, DOIP_RESERVED_ISO_LEN> reservedIso;
		};
#pragma pack(pop)
		routing_activation_response* getRoutingResponse() const
		{
			return reinterpret_cast<routing_activation_response*>(m_Data);
		}
		static constexpr size_t FIXED_LEN = sizeof(routing_activation_response);
		static constexpr size_t OPT_LEN = FIXED_LEN + DOIP_RESERVED_OEM_LEN;
	};

	//~~~~~~~~~~~~~~~~~~~~~~|
	// DoIpGenericHeaderNack|
	//~~~~~~~~~~~~~~~~~~~~~~|

	/// @class DoIpGenericHeaderNack
	/// @brief Represents a DoIP Generic Header Negative Acknowledgement message.
	///
	/// This message indicates that a received DoIP header was invalid or unsupported.
	class DoIpGenericHeaderNack : public DoIpLayer
	{
	public:
		/// @brief Constructs the layer from raw DoIP packet data.
		/// @param[in] data Pointer to raw packet data.
		/// @param[in] dataLen Length of the raw data.
		/// @param[in] prevLayer Pointer to the previous layer.
		/// @param[in] packet Pointer to the parent packet instance.
		DoIpGenericHeaderNack(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/// @brief Constructs the message with a specific NACK code.
		/// @param[in] nackCode The generic header NACK code.
		explicit DoIpGenericHeaderNack(DoIpGenericHeaderNackCodes nackCode);

		/// @brief Gets the NACK code.
		DoIpGenericHeaderNackCodes getNackCode() const;

		/// @brief Sets the NACK code.
		void setNackCode(DoIpGenericHeaderNackCodes code);

		/// @brief Sets the Raw NACK code for debugging/testing.
		void setNackCode(uint8_t code);

		/// @brief Returns a human-readable summary of the message.
		std::string getSummary() const;

		/// @brief Returns the DoIP payload type for this message.
		DoIpPayloadTypes getPayloadType() const override
		{
			return DoIpPayloadTypes::GENERIC_HEADER_NEG_ACK;
		}

		/// @brief Checks if the NACK data length is valid.
		/// @param[in] dataLen Length of the data buffer.
		/// @return true if the data length is valid, false otherwise.
		static inline bool isDataLenValid(size_t dataLen)
		{
			return (dataLen == FIXED_LEN);
		}

	private:
		static constexpr size_t NACK_CODE_OFFSET = DOIP_HEADER_LEN;
		static constexpr size_t NACK_CODE_LEN = sizeof(uint8_t);
		static constexpr size_t FIXED_LEN = NACK_CODE_OFFSET + NACK_CODE_LEN;
	};

	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	// DoIpVehicleIdentificationRequestEID|
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|

	/// @class DoIpVehicleIdentificationRequestEID
	/// @brief Represents a DoIP Vehicle Identification Request with EID.
	///
	/// This message is used to identify a vehicle based on its Entity ID (EID).
	class DoIpVehicleIdentificationRequestEID : public DoIpLayer
	{
	public:
		/// @brief Constructs the layer from raw DoIP packet data.
		/// @param[in] data Pointer to raw packet data.
		/// @param[in] dataLen Length of the raw data.
		/// @param[in] prevLayer Pointer to the previous layer.
		/// @param[in] packet Pointer to the parent packet instance.
		DoIpVehicleIdentificationRequestEID(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/// @brief Constructs the message using the specified EID.
		/// @param[in] eid A 6-byte Entity ID used for vehicle identification.
		explicit DoIpVehicleIdentificationRequestEID(const std::array<uint8_t, DOIP_EID_LEN>& eid = {});

		/// @brief Gets the Entity ID (EID).
		std::array<uint8_t, DOIP_EID_LEN> getEID() const;

		/// @brief Sets the Entity ID (EID).
		void setEID(const std::array<uint8_t, DOIP_EID_LEN>& eid);

		/// @brief Returns a human-readable summary of the message.
		std::string getSummary() const;

		/// @brief Returns the DoIP payload type for this message.
		DoIpPayloadTypes getPayloadType() const override
		{
			return DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST_WITH_EID;
		}

		/// @brief Checks if the EID data length is valid.
		/// @param[in] dataLen Length of the data buffer.
		/// @return true if the data length is valid, false otherwise.
		static inline bool isDataLenValid(size_t dataLen)
		{
			return (dataLen == FIXED_LEN);
		}

	private:
		static constexpr size_t EID_OFFSET = DOIP_HEADER_LEN;
		static constexpr size_t FIXED_LEN = EID_OFFSET + DOIP_EID_LEN;
	};

	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	// DoIpVehicleIdentificationRequestVIN|
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|

	/// @class DoIpVehicleIdentificationRequestVIN
	/// @brief Represents a DoIP Vehicle Identification Request with VIN.
	///
	/// This message is used to identify a vehicle based on its Vehicle Identification Number (VIN).
	class DoIpVehicleIdentificationRequestVIN : public DoIpLayer
	{
	public:
		/// @brief Constructs the layer from raw DoIP packet data.
		/// @param[in] data Pointer to raw packet data.
		/// @param[in] dataLen Length of the raw data.
		/// @param[in] prevLayer Pointer to the previous layer.
		/// @param[in] packet Pointer to the parent packet instance.
		DoIpVehicleIdentificationRequestVIN(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/// @brief Constructs the message using the specified VIN.
		/// @param[in] vin A 17-byte Vehicle Identification Number.
		explicit DoIpVehicleIdentificationRequestVIN(const std::array<uint8_t, DOIP_VIN_LEN>& vin = {});

		/// @brief Gets the Vehicle Identification Number (VIN).
		std::array<uint8_t, DOIP_VIN_LEN> getVIN() const;

		/// @brief Sets the Vehicle Identification Number (VIN).
		void setVIN(const std::array<uint8_t, DOIP_VIN_LEN>& vin);

		/// @brief Returns a human-readable summary of the message.
		std::string getSummary() const;

		/// @brief Returns the DoIP payload type for this message.
		DoIpPayloadTypes getPayloadType() const override
		{
			return DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST_WITH_VIN;
		}

		/// @brief Checks if the VIN data length is valid.
		/// @param[in] dataLen Length of the data buffer.
		/// @return true if the data length is valid, false otherwise.
		static inline bool isDataLenValid(size_t dataLen)
		{
			return (dataLen == FIXED_LEN);
		}

	private:
		static constexpr size_t VIN_OFFSET = DOIP_HEADER_LEN;
		static constexpr size_t FIXED_LEN = VIN_OFFSET + DOIP_VIN_LEN;
	};

	//~~~~~~~~~~~~~~~~~~~~~~~~|
	// DoIpVehicleAnnouncement|
	//~~~~~~~~~~~~~~~~~~~~~~~~|

	/// @class DoIpVehicleAnnouncement
	/// @brief Represents a DoIP Vehicle Announcement message.
	///
	/// This message is broadcasted by a vehicle to announce its presence, including VIN,
	/// logical address, EID, GID, and optionally synchronization status.
	class DoIpVehicleAnnouncement : public DoIpLayer
	{
	public:
		/// @brief Constructs the layer from raw DoIP packet data.
		/// @param[in] data Pointer to the raw data buffer.
		/// @param[in] dataLen Size of the data buffer in bytes.
		/// @param[in] prevLayer Pointer to the previous protocol layer.
		/// @param[in] packet Pointer to the parent packet.
		DoIpVehicleAnnouncement(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/// @brief Constructs the message using specified field values.
		/// @param[in] vin Vehicle Identification Number (VIN).
		/// @param[in] logicalAddress Logical address of the vehicle.
		/// @param[in] eid Entity Identifier (EID).
		/// @param[in] gid Group Identifier (GID).
		/// @param[in] actionCode Further action code.
		DoIpVehicleAnnouncement(const std::array<uint8_t, DOIP_VIN_LEN>& vin, uint16_t logicalAddress,
		                        const std::array<uint8_t, DOIP_EID_LEN>& eid,
		                        const std::array<uint8_t, DOIP_GID_LEN>& gid, DoIpActionCodes actionCode);

		/// @brief Gets the Vehicle Identification Number (VIN).
		std::array<uint8_t, DOIP_VIN_LEN> getVIN() const;

		/// @brief Gets the logical address of the vehicle.
		uint16_t getLogicalAddress() const;

		/// @brief Gets the Entity Identifier (EID).
		std::array<uint8_t, DOIP_EID_LEN> getEID() const;

		/// @brief Gets the Group Identifier (GID).
		std::array<uint8_t, DOIP_GID_LEN> getGID() const;

		/// @brief Gets the further action required code.
		DoIpActionCodes getFurtherActionRequired() const;

		/// @brief Gets the optional synchronization status if available.
		const DoIpSyncStatus* getSyncStatus() const;

		/// @brief Sets the Vehicle Identification Number (VIN).
		void setVIN(const std::array<uint8_t, DOIP_VIN_LEN>& vin);

		/// @brief Sets the logical address.
		void setLogicalAddress(uint16_t address);

		/// @brief Sets the Entity Identifier (EID).
		void setEID(const std::array<uint8_t, DOIP_EID_LEN>& eid);

		/// @brief Sets the Group Identifier (GID).
		void setGID(const std::array<uint8_t, DOIP_GID_LEN>& gid);

		/// @brief Sets the further action required code.
		void setFurtherActionRequired(DoIpActionCodes action);

		/// @brief Sets the synchronization status.
		void setSyncStatus(DoIpSyncStatus sync);

		/// @brief Checks whether the sync status is present.
		bool hasSyncStatus() const;

		/// @brief Clears the optional sync status field.
		void clearSyncStatus();

		/// @brief Returns a human-readable summary of the message.
		std::string getSummary() const;

		/// @brief Returns the DoIP payload type.
		DoIpPayloadTypes getPayloadType() const override
		{
			return DoIpPayloadTypes::ANNOUNCEMENT_MESSAGE;
		}

		/// @brief checks if the vehicle announcement data length is valid.
		/// @param[in] dataLen Length of the data buffer.
		/// @return true if the data length is valid, false otherwise.
		static inline bool isDataLenValid(size_t dataLen)
		{
			return (dataLen == FIXED_LEN || dataLen == OPT_LEN);
		}

	private:
#pragma pack(push, 1)
		struct vehicle_announcement : doiphdr
		{
			std::array<uint8_t, DOIP_VIN_LEN> vin;

			uint16_t logicalAddress;

			std::array<uint8_t, DOIP_EID_LEN> eid;

			std::array<uint8_t, DOIP_GID_LEN> gid;

			uint8_t actionCode;
		};
#pragma pack(pop)

		vehicle_announcement* getVehicleAnnouncement() const
		{
			return reinterpret_cast<vehicle_announcement*>(m_Data);
		}
		static constexpr size_t FIXED_LEN = sizeof(vehicle_announcement);
		static constexpr size_t SYNC_STATUS_OFFSET = FIXED_LEN;
		static constexpr size_t SYNC_STATUS_LEN = 1;
		static constexpr size_t OPT_LEN = SYNC_STATUS_OFFSET + SYNC_STATUS_LEN;
	};

	//~~~~~~~~~~~~~~~~~~~~~~~|
	// DoIpAliveCheckResponse|
	//~~~~~~~~~~~~~~~~~~~~~~~|

	/// @class DoIpAliveCheckResponse
	/// @brief Represents a DoIP Alive Check Response message.
	///
	/// The Alive Check Response is used to confirm that an entity is still active in the network.
	/// It contains the source address of the responder.
	class DoIpAliveCheckResponse : public DoIpLayer
	{
	public:
		/// @brief Constructs the layer from raw DoIP packet data.
		/// @param[in] data Pointer to the raw data buffer.
		/// @param[in] dataLen Size of the data buffer in bytes.
		/// @param[in] prevLayer Pointer to the previous protocol layer.
		/// @param[in] packet Pointer to the parent packet.
		DoIpAliveCheckResponse(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/// @brief Constructs the message using the specified source address.
		/// @param[in] sourceAddress The source address of the responder.
		explicit DoIpAliveCheckResponse(uint16_t sourceAddress);

		/// @brief Gets the source address.
		/// @return The 2-byte source address of the responder.
		uint16_t getSourceAddress() const;

		/// @brief Sets the source address.
		/// @param[in] address The new source address.
		void setSourceAddress(uint16_t address);

		/// @brief Returns a human-readable summary of the message.
		/// @return A string summarizing the Alive Check Response.
		std::string getSummary() const;

		/// @brief Returns the DoIP payload type.
		/// @return DoIpPayloadTypes::ALIVE_CHECK_RESPONSE
		DoIpPayloadTypes getPayloadType() const override
		{
			return DoIpPayloadTypes::ALIVE_CHECK_RESPONSE;
		}
		/// @brief Checks if the Alive Check Response data length is valid.
		/// @param[in] dataLen Length of the data buffer.
		/// @return true if the data length is valid, false otherwise.
		static inline bool isDataLenValid(size_t dataLen)
		{
			return (dataLen == FIXED_LEN);
		}

	private:
		static constexpr size_t SOURCE_ADDRESS_OFFSET = DOIP_HEADER_LEN;
		static constexpr size_t FIXED_LEN = SOURCE_ADDRESS_OFFSET + DOIP_SOURCE_ADDRESS_LEN;
	};

	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	// DoIpDiagnosticPowerModeResponse|
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|

	/// @class DoIpDiagnosticPowerModeResponse
	/// @brief Represents a DoIP Diagnostic Power Mode Response message.
	///
	/// This message is used to communicate the current power mode of the vehicle
	/// or control unit in response to a diagnostic power mode request.
	class DoIpDiagnosticPowerModeResponse : public DoIpLayer
	{
	public:
		/// @brief Constructs the layer from raw DoIP packet data.
		/// @param[in] data Pointer to the raw data buffer.
		/// @param[in] dataLen Size of the data buffer in bytes.
		/// @param[in] prevLayer Pointer to the previous protocol layer.
		/// @param[in] packet Pointer to the parent packet.
		DoIpDiagnosticPowerModeResponse(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/// @brief Constructs the message using the specified power mode code.
		/// @param[in] modeCode Diagnostic power mode code to set.
		explicit DoIpDiagnosticPowerModeResponse(DoIpDiagnosticPowerModeCodes modeCode);

		/// @brief Gets the current power mode code.
		/// @return The diagnostic power mode code.
		DoIpDiagnosticPowerModeCodes getPowerModeCode() const;

		/// @brief Sets the power mode code.
		/// @param[in] code The new diagnostic power mode code.
		void setPowerModeCode(DoIpDiagnosticPowerModeCodes code);

		/// @brief Returns a human-readable summary of the message.
		/// @return A string summarizing the Diagnostic Power Mode Response.
		std::string getSummary() const;

		/// @brief Returns the DoIP payload type.
		/// @return DoIpPayloadTypes::DIAGNOSTIC_POWER_MODE_RESPONSE
		DoIpPayloadTypes getPayloadType() const override
		{
			return DoIpPayloadTypes::DIAGNOSTIC_POWER_MODE_RESPONSE;
		}

		/// @brief Checks if the Diagnostic Power Mode Response data length is valid.
		/// @param[in] dataLen Length of the data buffer.
		/// @return true if the data length is valid, false otherwise.
		static inline bool isDataLenValid(size_t dataLen)
		{
			return (dataLen == FIXED_LEN);
		}

	private:
		static constexpr size_t POWER_MODE_CODE_OFFSET = DOIP_HEADER_LEN;
		static constexpr size_t POWER_MODE_CODE_LEN = sizeof(uint8_t);
		static constexpr size_t FIXED_LEN = POWER_MODE_CODE_OFFSET + POWER_MODE_CODE_LEN;
	};

	//~~~~~~~~~~~~~~~~~~~~~~~~~|
	// DoIpEntityStatusResponse|
	//~~~~~~~~~~~~~~~~~~~~~~~~~|

	/// @class DoIpEntityStatusResponse
	/// @brief Represents a DoIP Entity Status Response message.
	///
	/// This message provides the status of a DoIP entity, such as its type,
	/// the number of concurrent sockets it can support, and optionally the max data size.
	class DoIpEntityStatusResponse : public DoIpLayer
	{
	public:
		/// @brief Constructs the layer from raw DoIP packet data.
		/// @param[in] data Pointer to the raw data buffer.
		/// @param[in] dataLen Size of the data buffer in bytes.
		/// @param[in] prevLayer Pointer to the previous protocol layer.
		/// @param[in] packet Pointer to the parent packet.
		DoIpEntityStatusResponse(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/// @brief Constructs the message using provided field values.
		/// @param[in] nodeType Type of the DoIP node (default: GATEWAY).
		/// @param[in] maxConcurrentSockets Maximum supported concurrent sockets.
		/// @param[in] currentlyOpenSockets Currently active sockets.
		DoIpEntityStatusResponse(DoIpEntityStatusResponseCode nodeType, uint8_t maxConcurrentSockets,
		                         uint8_t currentlyOpenSockets);

		/// @brief Returns the DoIP payload type.
		/// @return DoIpPayloadTypes::ENTITY_STATUS_RESPONSE
		DoIpPayloadTypes getPayloadType() const override
		{
			return DoIpPayloadTypes::ENTITY_STATUS_RESPONSE;
		}

		/// @brief Gets the type of the DoIP node.
		/// @return The DoIP entity status value.
		DoIpEntityStatusResponseCode getNodeType() const;

		/// @brief Gets the maximum number of concurrent sockets supported.
		/// @return Max supported concurrent sockets.
		uint8_t getMaxConcurrentSockets() const;

		/// @brief Gets the number of currently open sockets.
		/// @return Number of currently open sockets.
		uint8_t getCurrentlyOpenSockets() const;

		/// @brief Gets the optional maximum data size field.
		/// @return Pointer to a 4-byte array representing max data size, or nullptr if not set.
		const uint8_t* getMaxDataSize() const;

		/// @brief Sets the DoIP node type.
		/// @param[in] status New DoIP entity status.
		void setNodeType(DoIpEntityStatusResponseCode status);

		/// @brief Sets the maximum number of concurrent sockets.
		/// @param[in] sockets New maximum concurrent socket count.
		void setMaxConcurrentSockets(uint8_t sockets);

		/// @brief Sets the number of currently open sockets.
		/// @param[in] sockets New count of currently open sockets.
		void setCurrentlyOpenSockets(uint8_t sockets);

		/// @brief Sets the maximum data size field.
		/// @param[in] data 4-byte array representing the max data size.
		void setMaxDataSize(const std::array<uint8_t, 4>& data);

		/// @brief Checks if the optional max data size is present.
		/// @return True if max data size is available, false otherwise.
		bool hasMaxDataSize() const;

		/// @brief Clears the optional max data size field.
		void clearMaxDataSize();

		/// @brief Returns a human-readable summary of the message.
		/// @return A string summarizing the Entity Status Response.
		std::string getSummary() const;

		/// @brief  Checks if the Entity Status Response data length is valid.
		/// @param[in] dataLen Length of the data buffer.
		/// @return  true if the data length is valid, false otherwise.
		static inline bool isDataLenValid(size_t dataLen)
		{
			return (dataLen == FIXED_LEN || dataLen == OPT_LEN);
		}

	private:
#pragma pack(push, 1)
		struct entity_status_response : doiphdr
		{
			uint8_t nodeType;

			uint8_t maxConcurrentSockets;

			uint8_t currentlyOpenSockets;
		};
#pragma pack(pop)

		entity_status_response* getEntityStatusResponsePtr() const
		{
			return reinterpret_cast<entity_status_response*>(m_Data);
		}
		static constexpr size_t FIXED_LEN = sizeof(entity_status_response);
		static constexpr size_t MAX_DATA_SIZE_OFFSET = FIXED_LEN;
		static constexpr size_t MAX_DATA_SIZE_LEN = sizeof(uint32_t);
		static constexpr size_t OPT_LEN = FIXED_LEN + MAX_DATA_SIZE_LEN;
	};

	//~~~~~~~~~~~~~~~~~~~|
	// DoIpDiagnosticBase|
	//~~~~~~~~~~~~~~~~~~~|

	/// @class DoIpDiagnosticBase
	/// @brief Represents a DoIP Diagnostic Message sent between tester and ECU.
	/// This class includes source and target addresses.
	class DoIpDiagnosticBase : public DoIpLayer
	{
	public:
		/// @brief Constructs the DiagnosticMessage from raw packet data.
		/// @param[in] data Pointer to the raw payload data.
		/// @param[in] dataLen Length of the data buffer.
		/// @param[in] prevLayer Pointer to the previous protocol layer.
		/// @param[in] packet Pointer to the parent packet.
		DoIpDiagnosticBase(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/// @brief default c'tor.
		DoIpDiagnosticBase() {};

/// @struct  common_diagnostic_header
/// Common first diagnostic data in DoIP
/// messages (diagnostic/diagnosticAck/diagnosticNack).
/// common_diagnostic_header message structure (extends DoIP header).
#pragma pack(push, 1)
		struct common_diagnostic_header : doiphdr
		{
			/// @brief Diagnostic source address
			uint16_t sourceAddress;

			/// @brief Diagnostic target address
			uint16_t targetAddress;
		};
#pragma pack(pop)

		/// @brief Gets the source logical address of the message.
		/// @return 16-bit address of the source ECU.
		uint16_t getSourceAddress() const;

		/// @brief Gets the target logical address of the message.
		/// @return 16-bit address of the destination ECU.
		uint16_t getTargetAddress() const;

		/// @brief Sets the source logical address.
		/// @param[in] sourceAddress New 16-bit source address.
		void setSourceAddress(uint16_t sourceAddress);

		/// @brief Sets the target logical address.
		/// @param[in] targetAddress New 16-bit target address.
		void setTargetAddress(uint16_t targetAddress);

		/// @brief Returns a human-readable summary of the message content.
		/// @return A string summarizing the diagnostic message.
		virtual std::string getSummary() const = 0;

	private:
		common_diagnostic_header* getCommonDiagnosticHeader() const
		{
			return reinterpret_cast<common_diagnostic_header*>(m_Data);
		}
	};

	//~~~~~~~~~~~~~~~~~~~~~~|
	// DoIpDiagnosticMessage|
	//~~~~~~~~~~~~~~~~~~~~~~|

	/// @class DoIpDiagnosticMessage
	/// @brief Represents a DoIP Diagnostic message sent between tester and ECU.
	///
	/// This message includes source and target addresses and carries diagnostic service data.
	class DoIpDiagnosticMessage : public DoIpDiagnosticBase
	{
	public:
		/// @brief Constructs the DiagnosticMessage from raw packet data.
		/// @param[in] data Pointer to the raw payload data.
		/// @param[in] dataLen Length of the data buffer.
		/// @param[in] prevLayer Pointer to the previous protocol layer.
		/// @param[in] packet Pointer to the parent packet.
		DoIpDiagnosticMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/// @brief Constructs a DiagnosticMessage from specified field values.
		/// @param[in] sourceAddress Address of the sending ECU/tester.
		/// @param[in] targetAddress Address of the target ECU.
		/// @param[in] diagData Vector containing UDS diagnostic service data.
		DoIpDiagnosticMessage(uint16_t sourceAddress, uint16_t targetAddress, const std::vector<uint8_t>& diagData);

		/// @brief Set the diagnostic data payload.
		/// @param[in] data A vector containing the diagnostic data bytes to be stored.
		void setDiagnosticData(const std::vector<uint8_t>& data);

		/// @brief Get the diagnostic data payload.
		/// @return A vector containing the diagnostic data bytes.
		const std::vector<uint8_t> getDiagnosticData() const;

		/// @brief Returns a human-readable summary of the message content.
		/// @return A string summarizing the diagnostic message.
		std::string getSummary() const override;

		/// @brief Returns the DoIP payload type.
		/// @return DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_TYPE
		DoIpPayloadTypes getPayloadType() const override
		{
			return DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_TYPE;
		}

		// override getHeaderLen()
		size_t getHeaderLen() const override
		{
			return sizeof(doiphdr) + 2 * sizeof(uint16_t);
		}

		/// @brief Checks if the diagnostic data length is valid.
		/// @return true if the data length is valid, false otherwise.
		static inline bool isDataLenValid(size_t dataLen)
		{
			return (dataLen > MIN_LEN);
		}

	private:
		static constexpr size_t DIAGNOSTIC_DATA_OFFSET = sizeof(common_diagnostic_header);
		static constexpr size_t MIN_LEN = DIAGNOSTIC_DATA_OFFSET + 1; /*Min diagnostic message Len*/
	};

	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	// DoIpDiagnosticResponseMessageBase|
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	/// @class DoIpDiagnosticResponseMessageBase
	/// @brief Represents a Basic class for Diagnostic message (ACK/NACK) sent back to tester.
	class DoIpDiagnosticResponseMessageBase : public DoIpDiagnosticBase
	{
	public:
		/// @brief Constructs the DiagnosticMessage from raw packet data.
		/// @param[in] data Pointer to the raw payload data.
		/// @param[in] dataLen Length of the data buffer.
		/// @param[in] prevLayer Pointer to the previous protocol layer.
		/// @param[in] packet Pointer to the parent packet.
		DoIpDiagnosticResponseMessageBase(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/// @brief Gets the acknowledgment/nack code (1-byte).
		uint8_t getResponseCode() const;

		/// @brief Sets the acknowledgment/nack code (1-byte).
		void setResponseCode(uint8_t code);

		/// @brief Gets the optional previously echoed diagnostic message.
		const std::vector<uint8_t> getPreviousMessage() const;

		/// @brief Checks if a previous message is attached.
		bool hasPreviousMessage() const;

		/// @brief Sets the previous echoed diagnostic message.
		void setPreviousMessage(const std::vector<uint8_t>& msg);

		/// @brief Clears the previously stored diagnostic message.
		void clearPreviousMessage();

		/// @brief Checks if data length is valid.
		/// @param[in] dataLen Length of the data buffer.
		/// @return true if the data length is valid, false otherwise.
		static inline bool isDataLenValid(size_t dataLen)
		{
			return (dataLen >= FIXED_LEN);
		}

	protected:
		DoIpDiagnosticResponseMessageBase(uint16_t sourceAddress, uint16_t targetAddress, DoIpPayloadTypes type);

	private:
		static constexpr size_t DIAGNOSTIC_CODE_OFFSET = sizeof(common_diagnostic_header);
		static constexpr size_t DIAGNOSTIC_CODE_LEN = sizeof(uint8_t);
		static constexpr size_t FIXED_LEN = DIAGNOSTIC_CODE_OFFSET + DIAGNOSTIC_CODE_LEN;
		static constexpr size_t PREVIOUS_MSG_OFFSET = FIXED_LEN;
	};

	//~~~~~~~~~~~~~~~~~~~~~~~~~|
	// DoIpDiagnosticAckMessage|
	//~~~~~~~~~~~~~~~~~~~~~~~~~|

	/// @class DoIpDiagnosticAckMessage
	/// @brief Represents a positive acknowledgment message in response to a DiagnosticMessage.
	///
	/// This message is sent by a DoIP node to acknowledge the correct reception and processing
	/// of a diagnostic message. Optionally, the original message (or part of it) may be echoed back.
	class DoIpDiagnosticAckMessage : public DoIpDiagnosticResponseMessageBase
	{
	public:
		/// @brief Constructs a DiagnosticAckMessage from raw packet data.
		/// @param[in] data Pointer to the raw payload data.
		/// @param[in] dataLen Length of the data buffer.
		/// @param[in] prevLayer Pointer to the previous protocol layer.
		/// @param[in] packet Pointer to the parent packet.
		DoIpDiagnosticAckMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/// @brief Constructs a DiagnosticAckMessage from specified field values.
		/// @param[in] sourceAddress Address of the sending ECU.
		/// @param[in] targetAddress Address of the receiving ECU.
		/// @param[in] ackCode Acknowledgment code describing the result.
		DoIpDiagnosticAckMessage(uint16_t sourceAddress, uint16_t targetAddress, DoIpDiagnosticAckCodes ackCode);

		/// @brief Gets the diagnostic acknowledgment code.
		DoIpDiagnosticAckCodes getAckCode() const;

		/// @brief Sets the acknowledgment code.
		void setAckCode(DoIpDiagnosticAckCodes code);

		/// @brief Returns a human-readable summary of the message.
		std::string getSummary() const override;

		/// @brief Returns the DoIP payload type.
		DoIpPayloadTypes getPayloadType() const override
		{
			return DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_POS_ACK;
		}
	};

	//~~~~~~~~~~~~~~~~~~~~~~~~~~|
	// DoIpDiagnosticNackMessage|
	//~~~~~~~~~~~~~~~~~~~~~~~~~~|

	/// @class DoIpDiagnosticNackMessage
	/// @brief Represents a negative acknowledgment message in response to a DiagnosticMessage.
	///
	/// This message is sent by a DoIP node when a diagnostic message is received but could not
	/// be processed successfully. It may include the original message for reference.
	class DoIpDiagnosticNackMessage : public DoIpDiagnosticResponseMessageBase
	{
	public:
		/// @brief Constructs a DiagnosticNackMessage from raw packet data.
		/// @param[in] data Pointer to the raw payload data.
		/// @param[in] dataLen Length of the data buffer.
		/// @param[in] prevLayer Pointer to the previous protocol layer.
		/// @param[in] packet Pointer to the parent packet.
		DoIpDiagnosticNackMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/// @brief Constructs a DiagnosticNackMessage from specified field values.
		/// @param[in] sourceAddress Address of the sending ECU.
		/// @param[in] targetAddress Address of the receiving ECU.
		/// @param[in] nackCode Negative acknowledgment code describing the failure.
		DoIpDiagnosticNackMessage(uint16_t sourceAddress, uint16_t targetAddress,
		                          DoIpDiagnosticMessageNackCodes nackCode);

		/// @brief Gets the negative acknowledgment code.
		DoIpDiagnosticMessageNackCodes getNackCode() const;

		/// @brief Sets the negative acknowledgment code.
		void setNackCode(DoIpDiagnosticMessageNackCodes code);

		/// @brief Returns a human-readable summary of the message.
		std::string getSummary() const override;

		/// @brief Returns the DoIP payload type.
		DoIpPayloadTypes getPayloadType() const override
		{
			return DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_NEG_ACK;
		}
	};

	//~~~~~~~~~~~~~~~~~~~~~~|
	// DoIpAliveCheckRequest|
	//~~~~~~~~~~~~~~~~~~~~~~|

	/// @class DoIpAliveCheckRequest
	/// @brief Represents an Alive Check Request message in the DoIP protocol.
	///
	/// This message is sent by a tester to verify if a DoIP entity is responsive.
	/// The responding DoIP node should reply with an Alive Check Response.
	class DoIpAliveCheckRequest : public DoIpLayer
	{
	public:
		/// @brief Constructs an AliveCheckRequest from raw packet data.
		/// @param[in] data Pointer to the raw payload data.
		/// @param[in] dataLen Length of the data buffer.
		/// @param[in] prevLayer Pointer to the previous protocol layer.
		/// @param[in] packet Pointer to the parent packet.
		DoIpAliveCheckRequest(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : DoIpLayer(data, dataLen, prevLayer, packet)
		{}

		/// @brief Default constructor to create an empty AliveCheckRequest message.
		DoIpAliveCheckRequest();

		/// @brief Returns the DoIP payload type for this message.
		DoIpPayloadTypes getPayloadType() const override
		{
			return DoIpPayloadTypes::ALIVE_CHECK_REQUEST;
		}
		/// @brief Checks if the Alive Check Request data length is valid.
		/// @param[in] dataLen Length of the data buffer.
		/// @return true if the data length is valid, false otherwise.
		static inline bool isDataLenValid(size_t dataLen)
		{
			return (dataLen == DOIP_HEADER_LEN);  // No payload
		}
	};

	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	// DoIpVehicleIdentificationRequest|
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|

	/// @class DoIpVehicleIdentificationRequest
	/// @brief Represents a Vehicle Identification Request message in the DoIP protocol.
	///
	/// This message is sent by a tester to request vehicle identification information
	/// such as VIN, logical addresses, and other metadata. It can be broadcast or directed.
	class DoIpVehicleIdentificationRequest : public DoIpLayer
	{
	public:
		/// @brief Constructs a VehicleIdentificationRequest from raw packet data.
		/// @param[in] data Pointer to the raw payload data.
		/// @param[in] dataLen Length of the data buffer.
		/// @param[in] prevLayer Pointer to the previous protocol layer.
		/// @param[in] packet Pointer to the parent packet.
		DoIpVehicleIdentificationRequest(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : DoIpLayer(data, dataLen, prevLayer, packet)
		{}

		/// @brief Default constructor to create an empty VehicleIdentificationRequest.
		DoIpVehicleIdentificationRequest();

		/// @brief Returns the DoIP payload type.
		DoIpPayloadTypes getPayloadType() const override
		{
			return DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST;
		}

		/// @brief Checks if the Vehicle Identification Request data length is valid.
		/// @param[in] dataLen Length of the data buffer.
		/// @return true if the data length is valid, false otherwise.
		static inline bool isDataLenValid(size_t dataLen)
		{
			return (dataLen == DOIP_HEADER_LEN);  // No payload
		}
	};

	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
	// DoIpDiagnosticPowerModeRequest|
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|

	/// @class DoIpDiagnosticPowerModeRequest
	/// @brief Represents a Diagnostic Power Mode Request message in the DoIP protocol.
	///
	/// This message is sent to inquire about the current power mode status of the vehicle,
	/// which helps determine if diagnostic communication can be initiated or continued.
	class DoIpDiagnosticPowerModeRequest : public DoIpLayer
	{
	public:
		/// @brief Constructs a DiagnosticPowerModeRequest from raw packet data.
		/// @param[in] data Pointer to the raw payload data.
		/// @param[in] dataLen Length of the data buffer.
		/// @param[in] prevLayer Pointer to the previous protocol layer.
		/// @param[in] packet Pointer to the parent packet.
		DoIpDiagnosticPowerModeRequest(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : DoIpLayer(data, dataLen, prevLayer, packet)
		{}

		/// @brief Default constructor to create an empty DiagnosticPowerModeRequest.
		DoIpDiagnosticPowerModeRequest();

		/// @brief Returns the DoIP payload type.
		DoIpPayloadTypes getPayloadType() const override
		{
			return DoIpPayloadTypes::DIAGNOSTIC_POWER_MODE_REQUEST;
		}

		/// @brief Checks if the Entity Status Request data length is valid.
		/// @param[in] dataLen Length of the data buffer.
		/// @return true if the data length is valid, false otherwise.
		static inline bool isDataLenValid(size_t dataLen)
		{
			return (dataLen == DOIP_HEADER_LEN);  // No payload
		}
	};

	//~~~~~~~~~~~~~~~~~~~~~~~~|
	// DoIpEntityStatusRequest|
	//~~~~~~~~~~~~~~~~~~~~~~~~|

	/// @class DoIpEntityStatusRequest
	/// @brief Represents an Entity Status Request message in the DoIP protocol.
	///
	/// This message is sent by a tester to request the current status of the DoIP entity,
	/// including capabilities such as maximum number of concurrent socket connections
	/// and optionally the maximum data size supported.
	class DoIpEntityStatusRequest : public DoIpLayer
	{
	public:
		/// @brief Constructs an EntityStatusRequest from raw packet data.
		/// @param[in] data Pointer to the raw payload data.
		/// @param[in] dataLen Length of the data buffer.
		/// @param[in] prevLayer Pointer to the previous protocol layer.
		/// @param[in] packet Pointer to the parent packet.
		DoIpEntityStatusRequest(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : DoIpLayer(data, dataLen, prevLayer, packet)
		{}

		/// @brief Default constructor to create an empty EntityStatusRequest message.
		DoIpEntityStatusRequest();

		/// @brief Returns the DoIP payload type for this message.
		DoIpPayloadTypes getPayloadType() const override
		{
			return DoIpPayloadTypes::ENTITY_STATUS_REQUEST;
		}

		/// @brief Checks if the Entity Status Request data length is valid.
		/// @param[in] dataLen Length of the data buffer.
		/// @return true if the data length is valid, false otherwise.
		static inline bool isDataLenValid(size_t dataLen)
		{
			return (dataLen == DOIP_HEADER_LEN);  // No payload
		}
	};

}  // namespace pcpp
