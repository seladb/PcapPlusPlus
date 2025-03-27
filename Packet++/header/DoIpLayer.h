#pragma once

#include <vector>
#include <unordered_map>
#include "Layer.h"
#include "PayloadLayer.h"
#include "IpAddress.h"
#include "MacAddress.h"
#include "Logger.h"

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	class IDoIpMessageData;

	enum class DoIpPayloadTypes : uint16_t;
	enum class DoIpProtocolVersion : uint8_t;

	extern const std::unordered_map<DoIpPayloadTypes, std::string> DoIpEnumToStringPayloadType;
	extern const std::unordered_map<DoIpProtocolVersion, std::string> DoIpEnumToStringProtocolVersion;

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

		/// @brief Represents an unknown or unsupported protocol version
		UnknownVersion = 0xEF
	};

	/// @brief Enum representing DoIP routing activation types.
	/// These values specify the type of routing activation used in DoIP(Diagnostic over IP).
	enum class DoIpActivationTypes : uint8_t
	{
		/// Default routing activation type.
		/// Used when no specific type is required.
		Default = 0x00U,

		/// WWH-OBD (Worldwide Harmonized On-Board Diagnostics) routing activation type.
		/// Used for vehicle diagnostics in compliance with WWH-OBD standards.
		WWH_OBD = 0x01U,

		/// Central security routing activation type.
		/// Used for secure communications involving a central security system.
		CENTRAL_SECURITY = 0xE0U
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
		DIAGNOSTIC_MESSAGE_NEG_ACK = 0x8003U,
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

		/// Acknowledgment./// Indicates successful receipt or acknowledgment of a diagnostic message.

		ACK = 0x00U
	};

	/// @brief Enum representing DoIP entity status response codes (ISO 13400).
	/// These codes are used to indicate the role or type of a DoIP entity in the network.
	enum class DoIpEntityStatus : uint8_t
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

		/// Check whether this field is initialised or not
		NON_INITIALIZED
	};

	/// @brief Enum representing DoIP diagnostic ports (ISO 13400).
	/// These ports are used for communication in the DoIP protocol over different transport layers.

	enum class DoIpPorts : uint16_t
	{

		/// UDP Port.
		/// The standard port for DoIP communication over UDP.
		UDP_PORT = 13400U,

		/// TCP Port.
		/// The standard port for DoIP communication over TCP.
		TCP_PORT = 13400U,

		/// TLS Port.
		/// The standard port for DoIP communication over a secure TLS connection.
		TLS_PORT = 3496U
	};

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

	/// @class DoIpLayer
	/// Represents an DoIP protocol layer. Currently only IPv4 DoIP messages are supported
	class DoIpLayer : public Layer
	{
	public:
		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data (will be casted to @ref doiphdr)
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		DoIpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, DOIP)
		{}

		/// A constructor that creates an generic doip layer and set header and payload fields
		/// @param[in] version DoIpProtocolVersion specify the doip protocol version
		/// @param[in] type DoIpPayloadTypes indicating the doip payload type
		/// @param[in] data IDoIpMessageData contains all doipMessage specification based on its payload type
		DoIpLayer(DoIpProtocolVersion version, DoIpPayloadTypes type, const IDoIpMessageData* data = nullptr);

		/// A constructor that create a doip announcement message with all
		/// zeros for vin, eid, gid and no further action required
		DoIpLayer();

		/// A destructor for DoIpLayer class
		virtual ~DoIpLayer() override = default;

		/// Get the version of DOIP protocol
		/// @return DoIpProtocolVersion presenting the used protocol version (DOIPV)
		DoIpProtocolVersion getProtocolVersion() const;

		/// Get the version of DOIP protocol
		/// @return string presentation the used protocol version (DOIPV)
		std::string getProtocolVersionAsStr() const;

		/// Set the version of DOIP protocol
		/// @param[in] version the version of DOIP protocol to set, restricted to existent doip version
		void setProtocolVersion(DoIpProtocolVersion version);

		/// Get the invert version of DOIP protocol
		/// @return A uint8_t presenting the used protocol invert version (DOIPV)
		uint8_t getInvertProtocolVersion() const;

		/// Set the invert protocol version of DOIP protocol
		/// @param[in] iVersion the invert version of DOIP protocol to set
		void setInvertProtocolVersion(uint8_t iVersion);

		/// Get the doip payload type
		/// @return DoIpPayloadTypes presenting the message doip payload type
		DoIpPayloadTypes getPayloadType() const;

		/// Get the doip payload type as string
		/// @return uint16_t presenting the message doip payload type as string
		std::string getPayloadTypeAsStr() const;

		/// Set the doip payload type
		/// @param[in] payloadType the payload type to set
		void setPayloadType(DoIpPayloadTypes payloadType);

		/// Get the doip payload length
		/// @return uint32_t presenting the length of doip paylad not including the header
		uint32_t getPayloadLength() const;

		/// Set the doip payload length
		/// @param[in] length the doip payload length to set
		void setPayloadLength(uint32_t length) const;

		/// copy data from msgFields to dest
		/// @param[in] dest pointer to where start copying
		/// @param[in] data the doip Fields to copy
		void serializeData(uint8_t* dest, std::vector<uint8_t> data);

		/// A static method that checks whether a port is considered as a DOIP port
		/// @param[in] port The port number to check
		/// @return True if this is a DOIP port number, false otherwise
		static inline bool isDoIpPort(uint16_t port);

		/// A static method that validates the input data
		/// @param[in] data The pointer to the beginning of a byte stream of an DOIP layer
		/// @param[in] dataLen The length of the byte stream
		/// @return True if the data is valid and can represent an DOIP layer
		static inline bool isDataValid(const uint8_t* data, size_t dataLen);

		/// @brief Builds the DoIP layer based on the payload type and provided data.
		///
		/// This function configures the DoIP layer with the appropriate payload type, payload length,
		/// and data, depending on the specified payload type. If the payload type does not require
		/// additional data, the payload length is set to zero. For payloads that require data, the data
		/// is serialized and added to the layer.
		///
		/// @param type The DoIP payload type to set for this layer.
		/// @param data Pointer to the message data (of type IDoIpMessageData) to be serialized into the layer.
		///             This parameter can be nullptr for payload types that do not require additional data.
		///
		/// @note If the payload type requires data and the `data` parameter is `nullptr`, an error message
		///       is logged, and the function does not build the layer.
		void buildLayer(DoIpPayloadTypes type, const IDoIpMessageData* data = nullptr);

		/// @brief Resolves and validates the DoIP layer.
		///
		/// This function validates the protocol version and payload length of the DoIP layer.
		/// If either validation fails, an error is logged, and the function returns `false`.
		///
		/// @return `true` if both the protocol version and payload length are valid;
		///         otherwise, `false`.
		///
		/// @note This function is typically used to ensure the integrity of the DoIP layer
		///       before further processing or transmission.
		bool isLayerDataValid() const;

		// implement abstract methods

		/// parse UDS layer
		void parseNextLayer() override;

		/// @return The size of @ref doiphdr + attached fields length
		size_t getHeaderLen() const override
		{
			return m_DataLen;
		}

		std::string toString() const override;

		void computeCalculateFields() override {};

		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelTransportLayer;
		}

	private:
		/// init doip layer with all zeros with size  of doip header.
		void initLayer();

		/// Get a pointer to the DoIP header. Notice this points directly to the data, so every change will change the
		/// actual packet data
		/// @return A pointer to the @ref doiphdr
		doiphdr* getDoIpHeader() const
		{
			return reinterpret_cast<doiphdr*>(m_Data);
		}

		/// Check the integrity of length field in doip header
		/// @return true if length represent the exact payload arg struct size
		bool isPayloadLengthValid() const;

		/// Check the integrity of protocol version in doip header
		/// @return true if version has no integration errors
		bool isProtocolVersionValid() const;
	};

	// inline methods definition
	inline bool DoIpLayer::isDoIpPort(uint16_t port)
	{
		return (static_cast<DoIpPorts>(port) == DoIpPorts::UDP_PORT ||
		        static_cast<DoIpPorts>(port) == DoIpPorts::TCP_PORT ||
		        static_cast<DoIpPorts>(port) == DoIpPorts::TLS_PORT);
	}

	inline bool DoIpLayer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		return (data && dataLen >= sizeof(doiphdr));
	}
}  // namespace pcpp
