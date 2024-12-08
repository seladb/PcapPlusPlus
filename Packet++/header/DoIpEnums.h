#pragma once

#include <string>
#include <stdint.h>

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
	/**
	 * @brief Represents the DoIP (Diagnostics over IP) protocol versions.
	 */
	enum class DoIpProtocolVersion : uint8_t
	{
		/**
		 * @brief Reserved protocol version.
		 * This value is used when the version is not specified or invalid.
		 */
		reservedVersion = 0x00U,

		/**
		 * @brief Protocol version 1, based on ISO 2010 specification.
		 */
		version01Iso2010 = 0x01U,

		/**
		 * @brief Protocol version 2, based on ISO 2012 specification.
		 */
		version02Iso2012 = 0x02U,

		/**
		 * @brief Protocol version 3, based on ISO 2019 specification.
		 */
		version03Iso2019 = 0x03U,

		/**
		 * @brief Protocol version 4, based on ISO 2019 AMD1 (Amendment 1) specification.
		 */
		version04Iso2019_AMD1 = 0x04U,

		/**
		 * @brief Default protocol version.
		 * Used for broadcast Vehicle Identification Request Messages.
		 */
		defaultVersion = 0xFFU
	};

	/**
	 * @brief Enum representing DoIP routing activation types.
	 * These values specify the type of routing activation used in DoIP (Diagnostic over IP).
	 */
	enum class DoIpActivationTypes : uint8_t
	{
		/**
		 * Default routing activation type.
		 * Used when no specific type is required.
		 */
		Default = 0x00U,

		/**
		 * WWH-OBD (Worldwide Harmonized On-Board Diagnostics) routing activation type.
		 * Used for vehicle diagnostics in compliance with WWH-OBD standards.
		 */
		WWH_OBD = 0x01U,

		/**
		 * Central security routing activation type.
		 * Used for secure communications involving a central security system.
		 */
		CENTRAL_SECURITY = 0xE0U
	};

	/**
	 * @brief Enum representing DoIP payload types.
	 *
	 * These payload types are defined as part of the DoIP (Diagnostic over IP) protocol
	 * and specify the type of message being transmitted.
	 */
	enum class DoIpPayloadTypes : uint16_t
	{
		/**
		 * Generic header negative acknowledgment.
		 * Indicates a failure or error in processing the generic header.
		 */
		GENERIC_HEADER_NEG_ACK = 0x0000U,

		/**
		 * Vehicle identification request.
		 * Used to request identification details of a vehicle.
		 */
		VEHICLE_IDENTIFICATION_REQUEST = 0x0001U,

		/**
		 * Vehicle identification request with EID.
		 * Requests identification using an external identifier (EID).
		 */
		VEHICLE_IDENTIFICATION_REQUEST_WITH_EID = 0x0002U,

		/**
		 * Vehicle identification request with VIN.
		 * Requests identification using the vehicle's VIN (Vehicle Identification Number).
		 */
		VEHICLE_IDENTIFICATION_REQUEST_WITH_VIN = 0x0003U,

		/**
		 * Announcement message.
		 * Sent to announce the availability of a DoIP entity.
		 */
		ANNOUNCEMENT_MESSAGE = 0x0004U,

		/**
		 * Routing activation request.
		 * Initiates a routing activation procedure.
		 */
		ROUTING_ACTIVATION_REQUEST = 0x0005U,

		/**
		 * Routing activation response.
		 * Response to a routing activation request.
		 */
		ROUTING_ACTIVATION_RESPONSE = 0x0006U,

		/**
		 * Alive check request.
		 * Sent to verify that a DoIP entity is still operational.
		 */
		ALIVE_CHECK_REQUEST = 0x0007U,

		/**
		 * Alive check response.
		 * Response to an alive check request.
		 */
		ALIVE_CHECK_RESPONSE = 0x0008U,

		/**
		 * Entity status request.
		 * Used to request the status of a DoIP entity.
		 */
		ENTITY_STATUS_REQUEST = 0x4001U,

		/**
		 * Entity status response.
		 * Response to an entity status request.
		 */
		ENTITY_STATUS_RESPONSE = 0x4002U,

		/**
		 * Diagnostic power mode request.
		 * Requests the current power mode of a DoIP entity.
		 */
		DIAGNOSTIC_POWER_MODE_REQUEST = 0x4003U,

		/**
		 * Diagnostic power mode response.
		 * Response to a diagnostic power mode request.
		 */
		DIAGNOSTIC_POWER_MODE_RESPONSE = 0x4004U,

		/**
		 * Diagnostic message type.
		 * Represents a generic diagnostic message.
		 */
		DIAGNOSTIC_MESSAGE_TYPE = 0x8001U,

		/**
		 * Diagnostic message positive acknowledgment.
		 * Indicates successful processing of a diagnostic message.
		 */
		DIAGNOSTIC_MESSAGE_POS_ACK = 0x8002U,

		/**
		 * Diagnostic message negative acknowledgment.
		 * Indicates an error in processing a diagnostic message.
		 */
		DIAGNOSTIC_MESSAGE_NEG_ACK = 0x8003U,
	};

	/**
	 * @brief Enum representing DoIP Generic Header NACK codes (ISO 13400).
	 *
	 * These codes are used to indicate specific errors in the DoIP Generic Header.
	 */
	enum class DoIpGenericHeaderNackCodes : uint8_t
	{
		/**
		 * Incorrect pattern detected in the header.
		 * Indicates that the header does not follow the expected pattern.
		 */
		INCORRECT_PATTERN = 0x00U,

		/**
		 * Unknown payload type.
		 * The payload type in the message is not recognized.
		 */
		INKNOWN_PAYLOAD_TYPE = 0x01U,

		/**
		 * Message too large.
		 * The message size exceeds the allowed limit.
		 */
		MESSAGE_TOO_LARGE = 0x02U,

		/**
		 * Out of memory.
		 * There is insufficient memory available to process the message.
		 */
		OUT_OF_MEMORY = 0x03U,

		/**
		 * Invalid payload length.
		 * The payload length specified in the header is invalid.
		 */
		INVALID_PAYLOAD_LENGTH = 0x04U,
	};

	/**
	 * @brief Enum representing DoIP action codes for DoIP announcement messages (ISO 13400).
	 *
	 * These action codes specify the next steps required after receiving a DoIP announcement message.
	 * Some codes are reserved for future use by ISO standards.
	 */
	enum class DoIpActionCodes : uint8_t
	{
		/**
		 * No further action required.
		 * Indicates that no additional steps are needed after the announcement.
		 */
		NO_FURTHER_ACTION_REQUIRED = 0x00U,

		/**
		 * Reserved for ISO (0x01).
		 * Reserved for future use as per ISO standards.
		 */
		RESERVED_ISO_0x01 = 0x01U,

		/**
		 * Reserved for ISO (0x02).
		 * Reserved for future use as per ISO standards.
		 */
		RESERVED_ISO_0x02 = 0x02U,

		/**
		 * Reserved for ISO (0x03).
		 * Reserved for future use as per ISO standards.
		 */
		RESERVED_ISO_0x03 = 0x03U,

		/**
		 * Reserved for ISO (0x04).
		 * Reserved for future use as per ISO standards.
		 */
		RESERVED_ISO_0x04 = 0x04U,

		/**
		 * Reserved for ISO (0x05).
		 * Reserved for future use as per ISO standards.
		 */
		RESERVED_ISO_0x05 = 0x05U,

		/**
		 * Reserved for ISO (0x06).
		 * Reserved for future use as per ISO standards.
		 */
		RESERVED_ISO_0x06 = 0x06U,

		/**
		 * Reserved for ISO (0x07).
		 * Reserved for future use as per ISO standards.
		 */
		RESERVED_ISO_0x07 = 0x07U,

		/**
		 * Reserved for ISO (0x08).
		 * Reserved for future use as per ISO standards.
		 */
		RESERVED_ISO_0x08 = 0x08U,

		/**
		 * Reserved for ISO (0x09).
		 * Reserved for future use as per ISO standards.
		 */
		RESERVED_ISO_0x09 = 0x09U,

		/**
		 * Reserved for ISO (0x0A).
		 * Reserved for future use as per ISO standards.
		 */
		RESERVED_ISO_0x0A = 0x0AU,

		/**
		 * Reserved for ISO (0x0B).
		 * Reserved for future use as per ISO standards.
		 */
		RESERVED_ISO_0x0B = 0x0BU,

		/**
		 * Reserved for ISO (0x0C).
		 * Reserved for future use as per ISO standards.
		 */
		RESERVED_ISO_0x0C = 0x0CU,

		/**
		 * Reserved for ISO (0x0D).
		 * Reserved for future use as per ISO standards.
		 */
		RESERVED_ISO_0x0D = 0x0DU,

		/**
		 * Reserved for ISO (0x0E).
		 * Reserved for future use as per ISO standards.
		 */
		RESERVED_ISO_0x0E = 0x0EU,

		/**
		 * Reserved for ISO (0x0F).
		 * Reserved for future use as per ISO standards.
		 */
		RESERVED_ISO_0x0F = 0x0FU,

		/**
		 * Routing activation required.
		 * Indicates that routing activation is needed after the announcement message.
		 */
		ROUTING_ACTIVATION_REQUIRED = 0x10U,
	};

	/**
	 * @brief Enum representing DoIP routing activation response codes (ISO 13400).
	 *
	 * These codes are used in response to routing activation requests, providing status
	 * or error information related to the request.
	 */
	enum class DoIpRoutingResponseCodes : uint8_t
	{
		/**
		 * Unknown source address.
		 * The source address provided in the request is not recognized.
		 */
		UNKNOWN_SOURCE_ADDRESS = 0x00U,

		/**
		 * No free socket.
		 * There are no available sockets to establish the connection.
		 */
		NO_FREE_SOCKET = 0x01U,

		/**
		 * Wrong source address.
		 * The source address provided in the request is invalid.
		 */
		WRONG_SOURCE_ADDRESS = 0x02U,

		/**
		 * Source address already registered.
		 * The provided source address has already been activated.
		 */
		SOURCE_ADDRESS_ALREADY_REGISTERED = 0x03U,

		/**
		 * Missing authentication.
		 * The request is missing required authentication credentials.
		 */
		MISSING_AUTHENTICATION = 0x04U,

		/**
		 * Rejected confirmation.
		 * The confirmation of routing activation was rejected.
		 */
		REJECTED_CONFIRMATION = 0x05U,

		/**
		 * Unsupported activation type.
		 * The requested routing activation type is not supported.
		 */
		UNSUPPORTED_ACTIVATION_TYPE = 0x06U,

		/**
		 * Encrypted connection required (TLS).
		 * Indicates that the routing activation requires a secure TLS connection.
		 */
		ENCRYPTED_CONNECTION_TLS = 0x07U,

		/**
		 * Reserved for ISO (0x08).
		 * Reserved for future use as per ISO standards.
		 */
		RESERVED_ISO_0x08 = 0x08U,

		/**
		 * Reserved for ISO (0x09).
		 * Reserved for future use as per ISO standards.
		 */
		RESERVED_ISO_0x09 = 0x09U,

		/**
		 * Reserved for ISO (0x0A).
		 * Reserved for future use as per ISO standards.
		 */
		RESERVED_ISO_0x0A = 0x0AU,

		/**
		 * Reserved for ISO (0x0B).
		 * Reserved for future use as per ISO standards.
		 */
		RESERVED_ISO_0x0B = 0x0BU,

		/**
		 * Reserved for ISO (0x0C).
		 * Reserved for future use as per ISO standards.
		 */
		RESERVED_ISO_0x0C = 0x0CU,

		/**
		 * Reserved for ISO (0x0D).
		 * Reserved for future use as per ISO standards.
		 */
		RESERVED_ISO_0x0D = 0x0DU,

		/**
		 * Reserved for ISO (0x0E).
		 * Reserved for future use as per ISO standards.
		 */
		RESERVED_ISO_0x0E = 0x0EU,

		/**
		 * Reserved for ISO (0x0F).
		 * Reserved for future use as per ISO standards.
		 */
		RESERVED_ISO_0x0F = 0x0FU,

		/**
		 * Routing successfully activated.
		 * The routing activation request was processed successfully.
		 */
		ROUTING_SUCCESSFULLY_ACTIVATED = 0x10U,

		/**
		 * Confirmation required.
		 * Additional confirmation is required to complete the routing activation.
		 */
		CONFIRMATION_REQUIRED = 0x11U,
	};

	/**
	 * @brief Enum representing DoIP diagnostic message NACK codes (ISO 13400).
	 *
	 * These codes indicate reasons for rejecting or failing to process a diagnostic message
	 * in the DoIP protocol.
	 */
	enum class DoIpDiagnosticMessageNackCodes : uint8_t
	{
		/**
		 * Reserved for ISO (0x00).
		 * Reserved for future use as per ISO standards.
		 */
		RESERVED_ISO_0x00 = 0x00U,

		/**
		 * Reserved for ISO (0x01).
		 * Reserved for future use as per ISO standards.
		 */
		RESERVED_ISO_0x01 = 0x01U,

		/**
		 * Invalid source address.
		 * The source address specified in the message is invalid.
		 */
		INVALID_SOURCE_ADDRESS = 0x02U,

		/**
		 * Invalid target address.
		 * The target address specified in the message is invalid.
		 */
		INVALID_TARGET_ADDRESS = 0x03U,

		/**
		 * Message too large.
		 * The size of the message exceeds the maximum allowed limit.
		 */
		MESSAGE_TOO_LARGE = 0x04U,

		/**
		 * Out of memory.
		 * There is insufficient memory available to process the message.
		 */
		OUT_OF_MEMORY = 0x05U,

		/**
		 * Target unreachable.
		 * The specified target address cannot be reached.
		 */
		TARGET_UNREACHABLE = 0x06U,

		/**
		 * Unknown network.
		 * The message references a network that is not recognized or supported.
		 */
		UNKNOWN_NETWORK = 0x07U,

		/**
		 * Transport protocol error.
		 * An error occurred at the transport protocol level, preventing the message from being processed.
		 */
		TRANSPORT_PROTOCOL_ERROR = 0x08U,
	};

	/**
	 * @brief Enum representing DoIP diagnostic power mode codes (ISO 13400).
	 *
	 * These codes indicate the diagnostic power mode status of a DoIP entity,
	 * providing information about its readiness for diagnostic operations.
	 */
	enum class DoIpDiagnosticPowerModeCodes : uint8_t
	{
		/**
		 * Not ready.
		 * The DoIP entity is not ready to perform diagnostic operations.
		 */
		NOT_READY = 0x00U,

		/**
		 * Ready.
		 * The DoIP entity is ready to perform diagnostic operations.
		 */
		READY = 0x01U,

		/**
		 * Not supported.
		 * The DoIP entity does not support diagnostic power mode reporting.
		 */
		NOT_SUPPORTED = 0x02U
	};

	/**
	 * @brief Enum representing DoIP diagnostic acknowledgment codes (ISO 13400).
	 *
	 * These codes are used to acknowledge the receipt or processing of diagnostic messages
	 * in the DoIP protocol.
	 */
	enum class DoIpDiagnosticAckCodes : uint8_t
	{
		/**
		 * Acknowledgment.
		 * Indicates successful receipt or acknowledgment of a diagnostic message.
		 */
		ACK = 0x00U
	};

	/**
	 * @brief Enum representing DoIP entity status response codes (ISO 13400).
	 *
	 * These codes are used to indicate the role or type of a DoIP entity in the network.
	 */
	enum class DoIpEntityStatus : uint8_t
	{
		/**
		 * Gateway.
		 * The entity functions as a gateway, facilitating communication between networks.
		 */
		GATEWAY = 0x00U,

		/**
		 * Node.
		 * The entity functions as an individual node within the DoIP network.
		 */
		NODE = 0x01U
	};

	enum class DoIpSyncStatus : uint8_t
	{
		/**
		 * VIN and/or GID are synchronized.
		 */
		VIN_AND_OR_GID_ARE_SINCHRONIZED = 0x00,

		/**
		 * Reserved for ISO (0x01).
		 * Reserved for future use as per ISO standards.
		 */
		RESERVED_ISO_0x01 = 0x01U,

		/**
		 * Reserved for ISO (0x02).
		 * Reserved for future use as per ISO standards.
		 */
		RESERVED_ISO_0x02 = 0x02U,

		/**
		 * Reserved for ISO (0x03).
		 * Reserved for future use as per ISO standards.
		 */
		RESERVED_ISO_0x03 = 0x03U,

		/**
		 * Reserved for ISO (0x04).
		 * Reserved for future use as per ISO standards.
		 */
		RESERVED_ISO_0x04 = 0x04U,

		/**
		 * Reserved for ISO (0x05).
		 * Reserved for future use as per ISO standards.
		 */
		RESERVED_ISO_0x05 = 0x05U,

		/**
		 * Reserved for ISO (0x06).
		 * Reserved for future use as per ISO standards.
		 */
		RESERVED_ISO_0x06 = 0x06U,

		/**
		 * Reserved for ISO (0x07).
		 * Reserved for future use as per ISO standards.
		 */
		RESERVED_ISO_0x07 = 0x07U,

		/**
		 * Reserved for ISO (0x08).
		 * Reserved for future use as per ISO standards.
		 */
		RESERVED_ISO_0x08 = 0x08U,

		/**
		 * Reserved for ISO (0x09).
		 * Reserved for future use as per ISO standards.
		 */
		RESERVED_ISO_0x09 = 0x09U,

		/**
		 * Reserved for ISO (0x0A).
		 * Reserved for future use as per ISO standards.
		 */
		RESERVED_ISO_0x0A = 0x0AU,

		/**
		 * Reserved for ISO (0x0B).
		 * Reserved for future use as per ISO standards.
		 */
		RESERVED_ISO_0x0B = 0x0BU,
		/**
		 * Reserved for ISO (0x0C).
		 * Reserved for future use as per ISO standards.
		 */
		RESERVED_ISO_0x0C = 0x0CU,

		/**
		 * Reserved for ISO (0x0D).
		 * Reserved for future use as per ISO standards.
		 */
		RESERVED_ISO_0x0D = 0x0DU,

		/**
		 * Reserved for ISO (0x0E).
		 * Reserved for future use as per ISO standards.
		 */
		RESERVED_ISO_0x0E = 0x0EU,

		/**
		 * Reserved for ISO (0x08).
		 * Reserved for future use as per ISO standards.
		 */
		RESERVED_ISO_0x0F = 0x0FU,

		/**
		 * VIN and/or GID are not synchronized.
		 */
		VIN_AND_OR_GID_ARE_NOT_SINCHRONIZED = 0x10U,

		/**
		 * Check whether this field is initialised or not
		 */
		NON_INITIALIZED
	};

	/**
	 * @brief Enum representing DoIP diagnostic ports (ISO 13400).
	 *
	 * These ports are used for communication in the DoIP protocol over different transport layers.
	 */
	enum class DoIpPorts : uint16_t
	{
		/**
		 * UDP Port.
		 * The standard port for DoIP communication over UDP.
		 */
		UDP_PORT = 13400U,

		/**
		 * TCP Port.
		 * The standard port for DoIP communication over TCP.
		 */
		TCP_PORT = 13400U,

		/**
		 * TLS Port.
		 * The standard port for DoIP communication over a secure TLS connection.
		 */
		TLS_PORT = 3496U
	};

}  // namespace pcpp
