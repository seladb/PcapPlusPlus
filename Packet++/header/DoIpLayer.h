#pragma once

#include "Layer.h"
#include "IpAddress.h"
#include "MacAddress.h"
#include "Logger.h"

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	class IDoIpMessageData;

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
		/// Used to indicate an unsupported or unknown protocol version for internal handling.
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
		DIAGNOSTIC_MESSAGE_NEG_ACK = 0x8003U,

		/// Represents an invalid payload type (not specified by ISO).
		/// Used to indicate an unsupported or unrecognized payload type for internal handling.
		UNKNOWN_PAYLOAD_TYPE = 0xFFFFU,
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
		/// @param[in] data IDoIpMessageData contains all doipMessage specification based on its payload type
		DoIpLayer(DoIpProtocolVersion version, const IDoIpMessageData& data);

		/// A constructor that create a doip announcement message with all
		/// zeros for vin, eid, gid and no further action required
		DoIpLayer();

		/// A destructor for DoIpLayer class
		~DoIpLayer() override = default;

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

		/// A static method that checks whether a port is considered as a DOIP port
		/// @param[in] port The port number to check
		/// @return True if this is a DOIP port number, false otherwise
		static inline bool isDoIpPort(uint16_t port);

		/// A static method that validates the input data
		/// @param[in] data The pointer to the beginning of a byte stream of an DOIP layer
		/// @param[in] dataLen The length of the byte stream
		/// @return True if the data is valid and can represent an DOIP layer
		static inline bool isDataValid(const uint8_t* data, size_t dataLen);

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
		void initLayer();

		doiphdr* getDoIpHeader() const
		{
			return reinterpret_cast<doiphdr*>(m_Data);
		}

		bool isPayloadLengthValid() const;

		bool isProtocolVersionValid() const;

		void buildLayer(const IDoIpMessageData& data);
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
