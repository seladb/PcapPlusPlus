#ifndef PACKETPP_SOMEIP_LAYER
#define PACKETPP_SOMEIP_LAYER

#include "Layer.h"
#include <unordered_set>

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

/**
 * @class SomeIpLayer
 * Represents a SOME/IP protocol layer
 */
class SomeIpLayer : public Layer
{
public:
	/**
	 * SOME/IP message types
	 */
	enum class MsgType : uint8_t
	{
		/** A request expecting a response (even void) */
		REQUEST = 0x00,
		/** Acknowledgment for REQUEST(optional) */
		REQUEST_ACK = 0x40,
		/** A fire&forget request */
		REQUEST_NO_RETURN = 0x01,
		/** Acknowledgment for REQUEST_NO_RETURN(informational) */
		REQUEST_NO_RETURN_ACK = 0x41,
		/** A request of a notification expecting no response */
		NOTIFICATION = 0x02,
		/** Acknowledgment for NOTIFICATION(informational) */
		NOTIFICATION_ACK = 0x42,
		/** The response message */
		RESPONSE = 0x80,
		/** The Acknowledgment for RESPONSE(informational) */
		RESPONSE_ACK = 0xC0,
		/** The response containing an error */
		ERRORS = 0x81,
		/** Acknowledgment for ERROR(informational) */
		ERROR_ACK = 0xC1,
		/** A TP request expecting a response (even void) */
		TP_REQUEST = 0x20,
		/** A TP fire&forget request */
		TP_REQUEST_NO_RETURN = 0x21,
		/** A TP request of a notification/event callback expecting no response */
		TP_NOTIFICATION = 0x22,
		/** The TP response message */
		TP_RESPONSE = 0xa0,
		/** The TP response containing an error */
		TP_ERROR = 0xa1,
	};

	/**
	 * @struct someiphdr
	 * Represents a SOME/IP protocol header
	 */
#pragma pack(push, 1)
	struct someiphdr
	{
		/** Service ID */
		uint16_t serviceID;
		/** Method ID. Most significant bit 0 when E2E communication. 1 when SOME/IP event */
		uint16_t methodID;
		/** Length. Also covers payload. Excludes serviceID, methodID and length field itself */
		uint32_t length;
		/** Client ID */
		uint16_t clientID;
		/** Session ID */
		uint16_t sessionID;
		/** Protocol Version */
		uint8_t protocolVersion;
		/** Interface Version */
		uint8_t interfaceVersion;
		/** Message Type */
		uint8_t msgType;
		/** Return Code */
		uint8_t returnCode;
	};
#pragma pack(pop)

	/**
	 * A constructor that creates the layer from an existing packet raw data
	 * @param[in] data A pointer to the raw data (will be casted to @ref someiphdr)
	 * @param[in] dataLen Size of the data in bytes
	 * @param[in] prevLayer A pointer to the previous layer
	 * @param[in] packet A pointer to the Packet instance where layer will be stored in
	 */
	SomeIpLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet)
		: Layer(data, dataLen, prevLayer, packet)
	{
		m_Protocol = SomeIP;
	}

	/**
	 * Construct a new layer object
	 * @param[in] serviceID Service ID
	 * @param[in] methodID Method ID
	 * @param[in] clientID Client ID
	 * @param[in] sessionID Session ID
	 * @param[in] interfaceVersion Interface Version
	 * @param[in] type Type of the message
	 * @param[in] returnCode Return Code
	 * @param[in] data A pointer to the raw data
	 * @param[in] dataLen Size of the data in bytes
	 * holds the reference to a data buffer. This option can be used to reduce the number of copies to generate packets.
	 */
	SomeIpLayer(uint16_t serviceID, uint16_t methodID, uint16_t clientID, uint16_t sessionID, uint8_t interfaceVersion,
				MsgType type, uint8_t returnCode, const uint8_t *const data = nullptr, size_t dataLen = 0);

	/**
	 * Destroy the layer object
	 */
	~SomeIpLayer() {}

	/**
	 * Get a pointer to the basic SOME/IP header. Notice this points directly to the data, so every change will change
	 * the actual packet data
	 * @return A pointer to the @ref someiphdr
	 */
	someiphdr *getSomeIpHeader() const { return (someiphdr *)m_Data; }

	/**
	 * Checks if given port is a SOME/IP protocol port (only Service Discovery ports are checked for now)
	 * @param[in] port Port to check
	 * @return true if SOME/IP protocol port, false if not
	 */
	static bool isSomeIpPort(uint16_t port);

	/**
	 * Adds port to a list of ports where pcap checks for SOME/IP communication.
	 * Each port must be removed at the end in order to have no memory leak.
	 * @param[in] port Port to add
	 */
	static void addSomeIpPort(uint16_t port);

	/**
	 * Removes port from a list of ports where pcap checks for SOME/IP communication.
	 * @param[in] port Port to remove
	 */
	static void removeSomeIpPort(uint16_t port);

	/**
	 * Removes all ports from a list of ports where pcap checks for SOME/IP communication.
	 */
	static void removeAllSomeIpPorts();

	/**
	 * A static method that validates the input data
	 * @param[in] data The pointer to the beginning of a byte stream of a SOME/IP packet
	 * @param[in] dataLen The length of the byte stream
	 * @return true if SOME/IP protocol, false otherwise
	 */
	static bool isDataValid(uint8_t *data, uint32_t dataLen);

	/**
	 * Get the messageID
	 * @return uint32_t returned in host endian
	 */
	uint32_t getMessageID() const;

	/**
	 * Set the Message ID
	 * @param[in] messageID messageID to set
	 */
	void setMessageID(uint32_t messageID);

	/**
	 * Get the serviceID
	 * @return uint16_t returned in host endian
	 */
	uint16_t getServiceID() const;

	/**
	 * Set the Service ID
	 * @param[in] serviceID serviceID to set
	 */
	void setServiceID(uint16_t serviceID);

	/**
	 * Get the methodID
	 * @return uint16_t returned in host endian
	 */
	uint16_t getMethodID() const;

	/**
	 * Set the Method ID
	 * @param[in] methodID methodID to set
	 */
	void setMethodID(uint16_t methodID);

	/**
	 * Get the Length Field of the SOME/IP header
	 * @return uint32_t The length field of the SOME/IP header
	 */
	uint32_t getLengthField() const;

	/**
	 * Get the requestID
	 * @return uint32_t returned in host endian
	 */
	uint32_t getRequestID() const;

	/**
	 * Set the Request ID
	 * @param[in] requestID requestID to set
	 */
	void setRequestID(uint32_t requestID);

	/**
	 * Get the sessionID
	 * @return uint16_t returned in host endian
	 */
	uint16_t getSessionID() const;

	/**
	 * Set the Session ID
	 * @param[in] sessionID sessionID to set
	 */
	void setSessionID(uint16_t sessionID);

	/**
	 * Get the clientID
	 * @return uint16_t returned in host endian
	 */
	uint16_t getClientID() const;

	/**
	 * Set the Client ID
	 * @param[in] clientID clientID to set
	 */
	void setClientID(uint16_t clientID);

	/**
	 * Get the protocolVersion
	 * @return uint8_t
	 */
	uint8_t getProtocolVersion() const;

	/**
	 * Set the Protocol Version
	 * @param[in] version version to set
	 */
	void setProtocolVersion(uint8_t version);

	/**
	 * Get the interfaceVersion
	 * @return uint8_t
	 */
	uint8_t getInterfaceVersion() const;

	/**
	 * Set the Interface Version
	 * @param[in] version version to set
	 */
	void setInterfaceVersion(uint8_t version);

	/**
	 * Get the message type
	 * @return uint8_t
	 */
	uint8_t getMessageTypeAsInt() const;

	/**
	 * Get the message type
	 * @return SomeIpLayer::MsgType
	 */
	SomeIpLayer::MsgType getMessageType() const;

	/**
	 * Set the Message Type
	 * @param[in] type Type to set
	 */
	void setMessageType(MsgType type);

	/**
	 * Set the Message Type
	 * @param[in] type Type to set
	 */
	void setMessageType(uint8_t type);

	/**
	 * Get the returnCode
	 * @return uint8_t
	 */
	uint8_t getReturnCode() const;

	/**
	 * Set the returnCode
	 * @param[in] returnCode ReturnCode to set
	 */
	void setReturnCode(uint8_t returnCode);

	/**
	 * Set the length field of the SOME/IP header
	 * @param[in] payloadLength Length of the payload
	 */
	void setPayloadLength(uint32_t payloadLength);

	/**
	 * Get the Header Length With Payload, as is stated in the length field of the SOME/IP header.
	 * @return uint32_t Length of the complete SOME/IP Pdu, including header and payload
	 */
	uint32_t getHeaderLengthWithPayload() const;

	/**
	 * @return A pointer for the layer payload, meaning the first byte after the header
	 */
	uint8_t *getPduPayload() const { return m_Data + sizeof(someiphdr);	}

	/**
	 * @return The size in bytes of the payload
	 */
	size_t getPduPayloadSize() const { return getHeaderLengthWithPayload() - sizeof(someiphdr); }

	/**
	 * Get the Length of the SOME/IP header inc payload
	 * @return size_t
	 */
	size_t getHeaderLen() const;

	/**
	 * Does nothing for this layer
	 */
	void computeCalculateFields() {}

	/**
	 * Identifies next layer and tries to create it
	 */
	void parseNextLayer();

	/**
	 * @return The string representation of the SOME/IP layer
	 */
	std::string toString() const;

	/**
	 * @return The OSI model layer of this layer
	 */
	OsiModelLayer getOsiModelLayer() const { return OsiModelApplicationLayer; }

private:
	static const uint8_t SOMEIP_PROTOCOL_VERSION = 1;

	/* Using unordered_set since insertion and search should be almost constant time */
	static std::unordered_set<uint16_t> m_SomeIpPorts;

	bool subProtocolFollows() const;

	static bool isSomeIpSdPacket(uint16_t serviceId, uint16_t methodId);
	static bool isSomeIpTpPacket(uint8_t msgType);
};
} // namespace pcpp
#endif /* PACKETPP_SOMEIP_LAYER */
