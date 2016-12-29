#ifndef PACKETPP_IGMP_LAYER
#define PACKETPP_IGMP_LAYER

#include <Layer.h>
#include <IpAddress.h>

namespace pcpp
{

struct igmp_header
{
	uint8_t type;
	uint8_t maxResponseTime;
	uint16_t checksum;
	uint32_t groupAddress;
};

enum IgmpType
{
	IgmpType_Unknown = 0,
	IgmpType_MembershipQuery = 0x11,
	IgmpType_MembershipReportV1 = 0x12,
	IgmpType_DVMRP = 0x13,
	IgmpType_P1Mv1 = 0x14,
	IgmpType_CiscoTrace = 0x15,
	IgmpType_MembershipReportV2 = 0x16,
	IgmpType_LeaveGroup = 0x17,
	IgmpType_MulticastTracerouteResponse = 0x1e,
	IgmpType_MulticastTraceroute = 0x1f,
	IgmpType_MembershipReportV3 = 0x22,
	IgmpType_MulticastRouterAdvertisement = 0x30,
	IgmpType_MulticastRouterSolicitation = 0x31,
	IgmpType_MulticastRouterTermination = 0x32,
};

class IgmpLayer : public Layer
{
protected:

	IgmpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet, ProtocolType igmpVer) : Layer(data, dataLen, NULL, packet) { m_Protocol = igmpVer; }

	IgmpLayer(IgmpType type, const IPv4Address& groupAddr, uint8_t maxResponseTime, ProtocolType igmpVer);

	uint16_t calculateChecksum();
public:

	virtual ~IgmpLayer() {}

	/**
	 * Get a pointer to the raw IGMP header. Notice this points directly to the data, so every change will change the actual packet data
	 * @return A pointer to the @ref igmp_header
	 */
	inline igmp_header* getIgmpHeader() { return (igmp_header*)m_Data; }

	/**
	 * @return The IPv4 address in stored igmp_header#groupAddress
	 */
	inline IPv4Address getGroupAddress() { return IPv4Address(getIgmpHeader()->groupAddress); }

	/**
	 * Set group IPv4 address
	 * @param[in] groupAddr The IPv4 address to set
	 */
	void setGroupAddress(const IPv4Address& groupAddr);

	/**
	 * @return IGMP type set in igmp_header#type as IgmpType enum. Notice that if igmp_header#type contains a value
	 * that doesn't appear in the IgmpType enum, ::IgmpType_Unknown will be returned
	 */
	IgmpType getType();

	/**
	 * Set IGMP type
	 * @param[in] type The type to set
	 */
	void setType(IgmpType type);

	/**
	 * A static method that get raw IGMP data (byte stream) and returns which IGMP version it probably is
	 * @param[in] data The IGMP raw data (byte stream)
	 * @param[in] dataLen Raw data length
	 * @return One of the values ::IGMPv1, ::IGMPv2 or ::Unknown, according to detected IGMP version
	 */
	static ProtocolType getIGMPVerFromData(uint8_t* data, size_t dataLen);


	// implement abstract methods

	/**
	 * Does nothing for this layer (IGMP layer is always last)
	 */
	void parseNextLayer() {}

	/**
	 * @return Size of IGMP header = 8B
	 */
	inline size_t getHeaderLen() { return sizeof(igmp_header); }

	std::string toString();
};

class IgmpV1Layer : public IgmpLayer
{
public:
	 /** A constructor that creates the layer from an existing packet raw data
	 * @param[in] data A pointer to the raw data
	 * @param[in] dataLen Size of the data in bytes
	 * @param[in] packet A pointer to the Packet instance where layer will be stored in
	 */
	IgmpV1Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

	/**
	 * A constructor that allocates a new IGMPv1 header
	 * @param[in] type The message type to set
	 * @param[in] groupAddr The group address set. An optional parameter, set to IPv4Address#Zero if not provided
	 */
	IgmpV1Layer(IgmpType type, const IPv4Address& groupAddr = IPv4Address::Zero);

	/**
	 * A destructor for this layer (does nothing)
	 */
	~IgmpV1Layer() {}


	// implement abstract methods

	/**
	 * Calculate the IGMP checksum and set igmp_header#maxResponseTime to 0 (this field is unused in IGMPv1)
	 */
	void computeCalculateFields();

};

class IgmpV2Layer : public IgmpLayer
{
public:
	 /** A constructor that creates the layer from an existing packet raw data
	 * @param[in] data A pointer to the raw data
	 * @param[in] dataLen Size of the data in bytes
	 * @param[in] packet A pointer to the Packet instance where layer will be stored in
	 */
	IgmpV2Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

	/**
	 * A constructor that allocates a new IGMPv2 header
	 * @param[in] type The message type to set
	 * @param[in] groupAddr The group address set. An optional parameter, set to IPv4Address#Zero if not provided
	 * @param[in] maxResponseTime The max response time to set. An optional parameter, set to 0 if not provided
	 */
	IgmpV2Layer(IgmpType type, const IPv4Address& groupAddr = IPv4Address::Zero, uint8_t maxResponseTime = 0);

	/**
	 * A destructor for this layer (does nothing)
	 */
	~IgmpV2Layer() {}


	// implement abstract methods

	/**
	 * Calculate the IGMP checksum
	 */
	void computeCalculateFields();
};

}

#endif // PACKETPP_IGMP_LAYER
