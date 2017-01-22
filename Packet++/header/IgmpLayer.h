#ifndef PACKETPP_IGMP_LAYER
#define PACKETPP_IGMP_LAYER

#include <Layer.h>
#include <IpAddress.h>
#include <vector>

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

/**
 * @struct igmp_header
 * IGMPv1 and IGMPv2 basic protocol header
 */
struct igmp_header
{
	/** Indicates the message type. The enum for message type is pcpp::IgmpType */
	uint8_t type;
	/** Specifies the time limit for the corresponding report. The field has a resolution of 100 milliseconds */
	uint8_t maxResponseTime;
	/** This is the 16-bit one's complement of the one's complement sum of the entire IGMP message */
	uint16_t checksum;
	/** This is the multicast address being queried when sending a Group-Specific or Group-and-Source-Specific Query */
	uint32_t groupAddress;
};


/**
 * @struct igmpv3_query_header
 * IGMPv3 membership query basic header
 */
struct igmpv3_query_header
{
	/** IGMP message type. Should always have value of membership query (::IgmpType_MembershipQuery)  */
	uint8_t type;
	/** This field specifies the maximum time (in 1/10 second) allowed before sending a responding report */
	uint8_t maxResponseTime;
	/** This is the 16-bit one's complement of the one's complement sum of the entire IGMP message */
	uint16_t checksum;
	/** This is the multicast address being queried when sending a Group-Specific or Group-and-Source-Specific Query */
	uint32_t groupAddress;
	/** Suppress Router-side Processing Flag + Querier's Robustness Variable */
	uint8_t s_qrv;
	/** Querier's Query Interval Code */
	uint8_t qqic;
	/** This field specifies the number of source addresses present in the Query */
	uint16_t numOfSources;
};


/**
 * @struct igmpv3_report_header
 * IGMPv3 membership report basic header
 */
struct igmpv3_report_header
{
	/** IGMP message type. Should always have value of IGMPv3 membership report (::IgmpType_MembershipReportV3)  */
	uint8_t type;
	/** Unused bytes */
	uint8_t reserved1;
	/** This is the 16-bit one's complement of the one's complement sum of the entire IGMP message */
	uint16_t checksum;
	/** Unused bytes */
	uint16_t reserved2;
	/** This field specifies the number of group records present in the Report */
	uint16_t numOfGroupRecords;
};


/**
 * @struct igmpv3_group_record
 * A block of fields containing information pertaining to the sender's membership in a single multicast group on the interface
 * from which the Report is sent. Relevant only for IGMPv3 membership report messages
 */
struct igmpv3_group_record
{
	/** Group record type */
	uint8_t recordType;
	/** contains the length of the Auxiliary Data field in this Group Record. A value other than 0 isn't supported */
	uint8_t auxDataLen;
	/** The Number of Sources field specifies how many source addresses are present in this Group Record */
	uint16_t numOfSources;
	/** Contains the IP multicast address to which this Group Record pertains */
	uint32_t multicastAddress;
	/** A vector of n IP unicast addresses, where n is the value in this record's Number of Sources field */
	uint8_t sourceAddresses[];

	/**
	 * @return The multicast address in igmpv3_group_record#multicastAddress as IPv4Address instance
	 */
	IPv4Address getMulticastAddress();

	/**
	 * @return The number of source addresses in this group record
	 */
	uint16_t getSourceAdressCount();

	/**
	 * Get the source address in a certain index
	 * @param[in] index The index of the source address in the group record
	 * @return The source address in the requested index. If index is negative or higher than the number of source addresses in this
	 * group record the value if IPv4Address#Zero is returned
	 */
	IPv4Address getSoruceAddressAtIndex(int index);

	/**
	 * @return The total size in bytes of group record
	 */
	size_t getRecordLen();
};


/**
 * IGMP message types
 */
enum IgmpType
{
	/** Unknown message type */
	IgmpType_Unknown = 0,
	/** IGMP Membership Query */
	IgmpType_MembershipQuery = 0x11,
	/** IGMPv1 Membership Report */
	IgmpType_MembershipReportV1 = 0x12,
	/** DVMRP */
	IgmpType_DVMRP = 0x13,
	/** PIM version 1 */
	IgmpType_P1Mv1 = 0x14,
	/** Cisco Trace Messages */
	IgmpType_CiscoTrace = 0x15,
	/** IGMPv2 Membership Report */
	IgmpType_MembershipReportV2 = 0x16,
	/** IGMPv2 Leave Group */
	IgmpType_LeaveGroup = 0x17,
	/** Multicast Traceroute Response */
	IgmpType_MulticastTracerouteResponse = 0x1e,
	/** Multicast Traceroute */
	IgmpType_MulticastTraceroute = 0x1f,
	/** IGMPv3 Membership Report */
	IgmpType_MembershipReportV3 = 0x22,
	/** MRD, Multicast Router Advertisement */
	IgmpType_MulticastRouterAdvertisement = 0x30,
	/** MRD, Multicast Router Solicitation */
	IgmpType_MulticastRouterSolicitation = 0x31,
	/** MRD, Multicast Router Termination */
	IgmpType_MulticastRouterTermination = 0x32,
};

class IgmpLayer : public Layer
{
protected:

	IgmpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet, ProtocolType igmpVer) : Layer(data, dataLen, NULL, packet) { m_Protocol = igmpVer; }

	IgmpLayer(IgmpType type, const IPv4Address& groupAddr, uint8_t maxResponseTime, ProtocolType igmpVer);

	uint16_t calculateChecksum();

	size_t getHeaderSizeByVerAndType(ProtocolType igmpVer, IgmpType igmpType);
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
	static ProtocolType getIGMPVerFromData(uint8_t* data, size_t dataLen, bool& isQuery);


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

class IgmpV3QueryLayer : public IgmpLayer
{
public:

	 /** A constructor that creates the layer from an existing packet raw data
	 * @param[in] data A pointer to the raw data
	 * @param[in] dataLen Size of the data in bytes
	 * @param[in] packet A pointer to the Packet instance where layer will be stored in
	 */
	IgmpV3QueryLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

	IgmpV3QueryLayer(const IPv4Address& multicastAddr = IPv4Address::Zero, uint8_t maxResponseTime = 0, uint8_t s_qrv = 0);

	inline igmpv3_query_header* getIgmpV3QueryHeader() { return (igmpv3_query_header*)m_Data; }

	uint16_t getSourceAddressCount();

	IPv4Address getSourceAddressAtIndex(int index);

	bool addSourceAddress(const IPv4Address& addr);

	bool addSourceAddressAtIndex(const IPv4Address& addr, int index);

	bool removeSourceAddressAtIndex(int index);

	bool removeAllSourceAddresses();

	// implement abstract methods

	void computeCalculateFields();

	size_t getHeaderLen();
};

class IgmpV3ReportLayer : public IgmpLayer
{
private:
	igmpv3_group_record* addGroupRecordAt(uint8_t recordType, const IPv4Address& multicastAddress, const std::vector<IPv4Address>& sourceAddresses, int offset);

public:

	 /** A constructor that creates the layer from an existing packet raw data
	 * @param[in] data A pointer to the raw data
	 * @param[in] dataLen Size of the data in bytes
	 * @param[in] packet A pointer to the Packet instance where layer will be stored in
	 */
	IgmpV3ReportLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

	IgmpV3ReportLayer();

	inline igmpv3_report_header* getReportHeader() { return (igmpv3_report_header*)m_Data; }

	uint16_t getGroupRecordCount();

	igmpv3_group_record* getFirstGroupRecord();

	igmpv3_group_record* getNextGroupRecord(igmpv3_group_record* groupRecord);

	igmpv3_group_record* addGroupRecord(uint8_t recordType, const IPv4Address& multicastAddress, const std::vector<IPv4Address>& sourceAddresses);

	igmpv3_group_record* addGroupRecordAtIndex(uint8_t recordType, const IPv4Address& multicastAddress, const std::vector<IPv4Address>& sourceAddresses, int index);

	bool removeGroupRecordAtIndex(int index);

	bool removeAllGroupRecords();

	// implement abstract methods

	void computeCalculateFields();

	size_t getHeaderLen();
};

}

#endif // PACKETPP_IGMP_LAYER
