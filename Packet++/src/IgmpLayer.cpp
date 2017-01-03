#include <IgmpLayer.h>
#include <IpUtils.h>
#include <string.h>
#ifdef WIN32 //for using ntohl, ntohs, etc.
#include <winsock2.h>
#elif LINUX
#include <in.h> //for using ntohl, ntohs, etc.
#elif MAC_OS_X
#include <arpa/inet.h> //for using ntohl, ntohs, etc.
#endif

namespace pcpp
{

/*************
 * IgmpLayer
 *************/

IgmpLayer::IgmpLayer(IgmpType type, const IPv4Address& groupAddr, uint8_t maxResponseTime, ProtocolType igmpVer)
{
	m_DataLen = getHeaderSizeByVer(igmpVer);
	m_Data = new uint8_t[m_DataLen];
	memset(m_Data, 0, m_DataLen);
	m_Protocol = igmpVer;

	setType(type);
	if (groupAddr != IPv4Address::Zero)
		setGroupAddress(groupAddr);

	getIgmpHeader()->maxResponseTime = maxResponseTime;
}

void IgmpLayer::setGroupAddress(const IPv4Address& groupAddr)
{
	igmp_header* hdr = getIgmpHeader();
	hdr->groupAddress = groupAddr.toInt();
}

IgmpType IgmpLayer::getType()
{
	uint8_t type = getIgmpHeader()->type;
	if (type < (uint8_t)IgmpType_MembershipQuery ||
			(type > (uint8_t)IgmpType_LeaveGroup && type < (uint8_t)IgmpType_MulticastTracerouteResponse) ||
			(type > (uint8_t)IgmpType_MulticastTraceroute && type < (uint8_t)IgmpType_MembershipReportV3) ||
			(type > (uint8_t)IgmpType_MembershipReportV3 && type < (uint8_t)IgmpType_MulticastRouterAdvertisement) ||
			type > IgmpType_MulticastRouterTermination)
		return IgmpType_Unknown;

	return (IgmpType)type;
}

void IgmpLayer::setType(IgmpType type)
{
	if (type == IgmpType_Unknown)
		return;

	igmp_header* hdr = getIgmpHeader();
	hdr->type = type;
}

ProtocolType IgmpLayer::getIGMPVerFromData(uint8_t* data, size_t dataLen, bool& isQuery)
{
	isQuery = false;

	if (dataLen < 8 || data == NULL)
		return Unknown;

	switch ((int)data[0])
	{
	case IgmpType_MembershipReportV2:
	case IgmpType_LeaveGroup:
		return IGMPv2;
	case IgmpType_MembershipReportV1:
		return IGMPv1;
	case IgmpType_MembershipReportV3:
		return IGMPv3;
	case IgmpType_MembershipQuery:
	{
		isQuery = true;

		if (dataLen >= sizeof(igmpv3_query_header))
			return IGMPv3;

		if (data[1] == 0)
			return IGMPv1;
		else
			return IGMPv2;
	}
	default:
		return Unknown;
	}
}

uint16_t IgmpLayer::calculateChecksum()
{
	ScalarBuffer<uint16_t> buffer;
	buffer.buffer = (uint16_t*)getIgmpHeader();
	buffer.len = getHeaderLen();
	return compute_checksum(&buffer, 1);
}

size_t IgmpLayer::getHeaderSizeByVer(ProtocolType igmpVer)
{
	if (igmpVer == IGMPv1 || igmpVer == IGMPv2)
		return sizeof(igmp_header);

	if (igmpVer == IGMPv3)
		return sizeof(igmpv3_query_header);

	return 0;
}

std::string IgmpLayer::toString()
{
	std::string igmpVer = "";
	switch (getProtocol())
	{
	case IGMPv1:
		igmpVer = "1";
		break;
	case IGMPv2:
		igmpVer = "2";
		break;
	default:
		igmpVer = "3";
	}

	std::string msgType;

	switch (getType())
	{
	case IgmpType_MembershipQuery:
		msgType = "Membership Query";
		break;
	case IgmpType_MembershipReportV1:
		msgType = "Membership Report";
		break;
	case IgmpType_DVMRP:
		msgType = "DVMRP";
		break;
	case IgmpType_P1Mv1:
		msgType = "PIMv1";
		break;
	case IgmpType_CiscoTrace:
		msgType = "Cisco Trace";
		break;
	case IgmpType_MembershipReportV2:
		msgType = "Membership Report";
		break;
	case IgmpType_LeaveGroup:
		msgType = "Leave Group";
		break;
	case IgmpType_MulticastTracerouteResponse:
		msgType = "Multicast Traceroute Response";
		break;
	case IgmpType_MulticastTraceroute:
		msgType = "Multicast Traceroute";
		break;
	case IgmpType_MembershipReportV3:
		msgType = "Membership Report";
		break;
	case IgmpType_MulticastRouterAdvertisement:
		msgType = "Multicast Router Advertisement";
		break;
	case IgmpType_MulticastRouterSolicitation:
		msgType = "Multicast Router Solicitation";
		break;
	case IgmpType_MulticastRouterTermination:
		msgType = "Multicast Router Termination";
		break;
	default:
		msgType = "Unknown";
		break;
	}

	std::string result = "IGMPv" + igmpVer + " Layer, " + msgType + " message";
	return result;
}




/*************
 * IgmpV1Layer
 *************/

IgmpV1Layer::IgmpV1Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) :
		IgmpLayer(data, dataLen, prevLayer, packet, IGMPv1)
{
}

IgmpV1Layer::IgmpV1Layer(IgmpType type, const IPv4Address& groupAddr) :
		IgmpLayer(type, groupAddr, 0, IGMPv1)
{
}

void IgmpV1Layer::computeCalculateFields()
{
	igmp_header* hdr = getIgmpHeader();
	hdr->checksum = 0;
	hdr->checksum = htons(calculateChecksum());
	hdr->maxResponseTime = 0;
}





/*************
 * IgmpV2Layer
 *************/

IgmpV2Layer::IgmpV2Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) :
		IgmpLayer(data, dataLen, prevLayer, packet, IGMPv2)
{
}

IgmpV2Layer::IgmpV2Layer(IgmpType type, const IPv4Address& groupAddr, uint8_t maxResponseTime) :
		IgmpLayer(type, groupAddr, maxResponseTime, IGMPv2)
{
}

void IgmpV2Layer::computeCalculateFields()
{
	igmp_header* hdr = getIgmpHeader();
	hdr->checksum = 0;
	hdr->checksum = htons(calculateChecksum());
}





/******************
 * IgmpV3QueryLayer
 ******************/


IgmpV3QueryLayer::IgmpV3QueryLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) :
		IgmpLayer(data, dataLen, prevLayer, packet, IGMPv3)
{
}

uint16_t IgmpV3QueryLayer::getNumOfSources()
{
	return ntohs(getQueryHeader()->numOfSources);
}

IPv4Address IgmpV3QueryLayer::getSourceAddressAtIndex(int index)
{
	uint16_t numOfSources = getNumOfSources();
	if (index < 0 || index >= numOfSources)
		return IPv4Address::Zero;

	// verify numOfRecords is a reasonable number that points to data within the packet
	int ptrOffset = index * sizeof(uint32_t) + sizeof(igmpv3_query_header);
	if (ptrOffset + sizeof(uint32_t) > getDataLen())
		return IPv4Address::Zero;

	uint8_t* ptr = m_Data + ptrOffset;
	return IPv4Address(*(uint32_t*)ptr);
}

size_t IgmpV3QueryLayer::getHeaderLen()
{
	uint16_t numOfSources = getNumOfSources();

	int headerLen = numOfSources * sizeof(uint32_t) + sizeof(igmpv3_query_header);

	// verify numOfRecords is a reasonable number that points to data within the packet
	if ((size_t)headerLen > getDataLen())
		return getDataLen();

	return (size_t)headerLen;
}

void IgmpV3QueryLayer::computeCalculateFields()
{
	igmpv3_query_header* hdr = getQueryHeader();
	hdr->checksum = 0;
	hdr->checksum = htons(calculateChecksum());
	//TODO
}




/*******************
 * IgmpV3ReportLayer
 *******************/

IgmpV3ReportLayer::IgmpV3ReportLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) :
		IgmpLayer(data, dataLen, prevLayer, packet, IGMPv3)
{
}

uint16_t IgmpV3ReportLayer::getNumOfGroupRecords()
{
	return ntohs(getReportHeader()->numOfGroupRecords);

}

igmpv3_group_record* IgmpV3ReportLayer::getFirstGroupRecord()
{
	// check if there are group records at all
	if (getHeaderLen() <= sizeof(igmpv3_report_header))
		return NULL;

	uint8_t* curGroupPtr = m_Data + sizeof(igmpv3_report_header);
	return (igmpv3_group_record*)curGroupPtr;
}

igmpv3_group_record* IgmpV3ReportLayer::getNextGroupRecord(igmpv3_group_record* groupRecord)
{
	if (groupRecord == NULL)
		return NULL;

	// prev group was the last group
	if ((uint8_t*)groupRecord + groupRecord->getRecordLen() - m_Data >= (int)getHeaderLen())
		return NULL;

	igmpv3_group_record* nextGroup = (igmpv3_group_record*)((uint8_t*)groupRecord + groupRecord->getRecordLen());

	return nextGroup;
}

size_t IgmpV3ReportLayer::getHeaderLen()
{
	return m_DataLen;
}

void IgmpV3ReportLayer::computeCalculateFields()
{
	igmpv3_report_header* hdr = getReportHeader();
	hdr->checksum = 0;
	hdr->checksum = htons(calculateChecksum());
	//TODO
}




/*********************
 * igmpv3_group_record
 *********************/

IPv4Address igmpv3_group_record::getMulticastAddress()
{
	return IPv4Address(multicastAddress);
}

uint16_t igmpv3_group_record::getSourceAdressCount()
{
	return ntohs(numOfSources);
}

IPv4Address igmpv3_group_record::getSoruceAddressAtIndex(int index)
{
	uint16_t numOfRecords = getSourceAdressCount();
	if (index < 0 || index >= numOfRecords)
		return IPv4Address::Zero;

	int offset = index * sizeof(uint32_t);
	uint8_t* ptr = sourceAddresses + offset;
	return IPv4Address(*(uint32_t*)ptr);
}

size_t igmpv3_group_record::getRecordLen()
{
	uint16_t numOfRecords = getSourceAdressCount();

	int headerLen = numOfRecords * sizeof(uint32_t) + sizeof(igmpv3_group_record);
	return (size_t)headerLen;
}

}
