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

IgmpLayer::IgmpLayer(IgmpType type, const IPv4Address& groupAddr, uint8_t maxResponseTime, ProtocolType igmpVer)
{
	m_DataLen = sizeof(igmp_header);
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

ProtocolType IgmpLayer::getIGMPVerFromData(uint8_t* data, size_t dataLen)
{
	if (dataLen < 2 || data == NULL)
		return Unknown;
	switch ((int)data[0])
	{
	case IgmpType_MembershipReportV2:
	case IgmpType_LeaveGroup:
		return IGMPv2;
	case IgmpType_MembershipReportV1:
		return IGMPv1;
	case IgmpType_MembershipQuery:
	{
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
	buffer.len = sizeof(igmp_header);
	return compute_checksum(&buffer, 1);
}

std::string IgmpLayer::toString()
{
	std::string igmpVer = (getProtocol() == IGMPv1) ? "1" : "2";
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

}
