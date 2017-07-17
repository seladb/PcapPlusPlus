#define LOG_MODULE PacketLogModuleIPv6Layer

#include <IPv6Layer.h>
#include <IPv4Layer.h>
#include <PayloadLayer.h>
#include <UdpLayer.h>
#include <TcpLayer.h>
#include <GreLayer.h>
#include <string.h>
#include <IpUtils.h>

namespace pcpp
{

void IPv6Layer::initLayer()
{
	m_DataLen = sizeof(ip6_hdr);
	m_Data = new uint8_t[m_DataLen];
	m_Protocol = IPv6;
	memset(m_Data, 0, sizeof(ip6_hdr));
}

IPv6Layer::IPv6Layer()
{
	initLayer();
}

IPv6Layer::IPv6Layer(const IPv6Address& srcIP, const IPv6Address& dstIP)
{
	initLayer();
	ip6_hdr* ipHdr = getIPv6Header();
	srcIP.copyTo(ipHdr->ipSrc);
	dstIP.copyTo(ipHdr->ipDst);
}

void IPv6Layer::parseNextLayer()
{
	if (m_DataLen <= sizeof(ip6_hdr))
		return;

	ip6_hdr* ipHdr = getIPv6Header();

	ProtocolType greVer = UnknownProtocol;

	uint8_t ipVersion = 0;

	switch (ipHdr->nextHeader)
	{
	case PACKETPP_IPPROTO_UDP:
		m_NextLayer = new UdpLayer(m_Data + sizeof(ip6_hdr), m_DataLen - sizeof(ip6_hdr), this, m_Packet);
		break;
	case PACKETPP_IPPROTO_TCP:
		m_NextLayer = new TcpLayer(m_Data + sizeof(ip6_hdr), m_DataLen - sizeof(ip6_hdr), this, m_Packet);
		break;
	case PACKETPP_IPPROTO_IPIP:
		ipVersion = *(m_Data + sizeof(ip6_hdr));
		if (ipVersion >> 4 == 4)
			m_NextLayer = new IPv4Layer(m_Data + sizeof(ip6_hdr), m_DataLen - sizeof(ip6_hdr), this, m_Packet);
		else if (ipVersion >> 4 == 6)
			m_NextLayer = new IPv6Layer(m_Data + sizeof(ip6_hdr), m_DataLen - sizeof(ip6_hdr), this, m_Packet);
		else
			m_NextLayer = new PayloadLayer(m_Data + sizeof(ip6_hdr), m_DataLen - sizeof(ip6_hdr), this, m_Packet);
		break;
	case PACKETPP_IPPROTO_GRE:
		greVer = GreLayer::getGREVersion(m_Data + sizeof(ip6_hdr), m_DataLen - sizeof(ip6_hdr));
		if (greVer == GREv0)
			m_NextLayer = new GREv0Layer(m_Data + sizeof(ip6_hdr), m_DataLen - sizeof(ip6_hdr), this, m_Packet);
		else if (greVer == GREv1)
			m_NextLayer = new GREv1Layer(m_Data + sizeof(ip6_hdr), m_DataLen - sizeof(ip6_hdr), this, m_Packet);
		else
			m_NextLayer = new PayloadLayer(m_Data + sizeof(ip6_hdr), m_DataLen - sizeof(ip6_hdr), this, m_Packet);
		break;
	default:
		m_NextLayer = new PayloadLayer(m_Data + sizeof(ip6_hdr), m_DataLen - sizeof(ip6_hdr), this, m_Packet);
		return;
	}
}

void IPv6Layer::computeCalculateFields()
{
	ip6_hdr* ipHdr = getIPv6Header();
	ipHdr->payloadLength = htons(m_DataLen - sizeof(ip6_hdr));
	ipHdr->ipVersion = (6 & 0x0f);

	if (m_NextLayer != NULL)
	{
		switch (m_NextLayer->getProtocol())
		{
		case TCP:
			ipHdr->nextHeader = PACKETPP_IPPROTO_TCP;
			break;
		case UDP:
			ipHdr->nextHeader = PACKETPP_IPPROTO_UDP;
			break;
		case ICMP:
			ipHdr->nextHeader = PACKETPP_IPPROTO_ICMP;
			break;
		case GRE:
			ipHdr->nextHeader = PACKETPP_IPPROTO_GRE;
			break;
		default:
			break;
		}
	}
}

std::string IPv6Layer::toString()
{
	return "IPv6 Layer, Src: " + getSrcIpAddress().toString() + ", Dst: " + getDstIpAddress().toString();
}

}// namespace pcpp
