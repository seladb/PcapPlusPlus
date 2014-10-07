#define LOG_MODULE eIPv6Layer

#include <IPv6Layer.h>
#include <IPv4Layer.h>
#include <PayloadLayer.h>
#include <UdpLayer.h>
#include <TcpLayer.h>
#include <string.h>
#include <IpUtils.h>

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

	switch (ipHdr->nextHeader)
	{
	case PACKETPP_IPPROTO_UDP:
		m_NextLayer = new UdpLayer(m_Data + sizeof(ip6_hdr), m_DataLen - sizeof(ip6_hdr), this);
		break;
	case PACKETPP_IPPROTO_TCP:
		m_NextLayer = new TcpLayer(m_Data + sizeof(ip6_hdr), m_DataLen - sizeof(ip6_hdr), this);
		break;
	default:
		m_NextLayer = new PayloadLayer(m_Data + sizeof(ip6_hdr), m_DataLen - sizeof(ip6_hdr), this);
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
		default:
			break;
		}
	}
}
