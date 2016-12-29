#define LOG_MODULE PacketLogModuleIPv4Layer

#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <PayloadLayer.h>
#include <UdpLayer.h>
#include <TcpLayer.h>
#include <IcmpLayer.h>
#include <GreLayer.h>
#include <IgmpLayer.h>
#include <string.h>
#include <sstream>
#include <IpUtils.h>

namespace pcpp
{

void IPv4Layer::initLayer()
{
	m_DataLen = sizeof(iphdr);
	m_Data = new uint8_t[m_DataLen];
	m_Protocol = IPv4;
	memset(m_Data, 0, sizeof(iphdr));
}

IPv4Layer::IPv4Layer()
{
	initLayer();
}

IPv4Layer::IPv4Layer(const IPv4Address& srcIP, const IPv4Address& dstIP)
{
	initLayer();
	iphdr* ipHdr = getIPv4Header();
	ipHdr->ipSrc = srcIP.toInt();
	ipHdr->ipDst = dstIP.toInt();
}

void IPv4Layer::parseNextLayer()
{
	if (m_DataLen <= sizeof(iphdr))
		return;

	iphdr* ipHdr = getIPv4Header();

	ProtocolType greVer = Unknown;
	ProtocolType igmpVer = Unknown;

	uint8_t ipVersion = 0;

	// If it's a fragment don't parse upper layers, unless if it's the first fragment
	// TODO: assuming first fragment contains at least L4 header, what if it's not true?
	if (isFragment())
	{
		m_NextLayer = new PayloadLayer(m_Data + sizeof(iphdr), m_DataLen - sizeof(iphdr), this, m_Packet);
		return;
	}

	switch (ipHdr->protocol)
	{
	case PACKETPP_IPPROTO_UDP:
		if (m_DataLen - sizeof(iphdr) >= sizeof(udphdr))
			m_NextLayer = new UdpLayer(m_Data + sizeof(iphdr), m_DataLen - sizeof(iphdr), this, m_Packet);
		break;
	case PACKETPP_IPPROTO_TCP:
		if (m_DataLen - sizeof(iphdr) >= sizeof(tcphdr))
			m_NextLayer = new TcpLayer(m_Data + sizeof(iphdr), m_DataLen - sizeof(iphdr), this, m_Packet);
		break;
	case PACKETPP_IPPROTO_ICMP:
		m_NextLayer = new IcmpLayer(m_Data + sizeof(iphdr), m_DataLen - sizeof(iphdr), this, m_Packet);
		break;
	case PACKETPP_IPPROTO_IPIP:
		ipVersion = *(m_Data + sizeof(iphdr));
		if (ipVersion >> 4 == 4)
			m_NextLayer = new IPv4Layer(m_Data + sizeof(iphdr), m_DataLen - sizeof(iphdr), this, m_Packet);
		else if (ipVersion >> 4 == 6)
			m_NextLayer = new IPv6Layer(m_Data + sizeof(iphdr), m_DataLen - sizeof(iphdr), this, m_Packet);
		else
			m_NextLayer = new PayloadLayer(m_Data + sizeof(iphdr), m_DataLen - sizeof(iphdr), this, m_Packet);
		break;
	case PACKETPP_IPPROTO_GRE:
		greVer = GreLayer::getGREVersion(m_Data + sizeof(iphdr), m_DataLen - sizeof(iphdr));
		if (greVer == GREv0)
			m_NextLayer = new GREv0Layer(m_Data + sizeof(iphdr), m_DataLen - sizeof(iphdr), this, m_Packet);
		else if (greVer == GREv1)
			m_NextLayer = new GREv1Layer(m_Data + sizeof(iphdr), m_DataLen - sizeof(iphdr), this, m_Packet);
		else
			m_NextLayer = new PayloadLayer(m_Data + sizeof(iphdr), m_DataLen - sizeof(iphdr), this, m_Packet);
		break;
	case PACKETPP_IPPROTO_IGMP:
		igmpVer = IgmpLayer::getIGMPVerFromData(m_Data + sizeof(iphdr), m_DataLen - sizeof(ipHdr));
		if (igmpVer == IGMPv1)
			m_NextLayer = new IgmpV1Layer(m_Data + sizeof(iphdr), m_DataLen - sizeof(iphdr), this, m_Packet);
		else if (igmpVer == IGMPv2)
			m_NextLayer = new IgmpV2Layer(m_Data + sizeof(iphdr), m_DataLen - sizeof(iphdr), this, m_Packet);
		else
			m_NextLayer = new PayloadLayer(m_Data + sizeof(iphdr), m_DataLen - sizeof(iphdr), this, m_Packet);
		break;
	default:
		m_NextLayer = new PayloadLayer(m_Data + sizeof(iphdr), m_DataLen - sizeof(iphdr), this, m_Packet);
		return;
	}
}

void IPv4Layer::computeCalculateFields()
{
	iphdr* ipHdr = getIPv4Header();
	ipHdr->internetHeaderLength = (5 & 0xf);
	ipHdr->ipVersion = (4 & 0x0f);
	ipHdr->totalLength = htons(m_DataLen);
	ipHdr->headerChecksum = 0;

	if (m_NextLayer != NULL)
	{
		switch (m_NextLayer->getProtocol())
		{
		case TCP:
			ipHdr->protocol = PACKETPP_IPPROTO_TCP;
			break;
		case UDP:
			ipHdr->protocol = PACKETPP_IPPROTO_UDP;
			break;
		case ICMP:
			ipHdr->protocol = PACKETPP_IPPROTO_ICMP;
			break;
		case GREv0:
		case GREv1:
			ipHdr->protocol = PACKETPP_IPPROTO_GRE;
			break;
		case IGMPv1:
		case IGMPv2:
			ipHdr->protocol = PACKETPP_IPPROTO_IGMP;
			break;
		default:
			break;
		}
	}

	ScalarBuffer<uint16_t> scalar = { (uint16_t*)ipHdr, ipHdr->internetHeaderLength*4 } ;
	ipHdr->headerChecksum = htons(compute_checksum(&scalar, 1));
}

bool IPv4Layer::isFragment()
{
	return ((getFragmentFlags() & PCPP_IP_MORE_FRAGMENTS) != 0 || getFragmentOffset() != 0);
}

bool IPv4Layer::isFirstFragment()
{
	return isFragment() && (getFragmentOffset() == 0);
}

bool IPv4Layer::isLastFragment()
{
	return isFragment() && ((getFragmentFlags() & PCPP_IP_MORE_FRAGMENTS) == 0);
}

uint8_t IPv4Layer::getFragmentFlags()
{
	return getIPv4Header()->fragmentOffset & 0xE0;
}

uint16_t IPv4Layer::getFragmentOffset()
{
	return ntohs(getIPv4Header()->fragmentOffset & (uint16_t)0xFF1F) * 8;
}

std::string IPv4Layer::toString()
{
	std::string fragmet = "";
	if (isFragment())
	{
		if (isFirstFragment())
			fragmet = "First fragment";
		else if (isLastFragment())
			fragmet = "Last fragment";
		else
			fragmet = "Fragment";

		std::stringstream sstm;
		sstm << fragmet << " [offset= " << getFragmentOffset() << "], ";
		fragmet = sstm.str();
	}


	return "IPv4 Layer, " + fragmet + "Src: " + getSrcIpAddress().toString() + ", Dst: " + getDstIpAddress().toString();
}

} // namespace pcpp
