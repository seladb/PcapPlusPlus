#define LOG_MODULE PacketLogModuleIPv6Layer

#include "IPv6Layer.h"
#include "IPv4Layer.h"
#include "PayloadLayer.h"
#include "UdpLayer.h"
#include "TcpLayer.h"
#include "GreLayer.h"
#include "Packet.h"
#include <string.h>
#include "IpUtils.h"

namespace pcpp
{

void IPv6Layer::initLayer()
{
	m_DataLen = sizeof(ip6_hdr);
	m_Data = new uint8_t[m_DataLen];
	m_Protocol = IPv6;
	m_FirstExtension = NULL;
	m_LastExtension = NULL;
	m_ExtensionsLen = 0;
	memset(m_Data, 0, sizeof(ip6_hdr));
}

IPv6Layer::IPv6Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet)
{
	m_Protocol = IPv6;
	m_FirstExtension = NULL;
	m_LastExtension = NULL;
	m_ExtensionsLen = 0;

	parseExtensions();
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

IPv6Layer::IPv6Layer(const IPv6Layer& other) : Layer(other)
{
	m_FirstExtension = NULL;
	m_LastExtension = NULL;
	m_ExtensionsLen = 0;
	parseExtensions();
}

IPv6Layer::~IPv6Layer()
{
	deleteExtensions();
}

IPv6Layer& IPv6Layer::operator=(const IPv6Layer& other)
{
	Layer::operator=(other);

	deleteExtensions();

	parseExtensions();

	return *this;
}

void IPv6Layer::parseExtensions()
{
	uint8_t nextHdr = getIPv6Header()->nextHeader;
	IPv6Extension* curExt = NULL;

	size_t offset = sizeof(ip6_hdr);

	while (offset <= m_DataLen )
	{
		IPv6Extension* newExt = NULL;

		switch (nextHdr)
		{
		case PACKETPP_IPPROTO_FRAGMENT:
		{
			newExt = new IPv6FragmentationHeader(this, offset);
			break;
		}
		case PACKETPP_IPPROTO_HOPOPTS:
		{
			newExt = new IPv6HopByHopHeader(this, offset);
			break;
		}
		case PACKETPP_IPPROTO_DSTOPTS:
		{
			newExt = new IPv6DestinationHeader(this, offset);
			break;
		}
		case PACKETPP_IPPROTO_ROUTING:
		{
			newExt = new IPv6RoutingHeader(this, offset);
			break;
		}
		case PACKETPP_IPPROTO_AH:
		{
			newExt = new IPv6AuthenticationHeader(this, offset);
			break;
		}
		default:
		{
			break;
		}
		}

		if (newExt == NULL)
			break;

		if (m_FirstExtension == NULL)
		{
			m_FirstExtension = newExt;
			curExt = m_FirstExtension;
		}
		else
		{
			curExt->setNextHeader(newExt);
			curExt = curExt->getNextHeader();
		}

		offset += newExt->getExtensionLen();
		nextHdr = newExt->getBaseHeader()->nextHeader;
		m_ExtensionsLen += newExt->getExtensionLen();
	}

	m_LastExtension = curExt;
}

void IPv6Layer::deleteExtensions()
{
	IPv6Extension* curExt = m_FirstExtension;
	while (curExt != NULL)
	{
		IPv6Extension* tmpExt = curExt->getNextHeader();
		delete curExt;
		curExt = tmpExt;
	}

	m_FirstExtension = NULL;
	m_LastExtension = NULL;
	m_ExtensionsLen = 0;

}

size_t IPv6Layer::getExtensionCount()
{
	size_t extensionCount = 0;

	IPv6Extension* curExt = m_FirstExtension;

	while (curExt != NULL)
	{
		extensionCount++;
		curExt = curExt->getNextHeader();
	}

	return extensionCount;
}

void IPv6Layer::removeAllExtensions()
{
	if (m_LastExtension != NULL)
		getIPv6Header()->nextHeader = m_LastExtension->getBaseHeader()->nextHeader;

	shortenLayer((int)sizeof(ip6_hdr), m_ExtensionsLen);

	deleteExtensions();
}

bool IPv6Layer::isFragment()
{
	IPv6FragmentationHeader* fragHdr = getExtensionOfType<IPv6FragmentationHeader>();
	return (fragHdr != NULL);
}

void IPv6Layer::parseNextLayer()
{
	size_t headerLen = getHeaderLen();

	if (m_DataLen <= headerLen)
		return;

	uint8_t nextHdr = 0;
	if (m_LastExtension != NULL)
	{
		if (m_LastExtension->getExtensionType() == IPv6Extension::IPv6Fragmentation)
		{
			m_NextLayer = new PayloadLayer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
			return;
		}

		nextHdr = m_LastExtension->getBaseHeader()->nextHeader;
	}
	else
	{
		nextHdr = getIPv6Header()->nextHeader;
	}

	ProtocolType greVer = UnknownProtocol;

	uint8_t ipVersion = 0;

	switch (nextHdr)
	{
	case PACKETPP_IPPROTO_UDP:
		m_NextLayer = new UdpLayer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
		break;
	case PACKETPP_IPPROTO_TCP:
		m_NextLayer = new TcpLayer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
		break;
	case PACKETPP_IPPROTO_IPIP:
		ipVersion = *(m_Data + headerLen);
		if (ipVersion >> 4 == 4)
			m_NextLayer = new IPv4Layer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
		else if (ipVersion >> 4 == 6)
			m_NextLayer = new IPv6Layer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
		else
			m_NextLayer = new PayloadLayer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
		break;
	case PACKETPP_IPPROTO_GRE:
		greVer = GreLayer::getGREVersion(m_Data + headerLen, m_DataLen - headerLen);
		if (greVer == GREv0)
			m_NextLayer = new GREv0Layer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
		else if (greVer == GREv1)
			m_NextLayer = new GREv1Layer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
		else
			m_NextLayer = new PayloadLayer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
		break;
	default:
		m_NextLayer = new PayloadLayer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
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
		uint8_t nextHeader = 0;
		switch (m_NextLayer->getProtocol())
		{
		case TCP:
			nextHeader = PACKETPP_IPPROTO_TCP;
			break;
		case UDP:
			nextHeader = PACKETPP_IPPROTO_UDP;
			break;
		case ICMP:
			nextHeader = PACKETPP_IPPROTO_ICMP;
			break;
		case GRE:
			nextHeader = PACKETPP_IPPROTO_GRE;
			break;
		default:
			break;
		}

		if (nextHeader != 0)
		{
			if (m_LastExtension != NULL)
				m_LastExtension->getBaseHeader()->nextHeader = nextHeader;
			else
				ipHdr->nextHeader = nextHeader;

		}
	}
}

std::string IPv6Layer::toString()
{
	std::string result = "IPv6 Layer, Src: " + getSrcIpAddress().toString() + ", Dst: " + getDstIpAddress().toString();
	if (m_ExtensionsLen > 0)
	{
		result += ", Options=[";
		IPv6Extension* curExt = m_FirstExtension;
		while (curExt != NULL)
		{
			switch (curExt->getExtensionType())
			{
			case IPv6Extension::IPv6Fragmentation:
				result += "Fragment,";
				break;
			case IPv6Extension::IPv6HopByHop:
				result += "Hop-By-Hop,";
				break;
			case IPv6Extension::IPv6Destination:
				result += "Destination,";
				break;
			case IPv6Extension::IPv6Routing:
				result += "Routing,";
				break;
			case IPv6Extension::IPv6AuthenticationHdr:
				result += "Authentication,";
				break;
			default:
				result += "Unknown,";
				break;
			}

			curExt = curExt->getNextHeader();
		}

		//remove last ','
		result = result.substr(0, result.size()-1);

		result +="]";
	}

	return result;
}

}// namespace pcpp
