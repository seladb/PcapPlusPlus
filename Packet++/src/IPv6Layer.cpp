#define LOG_MODULE PacketLogModuleIPv6Layer

#include "IPv6Layer.h"
#include "IPv4Layer.h"
#include "PayloadLayer.h"
#include "UdpLayer.h"
#include "TcpLayer.h"
#include "GreLayer.h"
#include "IPSecLayer.h"
#include "OspfLayer.h"
#include "Packet.h"
#include "PacketUtils.h"
#include <string.h>
#include "EndianPortable.h"

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

	size_t totalLen = be16toh(getIPv6Header()->payloadLength) + getHeaderLen();
	if (totalLen < m_DataLen)
		m_DataLen = totalLen;
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

	while (offset <= m_DataLen - 2*sizeof(uint8_t)) // 2*sizeof(uint8_t) is the min len for IPv6 extensions
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

size_t IPv6Layer::getExtensionCount() const
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

bool IPv6Layer::isFragment() const
{
	IPv6FragmentationHeader* fragHdr = getExtensionOfType<IPv6FragmentationHeader>();
	return (fragHdr != NULL);
}

void IPv6Layer::parseNextLayer()
{
	size_t headerLen = getHeaderLen();

	if (m_DataLen <= headerLen)
		return;

	uint8_t* payload = m_Data + headerLen;
	size_t payloadLen = m_DataLen - headerLen;

	uint8_t nextHdr;
	if (m_LastExtension != NULL)
	{
		if (m_LastExtension->getExtensionType() == IPv6Extension::IPv6Fragmentation)
		{
			m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
			return;
		}

		nextHdr = m_LastExtension->getBaseHeader()->nextHeader;
	}
	else
	{
		nextHdr = getIPv6Header()->nextHeader;
	}

	switch (nextHdr)
	{
	case PACKETPP_IPPROTO_UDP:
		m_NextLayer = new UdpLayer(payload, payloadLen, this, m_Packet);
		break;
	case PACKETPP_IPPROTO_TCP:
		m_NextLayer = TcpLayer::isDataValid(payload, payloadLen)
			? static_cast<Layer*>(new TcpLayer(payload, payloadLen, this, m_Packet))
			: static_cast<Layer*>(new PayloadLayer(payload, payloadLen, this, m_Packet));
		break;
	case PACKETPP_IPPROTO_IPIP:
	{
		uint8_t ipVersion = *payload >> 4;
		if (ipVersion == 4 && IPv4Layer::isDataValid(payload, payloadLen))
			m_NextLayer = new IPv4Layer(payload, payloadLen, this, m_Packet);
		else if (ipVersion == 6 && IPv6Layer::isDataValid(payload, payloadLen))
			m_NextLayer = new IPv6Layer(payload, payloadLen, this, m_Packet);
		else
			m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
		break;
	}
	case PACKETPP_IPPROTO_GRE:
	{
		ProtocolType greVer = GreLayer::getGREVersion(payload, payloadLen);
		if (greVer == GREv0)
			m_NextLayer = new GREv0Layer(payload, payloadLen, this, m_Packet);
		else if (greVer == GREv1)
			m_NextLayer = new GREv1Layer(payload, payloadLen, this, m_Packet);
		else
			m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
		break;
	}
	case PACKETPP_IPPROTO_AH:
		m_NextLayer = AuthenticationHeaderLayer::isDataValid(payload, payloadLen)
			? static_cast<Layer*>(new AuthenticationHeaderLayer(payload, payloadLen, this, m_Packet))
			: static_cast<Layer*>(new PayloadLayer(payload, payloadLen, this, m_Packet));
		break;
	case PACKETPP_IPPROTO_ESP:
		m_NextLayer = ESPLayer::isDataValid(payload, payloadLen)
			? static_cast<Layer*>(new ESPLayer(payload, payloadLen, this, m_Packet))
			: static_cast<Layer*>(new PayloadLayer(payload, payloadLen, this, m_Packet));
		break;
	case PACKETPP_IPPROTO_OSPF:
		m_NextLayer = OspfLayer::isDataValid(payload, payloadLen)
			? static_cast<Layer*>(new OspfLayer(payload, payloadLen, this, m_Packet))
			: static_cast<Layer*>(new PayloadLayer(payload, payloadLen, this, m_Packet));
		break;
	default:
		m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
		return;
	}
}

void IPv6Layer::computeCalculateFields()
{
	ip6_hdr* ipHdr = getIPv6Header();
	ipHdr->payloadLength = htobe16(m_DataLen - sizeof(ip6_hdr));
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
		case GREv0:
		case GREv1:
			nextHeader = PACKETPP_IPPROTO_GRE;
			break;
		case OSPF: 
			nextHeader = PACKETPP_IPPROTO_OSPF;
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

std::string IPv6Layer::toString() const
{
	std::string result = "IPv6 Layer, Src: " + getSrcIPv6Address().toString() + ", Dst: " + getDstIPv6Address().toString();
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

		// replace the last ','
		result[result.size() - 1] = ']';
	}

	return result;
}

}// namespace pcpp
