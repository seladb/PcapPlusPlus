#define LOG_MODULE PacketLogModuleUdpLayer

#include "EndianPortable.h"
#include "UdpLayer.h"
#include "PayloadLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "DnsLayer.h"
#include "DhcpLayer.h"
#include "DhcpV6Layer.h"
#include "DoIpLayer.h"
#include "VxlanLayer.h"
#include "SipLayer.h"
#include "RadiusLayer.h"
#include "GtpLayer.h"
#include "NtpLayer.h"
#include "SomeIpLayer.h"
#include "WakeOnLanLayer.h"
#include "WireGuardLayer.h"
#include "PacketUtils.h"
#include "Logger.h"
#include <sstream>

namespace pcpp
{

	UdpLayer::UdpLayer(uint16_t portSrc, uint16_t portDst)
	{
		const size_t headerLen = sizeof(udphdr);
		m_DataLen = headerLen;
		m_Data = new uint8_t[headerLen];
		memset(m_Data, 0, headerLen);
		udphdr* udpHdr = reinterpret_cast<udphdr*>(m_Data);
		udpHdr->portDst = htobe16(portDst);
		udpHdr->portSrc = htobe16(portSrc);
		m_Protocol = UDP;
	}

	uint16_t UdpLayer::getSrcPort() const
	{
		return be16toh(getUdpHeader()->portSrc);
	}

	uint16_t UdpLayer::getDstPort() const
	{
		return be16toh(getUdpHeader()->portDst);
	}

	uint16_t UdpLayer::calculateChecksum(bool writeResultToPacket)
	{
		udphdr* udpHdr = reinterpret_cast<udphdr*>(m_Data);
		uint16_t checksumRes = 0;
		uint16_t currChecksumValue = udpHdr->headerChecksum;

		if (m_PrevLayer != nullptr)
		{
			udpHdr->headerChecksum = 0;
			PCPP_LOG_DEBUG("UDP data len = " << m_DataLen);

			if (m_PrevLayer->getProtocol() == IPv4)
			{
				IPv4Address srcIP = static_cast<IPv4Layer*>(m_PrevLayer)->getSrcIPv4Address();
				IPv4Address dstIP = static_cast<IPv4Layer*>(m_PrevLayer)->getDstIPv4Address();

				checksumRes = pcpp::computePseudoHdrChecksum((uint8_t*)udpHdr, getDataLen(), IPAddress::IPv4AddressType,
				                                             PACKETPP_IPPROTO_UDP, srcIP, dstIP);

				PCPP_LOG_DEBUG("calculated IPv4 UDP checksum = 0x" << std::uppercase << std::hex << checksumRes);
			}
			else if (m_PrevLayer->getProtocol() == IPv6)
			{
				IPv6Address srcIP = static_cast<IPv6Layer*>(m_PrevLayer)->getSrcIPv6Address();
				IPv6Address dstIP = static_cast<IPv6Layer*>(m_PrevLayer)->getDstIPv6Address();

				checksumRes = computePseudoHdrChecksum((uint8_t*)udpHdr, getDataLen(), IPAddress::IPv6AddressType,
				                                       PACKETPP_IPPROTO_UDP, srcIP, dstIP);

				PCPP_LOG_DEBUG("calculated IPv6 UDP checksum = 0xX" << std::uppercase << std::hex << checksumRes);
			}
		}

		if (checksumRes == 0)
			checksumRes = 0xffff;

		if (writeResultToPacket)
			udpHdr->headerChecksum = htobe16(checksumRes);
		else
			udpHdr->headerChecksum = currChecksumValue;

		return checksumRes;
	}

	void UdpLayer::parseNextLayer()
	{
		if (m_DataLen <= sizeof(udphdr))
			return;

		uint16_t portDst = getDstPort();
		uint16_t portSrc = getSrcPort();

		uint8_t* udpData = m_Data + sizeof(udphdr);
		size_t udpDataLen = m_DataLen - sizeof(udphdr);

		if (DhcpLayer::isDhcpPorts(portSrc, portDst))
		{
			constructNextLayer<DhcpLayer>(udpData, udpDataLen);
		}
		else if (VxlanLayer::isVxlanPort(portDst))
		{
			constructNextLayer<VxlanLayer>(udpData, udpDataLen);
		}
		else if (DnsLayer::isDataValid(udpData, udpDataLen) &&
		         (DnsLayer::isDnsPort(portDst) || DnsLayer::isDnsPort(portSrc)))
		{
			constructNextLayer<DnsLayer>(udpData, udpDataLen);
		}
		else if (SipLayer::isSipPort(portDst) || SipLayer::isSipPort(portSrc))
		{
			// Resolves the overload of parseSipLayer, without static_casting a function pointer.
			auto*(*fac)(uint8_t*, size_t, Layer*, Packet*, uint16_t, uint16_t) = SipLayer::parseSipLayer;
			tryConstructNextLayerFromFactoryWithFallback<PayloadLayer>(fac, udpData, udpDataLen, portSrc, portDst);
		}
		else if((RadiusLayer::isRadiusPort(portDst) || RadiusLayer::isRadiusPort(portSrc)) &&
				 RadiusLayer::isDataValid(udpData,udpDataLen))
		{
			constructNextLayer<RadiusLayer>(udpData, udpDataLen);
		}
		else if ((GtpV1Layer::isGTPv1Port(portDst) || GtpV1Layer::isGTPv1Port(portSrc)) &&
		         GtpV1Layer::isGTPv1(udpData, udpDataLen))
		{
			constructNextLayer<GtpV1Layer>(udpData, udpDataLen);
		}
		else if ((GtpV2Layer::isGTPv2Port(portDst) || GtpV2Layer::isGTPv2Port(portSrc)) &&
		         GtpV2Layer::isDataValid(udpData, udpDataLen))
		{
			constructNextLayer<GtpV2Layer>(udpData, udpDataLen);
		}
		else if ((DhcpV6Layer::isDhcpV6Port(portSrc) || DhcpV6Layer::isDhcpV6Port(portDst)) &&
		         (DhcpV6Layer::isDataValid(udpData, udpDataLen)))
		{
			constructNextLayer<DhcpV6Layer>(udpData, udpDataLen);
		}
		else if ((NtpLayer::isNTPPort(portSrc) || NtpLayer::isNTPPort(portDst)) &&
		         NtpLayer::isDataValid(udpData, udpDataLen))
		{
			constructNextLayer<NtpLayer>(udpData, udpDataLen);
		}
		else if ((DoIpLayer::isDoIpPort(portSrc) || DoIpLayer::isDoIpPort(portDst)) &&
		         (DoIpLayer::isDataValid(udpData, udpDataLen)))
		{
			tryConstructNextLayerFromFactoryWithFallback<PayloadLayer>(DoIpLayer::parseDoIpLayer, udpData, udpDataLen);
		}
		else if (SomeIpLayer::isSomeIpPort(portSrc) || SomeIpLayer::isSomeIpPort(portDst))
		{
			constructNextLayerFromFactory(SomeIpLayer::parseSomeIpLayer, udpData, udpDataLen);
		}
		else if ((WakeOnLanLayer::isWakeOnLanPort(portDst) && WakeOnLanLayer::isDataValid(udpData, udpDataLen)))
		{
			constructNextLayer<WakeOnLanLayer>(udpData, udpDataLen);
		}
		else if ((WireGuardLayer::isWireGuardPorts(portDst, portSrc) &&
		          WireGuardLayer::isDataValid(udpData, udpDataLen)))
		{
			tryConstructNextLayerFromFactoryWithFallback<PayloadLayer>(WireGuardLayer::parseWireGuardLayer, udpData, udpDataLen);
		}

		// If a valid layer was found, return immediately
		if (hasNextLayer())
		{
			return;
		}

		// Here, heuristics for all protocols should be invoked to determine the correct layer
		{
			// Resolves the overload of parseSipLayer, without static_casting a function pointer.
			auto* (*fac)(uint8_t*, size_t, Layer*, Packet*) = SipLayer::parseSipLayer;
			tryConstructNextLayerFromFactoryWithFallback<PayloadLayer>(fac, udpData, udpDataLen);
		}

		if (!hasNextLayer())
		{
			constructNextLayer<PayloadLayer>(udpData, udpDataLen);
		}
	}

	void UdpLayer::computeCalculateFields()
	{
		udphdr* udpHdr = reinterpret_cast<udphdr*>(m_Data);
		udpHdr->length = htobe16(m_DataLen);
		calculateChecksum(true);
	}

	std::string UdpLayer::toString() const
	{
		std::ostringstream srcPortStream;
		srcPortStream << getSrcPort();
		std::ostringstream dstPortStream;
		dstPortStream << getDstPort();

		return "UDP Layer, Src port: " + srcPortStream.str() + ", Dst port: " + dstPortStream.str();
	}

}  // namespace pcpp
