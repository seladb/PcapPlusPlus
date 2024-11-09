#define LOG_MODULE PacketLogModuleUdpLayer

#include "EndianPortable.h"
#include "UdpLayer.h"
#include "PayloadLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "DnsLayer.h"
#include "DhcpLayer.h"
#include "DhcpV6Layer.h"
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
		udphdr* udpHdr = (udphdr*)m_Data;
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
		udphdr* udpHdr = (udphdr*)m_Data;
		uint16_t checksumRes = 0;
		uint16_t currChecksumValue = udpHdr->headerChecksum;

		if (m_PrevLayer != nullptr)
		{
			udpHdr->headerChecksum = 0;
			PCPP_LOG_DEBUG("UDP data len = " << m_DataLen);

			if (m_PrevLayer->getProtocol() == IPv4)
			{
				IPv4Address srcIP = ((IPv4Layer*)m_PrevLayer)->getSrcIPv4Address();
				IPv4Address dstIP = ((IPv4Layer*)m_PrevLayer)->getDstIPv4Address();

				checksumRes = pcpp::computePseudoHdrChecksum((uint8_t*)udpHdr, getDataLen(), IPAddress::IPv4AddressType,
				                                             PACKETPP_IPPROTO_UDP, srcIP, dstIP);

				PCPP_LOG_DEBUG("calculated IPv4 UDP checksum = 0x" << std::uppercase << std::hex << checksumRes);
			}
			else if (m_PrevLayer->getProtocol() == IPv6)
			{
				IPv6Address srcIP = ((IPv6Layer*)m_PrevLayer)->getSrcIPv6Address();
				IPv6Address dstIP = ((IPv6Layer*)m_PrevLayer)->getDstIPv6Address();

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
			m_NextLayer = new DhcpLayer(udpData, udpDataLen, this, m_Packet);
		else if (VxlanLayer::isVxlanPort(portDst))
			m_NextLayer = new VxlanLayer(udpData, udpDataLen, this, m_Packet);
		else if (DnsLayer::isDataValid(udpData, udpDataLen) &&
		         (DnsLayer::isDnsPort(portDst) || DnsLayer::isDnsPort(portSrc)))
			m_NextLayer = new DnsLayer(udpData, udpDataLen, this, m_Packet);
		else if (SipLayer::isSipPort(portDst) || SipLayer::isSipPort(portSrc))
		{
			if (SipRequestFirstLine::parseMethod((char*)udpData, udpDataLen) != SipRequestLayer::SipMethodUnknown)
				m_NextLayer = new SipRequestLayer(udpData, udpDataLen, this, m_Packet);
			else if (SipResponseFirstLine::parseStatusCode((char*)udpData, udpDataLen) !=
			             SipResponseLayer::SipStatusCodeUnknown &&
			         SipResponseFirstLine::parseVersion((char*)udpData, udpDataLen) != "")
				m_NextLayer = new SipResponseLayer(udpData, udpDataLen, this, m_Packet);
			else
				m_NextLayer = new PayloadLayer(udpData, udpDataLen, this, m_Packet);
		}
		else if ((RadiusLayer::isRadiusPort(portDst) || RadiusLayer::isRadiusPort(portSrc)) &&
		         RadiusLayer::isDataValid(udpData, udpDataLen))
			m_NextLayer = new RadiusLayer(udpData, udpDataLen, this, m_Packet);
		else if ((GtpV1Layer::isGTPv1Port(portDst) || GtpV1Layer::isGTPv1Port(portSrc)) &&
		         GtpV1Layer::isGTPv1(udpData, udpDataLen))
			m_NextLayer = new GtpV1Layer(udpData, udpDataLen, this, m_Packet);
		else if ((GtpV2Layer::isGTPv2Port(portDst) || GtpV2Layer::isGTPv2Port(portSrc)) &&
		         GtpV2Layer::isDataValid(udpData, udpDataLen))
			m_NextLayer = new GtpV2Layer(udpData, udpDataLen, this, m_Packet);
		else if ((DhcpV6Layer::isDhcpV6Port(portSrc) || DhcpV6Layer::isDhcpV6Port(portDst)) &&
		         (DhcpV6Layer::isDataValid(udpData, udpDataLen)))
			m_NextLayer = new DhcpV6Layer(udpData, udpDataLen, this, m_Packet);
		else if ((NtpLayer::isNTPPort(portSrc) || NtpLayer::isNTPPort(portDst)) &&
		         NtpLayer::isDataValid(udpData, udpDataLen))
			m_NextLayer = new NtpLayer(udpData, udpDataLen, this, m_Packet);
		else if (SomeIpLayer::isSomeIpPort(portSrc) || SomeIpLayer::isSomeIpPort(portDst))
			m_NextLayer = SomeIpLayer::parseSomeIpLayer(udpData, udpDataLen, this, m_Packet);
		else if ((WakeOnLanLayer::isWakeOnLanPort(portDst) && WakeOnLanLayer::isDataValid(udpData, udpDataLen)))
			m_NextLayer = new WakeOnLanLayer(udpData, udpDataLen, this, m_Packet);
		else if ((WireGuardLayer::isWireGuardPorts(portDst, portSrc) &&
		          WireGuardLayer::isDataValid(udpData, udpDataLen)))
		{
			m_NextLayer = WireGuardLayer::parseWireGuardLayer(udpData, udpDataLen, this, m_Packet);
			if (!m_NextLayer)
				m_NextLayer = new PayloadLayer(udpData, udpDataLen, this, m_Packet);
		}
		else
			m_NextLayer = new PayloadLayer(udpData, udpDataLen, this, m_Packet);
	}

	void UdpLayer::computeCalculateFields()
	{
		udphdr* udpHdr = (udphdr*)m_Data;
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
