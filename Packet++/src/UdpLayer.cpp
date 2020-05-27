#define LOG_MODULE PacketLogModuleUdpLayer

#include "EndianPortable.h"
#include "UdpLayer.h"
#include "IpUtils.h"
#include "PayloadLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "DnsLayer.h"
#include "DhcpLayer.h"
#include "VxlanLayer.h"
#include "SipLayer.h"
#include "RadiusLayer.h"
#include "GtpLayer.h"
#include "Logger.h"
#include <string.h>
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

uint16_t UdpLayer::calculateChecksum(bool writeResultToPacket)
{
	udphdr* udpHdr = (udphdr*)m_Data;
	uint16_t checksumRes = 0;
	uint16_t currChecksumValue = udpHdr->headerChecksum;

	if (m_PrevLayer != NULL)
	{
		udpHdr->headerChecksum = 0;
		ScalarBuffer<uint16_t> vec[2];
		LOG_DEBUG("data len =  %d", (int)m_DataLen);
		vec[0].buffer = (uint16_t*)m_Data;
		vec[0].len = m_DataLen;

		if (m_PrevLayer->getProtocol() == IPv4)
		{
			uint32_t srcIP = ((IPv4Layer*)m_PrevLayer)->getSrcIpAddress().toInt();
			uint32_t dstIP = ((IPv4Layer*)m_PrevLayer)->getDstIpAddress().toInt();
			uint16_t pseudoHeader[6];
			pseudoHeader[0] = srcIP >> 16;
			pseudoHeader[1] = srcIP & 0xFFFF;
			pseudoHeader[2] = dstIP >> 16;
			pseudoHeader[3] = dstIP & 0xFFFF;
			pseudoHeader[4] = 0xffff & udpHdr->length;
			pseudoHeader[5] = htobe16(0x00ff & PACKETPP_IPPROTO_UDP);
			vec[1].buffer = pseudoHeader;
			vec[1].len = 12;
			checksumRes = compute_checksum(vec, 2);
			LOG_DEBUG("calculated checksum = 0x%4X", checksumRes);
		}
		else if (m_PrevLayer->getProtocol() == IPv6)
		{
			uint16_t pseudoHeader[18];
			((IPv6Layer*)m_PrevLayer)->getSrcIpAddress().copyTo((uint8_t*)pseudoHeader);
			((IPv6Layer*)m_PrevLayer)->getDstIpAddress().copyTo((uint8_t*)(pseudoHeader+8));
			pseudoHeader[16] = 0xffff & udpHdr->length;
			pseudoHeader[17] = htobe16(0x00ff & PACKETPP_IPPROTO_UDP);
			vec[1].buffer = pseudoHeader;
			vec[1].len = 36;
			checksumRes = compute_checksum(vec, 2);
			LOG_DEBUG("calculated checksum = 0x%4X", checksumRes);
		}
	}

	if(writeResultToPacket)
		udpHdr->headerChecksum = htobe16(checksumRes);
	else
		udpHdr->headerChecksum = currChecksumValue;

	return checksumRes;
}

void UdpLayer::parseNextLayer()
{
	if (m_DataLen <= sizeof(udphdr))
		return;

	udphdr* udpHder = getUdpHeader();
	uint16_t portDst = be16toh(udpHder->portDst);
	uint16_t portSrc = be16toh(udpHder->portSrc);

	uint8_t* udpData = m_Data + sizeof(udphdr);
	size_t udpDataLen = m_DataLen - sizeof(udphdr);

	if ((portSrc == 68 && portDst == 67) || (portSrc == 67 && portDst == 68) || (portSrc == 67 && portDst == 67))
		m_NextLayer = new DhcpLayer(udpData, udpDataLen, this, m_Packet);
	else if (VxlanLayer::isVxlanPort(portDst))
		m_NextLayer = new VxlanLayer(udpData, udpDataLen, this, m_Packet);
	else if ((udpDataLen >= sizeof(dnshdr)) && (DnsLayer::isDnsPort(portDst) || DnsLayer::isDnsPort(portSrc)))
		m_NextLayer = new DnsLayer(udpData, udpDataLen, this, m_Packet);
	else if(SipLayer::isSipPort(portDst) || SipLayer::isSipPort(portSrc))
	{
		if (SipRequestFirstLine::parseMethod((char*)udpData, udpDataLen) != SipRequestLayer::SipMethodUnknown)
			m_NextLayer = new SipRequestLayer(udpData, udpDataLen, this, m_Packet);
		else if (SipResponseFirstLine::parseStatusCode((char*)udpData, udpDataLen) != SipResponseLayer::SipStatusCodeUnknown
						&& SipResponseFirstLine::parseVersion((char*)udpData, udpDataLen) != "")
			m_NextLayer = new SipResponseLayer(udpData, udpDataLen, this, m_Packet);
		else
			m_NextLayer = new PayloadLayer(udpData, udpDataLen, this, m_Packet);
	}
	else if ((RadiusLayer::isRadiusPort(portDst) || RadiusLayer::isRadiusPort(portSrc)) && RadiusLayer::isDataValid(udpData, udpDataLen))
		m_NextLayer = new RadiusLayer(udpData, udpDataLen, this, m_Packet);
	else if ((GtpV1Layer::isGTPv1Port(portDst) || GtpV1Layer::isGTPv1Port(portSrc)) && GtpV1Layer::isGTPv1(udpData, udpDataLen))
		m_NextLayer = new GtpV1Layer(udpData, udpDataLen, this, m_Packet);
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
	srcPortStream << be16toh(getUdpHeader()->portSrc);
	std::ostringstream dstPortStream;
	dstPortStream << be16toh(getUdpHeader()->portDst);

	return "UDP Layer, Src port: " + srcPortStream.str() + ", Dst port: " + dstPortStream.str();
}

} // namespace pcpp
