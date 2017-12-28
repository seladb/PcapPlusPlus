#define LOG_MODULE PacketLogModuleUdpLayer

#include "UdpLayer.h"
#include "IpUtils.h"
#include "PayloadLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "DnsLayer.h"
#include "DhcpLayer.h"
#include "VxlanLayer.h"
#include "SipLayer.h"
#include "Logger.h"
#include <string.h>
#include <sstream>

namespace pcpp
{

UdpLayer::UdpLayer(uint16_t portSrc, uint16_t portDst)
{
	m_DataLen = sizeof(udphdr);
	m_Data = new uint8_t[m_DataLen];
	memset(m_Data, 0, m_DataLen);
	udphdr* udpHdr = (udphdr*)m_Data;
	udpHdr->portDst = htons(portDst);
	udpHdr->portSrc = htons(portSrc);
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
			pseudoHeader[5] = htons(0x00ff & PACKETPP_IPPROTO_UDP);
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
			pseudoHeader[17] = htons(0x00ff & PACKETPP_IPPROTO_UDP);
			vec[1].buffer = pseudoHeader;
			vec[1].len = 36;
			checksumRes = compute_checksum(vec, 2);
			LOG_DEBUG("calculated checksum = 0x%4X", checksumRes);
		}
	}

	if(writeResultToPacket)
		udpHdr->headerChecksum = htons(checksumRes);
	else
		udpHdr->headerChecksum = currChecksumValue;

	return checksumRes;
}

void UdpLayer::parseNextLayer()
{
	if (m_DataLen <= sizeof(udphdr))
		return;

	udphdr* udpHder = getUdpHeader();
	uint16_t portDst = ntohs(udpHder->portDst);
	uint16_t portSrc = ntohs(udpHder->portSrc);

	if ((portSrc == 68 && portDst == 67) || (portSrc == 67 && portDst == 68) || (portSrc == 67 && portDst == 67))
		m_NextLayer = new DhcpLayer(m_Data + sizeof(udphdr), m_DataLen - sizeof(udphdr), this, m_Packet);
	else if (portDst == 4789)
		m_NextLayer = new VxlanLayer(m_Data + sizeof(udphdr), m_DataLen - sizeof(udphdr), this, m_Packet);
	else if ((m_DataLen - sizeof(udphdr) >= sizeof(dnshdr)) && (DnsLayer::getDNSPortMap()->find(portDst) != DnsLayer::getDNSPortMap()->end() || DnsLayer::getDNSPortMap()->find(portSrc) != DnsLayer::getDNSPortMap()->end()))
		m_NextLayer = new DnsLayer(m_Data + sizeof(udphdr), m_DataLen - sizeof(udphdr), this, m_Packet);
	else if (((portDst == 5060) || (portDst == 5061) || (portSrc == 5060) || (portSrc == 5061)) && (SipRequestFirstLine::parseMethod((char*)(m_Data + sizeof(udphdr)), m_DataLen - sizeof(udphdr)) != SipRequestLayer::SipMethodUnknown))
		m_NextLayer = new SipRequestLayer(m_Data + sizeof(udphdr), m_DataLen - sizeof(udphdr), this, m_Packet);
	else if (((portDst == 5060) || (portDst == 5061) || (portSrc == 5060) || (portSrc == 5061)) && (SipResponseFirstLine::parseStatusCode((char*)(m_Data + sizeof(udphdr)), m_DataLen - sizeof(udphdr)) != SipResponseLayer::SipStatusCodeUnknown))
		m_NextLayer = new SipResponseLayer(m_Data + sizeof(udphdr), m_DataLen - sizeof(udphdr), this, m_Packet);
	else
		m_NextLayer = new PayloadLayer(m_Data + sizeof(udphdr), m_DataLen - sizeof(udphdr), this, m_Packet);
}

void UdpLayer::computeCalculateFields()
{
	udphdr* udpHdr = (udphdr*)m_Data;
	udpHdr->length = htons(m_DataLen);
	calculateChecksum(true);
}

std::string UdpLayer::toString()
{
	std::ostringstream srcPortStream;
	srcPortStream << ntohs(getUdpHeader()->portSrc);
	std::ostringstream dstPortStream;
	dstPortStream << ntohs(getUdpHeader()->portDst);

	return "UDP Layer, Src port: " + srcPortStream.str() + ", Dst port: " + dstPortStream.str();
}

} // namespace pcpp
