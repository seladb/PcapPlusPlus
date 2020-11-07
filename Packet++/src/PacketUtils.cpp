#include <string.h>
#include "PacketUtils.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include "IcmpLayer.h"
#include "Logger.h"
#include "EndianPortable.h"

namespace pcpp
{

uint16_t computeChecksum(ScalarBuffer<uint16_t> vec[], size_t vecSize)
{
	uint32_t sum = 0;
	for (size_t i = 0; i<vecSize; i++)
	{
		uint32_t local_sum = 0;
		size_t buff_len = vec[i].len;
		while (buff_len > 1) {
			LOG_DEBUG("Value to add = 0x%4X", *(vec[i].buffer));
			local_sum += *(vec[i].buffer);
			++(vec[i].buffer);
			buff_len -= 2;
		}
		LOG_DEBUG("Local sum = %d, 0x%4X", local_sum, local_sum);

		if (buff_len == 1)
		{
			uint8_t lastByte = *(vec[i].buffer);
			LOG_DEBUG("1 byte left, adding value: 0x%4X", lastByte);
			local_sum += lastByte;
			LOG_DEBUG("Local sum = %d, 0x%4X", local_sum, local_sum);
		}

		while (local_sum>>16) {
			local_sum = (local_sum & 0xffff) + (local_sum >> 16);
		}
		local_sum = be16toh(local_sum);
		LOG_DEBUG("Local sum = %d, 0x%4X", local_sum, local_sum);
		sum += local_sum;
	}

	while (sum>>16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	LOG_DEBUG("Sum before invert = %d, 0x%4X", sum, sum);

	sum = ~sum;

	LOG_DEBUG("Calculated checksum = %d, 0x%4X", sum, sum);

	return ((uint16_t) sum);
}

static const uint32_t FNV_PRIME = 16777619u;
static const uint32_t OFFSET_BASIS = 2166136261u;

uint32_t fnvHash(ScalarBuffer<uint8_t> vec[], size_t vecSize)
{
	uint32_t hash = OFFSET_BASIS;
	for (size_t i = 0; i < vecSize; ++i)
	{
		for (size_t j = 0; j < vec[i].len; ++j)
		{
			hash *= FNV_PRIME;
			hash ^= vec[i].buffer[j];
		}
	}
	return hash;
}

uint32_t fnvHash(uint8_t* buffer, size_t bufSize)
{
	ScalarBuffer<uint8_t> scalarBuf;
	scalarBuf.buffer = buffer;
	scalarBuf.len = bufSize;
	return fnvHash(&scalarBuf, 1);
}

uint32_t hash5Tuple(Packet* packet, bool const& directionUnique)
{
	if (!packet->isPacketOfType(IPv4) && !packet->isPacketOfType(IPv6))
		return 0;

	if (packet->isPacketOfType(ICMP))
		return 0;

	if (!(packet->isPacketOfType(TCP)) && (!packet->isPacketOfType(UDP)))
		return 0;

	ScalarBuffer<uint8_t> vec[5];

	uint16_t portSrc = 0;
	uint16_t portDst = 0;
	int srcPosition = 0;

	TcpLayer* tcpLayer = packet->getLayerOfType<TcpLayer>(true); // lookup in reverse order
	if (tcpLayer != NULL)
	{
		portSrc = tcpLayer->getTcpHeader()->portSrc;
		portDst = tcpLayer->getTcpHeader()->portDst;
	}
	else
	{
		UdpLayer* udpLayer = packet->getLayerOfType<UdpLayer>(true);
		portSrc = udpLayer->getUdpHeader()->portSrc;
		portDst = udpLayer->getUdpHeader()->portDst;
	}

	if( ! directionUnique)
	{
		if (portDst < portSrc)
			srcPosition = 1;
	}

	vec[0 + srcPosition].buffer = (uint8_t*)&portSrc;
	vec[0 + srcPosition].len = 2;
	vec[1 - srcPosition].buffer = (uint8_t*)&portDst;
	vec[1 - srcPosition].len = 2;


	IPv4Layer* ipv4Layer = packet->getLayerOfType<IPv4Layer>();
	if (ipv4Layer != NULL)
	{
		if (portSrc == portDst && ipv4Layer->getIPv4Header()->ipDst < ipv4Layer->getIPv4Header()->ipSrc)
			srcPosition = 1;

		vec[2 + srcPosition].buffer = (uint8_t*)&ipv4Layer->getIPv4Header()->ipSrc;
		vec[2 + srcPosition].len = 4;
		vec[3 - srcPosition].buffer = (uint8_t*)&ipv4Layer->getIPv4Header()->ipDst;
		vec[3 - srcPosition].len = 4;
		vec[4].buffer = &(ipv4Layer->getIPv4Header()->protocol);
		vec[4].len = 1;
	}
	else
	{
		IPv6Layer* ipv6Layer = packet->getLayerOfType<IPv6Layer>();
		if (portSrc == portDst && (uint64_t)ipv6Layer->getIPv6Header()->ipDst < (uint64_t)ipv6Layer->getIPv6Header()->ipSrc)
			srcPosition = 1;

		vec[2 + srcPosition].buffer = ipv6Layer->getIPv6Header()->ipSrc;
		vec[2 + srcPosition].len = 16;
		vec[3 - srcPosition].buffer = ipv6Layer->getIPv6Header()->ipDst;
		vec[3 - srcPosition].len = 16;
		vec[4].buffer = &(ipv6Layer->getIPv6Header()->nextHeader);
		vec[4].len = 1;
	}

	return pcpp::fnvHash(vec, 5);
}


uint32_t hash2Tuple(Packet* packet)
{
	if (!packet->isPacketOfType(IPv4) && !packet->isPacketOfType(IPv6))
		return 0;

	ScalarBuffer<uint8_t> vec[2];

	IPv4Layer* ipv4Layer = packet->getLayerOfType<IPv4Layer>();
	if (ipv4Layer != NULL)
	{
		int srcPosition = 0;
		if (ipv4Layer->getIPv4Header()->ipDst < ipv4Layer->getIPv4Header()->ipSrc)
			srcPosition = 1;

		vec[0 + srcPosition].buffer = (uint8_t*)&ipv4Layer->getIPv4Header()->ipSrc;
		vec[0 + srcPosition].len = 4;
		vec[1 - srcPosition].buffer = (uint8_t*)&ipv4Layer->getIPv4Header()->ipDst;
		vec[1 - srcPosition].len = 4;
	}
	else
	{
		IPv6Layer* ipv6Layer = packet->getLayerOfType<IPv6Layer>();
		int srcPosition = 0;
		if ((uint64_t)ipv6Layer->getIPv6Header()->ipDst < (uint64_t)ipv6Layer->getIPv6Header()->ipSrc
				&& (uint64_t)(ipv6Layer->getIPv6Header()->ipDst+8) < (uint64_t)(ipv6Layer->getIPv6Header()->ipSrc+8))
			srcPosition = 1;

		vec[0 + srcPosition].buffer = ipv6Layer->getIPv6Header()->ipSrc;
		vec[0 + srcPosition].len = 16;
		vec[1 - srcPosition].buffer = ipv6Layer->getIPv6Header()->ipDst;
		vec[1 - srcPosition].len = 16;
	}

	return pcpp::fnvHash(vec, 2);
}

}  // namespace pcpp
