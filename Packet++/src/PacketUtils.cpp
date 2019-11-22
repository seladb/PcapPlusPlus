#include <string.h>
#include "PacketUtils.h"
#include "IpUtils.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"

namespace pcpp
{

uint32_t hash5Tuple(const Packet* packet, const Layer* networkLayer, const Layer* transportLayer)
{
	ScalarBuffer<uint8_t> vec[5];

	uint16_t portSrc;
	uint16_t portDst;

	if (packet->isPacketOfType(TCP))
	{
		const TcpLayer* tcpLayer = static_cast<const TcpLayer*>(transportLayer);
		portSrc = tcpLayer->getTcpHeader()->portSrc;
		portDst = tcpLayer->getTcpHeader()->portDst;
	}
	else // UDP
	{
		const UdpLayer* udpLayer = static_cast<const UdpLayer*>(transportLayer);
		portSrc = udpLayer->getUdpHeader()->portSrc;
		portDst = udpLayer->getUdpHeader()->portDst;
	}

	int srcPosition = (portDst < portSrc);

	vec[0 + srcPosition].buffer = (uint8_t*)&portSrc;
	vec[0 + srcPosition].len = 2;
	vec[1 - srcPosition].buffer = (uint8_t*)&portDst;
	vec[1 - srcPosition].len = 2;

	if (packet->isPacketOfType(IPv4))
	{
		const IPv4Layer* ipv4Layer = static_cast<const IPv4Layer*>(networkLayer);

		if (portSrc == portDst && ipv4Layer->getIPv4Header()->ipDst < ipv4Layer->getIPv4Header()->ipSrc)
			srcPosition = 1;

		vec[2 + srcPosition].buffer = (uint8_t*)&ipv4Layer->getIPv4Header()->ipSrc;
		vec[2 + srcPosition].len = 4;
		vec[3 - srcPosition].buffer = (uint8_t*)&ipv4Layer->getIPv4Header()->ipDst;
		vec[3 - srcPosition].len = 4;
		vec[4].buffer = &(ipv4Layer->getIPv4Header()->protocol);
		vec[4].len = 1;
	}
	else // IPv6
	{
		const IPv6Layer* ipv6Layer = static_cast<const IPv6Layer*>(networkLayer);

		if (portSrc == portDst && (uint64_t)ipv6Layer->getIPv6Header()->ipDst < (uint64_t)ipv6Layer->getIPv6Header()->ipSrc)
			srcPosition = 1;

		vec[2 + srcPosition].buffer = ipv6Layer->getIPv6Header()->ipSrc;
		vec[2 + srcPosition].len = 16;
		vec[3 - srcPosition].buffer = ipv6Layer->getIPv6Header()->ipDst;
		vec[3 - srcPosition].len = 16;
		vec[4].buffer = &(ipv6Layer->getIPv6Header()->nextHeader);
		vec[4].len = 1;
	}

	return pcpp::fnv_hash(vec, 5);
} // hash5Tuple without the checks


uint32_t hash5Tuple(const Packet* packet)
{
	if (packet->isPacketOfType(ICMP)) // refer to issue #124
		return 0;

	const Layer* networkLayer;

	if (packet->isPacketOfType(IPv4))
		networkLayer = packet->getLayerOfType<IPv4Layer>();
	else if (packet->isPacketOfType(IPv6))
		networkLayer = packet->getLayerOfType<IPv6Layer>();
	else
		return 0;

	const Layer* transportLayer;

	if (packet->isPacketOfType(TCP))
		transportLayer = packet->getLayerOfType<TcpLayer>();
	else if (packet->isPacketOfType(UDP))
		transportLayer = packet->getLayerOfType<UdpLayer>();
	else
		return 0;

	return hash5Tuple(packet, networkLayer, transportLayer);
} // hash5Tuple


uint32_t hash2Tuple(const Packet* packet)
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

	return pcpp::fnv_hash(vec, 2);
}

}  // namespace pcpp
