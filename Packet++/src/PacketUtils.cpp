#include "PacketUtils.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"

namespace pcpp
{

uint32_t hash5Tuple(Packet* packet)
{
	if (!packet->isPacketOfType(IPv4))
		return 0;

	if (!(packet->isPacketOfType(TCP)) && (!packet->isPacketOfType(UDP)))
		return 0;

	IPv4Layer* ipv4Layer = packet->getLayerOfType<IPv4Layer>();
	uint16_t portSrc = 0;
	uint16_t portDst = 0;

	TcpLayer* tcpLayer = packet->getLayerOfType<TcpLayer>();
	if (tcpLayer != NULL)
	{
		portSrc = tcpLayer->getTcpHeader()->portSrc;
		portDst = tcpLayer->getTcpHeader()->portDst;
	}
	else
	{
		UdpLayer* udpLayer = packet->getLayerOfType<UdpLayer>();
		portSrc = udpLayer->getUdpHeader()->portSrc;
		portDst = udpLayer->getUdpHeader()->portDst;
	}

	uint32_t ipSrcAsInt = ipv4Layer->getSrcIpAddress().toInt();
	uint32_t ipDstAsInt = ipv4Layer->getDstIpAddress().toInt();
	return ((ipSrcAsInt ^ portSrc) ^ (ipDstAsInt ^ portDst)) | ipv4Layer->getIPv4Header()->protocol;
}


uint32_t hash2Tuple(Packet* packet)
{
	if (!packet->isPacketOfType(IPv4))
		return 0;

	IPv4Layer* ipv4Layer = packet->getLayerOfType<IPv4Layer>();

	uint32_t ipSrcAsInt = ipv4Layer->getSrcIpAddress().toInt();
	uint32_t ipDstAsInt = ipv4Layer->getDstIpAddress().toInt();

	return (ipSrcAsInt ^ ipDstAsInt);
}

}  // namespace pcpp
