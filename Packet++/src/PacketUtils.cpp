#include "PacketUtils.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"

size_t hash5Tuple(Packet* packet)
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

	uint8_t* ipSrcAsByteArr = static_cast<uint8_t*>(static_cast<void*>(&ipv4Layer->getIPv4Header()->ipSrc));
	uint8_t* ipDstAsByteArr = static_cast<uint8_t*>(static_cast<void*>(&ipv4Layer->getIPv4Header()->ipDst));
	return(ipv4Layer->getIPv4Header()->protocol+
			ipSrcAsByteArr[0]+
			ipSrcAsByteArr[1]+
			ipSrcAsByteArr[2]+
			ipSrcAsByteArr[3]+
			ipDstAsByteArr[0]+
			ipDstAsByteArr[1]+
			ipDstAsByteArr[2]+
			ipDstAsByteArr[3]+
			portSrc+
			portDst);
}
