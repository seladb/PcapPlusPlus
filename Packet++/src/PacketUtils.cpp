#include <string.h>
#include "PacketUtils.h"
#include "IpUtils.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include "IcmpLayer.h"

namespace pcpp
{

uint32_t hash5Tuple(Packet* packet)
{
	if (!packet->isPacketOfType(IPv4) && !packet->isPacketOfType(IPv6))
		return 0;

	if (!(packet->isPacketOfType(TCP)) && (!packet->isPacketOfType(UDP)) && (!packet->isPacketOfType(ICMP)))
		return 0;

	ScalarBuffer<uint8_t> vec[5];

	uint16_t portSrc = 0;
	uint16_t portDst = 0;
	int srcPosition = 0;

	TcpLayer* tcpLayer = packet->getLayerOfType<TcpLayer>(true); // lookup in reverse order
	UdpLayer* udpLayer = packet->getLayerOfType<UdpLayer>(true);
	if (tcpLayer != NULL)
	{
		portSrc = tcpLayer->getTcpHeader()->portSrc;
		portDst = tcpLayer->getTcpHeader()->portDst;
	}
	else if(udpLayer != NULL)
	{
		portSrc = udpLayer->getUdpHeader()->portSrc;
		portDst = udpLayer->getUdpHeader()->portDst;
	}
	else
	{
		IcmpLayer* icmpLayer = packet->getLayerOfType<IcmpLayer>(true);
		IcmpMessageType type = icmpLayer->getMessageType();
		if(type == ICMP_INFO_REQUEST)
		{
			portSrc = ICMP_INFO_REQUEST + ICMP_INFO_REPLY;
			icmp_info_request* infoRequest(icmpLayer->getInfoRequestData());
			if(infoRequest)
				portDst = infoRequest->id;
			else
				return 0;
		}
		else if(type == ICMP_INFO_REPLY)
		{
			portSrc = ICMP_INFO_REQUEST + ICMP_INFO_REPLY;
			icmp_info_reply* infoReply(icmpLayer->getInfoReplyData());
			if(infoReply)
				portDst = infoReply->id;
			else
				return 0;
		}
		else if(type == ICMP_ECHO_REPLY)
		{
			portSrc = ICMP_ECHO_REPLY + ICMP_ECHO_REQUEST;
			icmp_echo_reply* echoReply(icmpLayer->getEchoReplyData());
			if(echoReply && echoReply->header)
				portDst = echoReply->header->id;
			else
				return 0;
		}
		else if(type == ICMP_ECHO_REQUEST)
		{
			portSrc = ICMP_ECHO_REPLY + ICMP_ECHO_REQUEST;
			icmp_echo_request* echoRequest(icmpLayer->getEchoRequestData());
			if(echoRequest && echoRequest->header)
				portDst = echoRequest->header->id;
			else
				return 0;
		}
		else if(type == ICMP_TIMESTAMP_REQUEST)
		{
			portSrc = ICMP_TIMESTAMP_REQUEST + ICMP_TIMESTAMP_REPLY;
			icmp_timestamp_request* timestampRequest(icmpLayer->getTimestampRequestData());
			if(timestampRequest)
				portDst = timestampRequest->id;
			else
				return 0;
		}
		else if(type == ICMP_TIMESTAMP_REPLY)
		{
			portSrc = ICMP_TIMESTAMP_REQUEST + ICMP_TIMESTAMP_REPLY;
			icmp_timestamp_reply* timestampReply(icmpLayer->getTimestampReplyData());
			if(timestampReply)
				portDst = timestampReply->id;
			else
				return 0;
		}
		else if(type == ICMP_ADDRESS_MASK_REQUEST)
		{
			portSrc = ICMP_ADDRESS_MASK_REQUEST + ICMP_ADDRESS_MASK_REPLY;
			icmp_address_mask_request* addressMaskRequest(icmpLayer->getAddressMaskRequestData());
			if(addressMaskRequest)
				portDst = addressMaskRequest->id;
			else
				return 0;
		}
		else if(type == ICMP_ADDRESS_MASK_REPLY)
		{
			portSrc = ICMP_ADDRESS_MASK_REQUEST + ICMP_ADDRESS_MASK_REPLY;
			icmp_address_mask_reply* addressMaskReply(icmpLayer->getAddressMaskReplyData());
			if(addressMaskReply)
				portDst = addressMaskReply->id;
			else
				return 0;
		}
		else
		{
			return 0;
		}
	}

	if (portDst < portSrc)
		srcPosition = 1;

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

	return pcpp::fnv_hash(vec, 5);
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

	return pcpp::fnv_hash(vec, 2);
}

}  // namespace pcpp
