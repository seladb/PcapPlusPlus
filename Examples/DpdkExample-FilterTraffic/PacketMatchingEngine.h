#pragma once

#include "Packet.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include <in.h>

/**
 * Responsible for matching packets by match criteria received from the user. Current match criteria are a combination of zero or more of the
 * following parameters: source IP, dest IP, source TCP/UDP port, dest TCP/UDP port and TCP/UDP protocol.
 */
class PacketMatchingEngine
{
private:
	pcpp::IPv4Address m_SrcIpToMatch, m_DstIpToMatch;
	uint16_t m_SrcPortToMatch, m_DstPortToMatch;
	pcpp::ProtocolType m_ProtocolToMatch;
	bool m_MatchSrcIp, m_MatchDstIp;
	bool m_MatchSrcPort, m_MatchDstPort;
	bool m_MatchProtocol;
public:
	PacketMatchingEngine(const pcpp::IPv4Address& srcIpToMatch, const pcpp::IPv4Address& dstIpToMatch, uint16_t srcPortToMatch, uint16_t dstPortToMatch, pcpp::ProtocolType protocolToMatch)
		: m_SrcIpToMatch(srcIpToMatch), m_DstIpToMatch(dstIpToMatch),
		  m_SrcPortToMatch(srcPortToMatch), m_DstPortToMatch(dstPortToMatch), m_ProtocolToMatch(protocolToMatch),
		  m_MatchSrcIp(false), m_MatchDstIp(false), m_MatchSrcPort(false), m_MatchDstPort(false), m_MatchProtocol(false)
	{
		if (m_SrcIpToMatch != pcpp::IPv4Address::Zero)
			m_MatchSrcIp = true;
		if (m_DstIpToMatch != pcpp::IPv4Address::Zero)
			m_MatchDstIp = true;
		if (m_SrcPortToMatch != 0)
			m_MatchSrcPort = true;
		if (m_DstPortToMatch != 0)
			m_MatchDstPort = true;
		if (m_ProtocolToMatch == pcpp::TCP || m_ProtocolToMatch == pcpp::UDP)
			m_MatchProtocol = true;
	}

	bool isMatched(pcpp::Packet& packet)
	{
		if (m_MatchSrcIp || m_MatchDstIp)
		{
			if (!packet.isPacketOfType(pcpp::IPv4))
			{
				return false;
			}

			pcpp::IPv4Layer* ip4Layer = packet.getLayerOfType<pcpp::IPv4Layer>();
			if (m_MatchSrcIp && (ip4Layer->getSrcIpAddress() != m_SrcIpToMatch))
			{
				return false;
			}

			if (m_MatchDstIp && (ip4Layer->getDstIpAddress() != m_DstIpToMatch))
			{
				return false;
			}
		}

		if (m_MatchSrcPort || m_MatchDstPort)
		{
			uint16_t srcPort, dstPort;
			if (packet.isPacketOfType(pcpp::TCP))
			{
				srcPort = ntohs(packet.getLayerOfType<pcpp::TcpLayer>()->getTcpHeader()->portSrc);
				dstPort = ntohs(packet.getLayerOfType<pcpp::TcpLayer>()->getTcpHeader()->portDst);
			}
			else if (packet.isPacketOfType(pcpp::UDP))
			{
				srcPort = ntohs(packet.getLayerOfType<pcpp::UdpLayer>()->getUdpHeader()->portSrc);
				dstPort = ntohs(packet.getLayerOfType<pcpp::UdpLayer>()->getUdpHeader()->portDst);
			}
			else
			{
				return false;
			}

			if (m_MatchSrcPort && (srcPort != m_SrcPortToMatch))
			{
				return false;
			}

			if (m_MatchDstPort && (dstPort != m_DstPortToMatch))
			{
				return false;
			}
		}

		if (m_MatchProtocol)
		{
			if (m_ProtocolToMatch == pcpp::TCP && (!packet.isPacketOfType(pcpp::TCP)))
			{
				return false;
			}

			if (m_ProtocolToMatch == pcpp::UDP && (!packet.isPacketOfType(pcpp::UDP)))
			{
				return false;
			}
		}

		return true;
	}
};
