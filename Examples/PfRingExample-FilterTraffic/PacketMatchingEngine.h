#pragma once

#include "Packet.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"

/**
 * Responsible for matching packets by match criteria received from the user. Current match criteria are a combination
 * of zero or more of the following parameters: source IP, dest IP, source TCP/UDP port, dest TCP/UDP port and TCP/UDP
 * protocol.
 */
class PacketMatchingEngine
{
private:
	pcpp::IPv4Address m_SrcIpToMatch, m_DstIpToMatch;
	uint16_t m_SrcPortToMatch, m_DstPortToMatch;
	pcpp::ProtocolType m_ProtocolToMatch;
	bool m_MatchSrcIp{ false }, m_MatchDstIp{ false };
	bool m_MatchSrcPort{ false }, m_MatchDstPort{ false };
	bool m_MatchProtocol{ false };

public:
	PacketMatchingEngine(const pcpp::IPv4Address& srcIpToMatch, const pcpp::IPv4Address& dstIpToMatch,
	                     uint16_t srcPortToMatch, uint16_t dstPortToMatch, pcpp::ProtocolType protocolToMatch)
	    : m_SrcIpToMatch(srcIpToMatch), m_DstIpToMatch(dstIpToMatch), m_SrcPortToMatch(srcPortToMatch),
	      m_DstPortToMatch(dstPortToMatch), m_ProtocolToMatch(protocolToMatch)
	{
		if (m_SrcIpToMatch != pcpp::IPv4Address::Zero)
		{
			m_MatchSrcIp = true;
		}
		if (m_DstIpToMatch != pcpp::IPv4Address::Zero)
		{
			m_MatchDstIp = true;
		}
		if (m_SrcPortToMatch != 0)
		{
			m_MatchSrcPort = true;
		}
		if (m_DstPortToMatch != 0)
		{
			m_MatchDstPort = true;
		}
		if (m_ProtocolToMatch == pcpp::TCP || m_ProtocolToMatch == pcpp::UDP)
		{
			m_MatchProtocol = true;
		}
	}

	bool isMatched(pcpp::Packet& packet)
	{
		if (m_MatchSrcIp || m_MatchDstIp)
		{
			if (!packet.isPacketOfType(pcpp::IPv4))
			{
				return false;
			}

			auto* ip4Layer = packet.getLayerOfType<pcpp::IPv4Layer>();
			if (m_MatchSrcIp && (ip4Layer->getSrcIPv4Address() != m_SrcIpToMatch))
			{
				return false;
			}

			if (m_MatchDstIp && (ip4Layer->getDstIPv4Address() != m_DstIpToMatch))
			{
				return false;
			}
		}

		if (m_MatchSrcPort || m_MatchDstPort)
		{
			uint16_t srcPort = 0;
			uint16_t dstPort = 0;
			if (packet.isPacketOfType(pcpp::TCP))
			{
				srcPort = packet.getLayerOfType<pcpp::TcpLayer>()->getSrcPort();
				dstPort = packet.getLayerOfType<pcpp::TcpLayer>()->getDstPort();
			}
			else if (packet.isPacketOfType(pcpp::UDP))
			{
				srcPort = packet.getLayerOfType<pcpp::UdpLayer>()->getSrcPort();
				dstPort = packet.getLayerOfType<pcpp::UdpLayer>()->getDstPort();
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
