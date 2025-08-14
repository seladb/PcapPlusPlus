#define LOG_MODULE PacketLogModuleUdpLayer

#include "EndianPortable.h"
#include "UdpLayer.h"
#include "PayloadLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "DnsLayer.h"
#include "DhcpLayer.h"
#include "DhcpV6Layer.h"
#include "DoIpLayer.h"
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

	void UdpLayer::parseNextLayer(ParserConfiguration const& config)
	{
		if (m_DataLen <= sizeof(udphdr))
			return;

		uint16_t portDst = getDstPort();
		uint16_t portSrc = getSrcPort();

		uint8_t* udpData = m_Data + sizeof(udphdr);
		size_t udpDataLen = m_DataLen - sizeof(udphdr);

		// Queries the port mapper for protocol mappings based on the source and destination ports
		// The returned array protocol family for exact match, source only match, destination only match.
		// The first protocol family that passes secondary validation (if any) will be used to construct the next layer.
		auto const portMatrix = config.portMapper.getMatchMatrix(portSrc, portDst);

		for (auto protoFamily : portMatrix)
		{
			// If the protocol family is UnknownProtocol, skip all other checks
			if (protoFamily == UnknownProtocol)
				continue;

			switch (protoFamily)
			{
			case DHCP:
			{
				constructNextLayer<DhcpLayer>(udpData, udpDataLen, m_Packet);
				break;
			}
			case VXLAN:
			{
				constructNextLayer<VxlanLayer>(udpData, udpDataLen, m_Packet);
				break;
			}
			case DNS:
			{
				if (DnsLayer::isDataValid(udpData, udpDataLen))
				{
					constructNextLayer<DnsLayer>(udpData, udpDataLen, m_Packet);
				}
				break;
			}
			case SIPRequest:
			case SIPResponse:
			case SIP:
			{
				if (SipRequestFirstLine::parseMethod((char*)udpData, udpDataLen) != SipRequestLayer::SipMethodUnknown)
				{
					constructNextLayer<SipRequestLayer>(udpData, udpDataLen, m_Packet);
				}
				else if (SipResponseFirstLine::parseStatusCode((char*)udpData, udpDataLen) !=
				             SipResponseLayer::SipStatusCodeUnknown &&
				         SipResponseFirstLine::parseVersion((char*)udpData, udpDataLen) != "")
				{
					constructNextLayer<SipResponseLayer>(udpData, udpDataLen, m_Packet);
				}
				else
				{
					// todo: If the data is not a valid SIP request or response, should be instead try to continue
					// matching?
					constructNextLayer<PayloadLayer>(udpData, udpDataLen, m_Packet);
				}
				break;
			}
			case Radius:
			{
				if (RadiusLayer::isDataValid(udpData, udpDataLen))
				{
					constructNextLayer<RadiusLayer>(udpData, udpDataLen, m_Packet);
				}
				break;
			}
			case GTPv1:
			case GTPv2:
			case GTP:
			{
				// GTP can be either v1 or v2
				if (GtpV1Layer::isGTPv1(udpData, udpDataLen))
				{
					constructNextLayer<GtpV1Layer>(udpData, udpDataLen, m_Packet);
				}
				else if (GtpV2Layer::isDataValid(udpData, udpDataLen))
				{
					constructNextLayer<GtpV2Layer>(udpData, udpDataLen, m_Packet);
				}
				break;
			}
			case DHCPv6:
			{
				if (DhcpV6Layer::isDataValid(udpData, udpDataLen))
				{
					constructNextLayer<DhcpV6Layer>(udpData, udpDataLen, m_Packet);
				}
				break;
			}
			case NTP:
			{
				if (NtpLayer::isDataValid(udpData, udpDataLen))
				{
					constructNextLayer<NtpLayer>(udpData, udpDataLen, m_Packet);
				}
				break;
			}
			case DOIP:
			{
				if (DoIpLayer::isDataValid(udpData, udpDataLen))
				{
					m_NextLayer = DoIpLayer::parseDoIpLayer(udpData, udpDataLen, this, m_Packet);
					if (!m_NextLayer)
						constructNextLayer<PayloadLayer>(udpData, udpDataLen, m_Packet);
                }
				break;
			}
			case SomeIP:
			{
				setNextLayer(SomeIpLayer::parseSomeIpLayer(udpData, udpDataLen, this, m_Packet));
				break;
			}
			case WakeOnLan:
			{
				if (WakeOnLanLayer::isDataValid(udpData, udpDataLen))
				{
					constructNextLayer<WakeOnLanLayer>(udpData, udpDataLen, m_Packet);
				}
				break;
			}
			case WireGuard:
			{
				if (WireGuardLayer::isDataValid(udpData, udpDataLen))
				{
					setNextLayer(WireGuardLayer::parseWireGuardLayer(udpData, udpDataLen, this, m_Packet));
					if (!m_NextLayer)
					{
						// If parsing failed, fallback to PayloadLayer
						// todo: Maybe continue matching partial matches instead?
						constructNextLayer<PayloadLayer>(udpData, udpDataLen, m_Packet);
					}
				}
				break;
			}
			}

			// If we already have a next layer, we don't need to parse further
			if (hasNextLayer())
				break;
		}

		if (!hasNextLayer())
		{
			// No specific layer matched, set as PayloadLayer
			constructNextLayer<PayloadLayer>(udpData, udpDataLen, m_Packet);
		}
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
