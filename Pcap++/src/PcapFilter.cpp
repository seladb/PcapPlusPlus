#define LOG_MODULE PcapLogModuleLiveDevice

#include "PcapFilter.h"
#include "Logger.h"
#include "IPv4Layer.h"
#include "PcapUtils.h"
#include <sstream>
#include <array>
#if defined(_WIN32)
#	include <winsock2.h>
#endif
#include "pcap.h"
#include "RawPacket.h"
#include "TimespecTimeval.h"

namespace pcpp
{

	static const int DEFAULT_SNAPLEN = 9000;

	bool GeneralFilter::matchPacketWithFilter(RawPacket* rawPacket)
	{
		std::string filterStr;
		parseToString(filterStr);

		if (!m_BpfWrapper.setFilter(filterStr))
			return false;

		return m_BpfWrapper.matchPacketWithFilter(rawPacket);
	}

	namespace internal
	{
		void BpfProgramDeleter::operator()(bpf_program* ptr) const noexcept
		{
			pcap_freecode(ptr);
			delete ptr;
		}
	}  // namespace internal

	BpfFilterWrapper::BpfFilterWrapper() : m_LinkType(LinkLayerType::LINKTYPE_ETHERNET)
	{}

	BpfFilterWrapper::BpfFilterWrapper(const BpfFilterWrapper& other) : BpfFilterWrapper()
	{
		setFilter(other.m_FilterStr, other.m_LinkType);
	}

	BpfFilterWrapper& BpfFilterWrapper::operator=(const BpfFilterWrapper& other)
	{
		setFilter(other.m_FilterStr, other.m_LinkType);
		return *this;
	}

	bool BpfFilterWrapper::setFilter(const std::string& filter, LinkLayerType linkType)
	{
		if (filter.empty())
		{
			freeProgram();
			return true;
		}

		if (filter != m_FilterStr || linkType != m_LinkType)
		{
			auto pcap = std::unique_ptr<pcap_t, internal::PcapCloseDeleter>(pcap_open_dead(linkType, DEFAULT_SNAPLEN));
			if (pcap == nullptr)
			{
				return false;
			}

			auto newProg = std::make_unique<bpf_program>();
			int ret = pcap_compile(pcap.get(), newProg.get(), filter.c_str(), 1, 0);
			if (ret < 0)
			{
				return false;
			}

			// Reassigns ownership of the bpf program to a new unique_ptr with a custom deleter as it now requires
			// specialized cleanup.
			m_Program = std::unique_ptr<bpf_program, internal::BpfProgramDeleter>(newProg.release());
			m_FilterStr = filter;
			m_LinkType = linkType;
		}

		return true;
	}

	void BpfFilterWrapper::freeProgram()
	{
		m_Program = nullptr;
		m_FilterStr.clear();
	}

	bool BpfFilterWrapper::matchPacketWithFilter(const RawPacket* rawPacket)
	{
		return matchPacketWithFilter(rawPacket->getRawData(), rawPacket->getRawDataLen(),
		                             rawPacket->getPacketTimeStamp(), rawPacket->getLinkLayerType());
	}

	bool BpfFilterWrapper::matchPacketWithFilter(const uint8_t* packetData, uint32_t packetDataLength,
	                                             timespec packetTimestamp, uint16_t linkType)
	{
		if (m_FilterStr.empty())
			return true;

		if (!setFilter(std::string(m_FilterStr), static_cast<LinkLayerType>(linkType)))
		{
			return false;
		}

		struct pcap_pkthdr pktHdr;
		pktHdr.caplen = packetDataLength;
		pktHdr.len = packetDataLength;
		pktHdr.ts = internal::toTimeval(packetTimestamp);

		return (pcap_offline_filter(m_Program.get(), &pktHdr, packetData) != 0);
	}

	void BPFStringFilter::parseToString(std::string& result)
	{
		result = m_FilterStr;
	}

	bool BPFStringFilter::verifyFilter()
	{
		return m_BpfWrapper.setFilter(m_FilterStr);
	}

	void IFilterWithDirection::parseDirection(std::string& directionAsString)
	{
		switch (m_Dir)
		{
		case SRC:
			directionAsString = "src";
			break;
		case DST:
			directionAsString = "dst";
			break;
		default:  // SRC_OR_DST:
			directionAsString = "src or dst";
			break;
		}
	}

	std::string IFilterWithOperator::parseOperator()
	{
		switch (m_Operator)
		{
		case EQUALS:
			return "=";
		case NOT_EQUALS:
			return "!=";
		case GREATER_THAN:
			return ">";
		case GREATER_OR_EQUAL:
			return ">=";
		case LESS_THAN:
			return "<";
		case LESS_OR_EQUAL:
			return "<=";
		default:
			return "";
		}
	}

	void IPFilter::parseToString(std::string& result)
	{
		std::string dir;
		std::string ipAddr = m_Network.toString();
		std::string ipProto = m_Network.isIPv6Network() ? "ip6" : "ip";

		parseDirection(dir);

		result.reserve(ipProto.size() + dir.size() + ipAddr.size() + 10 /* Hard-coded strings */);
		result = ipProto;
		result += " and ";
		result += dir;
		result += " net ";
		result += ipAddr;
	}

	void IPv4IDFilter::parseToString(std::string& result)
	{
		std::string op = parseOperator();
		std::ostringstream stream;
		stream << m_IpID;
		result = "ip[4:2] " + op + ' ' + stream.str();
	}

	void IPv4TotalLengthFilter::parseToString(std::string& result)
	{
		std::string op = parseOperator();
		std::ostringstream stream;
		stream << m_TotalLength;
		result = "ip[2:2] " + op + ' ' + stream.str();
	}

	void PortFilter::portToString(uint16_t portAsInt)
	{
		std::ostringstream stream;
		stream << portAsInt;
		m_Port = stream.str();
	}

	PortFilter::PortFilter(uint16_t port, Direction dir) : IFilterWithDirection(dir)
	{
		portToString(port);
	}

	void PortFilter::parseToString(std::string& result)
	{
		std::string dir;
		parseDirection(dir);
		result = dir + " port " + m_Port;
	}

	void PortRangeFilter::parseToString(std::string& result)
	{
		std::string dir;
		parseDirection(dir);

		std::ostringstream fromPortStream;
		fromPortStream << static_cast<int>(m_FromPort);
		std::ostringstream toPortStream;
		toPortStream << static_cast<int>(m_ToPort);

		result = dir + " portrange " + fromPortStream.str() + '-' + toPortStream.str();
	}

	void MacAddressFilter::parseToString(std::string& result)
	{
		if (getDir() != SRC_OR_DST)
		{
			std::string dir;
			parseDirection(dir);
			result = "ether " + dir + ' ' + m_MacAddress.toString();
		}
		else
			result = "ether host " + m_MacAddress.toString();
	}

	void EtherTypeFilter::parseToString(std::string& result)
	{
		std::ostringstream stream;
		stream << "0x" << std::hex << m_EtherType;
		result = "ether proto " + stream.str();
	}

	CompositeFilter::CompositeFilter(const std::vector<GeneralFilter*>& filters) : m_FilterList(filters)
	{}

	void CompositeFilter::removeFilter(GeneralFilter* filter)
	{
		for (auto it = m_FilterList.cbegin(); it != m_FilterList.cend(); ++it)
		{
			if (*it == filter)
			{
				m_FilterList.erase(it);
				break;
			}
		}
	}

	void CompositeFilter::setFilters(const std::vector<GeneralFilter*>& filters)
	{
		m_FilterList = filters;
	}

	void NotFilter::parseToString(std::string& result)
	{
		std::string innerFilterAsString;
		m_FilterToInverse->parseToString(innerFilterAsString);
		result = "not (" + innerFilterAsString + ')';
	}

	void ProtoFilter::parseToString(std::string& result)
	{
		std::ostringstream stream;

		switch (m_ProtoFamily)
		{
		case TCP:
			result = "tcp";
			break;
		case UDP:
			result = "udp";
			break;
		case ICMP:
			result = "icmp";
			break;
		case VLAN:
			result = "vlan";
			break;
		case IPv4:
			result = "ip";
			break;
		case IPv6:
			result = "ip6";
			break;
		case ARP:
			result = "arp";
			break;
		case Ethernet:
			result = "ether";
			break;
		case GRE:
			stream << "proto " << PACKETPP_IPPROTO_GRE;
			result = stream.str();
			break;
		case IGMP:
			stream << "proto " << PACKETPP_IPPROTO_IGMP;
			result = stream.str();
			break;
		default:
			break;
		}
	}

	void ArpFilter::parseToString(std::string& result)
	{
		std::ostringstream sstream;
		sstream << "arp[7] = " << m_OpCode;
		result += sstream.str();
	}

	void VlanFilter::parseToString(std::string& result)
	{
		std::ostringstream stream;
		stream << m_VlanID;
		result = "vlan " + stream.str();
	}

	void TcpFlagsFilter::parseToString(std::string& result)
	{
		if (m_TcpFlagsBitMask == 0)
		{
			result.clear();
			return;
		}

		result = "tcp[tcpflags] & (";
		if ((m_TcpFlagsBitMask & tcpFin) != 0)
			result += "tcp-fin|";
		if ((m_TcpFlagsBitMask & tcpSyn) != 0)
			result += "tcp-syn|";
		if ((m_TcpFlagsBitMask & tcpRst) != 0)
			result += "tcp-rst|";
		if ((m_TcpFlagsBitMask & tcpPush) != 0)
			result += "tcp-push|";
		if ((m_TcpFlagsBitMask & tcpAck) != 0)
			result += "tcp-ack|";
		if ((m_TcpFlagsBitMask & tcpUrg) != 0)
			result += "tcp-urg|";

		// replace the last '|' character
		result[result.size() - 1] = ')';

		if (m_MatchOption == MatchOneAtLeast)
			result += " != 0";
		else  // m_MatchOption == MatchAll
		{
			std::ostringstream stream;
			stream << static_cast<int>(m_TcpFlagsBitMask);
			result += " = " + stream.str();
		}
	}

	void TcpWindowSizeFilter::parseToString(std::string& result)
	{
		std::ostringstream stream;
		stream << m_WindowSize;
		result = "tcp[14:2] " + parseOperator() + ' ' + stream.str();
	}

	void UdpLengthFilter::parseToString(std::string& result)
	{
		std::ostringstream stream;
		stream << m_Length;
		result = "udp[4:2] " + parseOperator() + ' ' + stream.str();
	}

}  // namespace pcpp
