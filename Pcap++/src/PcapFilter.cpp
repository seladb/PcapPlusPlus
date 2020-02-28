#define LOG_MODULE PcapLogModuleLiveDevice

#include "PcapFilter.h"
#include "Logger.h"
#include "IPv4Layer.h"
#include <sstream>
#if defined(WIN32) || defined(WINx64) //for using ntohl, ntohs, etc.
#include <winsock2.h>
#elif LINUX
#include <in.h>
#endif
#include <pcap.h>
#include "RawPacket.h"
#include "TimespecTimeval.h"

namespace pcpp
{

bool GeneralFilter::matchPacketWithFilter(RawPacket* rawPacket)
{
	std::string filterStr;
	parseToString(filterStr);

	if (m_program == NULL || m_lastProgramString != filterStr)
	{
		freeProgram();

		m_program = new bpf_program();

		LOG_DEBUG("Compiling the filter '%s'", filterStr.c_str());
		if (pcap_compile_nopcap(9000, pcpp::LINKTYPE_ETHERNET, m_program, filterStr.c_str(), 1, 0) < 0)
		{
			//Filter not valid so delete member
			freeProgram();
			return false;
		}
		m_lastProgramString = filterStr;
	}

	struct pcap_pkthdr pktHdr;
	pktHdr.caplen = rawPacket->getRawDataLen();
	pktHdr.len = rawPacket->getRawDataLen();
	timespec ts = rawPacket->getPacketTimeStamp();
	TIMESPEC_TO_TIMEVAL(&pktHdr.ts, &ts);

	return (pcap_offline_filter(m_program, &pktHdr, rawPacket->getRawData()) != 0);
}

void GeneralFilter::freeProgram()
{
	if (m_program)
	{
		pcap_freecode(m_program);
		delete m_program;
		m_program = NULL;
		m_lastProgramString.clear();
	}
}


void BPFStringFilter::parseToString(std::string& result)
{
	if (verifyFilter())
		result = m_filterStr;
	else
		result.clear();
}

bool BPFStringFilter::verifyFilter()
{
	//If filter has been built before it must be valid
	if (m_program)
		return true;

	m_program = new bpf_program();
	LOG_DEBUG("Compiling the filter '%s'", m_filterStr.c_str());
	if (pcap_compile_nopcap(9000, pcpp::LINKTYPE_ETHERNET, m_program, m_filterStr.c_str(), 1, 0) < 0)
	{
		//Filter not valid so delete member
		freeProgram();
		return false;
	}
	m_lastProgramString = m_filterStr;

	return true;
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
	default: //SRC_OR_DST:
		directionAsString = "src or dst";
		break;
	}
}

std::string IFilterWithOperator::parseOperator()
{
	switch(m_Operator)
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

void IPFilter::convertToIPAddressWithMask(std::string& ipAddrmodified, std::string& mask) const
{
	if (m_IPv4Mask.empty())
		return;

	// Handle the mask

	// The following code lines verify both ipAddress and ipv4Mask are valid IPv4 addresses
	// The IPv4 limitation comes from the fact libPcap/WinPcap/Npcap doesn't support mask for IPv6 addresses

	IPv4Address ipAddr(m_Address);
	if (!ipAddr.isValid())
	{
		LOG_ERROR("IP filter with mask must be used with IPv4 valid address. Setting the mask to an empty value");
		mask.clear();
		return;
	}

	IPv4Address maskAsAddr(m_IPv4Mask);
	if (!maskAsAddr.isValid())
	{
		LOG_ERROR("Invalid IPv4 mask. Setting the mask to an empty");
		mask.clear();
		return;
	}

	// If all addresses are IPv4 valid addresses, make sure ipAddress matches the mask. If it's not, mask the address with the mask
	// The reason for doing that is libPcap/WinPcap/Npcap doesn't allow filtering an IP address that doesn't match the mask

	uint32_t addrAsIntAfterMask = ipAddr.toInt() & maskAsAddr.toInt();
	ipAddrmodified = IPv4Address(addrAsIntAfterMask).toString();
}

void IPFilter::convertToIPAddressWithLen(std::string& ipAddrmodified, int& len) const
{
	if (m_Len == 0)
		return;

	// Handle the length

	// The following code lines verify IP address is valid (IPv4 or IPv6)

	IPAddress::Ptr_t ipAddr = IPAddress::fromString(ipAddrmodified);
	if (ipAddr.get()->getType() == IPAddress::IPv4AddressType)
	{
		IPv4Address* ip4Addr = (IPv4Address*)ipAddr.get();
		uint32_t addrAsInt = ip4Addr->toInt();
		uint32_t mask = ((uint32_t) - 1) >> ((sizeof(uint32_t) * 8) - m_Len);
		addrAsInt &= mask;
		ipAddrmodified = IPv4Address(addrAsInt).toString();
	}
	else if (ipAddr.get()->getType() == IPAddress::IPv6AddressType)
	{
		IPv6Address* ip6Addr = (IPv6Address*)ipAddr.get();
		uint8_t* addrAsArr; size_t addrLen;
		ip6Addr->copyTo(&addrAsArr, addrLen);
		uint64_t addrLowerBytes = (long)addrAsArr;
		uint64_t addrHigherBytes = (long)(addrAsArr + 8);
		if (len > (int)(sizeof(uint64_t) * 8))
		{
			addrLowerBytes = 0;
			addrHigherBytes &= (-1 << (len - sizeof(uint64_t)));
		}
		else
		{
			addrLowerBytes &= (-1 << len);
		}

		ipAddrmodified = IPv6Address(addrAsArr).toString();
		delete [] addrAsArr;
	}
	else
	{
		LOG_ERROR("Invalid IP address '%s', setting len to zero", ipAddrmodified.c_str());
		len = 0;
	}
}

void IPFilter::parseToString(std::string& result)
{
	std::string dir;
	std::string ipAddr = m_Address;
	std::string mask = m_IPv4Mask;
	int len = m_Len;
	convertToIPAddressWithMask(ipAddr, mask);
	convertToIPAddressWithLen(ipAddr, len);
	parseDirection(dir);
	result = "ip and " + dir + " net " + ipAddr;
	if (m_IPv4Mask != "")
		result += " mask " + mask;
	else if (m_Len > 0)
	{
		std::ostringstream stream;
		stream << m_Len;
		result += '/' + stream.str();
	}
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
	fromPortStream << (int)m_FromPort;
	std::ostringstream toPortStream;
	toPortStream << (int)m_ToPort;

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

AndFilter::AndFilter(std::vector<GeneralFilter*>& filters)
{
	for(std::vector<GeneralFilter*>::iterator it = filters.begin(); it != filters.end(); ++it)
	{
		m_FilterList.push_back(*it);
	}
}

void AndFilter::setFilters(std::vector<GeneralFilter*>& filters)
{
	m_FilterList.clear();

	for(std::vector<GeneralFilter*>::iterator it = filters.begin(); it != filters.end(); ++it)
	{
		m_FilterList.push_back(*it);
	}
}

void AndFilter::parseToString(std::string& result)
{
	result.clear();
	for(std::vector<GeneralFilter*>::iterator it = m_FilterList.begin(); it != m_FilterList.end(); ++it)
	{
		std::string innerFilter;
		(*it)->parseToString(innerFilter);
		result += '(' + innerFilter + ')';
		if (m_FilterList.back() != *it)
		{
			result += " and ";
		}
	}
}

OrFilter::OrFilter(std::vector<GeneralFilter*>& filters)
{
	for(std::vector<GeneralFilter*>::iterator it = filters.begin(); it != filters.end(); ++it)
	{
		m_FilterList.push_back(*it);
	}
}

void OrFilter::parseToString(std::string& result)
{
	result.clear();
	for(std::vector<GeneralFilter*>::iterator it = m_FilterList.begin(); it != m_FilterList.end(); ++it)
	{
		std::string innerFilter;
		(*it)->parseToString(innerFilter);
		result += '(' + innerFilter + ')';
		if (m_FilterList.back() != *it)
		{
			result += " or ";
		}
	}
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

	switch (m_Proto)
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
	else //m_MatchOption == MatchAll
	{
		std::ostringstream stream;
		stream << (int)m_TcpFlagsBitMask;
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

} // namespace pcpp
