#define LOG_MODULE PcapLogModuleLiveDevice

#include "PcapFilter.h"
#include "Logger.h"
#include <sstream>
#if defined(WIN32) || defined(WINx64) //for using ntohl, ntohs, etc.
#include <winsock2.h>
#elif LINUX
#include <in.h>
#endif

namespace pcpp
{

GeneralFilter::~GeneralFilter()
{
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

void IPFilter::convertToIPAddressWithMask(std::string& ipAddrmodified, std::string& mask)
{
	if (m_IPv4Mask == "")

		return;

	// Handle the mask

	// The following code lines verify both ipAddress and ipv4Mask are valid IPv4 addresses
	// The IPv4 limitation comes from the fact libPcap/WinPcap doesn't support mask for IPv6 addresses

	IPv4Address ipAddr(m_Address);
	if (!ipAddr.isValid())
	{
		LOG_ERROR("IP filter with mask must be used with IPv4 valid address. Setting the mask to an empty value");
		mask = "";
		return;
	}

	IPv4Address maskAsAddr(m_IPv4Mask);
	if (!maskAsAddr.isValid())
	{
		LOG_ERROR("Invalid IPv4 mask. Setting the mask to an empty");
		mask = "";
		return;
	}

	// If all addresses are IPv4 valid addresses, make sure ipAddress matches the mask. If it's not, mask the address with the mask
	// The reason for doing that is libPcap/WinPcap doesn't allow filtering an IP address that doesn't match the mask

	uint32_t addrAsIntAfterMask = ipAddr.toInt() & maskAsAddr.toInt();
	ipAddrmodified = IPv4Address(addrAsIntAfterMask).toString();
}

void IPFilter::convertToIPAddressWithLen(std::string& ipAddrmodified, int& len)
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
		uint32_t mask = ((uint32_t)-1) >> ((sizeof(uint32_t)*8)-m_Len);
		addrAsInt &= mask;
		ipAddrmodified = IPv4Address(addrAsInt).toString();
	}
	else if (ipAddr.get()->getType() == IPAddress::IPv6AddressType)
	{
		IPv6Address* ip6Addr = (IPv6Address*)ipAddr.get();
		uint8_t* addrAsArr; size_t addrLen;
		ip6Addr->copyTo(&addrAsArr, addrLen);
		uint64_t addrLowerBytes = (long)addrAsArr;
		uint64_t addrHigherBytes = (long)(addrAsArr+8);
		if (len > (int)(sizeof(uint64_t)*8))
		{
			addrLowerBytes = 0;
			addrHigherBytes &= (-1 << (len-sizeof(uint64_t)));
		}
		else
		{
			addrLowerBytes &= (-1 << len);
		}

		ipAddrmodified = IPv6Address(addrAsArr).toString();
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
		result += "/" + stream.str();
	}
}

void IpV4IDFilter::parseToString(std::string& result)
{
	std::string op = parseOperator();
	std::ostringstream stream;
	stream << m_IpID;
	result = "ip[4:2] " + op + " " + stream.str();
}

void IpV4TotalLengthFilter::parseToString(std::string& result)
{
	std::string op = parseOperator();
	std::ostringstream stream;
	stream << m_TotalLength;
	result = "ip[2:2] " + op + " " + stream.str();
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

	result = dir + " portrange " + fromPortStream.str() + "-" + toPortStream.str();
}

void MacAddressFilter::parseToString(std::string& result)
{
	if (getDir() != SRC_OR_DST)
	{
		std::string dir;
		parseDirection(dir);
		result = "ether " + dir + " " + m_MacAddress.toString();
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

void AndFilter::parseToString(std::string& result)
{
	result = "";
	for(std::vector<GeneralFilter*>::iterator it = m_FilterList.begin(); it != m_FilterList.end(); ++it)
	{
		std::string innerFilter;
		(*it)->parseToString(innerFilter);
		result += "(" + innerFilter + ")";
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
	result = "";
	for(std::vector<GeneralFilter*>::iterator it = m_FilterList.begin(); it != m_FilterList.end(); ++it)
	{
		std::string innerFilter;
		(*it)->parseToString(innerFilter);
		result += "(" + innerFilter + ")";
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
	result = "not (" + innerFilterAsString + ")";
}

void ProtoFilter::parseToString(std::string& result)
{
	result = "";
	switch (m_Proto)
	{
	case TCP:
		result += "tcp";
		break;
	case UDP:
		result += "udp";
		break;
	case ICMP:
		result += "icmp";
		break;
	case VLAN:
		result += "vlan";
		break;
	case IPv4:
		result += "ip";
		break;
	case IPv6:
		result += "ip6";
		break;
	case ARP:
		result += "arp";
		break;
	case Ethernet:
		result += "ether";
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
	result = "";
	if (m_TcpFlagsBitMask == 0)
		return;

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

	//remove the last '|' character
	result = result.substr(0, result.size()-1);
	result += ")";

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
	result = "tcp[14:2] " + parseOperator() + " " + stream.str();
}

void UdpLengthFilter::parseToString(std::string& result)
{
	std::ostringstream stream;
	stream << m_Length;
	result = "udp[4:2] " + parseOperator() + " " + stream.str();
}

} // namespace pcpp
