#define LOG_MODULE PcapLogModuleLiveDevice

#include "PcapFilter.h"
#include "Logger.h"
#include <sstream>

GeneralFilter::~GeneralFilter()
{
}

void IFilterWithDirection::parseDirection(string& directionAsString)
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

IPFilter::IPFilter(string& ipAddress, Direction dir) : IFilterWithDirection(dir)
{
	m_Address = ipAddress;
}

void IPFilter::parseToString(string& result)
{
	string dir;
	parseDirection(dir);
	result = dir + " net " + m_Address;
}

void PortFilter::portToString(uint16_t portAsInt)
{
	ostringstream stream;
	stream << portAsInt;
	m_Port = stream.str();
}

PortFilter::PortFilter(uint16_t port, Direction dir) : IFilterWithDirection(dir)
{
	portToString(port);
}

void PortFilter::parseToString(string& result)
{
	string dir;
	parseDirection(dir);
	result = dir + " port " + m_Port;
}

AndFilter::AndFilter(vector<GeneralFilter*>& filters)
{
	for(vector<GeneralFilter*>::iterator it = filters.begin(); it != filters.end(); ++it)
	{
		m_xFilterList.push_back(*it);
	}
}

void AndFilter::parseToString(string& result)
{
	result = "";
	for(vector<GeneralFilter*>::iterator it = m_xFilterList.begin(); it != m_xFilterList.end(); ++it)
	{
		string innerFilter;
		(*it)->parseToString(innerFilter);
		result += "(" + innerFilter + ")";
		if (m_xFilterList.back() != *it)
		{
			result += " and ";
		}
	}
}

OrFilter::OrFilter(vector<GeneralFilter*>& filters)
{
	for(vector<GeneralFilter*>::iterator it = filters.begin(); it != filters.end(); ++it)
	{
		m_xFilterList.push_back(*it);
	}
}

void OrFilter::parseToString(string& result)
{
	result = "";
	for(vector<GeneralFilter*>::iterator it = m_xFilterList.begin(); it != m_xFilterList.end(); ++it)
	{
		string innerFilter;
		(*it)->parseToString(innerFilter);
		result += "(" + innerFilter + ")";
		if (m_xFilterList.back() != *it)
		{
			result += " or ";
		}
	}
}

void NotFilter::parseToString(string& result)
{
	string innerFilterAsString;
	m_pFilterToInverse->parseToString(innerFilterAsString);
	result = "not (" + innerFilterAsString + ")";
}

void ProtoFilter::parseToString(string& result)
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
	default:
		break;
	}
}

void ArpFilter::parseToString(string& result)
{
	ostringstream sstream;
	sstream << "arp[7] = " << m_OpCode;
	result += sstream.str();
}
