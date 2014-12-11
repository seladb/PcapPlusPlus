#ifndef PCAPP_FILTER
#define PCAPP_FILTER

#include <string>
#include <vector>
#include "ProtocolType.h"
#include <stdint.h>
#include <ArpLayer.h>

using namespace std;

typedef enum {SRC, DST, SRC_OR_DST} Direction;

typedef enum {EQUALS, NOT_EQUALS, GREATER_THAN, GREATER_OR_EQUAL, LESS_THAN, LESS_OR_EQUAL} FilterOperator;

class GeneralFilter
{
public:
	virtual void parseToString(string& result) = 0;
	virtual ~GeneralFilter();
};

class IFilterWithDirection : public GeneralFilter
{
private:
	Direction m_Dir;
protected:
	void parseDirection(string& directionAsString);
	inline Direction getDir() { return m_Dir; }
	IFilterWithDirection(Direction dir) { m_Dir = dir; }
public:
	void setDirection(Direction dir) { m_Dir = dir; }
};

class IFilterWithOperator : public GeneralFilter
{
private:
	FilterOperator m_Operator;
protected:
	string parseOperator();
	inline FilterOperator getOperator() { return m_Operator; }
	IFilterWithOperator(FilterOperator op) { m_Operator = op; }
public:
	void setOperator(FilterOperator op) { m_Operator = op; }
};

class IPFilter : public IFilterWithDirection
{
private:
	string m_Address;
	string m_IPv4Mask;
	int m_Len;
	void convertToIPAddressWithMask(string& ipAddrmodified, string& mask);
	void convertToIPAddressWithLen(string& ipAddrmodified, int& len);
public:
	IPFilter(const string& ipAddress, Direction dir) : IFilterWithDirection(dir), m_Address(ipAddress), m_IPv4Mask(""), m_Len(0) {}
	IPFilter(const string& ipAddress, Direction dir, const string& ipv4Mask) : IFilterWithDirection(dir), m_Address(ipAddress), m_IPv4Mask(ipv4Mask), m_Len(0) {}
	IPFilter(const string& ipAddress, Direction dir, int len) : IFilterWithDirection(dir), m_Address(ipAddress), m_IPv4Mask(""), m_Len(len) {}
	void parseToString(string& result);
	void setAddr(const string& ipAddress) { m_Address = ipAddress; }
	void setMask(const string& ipv4Mask) { m_IPv4Mask = ipv4Mask; m_Len = 0; }
	void setLen(int len) { m_IPv4Mask = ""; m_Len = len; }
};

class IpV4IDFilter : public IFilterWithOperator
{
private:
	uint16_t m_IpID;
public:
	IpV4IDFilter(uint16_t ipID, FilterOperator op) : IFilterWithOperator(op), m_IpID(ipID) {}
	void parseToString(string& result);
	void setIpID(uint16_t ipID) { m_IpID = ipID; }
};

class IpV4TotalLengthFilter : public IFilterWithOperator
{
private:
	uint16_t m_TotalLength;
public:
	IpV4TotalLengthFilter(uint16_t totalLength, FilterOperator op) : IFilterWithOperator(op), m_TotalLength(totalLength) {}
	void parseToString(string& result);
	void setIpID(uint16_t totalLength) { m_TotalLength = totalLength; }
};

class PortFilter : public IFilterWithDirection
{
private:
	string m_Port;
	void portToString(uint16_t portAsInt);
public:
	PortFilter(uint16_t port, Direction dir);
	void parseToString(string& result);
	void setPort(uint16_t port) { portToString(port); }
};

class PortRangeFilter : public IFilterWithDirection
{
private:
	uint16_t m_FromPort;
	uint16_t m_ToPort;
public:
	PortRangeFilter(uint16_t fromPort, uint16_t toPort, Direction dir) : IFilterWithDirection(dir), m_FromPort(fromPort), m_ToPort(toPort) {}
	void parseToString(string& result);
	void setFromPort(uint16_t fromPort) { m_FromPort = fromPort; }
	void setToPort(uint16_t toPort) { m_ToPort = toPort; }
};

class MacAddressFilter : public IFilterWithDirection
{
private:
	MacAddress m_MacAddress;
public:
	MacAddressFilter(MacAddress address, Direction dir) : IFilterWithDirection(dir), m_MacAddress(address) {}
	void parseToString(string& result);
	void setMacAddress(MacAddress address) { m_MacAddress = address; }
};

class EtherTypeFilter : public GeneralFilter
{
private:
	uint16_t m_EtherType;
public:
	EtherTypeFilter(uint16_t etherType) : m_EtherType(etherType) {}
	void parseToString(string& result);
	void setEtherType(uint16_t etherType) { m_EtherType = etherType; }
};

class AndFilter : public GeneralFilter
{
private:
	vector<GeneralFilter*> m_FilterList;
public:
	AndFilter(vector<GeneralFilter*>& filters);
	void parseToString(string& result);
};

class OrFilter : public GeneralFilter
{
private:
	vector<GeneralFilter*> m_FilterList;
public:
	OrFilter(vector<GeneralFilter*>& filters);
	void parseToString(string& result);
};

class NotFilter : public GeneralFilter
{
private:
	GeneralFilter* m_FilterToInverse;
public:
	NotFilter(GeneralFilter* filterToInverse) { m_FilterToInverse = filterToInverse; }
	void parseToString(string& result);
	void setFilter(GeneralFilter* filterToInverse) { m_FilterToInverse = filterToInverse; }
};

class ProtoFilter : public GeneralFilter
{
private:
	ProtocolType m_Proto;
public:
	ProtoFilter(ProtocolType proto) { m_Proto = proto; }
	void parseToString(string& result);
	void setProto(ProtocolType proto) { m_Proto = proto; }
};

class ArpFilter : public GeneralFilter
{
private:
	ArpOpcode m_OpCode;
public:
	ArpFilter(ArpOpcode opCode)
	{
		m_OpCode = opCode;
	}

	void setOpCode(ArpOpcode opCode) { m_OpCode = opCode; }

	void parseToString(string& result);
};

class VlanFilter : public GeneralFilter
{
private:
	uint16_t m_VlanID;
public:
	VlanFilter(uint16_t vlanId) : m_VlanID(vlanId) {}
	void setVlanID(uint16_t vlanId) { m_VlanID = vlanId; }
	void parseToString(string& result);
};

class TcpFlagsFilter : public GeneralFilter
{
public:
	enum TcpFlags { tcpFin = 1, tcpSyn = 2, tcpRst = 4, tcpPush = 8, tcpAck = 16, tcpUrg = 32 };
	enum MatchOptions { MatchAll, MatchOneAtLeast };
private:
	uint8_t m_TcpFlagsBitMask;
	MatchOptions m_MatchOption;
public:
	TcpFlagsFilter(uint8_t tcpFlagBitMask, MatchOptions matchOption) : m_TcpFlagsBitMask(tcpFlagBitMask), m_MatchOption(matchOption) {}
	void setTcpFlagsBitMask(uint8_t tcpFlagBitMask, MatchOptions matchOption) { m_TcpFlagsBitMask = tcpFlagBitMask; m_MatchOption = matchOption; }
	void parseToString(string& result);
};

class TcpWindowSizeFilter : public IFilterWithOperator
{
private:
	uint16_t m_WindowSize;
public:
	TcpWindowSizeFilter(uint16_t windowSize, FilterOperator op) : IFilterWithOperator(op), m_WindowSize(windowSize) {}
	void parseToString(string& result);
	void setWindowSize(uint16_t windowSize) { m_WindowSize = windowSize; }
};

class UdpLengthFilter : public IFilterWithOperator
{
private:
	uint16_t m_Length;
public:
	UdpLengthFilter(uint16_t legnth, FilterOperator op) : IFilterWithOperator(op), m_Length(legnth) {}
	void parseToString(string& result);
	void setLength(uint16_t legnth) { m_Length = legnth; }
};


#endif
