#ifndef PCAPP_FILTER
#define PCAPP_FILTER

#include <string>
#include <vector>
#include "ProtocolType.h"
#include <stdint.h>
#include <ArpLayer.h>

using namespace std;

typedef enum {SRC, DST, SRC_OR_DST} Direction;

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
public:
	IFilterWithDirection(Direction dir) { m_Dir = dir; }
	void setDirection(Direction dir) { m_Dir = dir; }
};

class IPFilter : public IFilterWithDirection
{
private:
	string m_Address;
public:
	IPFilter(string& ipAddress, Direction dir);
	void parseToString(string& result);
	void setAddr(string& ipAddress) { m_Address = ipAddress; }
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

#endif
