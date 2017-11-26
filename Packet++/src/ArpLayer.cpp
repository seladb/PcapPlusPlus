#define LOG_MODULE PacketLogModuleArpLayer

#include "ArpLayer.h"
#include "EthLayer.h"
#include <string.h>
#if defined(WIN32) || defined(WINx64)
#include <winsock2.h>
#elif LINUX
#include <in.h>
#elif MAC_OS_X
#include <arpa/inet.h>
#endif

namespace pcpp
{

ArpLayer::ArpLayer(ArpOpcode opCode, const MacAddress& senderMacAddr, const MacAddress& targetMacAddr, const IPv4Address senderIpAddr, const IPv4Address& targetIpAddr)
{
	m_DataLen = sizeof(arphdr);
	m_Data = new uint8_t[m_DataLen];
	memset(m_Data, 0, sizeof(m_DataLen));
	m_Protocol = ARP;

	arphdr* arpHeader = getArpHeader();
	arpHeader->opcode = htons(opCode);
	targetMacAddr.copyTo(arpHeader->targetMacAddr);
	senderMacAddr.copyTo(arpHeader->senderMacAddr);
	arpHeader->targetIpAddr = targetIpAddr.toInt();
	arpHeader->senderIpAddr = senderIpAddr.toInt();
}

void ArpLayer::computeCalculateFields()
{
	arphdr* arpHeader = getArpHeader();
	arpHeader->hardwareType = htons(1); //Ethernet
	arpHeader->hardwareSize = 6;
	arpHeader->protocolType = htons(PCPP_ETHERTYPE_IP); //assume IPv4 over ARP
	arpHeader->protocolSize = 4; //assume IPv4 over ARP
	if (arpHeader->opcode == htons(ARP_REQUEST))
	{
		MacAddress targetMacAddress("00:00:00:00:00:00");
		targetMacAddress.copyTo(arpHeader->targetMacAddr);
	}
}

std::string ArpLayer::toString()
{
	if (ntohs(getArpHeader()->opcode) == ARP_REQUEST)
	{
		return "ARP Layer, ARP request, who has " + getTargetIpAddr().toString() + " ? Tell " + getSenderIpAddr().toString();
	}
	else
	{
		return "ARP Layer, ARP reply, " + getSenderIpAddr().toString() + " is at " + getSenderMacAddress().toString();
	}
}

} // namespace pcpp
