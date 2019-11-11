#define LOG_MODULE PacketLogModuleArpLayer

#include "ArpLayer.h"
#include "EthLayer.h"
#include <string.h>
#if defined(WIN32) || defined(WINx64) || defined(PCAPPP_MINGW_ENV)
#include <winsock2.h>
#elif LINUX
#include <in.h>
#elif MAC_OS_X || FREEBSD
#include <arpa/inet.h>
#endif

namespace pcpp
{

ArpLayer::ArpLayer(ArpOpcode opCode, const MacAddress& senderMacAddr, const MacAddress& targetMacAddr, const IPv4Address senderIpAddr, const IPv4Address& targetIpAddr)
{
	const size_t headerLen = sizeof(arphdr);
	m_DataLen = headerLen;
	m_Data = new uint8_t[headerLen];
	memset(m_Data, 0, sizeof(headerLen));
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
		MacAddress::Zero.copyTo(arpHeader->targetMacAddr);
}

std::string ArpLayer::toString() const
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
