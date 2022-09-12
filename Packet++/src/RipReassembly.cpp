#define LOG_MODULE PacketLogModuleRipReassembly

#include "RipReassembly.h"
#include "EndianPortable.h"
#include "IPLayer.h"
#include "Logger.h"
#include "PacketUtils.h"
#include "RipLayer.h"
#include "UdpLayer.h"
#include <sstream>
#include <vector>

namespace pcpp
{

std::string RIPReassembly::getTupleName(IPAddress src, IPAddress dst, uint16_t srcPort, uint16_t dstPort)
{

	std::stringstream stream;

	std::string sourceIP = src.toString();
	std::string destIP = dst.toString();

	// for IPv6 addresses, replace ':' with '_'
	std::replace(sourceIP.begin(), sourceIP.end(), ':', '_');
	std::replace(destIP.begin(), destIP.end(), ':', '_');

	std::string protocol("rip");
	// 文件
	stream << sourceIP << '.' << srcPort << '-' << destIP << '.' << dstPort << '-' << protocol;

	// return the name
	return stream.str();
}

RIPReassembly::ReassemblyStatus RIPReassembly::reassemblePacket(RawPacket *ripRawData)
{
	Packet parsedPacket(ripRawData, false);
	return reassemblePacket(parsedPacket);
}

RIPReassembly::ReassemblyStatus RIPReassembly::reassemblePacket(Packet &ripData)
{
	// 1.

	IPAddress srcIP, dstIP;
	if (ripData.isPacketOfType(IP))
	{
		const IPLayer *ipLayer = ripData.getLayerOfType<IPLayer>();
		srcIP = ipLayer->getSrcIPAddress();
		dstIP = ipLayer->getDstIPAddress();
	}
	else
		return NonIpPacket;

	// in real traffic the IP addresses cannot be an unspecified
	if (!srcIP.isValid() || !dstIP.isValid())
		return NonIpPacket;

	// Ignore non-UDP packets
	UdpLayer *udpLayer = ripData.getLayerOfType<UdpLayer>();
	if (udpLayer == NULL)
	{
		return NonUdpPacket;
	}

	uint16_t srcPort = udpLayer->getSrcPort();
	uint16_t dstPort = udpLayer->getDstPort();

	// Ignore non-RIP packets
	RipLayer *ripLayer = ripData.getLayerOfType<RipLayer>();
	if (ripLayer == NULL)
	{
		return NonRipPacket;
	}

	// 2.
	//标记状态
	ReassemblyStatus status = RipMessageHandled;

	// 3.
	std::string tupleName = getTupleName(srcIP, dstIP, srcPort, dstPort);
	RipPacketData packetdata(ripLayer, tupleName);

	// 4.

	// send the data to the callback
	if (m_OnRipMessageReadyCallback != NULL)
	{
		m_OnRipMessageReadyCallback(&packetdata, m_CallbackUserCookie);
	}

	return status;
}

} // namespace pcpp
