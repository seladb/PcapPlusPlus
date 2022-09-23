#define LOG_MODULE PacketLogModuleL2tpReassembly

#include "L2tpReassembly.h"
#include "EndianPortable.h"
#include "IPLayer.h"
#include "UdpLayer.h"
#include "GreLayer.h"
#include "Logger.h"
#include "PacketUtils.h"
#include "L2tpLayer.h"
#include <sstream>
#include <vector>

namespace pcpp
{

std::string L2TPReassembly::getTupleName(IPAddress src, IPAddress dst, uint16_t srcPort, uint16_t dstPort)
{

	std::stringstream stream;

	std::string sourceIP = src.toString();
	std::string destIP = dst.toString();

	// for IPv6 addresses, replace ':' with '_'
	std::replace(sourceIP.begin(), sourceIP.end(), ':', '_');
	std::replace(destIP.begin(), destIP.end(), ':', '_');

	std::string protocol("l2tp");
	// 文件
	stream << sourceIP << '.' << srcPort << '-' << destIP << '.' << dstPort << '-' << protocol;

	// return the name
	return stream.str();
}

L2TPReassembly::ReassemblyStatus L2TPReassembly::reassemblePacket(RawPacket *l2tpRawData)
{
	Packet parsedPacket(l2tpRawData, false);
	return reassemblePacket(parsedPacket);
}

L2TPReassembly::ReassemblyStatus L2TPReassembly::reassemblePacket(Packet &l2tpData)
{
	// 1.

	IPAddress srcIP, dstIP;
	if (l2tpData.isPacketOfType(IP))
	{
		const IPLayer *ipLayer = l2tpData.getLayerOfType<IPLayer>();
		srcIP = ipLayer->getSrcIPAddress();
		dstIP = ipLayer->getDstIPAddress();
	}
	else
		return NonIpPacket;

	// in real traffic the IP addresses cannot be an unspecified
	if (!srcIP.isValid() || !dstIP.isValid())
		return NonIpPacket;

	// Ignore non-UDP packets
	UdpLayer *udpLayer = l2tpData.getLayerOfType<UdpLayer>();
	if (udpLayer == NULL)
	{
		return NonUdpPacket;
	}

	uint16_t srcPort = udpLayer->getSrcPort();
	uint16_t dstPort = udpLayer->getDstPort();

	// Ignore non-L2TP packets
	L2tpLayer *l2tpLayer = l2tpData.getLayerOfType<L2tpLayer>();
	if (l2tpLayer == NULL)
	{
		return NonL2tpPacket;
	}
	l2tpLayer->parseNextLayer();

	// 2.
	//标记状态
	ReassemblyStatus status = L2tpMessageHandled;

	// 3.
	std::string tupleName = getTupleName(srcIP, dstIP, srcPort, dstPort);
	L2tpPacketData packetdata(l2tpLayer, tupleName);

	// 4.

	// send the data to the callback
	if (m_OnL2tpMessageReadyCallback != NULL)
	{
		m_OnL2tpMessageReadyCallback(&packetdata, m_CallbackUserCookie);
	}

	return status;
}

} // namespace pcpp
