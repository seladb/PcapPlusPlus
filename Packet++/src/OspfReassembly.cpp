#define LOG_MODULE PacketLogModuleOspfReassembly

#include "OspfReassembly.h"
#include "EndianPortable.h"
#include "IPLayer.h"
#include "Logger.h"
#include "PacketUtils.h"
#include "OspfLayer.h"
#include <sstream>
#include <vector>

namespace pcpp
{

std::string OSPFReassembly::getTupleName(IPAddress src, IPAddress dst)
{

	std::stringstream stream;

	std::string sourceIP = src.toString();
	std::string destIP = dst.toString();

	// for IPv6 addresses, replace ':' with '_'
	std::replace(sourceIP.begin(), sourceIP.end(), ':', '_');
	std::replace(destIP.begin(), destIP.end(), ':', '_');

	std::string protocol("ospf");
	// 文件
	stream << sourceIP << '-' << destIP << '-' << protocol;

	// return the name
	return stream.str();
}

OSPFReassembly::ReassemblyStatus OSPFReassembly::reassemblePacket(RawPacket *ospfRawData)
{
	Packet parsedPacket(ospfRawData, false);
	return reassemblePacket(parsedPacket);
}

OSPFReassembly::ReassemblyStatus OSPFReassembly::reassemblePacket(Packet &ospfData)
{
	// 1.

	IPAddress srcIP, dstIP;
	if (ospfData.isPacketOfType(IP))
	{
		const IPLayer *ipLayer = ospfData.getLayerOfType<IPLayer>();
		srcIP = ipLayer->getSrcIPAddress();
		dstIP = ipLayer->getDstIPAddress();
	}
	else
		return NonIpPacket;

	// in real traffic the IP addresses cannot be an unspecified
	if (!srcIP.isValid() || !dstIP.isValid())
		return NonIpPacket;

	// Ignore non-OSPF packets
	OspfLayer *ospfLayer = ospfData.getLayerOfType<OspfLayer>();
	if (ospfLayer == NULL)
	{
		return NonOspfPacket;
	}
	ospfLayer->computeCalculateFields();

	// 2.
	//标记状态
	ReassemblyStatus status = OspfMessageHandled;

	// 3.
	std::string tupleName = getTupleName(srcIP, dstIP);
	OspfPacketData packetdata(ospfLayer, tupleName);

	// 4.

	// send the data to the callback
	if (m_OnOspfMessageReadyCallback != NULL)
	{
		m_OnOspfMessageReadyCallback(&packetdata, m_CallbackUserCookie);
	}

	return status;
}

} // namespace pcpp
