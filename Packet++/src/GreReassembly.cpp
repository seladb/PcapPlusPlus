#define LOG_MODULE PacketLogModuleGreReassembly

#include "GreReassembly.h"
#include "EndianPortable.h"
#include "GreLayer.h"
#include "IPLayer.h"
#include "Logger.h"
#include "PacketUtils.h"
#include <sstream>
#include <vector>

namespace pcpp
{

std::string GREReassembly::getTupleName(IPAddress src, IPAddress dst)
{

	std::stringstream stream;

	std::string sourceIP = src.toString();
	std::string destIP = dst.toString();

	// for IPv6 addresses, replace ':' with '_'
	std::replace(sourceIP.begin(), sourceIP.end(), ':', '_');
	std::replace(destIP.begin(), destIP.end(), ':', '_');

	std::string protocol("gre");
	stream << sourceIP << '-' << destIP << '-' << protocol;

	// return the name
	return stream.str();
}

GREReassembly::ReassemblyStatus GREReassembly::reassemblePacket(RawPacket *greRawData)
{
	Packet parsedPacket(greRawData, false);
	return reassemblePacket(parsedPacket);
}

GREReassembly::ReassemblyStatus GREReassembly::reassemblePacket(Packet &greData)
{
	// 1.

	IPAddress srcIP, dstIP;
	if (greData.isPacketOfType(IP))
	{
		const IPLayer *ipLayer = greData.getLayerOfType<IPLayer>();
		srcIP = ipLayer->getSrcIPAddress();
		dstIP = ipLayer->getDstIPAddress();
	}
	else
		return NonIpPacket;

	// in real traffic the IP addresses cannot be an unspecified
	if (!srcIP.isValid() || !dstIP.isValid())
		return NonIpPacket;

	// Ignore non-GRE packets
	GreLayer *greLayer = greData.getLayerOfType<GreLayer>(true); // lookup in reverse order
	if (greLayer == NULL)
	{
		return NonGrePacket;
	}

	// 2.
	//标记状态
	ReassemblyStatus status = GreMessageHandled;

	// 3.
	GREReassemblyData *greReassemblyData = NULL;

	std::string tupleName = getTupleName(srcIP, dstIP);

	// 元组列表里找对应的
	FragmentList::iterator iter = m_FragmentList.find(tupleName);

	if (iter == m_FragmentList.end())
	{
		std::pair<FragmentList::iterator, bool> pair =
			m_FragmentList.insert(std::make_pair(tupleName, GREReassemblyData()));
		greReassemblyData = &pair.first->second;
		greReassemblyData->srcIP = srcIP;
		greReassemblyData->dstIP = dstIP;
		greReassemblyData->tupleName = tupleName;
		greReassemblyData->number = 0;
	}

	// 包处理
	uint8_t *data = greLayer->getData();
	size_t len = greLayer->getDataLen();
	GrePacketData packetdata(data, len, tupleName);

	// 4.

	// send the data to the callback
	if (m_OnGreMessageReadyCallback != NULL)
	{
		m_OnGreMessageReadyCallback(&packetdata, m_CallbackUserCookie);
	}

	return status;
}

} // namespace pcpp
