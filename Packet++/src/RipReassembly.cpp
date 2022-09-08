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
	/*
		1. 拿到目标包的源IP和目的IP， 过滤非目标包
		2. 更新状态（返回值）
		3.  设置RIPReassemblyData
			计算链接tupleName，在fragment list找目标fragment，若不存在则添加
			再更新RIPReassemblyData 里的fragment信息
		4. 如果已经设置过回调函数，data调用该函数进行处理
	*/

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
	RIPReassemblyData *ripReassemblyData = NULL;
	std::string tupleName = getTupleName(srcIP, dstIP, srcPort, dstPort);

	// 元组列表里找对应的
	FragmentList::iterator iter = m_FragmentList.find(tupleName);

	if (iter == m_FragmentList.end())
	{
		std::pair<FragmentList::iterator, bool> pair =
			m_FragmentList.insert(std::make_pair(tupleName, RIPReassemblyData()));
		ripReassemblyData = &pair.first->second;
		ripReassemblyData->srcIP = srcIP;
		ripReassemblyData->dstIP = dstIP;
		ripReassemblyData->srcPort = srcPort;
		ripReassemblyData->dstPort = dstPort;
		ripReassemblyData->tupleName = tupleName;
		ripReassemblyData->number = 0;
	}

	// 包处理
	uint8_t *data = ripLayer->getData();
	size_t len = ripLayer->getDataLen();
	RipPacketData packetdata(data, len, tupleName);

	// 4.

	// send the data to the callback
	if (m_OnRipMessageReadyCallback != NULL)
	{
		m_OnRipMessageReadyCallback(&packetdata, m_CallbackUserCookie);
	}

	return status;
}

} // namespace pcpp
