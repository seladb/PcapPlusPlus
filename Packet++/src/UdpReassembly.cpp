#define LOG_MODULE PacketLogModuleUdpReassembly

#include "UdpReassembly.h"
#include "EndianPortable.h"
#include "IPLayer.h"
#include "Logger.h"
#include "PacketUtils.h"
#include "UdpLayer.h"
#include <sstream>
#include <vector>

namespace pcpp
{

std::string UDPReassembly::getTupleName(IPAddress src, IPAddress dst, uint16_t srcPort, uint16_t dstPort)
{

	std::stringstream stream;

	std::string sourceIP = src.toString();
	std::string destIP = dst.toString();

	// for IPv6 addresses, replace ':' with '_'
	std::replace(sourceIP.begin(), sourceIP.end(), ':', '_');
	std::replace(destIP.begin(), destIP.end(), ':', '_');

	std::string protocol("udp");
	// 文件
	stream << sourceIP << '.' << srcPort << '-' << destIP << '.' << dstPort << '-' << protocol;

	// return the name
	return stream.str();
}

UDPReassembly::ReassemblyStatus UDPReassembly::reassemblePacket(RawPacket *udpRawData)
{
	Packet parsedPacket(udpRawData, false);
	return reassemblePacket(parsedPacket);
}

UDPReassembly::ReassemblyStatus UDPReassembly::reassemblePacket(Packet &udpData)
{

    // connection list -》 tuple list
/* 	
    1. 拿到目标包的源IP和目的IP， 过滤非目标包
	2. 更新状态（返回值）
	3.  设置UDPReassemblyData
		计算链接tupleName，在fragment list找目标fragment，若不存在则添加
		再更新UDPReassemblyData 里的fragment信息
	4. 如果已经设置过回调函数，data调用该函数进行处理 
*/

    // 1. 

	IPAddress srcIP, dstIP;
	if (udpData.isPacketOfType(IP))
	{
		const IPLayer *ipLayer = udpData.getLayerOfType<IPLayer>();
		srcIP = ipLayer->getSrcIPAddress();
		dstIP = ipLayer->getDstIPAddress();
	}
	else
		return NonIpPacket;

	// in real traffic the IP addresses cannot be an unspecified
	if (!srcIP.isValid() || !dstIP.isValid())
		return NonIpPacket;

	// Ignore non-UDP packets
	UdpLayer *udpLayer = udpData.getLayerOfType<UdpLayer>(true); // lookup in reverse order
	if (udpLayer == NULL)
	{
		return NonUdpPacket;
	}
    

    // 2.
	//标记状态
	ReassemblyStatus status = UdpMessageHandled;

    // 3.
	UDPReassemblyData *udpReassemblyData = NULL;

	uint16_t srcPort = udpLayer->getSrcPort();
	uint16_t dstPort = udpLayer->getDstPort();
	std::string tupleName = getTupleName(srcIP, dstIP, srcPort, dstPort);

	// 元组列表里找对应的
	FragmentList::iterator iter = m_FragmentList.find(tupleName);

	if (iter == m_FragmentList.end())
	{
		std::pair<FragmentList::iterator, bool> pair =
			m_FragmentList.insert(std::make_pair(tupleName, UDPReassemblyData()));
		udpReassemblyData = &pair.first->second;
		udpReassemblyData->srcIP = srcIP;
		udpReassemblyData->dstIP = dstIP;
		udpReassemblyData->srcPort = srcPort;
		udpReassemblyData->dstPort = dstPort;
		udpReassemblyData->tupleName = tupleName;
        udpReassemblyData->number = 0;
	}

	// 包处理
	uint8_t *data = udpLayer->getData();
	size_t len = udpLayer->getDataLen();
	UdpPacketData packetdata(data, len, tupleName);


    // 4.

	// send the data to the callback
	if (m_OnUdpMessageReadyCallback != NULL)
	{
		m_OnUdpMessageReadyCallback(&packetdata, m_CallbackUserCookie);
	}

	return status;
}

} // namespace pcpp
