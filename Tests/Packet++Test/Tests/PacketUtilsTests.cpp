#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "Packet.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include "SystemUtils.h"
#include "PacketUtils.h"

PTF_TEST_CASE(PacketUtilsHash5TupleUdp)
{
	pcpp::IPv4Address dstIP("10.0.0.6");
	pcpp::IPv4Address srcIP("212.199.202.9");

	pcpp::IPv4Layer ipLayer(srcIP, dstIP);
	ipLayer.getIPv4Header()->ipId = htobe16(20300);
	ipLayer.getIPv4Header()->fragmentOffset = htobe16(0x4000);
	ipLayer.getIPv4Header()->timeToLive = 59;
	pcpp::UdpLayer udpLayer(63628, 1900);

	pcpp::Packet srcDstPacket(1);
	srcDstPacket.addLayer(&ipLayer);
	srcDstPacket.addLayer(&udpLayer);
	srcDstPacket.computeCalculateFields();

	pcpp::IPv4Layer ipLayer2(dstIP, srcIP);
	ipLayer2.getIPv4Header()->ipId = htobe16(20300);
	ipLayer2.getIPv4Header()->fragmentOffset = htobe16(0x4000);
	ipLayer2.getIPv4Header()->timeToLive = 59;
	pcpp::UdpLayer udpLayer2(1900, 63628);

	pcpp::Packet dstSrcPacket(1);
	dstSrcPacket.addLayer(&ipLayer2);
	dstSrcPacket.addLayer(&udpLayer2);
	dstSrcPacket.computeCalculateFields();

	// Test default behaviour where hash of SRC->DST == DST->SRC
	PTF_ASSERT_EQUAL(pcpp::hash5Tuple(&srcDstPacket), pcpp::hash5Tuple(&dstSrcPacket));

	// Test of direction-unique-hash where SRC->DST != DST->SRC
	PTF_ASSERT_NOT_EQUAL(pcpp::hash5Tuple(&srcDstPacket, true), pcpp::hash5Tuple(&dstSrcPacket, true));

	PTF_ASSERT_EQUAL(pcpp::hash5Tuple(&srcDstPacket, false), 683027169);
	PTF_ASSERT_EQUAL(pcpp::hash5Tuple(&srcDstPacket, true), 926590153);
	PTF_ASSERT_EQUAL(pcpp::hash5Tuple(&dstSrcPacket, false), 683027169);
	PTF_ASSERT_EQUAL(pcpp::hash5Tuple(&dstSrcPacket, true), 683027169);

}  // PacketUtilsHash5TupleUdp

PTF_TEST_CASE(PacketUtilsHash5TupleTcp)
{
	pcpp::IPv4Address dstIP("10.0.0.6");
	pcpp::IPv4Address srcIP("212.199.202.9");

	pcpp::IPv4Layer ipLayer(srcIP, dstIP);
	ipLayer.getIPv4Header()->ipId = htobe16(20300);
	ipLayer.getIPv4Header()->fragmentOffset = htobe16(0x4000);
	ipLayer.getIPv4Header()->timeToLive = 59;
	pcpp::TcpLayer tcpLayer((uint16_t)60388, (uint16_t)80);
	tcpLayer.getTcpHeader()->sequenceNumber = htobe32(0xb829cb98);
	tcpLayer.getTcpHeader()->ackNumber = htobe32(0xe9771586);
	tcpLayer.getTcpHeader()->ackFlag = 1;
	tcpLayer.getTcpHeader()->pshFlag = 1;
	tcpLayer.getTcpHeader()->windowSize = htobe16(20178);
	pcpp::Packet srcDstPacket(1);
	srcDstPacket.addLayer(&ipLayer);
	srcDstPacket.addLayer(&tcpLayer);
	srcDstPacket.computeCalculateFields();

	pcpp::IPv4Layer ipLayer2(dstIP, srcIP);
	ipLayer2.getIPv4Header()->ipId = htobe16(20300);
	ipLayer2.getIPv4Header()->fragmentOffset = htobe16(0x4000);
	ipLayer2.getIPv4Header()->timeToLive = 59;
	pcpp::TcpLayer tcpLayer2((uint16_t)80, (uint16_t)60388);
	tcpLayer2.getTcpHeader()->sequenceNumber = htobe32(0xb829cb98);
	tcpLayer2.getTcpHeader()->ackNumber = htobe32(0xe9771586);
	tcpLayer2.getTcpHeader()->ackFlag = 1;
	tcpLayer2.getTcpHeader()->pshFlag = 1;
	tcpLayer2.getTcpHeader()->windowSize = htobe16(20178);
	pcpp::Packet dstSrcPacket(1);
	dstSrcPacket.addLayer(&ipLayer2);
	dstSrcPacket.addLayer(&tcpLayer2);
	dstSrcPacket.computeCalculateFields();

	// Test default behaviour where hash of SRC->DST == DST->SRC
	PTF_ASSERT_EQUAL(pcpp::hash5Tuple(&srcDstPacket), pcpp::hash5Tuple(&dstSrcPacket));

	// Test of direction-unique-hash where SRC->DST != DST->SRC
	PTF_ASSERT_NOT_EQUAL(pcpp::hash5Tuple(&srcDstPacket, true), pcpp::hash5Tuple(&dstSrcPacket, true));

	PTF_ASSERT_EQUAL(pcpp::hash5Tuple(&srcDstPacket, false), 1576639238);
	PTF_ASSERT_EQUAL(pcpp::hash5Tuple(&srcDstPacket, true), 2243556734);
	PTF_ASSERT_EQUAL(pcpp::hash5Tuple(&dstSrcPacket, false), 1576639238);
	PTF_ASSERT_EQUAL(pcpp::hash5Tuple(&dstSrcPacket, true), 1576639238);

	tcpLayer.getTcpHeader()->portDst = 80;
	tcpLayer.getTcpHeader()->portSrc = 80;

	tcpLayer2.getTcpHeader()->portDst = 80;
	tcpLayer2.getTcpHeader()->portSrc = 80;

	PTF_ASSERT_EQUAL(pcpp::hash5Tuple(&srcDstPacket), pcpp::hash5Tuple(&dstSrcPacket));
	PTF_ASSERT_NOT_EQUAL(pcpp::hash5Tuple(&srcDstPacket, true), pcpp::hash5Tuple(&dstSrcPacket, true));

}  // PacketUtilsHash5TupleTcp

PTF_TEST_CASE(PacketUtilsHash5TupleIPv6)
{
	pcpp::IPv6Address dstIP("fe80::4dc7:f593:1f7b:dc11");
	pcpp::IPv6Address srcIP("ff02::c");

	pcpp::IPv6Layer ipLayer(srcIP, dstIP);
	pcpp::UdpLayer udpLayer(63628, 1900);

	pcpp::Packet srcDstPacket(1);
	srcDstPacket.addLayer(&ipLayer);
	srcDstPacket.addLayer(&udpLayer);
	srcDstPacket.computeCalculateFields();

	pcpp::IPv6Layer ipLayer2(dstIP, srcIP);
	pcpp::UdpLayer udpLayer2(1900, 63628);

	pcpp::Packet dstSrcPacket(1);
	dstSrcPacket.addLayer(&ipLayer2);
	dstSrcPacket.addLayer(&udpLayer2);
	dstSrcPacket.computeCalculateFields();

	// Test default behaviour where hash of SRC->DST == DST->SRC
	PTF_ASSERT_EQUAL(pcpp::hash5Tuple(&srcDstPacket), pcpp::hash5Tuple(&dstSrcPacket));

	// Test of direction-unique-hash where SRC->DST != DST->SRC
	PTF_ASSERT_NOT_EQUAL(pcpp::hash5Tuple(&srcDstPacket, true), pcpp::hash5Tuple(&dstSrcPacket, true));

	PTF_ASSERT_EQUAL(pcpp::hash5Tuple(&srcDstPacket, false), 4288746927);
	PTF_ASSERT_EQUAL(pcpp::hash5Tuple(&srcDstPacket, true), 2229527039);
	PTF_ASSERT_EQUAL(pcpp::hash5Tuple(&dstSrcPacket, false), 4288746927);
	PTF_ASSERT_EQUAL(pcpp::hash5Tuple(&dstSrcPacket, true), 4288746927);

	udpLayer.getUdpHeader()->portDst = 80;
	udpLayer.getUdpHeader()->portSrc = 80;

	udpLayer2.getUdpHeader()->portDst = 80;
	udpLayer2.getUdpHeader()->portSrc = 80;

	PTF_ASSERT_EQUAL(pcpp::hash5Tuple(&srcDstPacket), pcpp::hash5Tuple(&dstSrcPacket));
	PTF_ASSERT_NOT_EQUAL(pcpp::hash5Tuple(&srcDstPacket, true), pcpp::hash5Tuple(&dstSrcPacket, true));

}  // PacketUtilsHash5TupleIPv6
