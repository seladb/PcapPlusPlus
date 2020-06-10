#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "PayloadLayer.h"
#include "SystemUtils.h"

PTF_TEST_CASE(TcpPacketNoOptionsParsing)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/TcpPacketNoOptions.dat");

	pcpp::Packet tcpPacketNoOptions(&rawPacket1);
	PTF_ASSERT_TRUE(tcpPacketNoOptions.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(tcpPacketNoOptions.isPacketOfType(pcpp::TCP));

	pcpp::TcpLayer* tcpLayer = tcpPacketNoOptions.getLayerOfType<pcpp::TcpLayer>();
	PTF_ASSERT_NOT_NULL(tcpLayer);

	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->portDst, htobe16(60388), u16);
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->portSrc, htobe16(80), u16);
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->sequenceNumber, htobe32(0xbeab364a), u32);
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->ackNumber, htobe32(0xf9ffb58e), u32);
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->dataOffset, 5, u16);
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->urgentPointer, 0, u16);
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->headerChecksum, htobe16(0x4c03), u16);

	// Flags
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->ackFlag, 1, u16);
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->pshFlag, 1, u16);
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->urgFlag, 0, u16);
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->cwrFlag, 0, u16);
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->synFlag, 0, u16);
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->finFlag, 0, u16);
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->rstFlag, 0, u16);
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->eceFlag, 0, u16);
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->reserved, 0, u16);

	// TCP options
	PTF_ASSERT_EQUAL(tcpLayer->getTcpOptionCount(), 0, size);
	PTF_ASSERT_TRUE(tcpLayer->getTcpOption(pcpp::PCPP_TCPOPT_NOP).isNull());
	PTF_ASSERT_TRUE(tcpLayer->getTcpOption(pcpp::PCPP_TCPOPT_TIMESTAMP).isNull());

	pcpp::Layer* afterTcpLayer = tcpLayer->getNextLayer();
	PTF_ASSERT_NOT_NULL(afterTcpLayer);
	PTF_ASSERT_EQUAL(afterTcpLayer->getProtocol(), pcpp::HTTPResponse, enum);
} // TcpPacketNoOptionsParsing



PTF_TEST_CASE(TcpPacketWithOptionsParsing)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/TcpPacketWithOptions.dat");

	pcpp::Packet tcpPaketWithOptions(&rawPacket1);
	PTF_ASSERT_TRUE(tcpPaketWithOptions.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(tcpPaketWithOptions.isPacketOfType(pcpp::TCP));

	pcpp::TcpLayer* tcpLayer = tcpPaketWithOptions.getLayerOfType<pcpp::TcpLayer>();
	PTF_ASSERT_NOT_NULL(tcpLayer);

	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->portSrc, htobe16(44147), u16);
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->portDst, htobe16(80), u16);
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->ackFlag, 1, u16);
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->pshFlag, 1, u16);
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->synFlag, 0, u16);
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->urgentPointer, 0, u16);

	// TCP options
	PTF_ASSERT_EQUAL(tcpLayer->getTcpOptionCount(), 3, size);
	pcpp::TcpOption timestampOptionData = tcpLayer->getTcpOption(pcpp::PCPP_TCPOPT_TIMESTAMP);
	PTF_ASSERT_TRUE(!timestampOptionData.isNull());
	PTF_ASSERT_TRUE(!tcpLayer->getTcpOption(pcpp::PCPP_TCPOPT_NOP).isNull());
	PTF_ASSERT_EQUAL(timestampOptionData.getTotalSize(), 10, size);
	uint32_t tsValue = timestampOptionData.getValueAs<uint32_t>();
	uint32_t tsEchoReply = timestampOptionData.getValueAs<uint32_t>(4);
	PTF_ASSERT_EQUAL(tsValue, htobe32(195102), u32);
	PTF_ASSERT_EQUAL(tsEchoReply, htobe32(3555729271UL), u32);
} // TcpPacketWithOptionsParsing



PTF_TEST_CASE(TcpPacketWithOptionsParsing2)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/TcpPacketWithOptions3.dat");

	pcpp::Packet tcpPaketWithOptions(&rawPacket1);

	pcpp::TcpLayer* tcpLayer = tcpPaketWithOptions.getLayerOfType<pcpp::TcpLayer>();
	PTF_ASSERT_NOT_NULL(tcpLayer);

	PTF_ASSERT_EQUAL(tcpLayer->getTcpOptionCount(), 5, size);
	pcpp::TcpOption mssOption = tcpLayer->getTcpOption(pcpp::TCPOPT_MSS);
	pcpp::TcpOption sackParmOption = tcpLayer->getTcpOption(pcpp::TCPOPT_SACK_PERM);
	pcpp::TcpOption windowScaleOption = tcpLayer->getTcpOption(pcpp::PCPP_TCPOPT_WINDOW);
	PTF_ASSERT_TRUE(mssOption.isNotNull());
	PTF_ASSERT_TRUE(sackParmOption.isNotNull());
	PTF_ASSERT_TRUE(windowScaleOption.isNotNull());

	PTF_ASSERT_EQUAL(mssOption.getTcpOptionType(), pcpp::TCPOPT_MSS, enum);
	PTF_ASSERT_EQUAL(sackParmOption.getTcpOptionType(), pcpp::TCPOPT_SACK_PERM, enum);
	PTF_ASSERT_EQUAL(windowScaleOption.getTcpOptionType(), pcpp::PCPP_TCPOPT_WINDOW, enum);

	PTF_ASSERT_EQUAL(mssOption.getTotalSize(), 4, size);
	PTF_ASSERT_EQUAL(sackParmOption.getTotalSize(), 2, size);
	PTF_ASSERT_EQUAL(windowScaleOption.getTotalSize(), 3, size);

	PTF_ASSERT_EQUAL(mssOption.getValueAs<uint16_t>(), htobe16(1460), u16);
	PTF_ASSERT_EQUAL(windowScaleOption.getValueAs<uint8_t>(), 4, u8);
	PTF_ASSERT_EQUAL(sackParmOption.getValueAs<uint32_t>(), 0, u32);
	PTF_ASSERT_EQUAL(mssOption.getValueAs<uint32_t>(), 0, u32);
	PTF_ASSERT_EQUAL(mssOption.getValueAs<uint16_t>(1), 0, u16);

	pcpp::TcpOption curOpt = tcpLayer->getFirstTcpOption();
	PTF_ASSERT_TRUE(curOpt.isNotNull() && curOpt.getTcpOptionType() == pcpp::TCPOPT_MSS);
	curOpt = tcpLayer->getNextTcpOption(curOpt);
	PTF_ASSERT_TRUE(curOpt.isNotNull() && curOpt.getTcpOptionType() == pcpp::TCPOPT_SACK_PERM);
	curOpt = tcpLayer->getNextTcpOption(curOpt);
	PTF_ASSERT_TRUE(curOpt.isNotNull() && curOpt.getTcpOptionType() == pcpp::PCPP_TCPOPT_TIMESTAMP);
	curOpt = tcpLayer->getNextTcpOption(curOpt);
	PTF_ASSERT_TRUE(curOpt.isNotNull() && curOpt.getTcpOptionType() == pcpp::PCPP_TCPOPT_NOP);
	curOpt = tcpLayer->getNextTcpOption(curOpt);
	PTF_ASSERT_TRUE(curOpt.isNotNull() && curOpt.getTcpOptionType() == pcpp::PCPP_TCPOPT_WINDOW);
	curOpt = tcpLayer->getNextTcpOption(curOpt);
	PTF_ASSERT_TRUE(curOpt.isNull());
} // TcpPacketWithOptionsParsing2



PTF_TEST_CASE(TcpMalformedPacketParsing)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/tcp-malformed1.dat");

	pcpp::Packet badTcpPacket(&rawPacket1);

	PTF_ASSERT_NOT_NULL(badTcpPacket.getLayerOfType<pcpp::IPv4Layer>());
	PTF_ASSERT_NULL(badTcpPacket.getLayerOfType<pcpp::TcpLayer>());
} // TcpMalformedPacketParsing



PTF_TEST_CASE(TcpPacketCreation)
{
	pcpp::MacAddress srcMac("30:46:9a:23:fb:fa");
	pcpp::MacAddress dstMac("08:00:27:19:1c:78");
	pcpp::EthLayer ethLayer(srcMac, dstMac, PCPP_ETHERTYPE_IP);
	pcpp::IPv4Address dstIP("10.0.0.6");
	pcpp::IPv4Address srcIP("212.199.202.9");
	pcpp::IPv4Layer ipLayer(srcIP, dstIP);
	ipLayer.getIPv4Header()->ipId = htobe16(20300);
	ipLayer.getIPv4Header()->fragmentOffset = htobe16(0x4000);
	ipLayer.getIPv4Header()->timeToLive = 59;
	pcpp::TcpLayer tcpLayer((uint16_t)80, (uint16_t)44160);
	tcpLayer.getTcpHeader()->sequenceNumber = htobe32(0xb829cb98);
	tcpLayer.getTcpHeader()->ackNumber = htobe32(0xe9771586);
	tcpLayer.getTcpHeader()->ackFlag = 1;
	tcpLayer.getTcpHeader()->pshFlag = 1;
	tcpLayer.getTcpHeader()->windowSize = htobe16(20178);
	PTF_ASSERT_TRUE(tcpLayer.addTcpOption(pcpp::TcpOptionBuilder(pcpp::TcpOptionBuilder::NOP)).isNotNull());
	PTF_ASSERT_EQUAL(tcpLayer.getHeaderLen(), 24, size)
	PTF_ASSERT_TRUE(tcpLayer.addTcpOption(pcpp::TcpOptionBuilder(pcpp::TcpOptionBuilder::NOP)).isNotNull());
	PTF_ASSERT_EQUAL(tcpLayer.getHeaderLen(), 24, size)
	PTF_ASSERT_TRUE(tcpLayer.addTcpOption(pcpp::TcpOptionBuilder(pcpp::PCPP_TCPOPT_TIMESTAMP, NULL, PCPP_TCPOLEN_TIMESTAMP-2)).isNotNull());
	PTF_ASSERT_EQUAL(tcpLayer.getHeaderLen(), 32, size)
	PTF_ASSERT_EQUAL(tcpLayer.getTcpOptionCount(), 3, size);

	uint8_t payloadData[9] = { 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82 };
	pcpp::PayloadLayer payloadLayer(payloadData, 9, true);

	pcpp::Packet tcpPacket(1);
	tcpPacket.addLayer(&ethLayer);
	tcpPacket.addLayer(&ipLayer);
	tcpPacket.addLayer(&tcpLayer);
	tcpPacket.addLayer(&payloadLayer);

	uint32_t tsEchoReply = htobe32(196757);
	uint32_t tsValue = htobe32(3555735960UL);
	pcpp::TcpOption tsOption = tcpLayer.getTcpOption(pcpp::PCPP_TCPOPT_TIMESTAMP);
	PTF_ASSERT_TRUE(tsOption.isNotNull());
	tsOption.setValue<uint32_t>(tsValue);
	tsOption.setValue<uint32_t>(tsEchoReply, 4);

	PTF_ASSERT_EQUAL(tcpLayer.getTcpOptionCount(), 3, size);

	tcpPacket.computeCalculateFields();

	READ_FILE_INTO_BUFFER(1, "PacketExamples/TcpPacketWithOptions2.dat");

	PTF_ASSERT_BUF_COMPARE(tcpPacket.getRawPacket()->getRawData(), buffer1, bufferLength1);

	delete [] buffer1;
} // TcpPacketCreation



PTF_TEST_CASE(TcpPacketCreation2)
{
	pcpp::MacAddress srcMac("08:00:27:19:1c:78");
	pcpp::MacAddress dstMac("30:46:9a:23:fb:fa");
	pcpp::EthLayer ethLayer(srcMac, dstMac, PCPP_ETHERTYPE_IP);
	pcpp::IPv4Address dstIP("23.44.242.127");
	pcpp::IPv4Address srcIP("10.0.0.6");
	pcpp::IPv4Layer ipLayer(srcIP, dstIP);
	ipLayer.getIPv4Header()->ipId = htobe16(1556);
	ipLayer.getIPv4Header()->fragmentOffset = 0x40;
	ipLayer.getIPv4Header()->timeToLive = 64;
	pcpp::TcpLayer tcpLayer((uint16_t)60225, (uint16_t)80);
	tcpLayer.getTcpHeader()->sequenceNumber = htobe32(0x2d3904e0);
	tcpLayer.getTcpHeader()->ackNumber = 0;
	tcpLayer.getTcpHeader()->synFlag = 1;
	tcpLayer.getTcpHeader()->windowSize = htobe16(14600);

	PTF_ASSERT_TRUE(tcpLayer.addTcpOption(pcpp::TcpOptionBuilder(pcpp::TcpOptionBuilder::NOP)).isNotNull());
	PTF_ASSERT_EQUAL(tcpLayer.getHeaderLen(), 24, size);

	PTF_ASSERT_TRUE(tcpLayer.addTcpOptionAfter(pcpp::TcpOptionBuilder(pcpp::TCPOPT_MSS, (uint16_t)1460)).isNotNull());
	PTF_ASSERT_EQUAL(tcpLayer.getHeaderLen(), 28, size)

	pcpp::TcpOption tsOption = tcpLayer.addTcpOptionAfter(pcpp::TcpOptionBuilder(pcpp::PCPP_TCPOPT_TIMESTAMP, NULL, PCPP_TCPOLEN_TIMESTAMP-2), pcpp::TCPOPT_MSS);
	PTF_ASSERT_TRUE(tsOption.isNotNull());
	tsOption.setValue<uint32_t>(htobe32(197364));
	tsOption.setValue<uint32_t>(0, 4);
	PTF_ASSERT_EQUAL(tcpLayer.getHeaderLen(), 36, size)

	pcpp::TcpOption winScaleOption = tcpLayer.addTcpOption(pcpp::TcpOptionBuilder(pcpp::PCPP_TCPOPT_WINDOW, (uint8_t)4));
	PTF_ASSERT_TRUE(winScaleOption.isNotNull());
	PTF_ASSERT_EQUAL(tcpLayer.getHeaderLen(), 40, size);

	PTF_ASSERT_TRUE(tcpLayer.addTcpOptionAfter(pcpp::TcpOptionBuilder(pcpp::TCPOPT_SACK_PERM, NULL, 0), pcpp::TCPOPT_MSS).isNotNull());
	PTF_ASSERT_EQUAL(tcpLayer.getHeaderLen(), 40, size)

	PTF_ASSERT_EQUAL(tcpLayer.getTcpOptionCount(), 5, size);

	pcpp::Packet tcpPacket(1);
	PTF_ASSERT_TRUE(tcpPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(tcpPacket.addLayer(&ipLayer));
	PTF_ASSERT_TRUE(tcpPacket.addLayer(&tcpLayer));

	tcpPacket.computeCalculateFields();

	tcpLayer.getTcpHeader()->headerChecksum = 0xe013;

	READ_FILE_INTO_BUFFER(1, "PacketExamples/TcpPacketWithOptions3.dat");

	PTF_ASSERT_BUF_COMPARE(tcpPacket.getRawPacket()->getRawData(), buffer1, bufferLength1);

	pcpp::TcpOption qsOption = tcpLayer.addTcpOptionAfter(pcpp::TcpOptionBuilder(pcpp::TCPOPT_QS, NULL, PCPP_TCPOLEN_QS), pcpp::TCPOPT_MSS);
	PTF_ASSERT_TRUE(qsOption.isNotNull());
	PTF_ASSERT_TRUE(qsOption.setValue(htobe32(9999)));
	PTF_ASSERT_TRUE(tcpLayer.addTcpOption(pcpp::TcpOptionBuilder(pcpp::TCPOPT_SNACK, (uint32_t)htobe32(1000))).isNotNull());
	PTF_ASSERT_TRUE(tcpLayer.addTcpOptionAfter(pcpp::TcpOptionBuilder(pcpp::TcpOptionBuilder::NOP), pcpp::PCPP_TCPOPT_TIMESTAMP).isNotNull());

	PTF_ASSERT_EQUAL(tcpLayer.getTcpOptionCount(), 8, size);

	PTF_ASSERT_TRUE(tcpLayer.removeTcpOption(pcpp::TCPOPT_QS));
	PTF_ASSERT_EQUAL(tcpLayer.getTcpOptionCount(), 7, size);
	PTF_ASSERT_TRUE(tcpLayer.removeTcpOption(pcpp::TCPOPT_SNACK));
	PTF_ASSERT_TRUE(tcpLayer.removeTcpOption(pcpp::PCPP_TCPOPT_NOP));
	PTF_ASSERT_EQUAL(tcpLayer.getTcpOptionCount(), 5, size);

	PTF_ASSERT_BUF_COMPARE(tcpPacket.getRawPacket()->getRawData(), buffer1, bufferLength1);

	delete [] buffer1;

	PTF_ASSERT_TRUE(tcpLayer.removeAllTcpOptions());
	PTF_ASSERT_EQUAL(tcpLayer.getTcpOptionCount(), 0, size);
	PTF_ASSERT_TRUE(tcpLayer.getFirstTcpOption().isNull());
	PTF_ASSERT_EQUAL(tcpLayer.getHeaderLen(), 20, size);
	PTF_ASSERT_TRUE(tcpLayer.getTcpOption(pcpp::PCPP_TCPOPT_TIMESTAMP).isNull());

	pcpp::TcpOption tcpSnackOption = tcpLayer.addTcpOption(pcpp::TcpOptionBuilder(pcpp::TCPOPT_SNACK, NULL, PCPP_TCPOLEN_SNACK));
	PTF_ASSERT_TRUE(tcpSnackOption.isNotNull());
	PTF_ASSERT_TRUE(tcpSnackOption.setValue(htobe32(1000)));
} // TcpPacketCreation2