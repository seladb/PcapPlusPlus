#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "PayloadLayer.h"
#include "SystemUtils.h"
#include "PacketUtils.h"
#include "DeprecationUtils.h"

// TODO: remove these macros, when deprecated code is gone
DISABLE_WARNING_PUSH
DISABLE_WARNING_DEPRECATED

PTF_TEST_CASE(TcpPacketNoOptionsParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/TcpPacketNoOptions.dat");

	pcpp::Packet tcpPacketNoOptions(&rawPacket1);
	PTF_ASSERT_TRUE(tcpPacketNoOptions.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(tcpPacketNoOptions.isPacketOfType(pcpp::TCP));

	pcpp::TcpLayer* tcpLayer = tcpPacketNoOptions.getLayerOfType<pcpp::TcpLayer>();
	PTF_ASSERT_NOT_NULL(tcpLayer);

	PTF_ASSERT_EQUAL(tcpLayer->getDstPort(), 60388);
	PTF_ASSERT_EQUAL(tcpLayer->getSrcPort(), 80);
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->sequenceNumber, htobe32(0xbeab364a));
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->ackNumber, htobe32(0xf9ffb58e));
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->dataOffset, 5);
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->urgentPointer, 0);
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->headerChecksum, htobe16(0x4c03));

	// Flags
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->ackFlag, 1);
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->pshFlag, 1);
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->urgFlag, 0);
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->cwrFlag, 0);
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->synFlag, 0);
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->finFlag, 0);
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->rstFlag, 0);
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->eceFlag, 0);
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->reserved, 0);
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->accurateEcnFlag, 0);

	// TCP options
	PTF_ASSERT_EQUAL(tcpLayer->getTcpOptionCount(), 0);

	// TODO: remove deprecated
	PTF_ASSERT_TRUE(tcpLayer->getTcpOption(pcpp::PCPP_TCPOPT_NOP).isNull());
	PTF_ASSERT_TRUE(tcpLayer->getTcpOption(pcpp::PCPP_TCPOPT_TIMESTAMP).isNull());
	// end deprecated

	PTF_ASSERT_TRUE(tcpLayer->getTcpOption(pcpp::TcpOptionEnumType::Nop).isNull());
	PTF_ASSERT_TRUE(tcpLayer->getTcpOption(pcpp::TcpOptionEnumType::Timestamp).isNull());

	pcpp::Layer* afterTcpLayer = tcpLayer->getNextLayer();
	PTF_ASSERT_NOT_NULL(afterTcpLayer);
	PTF_ASSERT_EQUAL(afterTcpLayer->getProtocol(), pcpp::HTTPResponse, enum);
}  // TcpPacketNoOptionsParsing

PTF_TEST_CASE(TcpPacketWithAccurateEcnParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/TcpPacketNoOptionsAccEcn.dat");

	pcpp::Packet TcpPacketWithAccurateEcn(&rawPacket1);
	PTF_ASSERT_TRUE(TcpPacketWithAccurateEcn.isPacketOfType(pcpp::TCP));

	pcpp::TcpLayer* tcpLayer = TcpPacketWithAccurateEcn.getLayerOfType<pcpp::TcpLayer>();
	PTF_ASSERT_NOT_NULL(tcpLayer);

	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->reserved, 0);
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->accurateEcnFlag, 1);
}  // TcpPacketWithAccurateEcnParsing

PTF_TEST_CASE(TcpPacketWithOptionsParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/TcpPacketWithOptions.dat");

	pcpp::Packet tcpPacketWithOptions(&rawPacket1);
	PTF_ASSERT_TRUE(tcpPacketWithOptions.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(tcpPacketWithOptions.isPacketOfType(pcpp::TCP));

	pcpp::TcpLayer* tcpLayer = tcpPacketWithOptions.getLayerOfType<pcpp::TcpLayer>();
	PTF_ASSERT_NOT_NULL(tcpLayer);

	PTF_ASSERT_EQUAL(tcpLayer->getSrcPort(), 44147);
	PTF_ASSERT_EQUAL(tcpLayer->getDstPort(), 80);
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->ackFlag, 1);
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->pshFlag, 1);
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->synFlag, 0);
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->urgentPointer, 0);

	// TCP options
	PTF_ASSERT_EQUAL(tcpLayer->getTcpOptionCount(), 3);

	// TODO: remove deprecated
	PTF_ASSERT_TRUE(!tcpLayer->getTcpOption(pcpp::PCPP_TCPOPT_NOP).isNull());
	pcpp::TcpOption timestampOptionData = tcpLayer->getTcpOption(pcpp::PCPP_TCPOPT_TIMESTAMP);
	PTF_ASSERT_TRUE(!timestampOptionData.isNull());
	PTF_ASSERT_EQUAL(timestampOptionData.getTotalSize(), 10);
	uint32_t tsValue = timestampOptionData.getValueAs<uint32_t>();
	uint32_t tsEchoReply = timestampOptionData.getValueAs<uint32_t>(4);
	PTF_ASSERT_EQUAL(tsValue, htobe32(195102));
	PTF_ASSERT_EQUAL(tsEchoReply, htobe32(3555729271UL));
	// end deprecated

	PTF_ASSERT_TRUE(!tcpLayer->getTcpOption(pcpp::TcpOptionEnumType::Nop).isNull());
	pcpp::TcpOption timestampOptionData2 = tcpLayer->getTcpOption(pcpp::TcpOptionEnumType::Timestamp);
	PTF_ASSERT_TRUE(!timestampOptionData2.isNull());
	PTF_ASSERT_EQUAL(timestampOptionData2.getTotalSize(), 10);
	uint32_t tsValue2 = timestampOptionData2.getValueAs<uint32_t>();
	uint32_t tsEchoReply2 = timestampOptionData2.getValueAs<uint32_t>(4);
	PTF_ASSERT_EQUAL(tsValue2, htobe32(195102));
	PTF_ASSERT_EQUAL(tsEchoReply2, htobe32(3555729271UL));
}  // TcpPacketWithOptionsParsing

PTF_TEST_CASE(TcpPacketWithOptionsParsing2)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/TcpPacketWithOptions3.dat");

	pcpp::Packet tcpPacketWithOptions(&rawPacket1);

	pcpp::TcpLayer* tcpLayer = tcpPacketWithOptions.getLayerOfType<pcpp::TcpLayer>();
	PTF_ASSERT_NOT_NULL(tcpLayer);

	PTF_ASSERT_EQUAL(tcpLayer->getTcpOptionCount(), 5);

	// TODO: remove deprecated
	pcpp::TcpOption mssOption = tcpLayer->getTcpOption(pcpp::TCPOPT_MSS);
	pcpp::TcpOption sackPermOption = tcpLayer->getTcpOption(pcpp::TCPOPT_SACK_PERM);
	pcpp::TcpOption windowScaleOption = tcpLayer->getTcpOption(pcpp::PCPP_TCPOPT_WINDOW);
	PTF_ASSERT_TRUE(mssOption.isNotNull());
	PTF_ASSERT_TRUE(sackPermOption.isNotNull());
	PTF_ASSERT_TRUE(windowScaleOption.isNotNull());

	PTF_ASSERT_EQUAL(mssOption.getTcpOptionType(), pcpp::TCPOPT_MSS, enum);
	PTF_ASSERT_EQUAL(sackPermOption.getTcpOptionType(), pcpp::TCPOPT_SACK_PERM, enum);
	PTF_ASSERT_EQUAL(windowScaleOption.getTcpOptionType(), pcpp::PCPP_TCPOPT_WINDOW, enum);

	PTF_ASSERT_EQUAL(mssOption.getTotalSize(), 4);
	PTF_ASSERT_EQUAL(sackPermOption.getTotalSize(), 2);
	PTF_ASSERT_EQUAL(windowScaleOption.getTotalSize(), 3);

	PTF_ASSERT_EQUAL(mssOption.getValueAs<uint16_t>(), htobe16(1460));
	PTF_ASSERT_EQUAL(windowScaleOption.getValueAs<uint8_t>(), 4);
	PTF_ASSERT_EQUAL(sackPermOption.getValueAs<uint32_t>(), 0);
	PTF_ASSERT_EQUAL(mssOption.getValueAs<uint32_t>(), 0);
	PTF_ASSERT_EQUAL(mssOption.getValueAs<uint16_t>(1), 0);
	// end deprecated

	pcpp::TcpOption mssOption2 = tcpLayer->getTcpOption(pcpp::TcpOptionEnumType::Mss);
	pcpp::TcpOption sackPermOption2 = tcpLayer->getTcpOption(pcpp::TcpOptionEnumType::SackPerm);
	pcpp::TcpOption windowScaleOption2 = tcpLayer->getTcpOption(pcpp::TcpOptionEnumType::Window);
	PTF_ASSERT_TRUE(mssOption2.isNotNull());
	PTF_ASSERT_TRUE(sackPermOption2.isNotNull());
	PTF_ASSERT_TRUE(windowScaleOption2.isNotNull());

	PTF_ASSERT_EQUAL(mssOption2.getTcpOptionEnumType(), pcpp::TcpOptionEnumType::Mss, enumclass);
	PTF_ASSERT_EQUAL(sackPermOption2.getTcpOptionEnumType(), pcpp::TcpOptionEnumType::SackPerm, enumclass);
	PTF_ASSERT_EQUAL(windowScaleOption2.getTcpOptionEnumType(), pcpp::TcpOptionEnumType::Window, enumclass);

	PTF_ASSERT_EQUAL(mssOption2.getTotalSize(), 4);
	PTF_ASSERT_EQUAL(sackPermOption2.getTotalSize(), 2);
	PTF_ASSERT_EQUAL(windowScaleOption2.getTotalSize(), 3);

	PTF_ASSERT_EQUAL(mssOption2.getValueAs<uint16_t>(), htobe16(1460));
	PTF_ASSERT_EQUAL(windowScaleOption2.getValueAs<uint8_t>(), 4);
	PTF_ASSERT_EQUAL(sackPermOption2.getValueAs<uint32_t>(), 0);
	PTF_ASSERT_EQUAL(mssOption2.getValueAs<uint32_t>(), 0);
	PTF_ASSERT_EQUAL(mssOption2.getValueAs<uint16_t>(1), 0);

	// TODO: remove deprecated
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
	// end deprecated

	curOpt = tcpLayer->getFirstTcpOption();
	PTF_ASSERT_TRUE(curOpt.isNotNull() && curOpt.getTcpOptionEnumType() == pcpp::TcpOptionEnumType::Mss);
	curOpt = tcpLayer->getNextTcpOption(curOpt);
	PTF_ASSERT_TRUE(curOpt.isNotNull() && curOpt.getTcpOptionEnumType() == pcpp::TcpOptionEnumType::SackPerm);
	curOpt = tcpLayer->getNextTcpOption(curOpt);
	PTF_ASSERT_TRUE(curOpt.isNotNull() && curOpt.getTcpOptionEnumType() == pcpp::TcpOptionEnumType::Timestamp);
	curOpt = tcpLayer->getNextTcpOption(curOpt);
	PTF_ASSERT_TRUE(curOpt.isNotNull() && curOpt.getTcpOptionEnumType() == pcpp::TcpOptionEnumType::Nop);
	curOpt = tcpLayer->getNextTcpOption(curOpt);
	PTF_ASSERT_TRUE(curOpt.isNotNull() && curOpt.getTcpOptionEnumType() == pcpp::TcpOptionEnumType::Window);
	curOpt = tcpLayer->getNextTcpOption(curOpt);
	PTF_ASSERT_TRUE(curOpt.isNull());
}  // TcpPacketWithOptionsParsing2

PTF_TEST_CASE(TcpMalformedPacketParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/tcp-malformed1.dat");

	pcpp::Packet badTcpPacket(&rawPacket1);

	PTF_ASSERT_NOT_NULL(badTcpPacket.getLayerOfType<pcpp::IPv4Layer>());
	PTF_ASSERT_NULL(badTcpPacket.getLayerOfType<pcpp::TcpLayer>());
}  // TcpMalformedPacketParsing

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
	PTF_ASSERT_EQUAL(tcpLayer.getHeaderLen(), 24);
	PTF_ASSERT_TRUE(tcpLayer.addTcpOption(pcpp::TcpOptionBuilder(pcpp::TcpOptionBuilder::NOP)).isNotNull());
	PTF_ASSERT_EQUAL(tcpLayer.getHeaderLen(), 24);
	PTF_ASSERT_TRUE(
	    tcpLayer.addTcpOption(pcpp::TcpOptionBuilder(pcpp::PCPP_TCPOPT_TIMESTAMP, nullptr, PCPP_TCPOLEN_TIMESTAMP - 2))
	        .isNotNull());
	PTF_ASSERT_EQUAL(tcpLayer.getHeaderLen(), 32);

	PTF_ASSERT_TRUE(
	    tcpLayer.addTcpOption(pcpp::TcpOptionBuilder(pcpp::TcpOptionBuilder::NopEolOptionEnumType::Nop)).isNotNull());
	PTF_ASSERT_TRUE(
	    tcpLayer.addTcpOption(pcpp::TcpOptionBuilder(pcpp::TcpOptionEnumType::Window, nullptr, PCPP_TCPOLEN_WINDOW - 2))
	        .isNotNull());
	PTF_ASSERT_EQUAL(tcpLayer.getHeaderLen(), 36);
	PTF_ASSERT_EQUAL(tcpLayer.getTcpOptionCount(), 5);

	uint8_t payloadData[9] = { 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82 };
	pcpp::PayloadLayer payloadLayer(payloadData, 9);

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

	uint8_t windowScaleFactor = 2;
	pcpp::TcpOption windowOption = tcpLayer.getTcpOption(pcpp::TcpOptionEnumType::Window);
	PTF_ASSERT_TRUE(windowOption.isNotNull());
	windowOption.setValue<uint8_t>(windowScaleFactor);

	PTF_ASSERT_EQUAL(tcpLayer.getTcpOptionCount(), 5);

	tcpPacket.computeCalculateFields();

	READ_FILE_INTO_BUFFER(1, "PacketExamples/TcpPacketWithOptions2.dat");

	PTF_ASSERT_BUF_COMPARE(tcpPacket.getRawPacket()->getRawData(), buffer1, bufferLength1);

	delete[] buffer1;
}  // TcpPacketCreation

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
	PTF_ASSERT_EQUAL(tcpLayer.getHeaderLen(), 24);

	PTF_ASSERT_TRUE(tcpLayer.addTcpOptionAfter(pcpp::TcpOptionBuilder(pcpp::TCPOPT_MSS, (uint16_t)1460)).isNotNull());
	PTF_ASSERT_EQUAL(tcpLayer.getHeaderLen(), 28);

	pcpp::TcpOption tsOption = tcpLayer.addTcpOptionAfter(
	    pcpp::TcpOptionBuilder(pcpp::PCPP_TCPOPT_TIMESTAMP, nullptr, PCPP_TCPOLEN_TIMESTAMP - 2), pcpp::TCPOPT_MSS);
	PTF_ASSERT_TRUE(tsOption.isNotNull());
	tsOption.setValue<uint32_t>(htobe32(197364));
	tsOption.setValue<uint32_t>(0, 4);
	PTF_ASSERT_EQUAL(tcpLayer.getHeaderLen(), 36);

	pcpp::TcpOption winScaleOption =
	    tcpLayer.addTcpOption(pcpp::TcpOptionBuilder(pcpp::PCPP_TCPOPT_WINDOW, (uint8_t)4));
	PTF_ASSERT_TRUE(winScaleOption.isNotNull());
	PTF_ASSERT_EQUAL(tcpLayer.getHeaderLen(), 40);

	PTF_ASSERT_TRUE(
	    tcpLayer.addTcpOptionAfter(pcpp::TcpOptionBuilder(pcpp::TCPOPT_SACK_PERM, nullptr, 0), pcpp::TCPOPT_MSS)
	        .isNotNull());
	PTF_ASSERT_EQUAL(tcpLayer.getHeaderLen(), 40);

	PTF_ASSERT_EQUAL(tcpLayer.getTcpOptionCount(), 5);

	pcpp::Packet tcpPacket(1);
	PTF_ASSERT_TRUE(tcpPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(tcpPacket.addLayer(&ipLayer));
	PTF_ASSERT_TRUE(tcpPacket.addLayer(&tcpLayer));

	tcpPacket.computeCalculateFields();

	tcpLayer.getTcpHeader()->headerChecksum = 0xe013;

	READ_FILE_INTO_BUFFER(1, "PacketExamples/TcpPacketWithOptions3.dat");

	PTF_ASSERT_BUF_COMPARE(tcpPacket.getRawPacket()->getRawData(), buffer1, bufferLength1);

	pcpp::TcpOption qsOption =
	    tcpLayer.addTcpOptionAfter(pcpp::TcpOptionBuilder(pcpp::TCPOPT_QS, nullptr, PCPP_TCPOLEN_QS), pcpp::TCPOPT_MSS);
	PTF_ASSERT_TRUE(qsOption.isNotNull());
	PTF_ASSERT_TRUE(qsOption.setValue(htobe32(9999)));
	PTF_ASSERT_TRUE(
	    tcpLayer
	        .addTcpOption(pcpp::TcpOptionBuilder(pcpp::TcpOptionEnumType::Snack, static_cast<uint32_t>(htobe32(1000))))
	        .isNotNull());
	PTF_ASSERT_TRUE(tcpLayer
	                    .insertTcpOptionAfter(pcpp::TcpOptionBuilder(pcpp::TcpOptionBuilder::NopEolOptionEnumType::Nop),
	                                          pcpp::TcpOptionEnumType::Timestamp)
	                    .isNotNull());

	PTF_ASSERT_EQUAL(tcpLayer.getTcpOptionCount(), 8);

	PTF_ASSERT_TRUE(tcpLayer.removeTcpOption(pcpp::TcpOptionEnumType::Qs));
	PTF_ASSERT_EQUAL(tcpLayer.getTcpOptionCount(), 7);
	PTF_ASSERT_TRUE(tcpLayer.removeTcpOption(pcpp::TCPOPT_SNACK));
	PTF_ASSERT_TRUE(tcpLayer.removeTcpOption(pcpp::TcpOptionEnumType::Nop));
	PTF_ASSERT_EQUAL(tcpLayer.getTcpOptionCount(), 5);

	PTF_ASSERT_BUF_COMPARE(tcpPacket.getRawPacket()->getRawData(), buffer1, bufferLength1);

	delete[] buffer1;

	PTF_ASSERT_TRUE(tcpLayer.removeAllTcpOptions());
	PTF_ASSERT_EQUAL(tcpLayer.getTcpOptionCount(), 0);
	PTF_ASSERT_TRUE(tcpLayer.getFirstTcpOption().isNull());
	PTF_ASSERT_EQUAL(tcpLayer.getHeaderLen(), 20);
	PTF_ASSERT_TRUE(tcpLayer.getTcpOption(pcpp::PCPP_TCPOPT_TIMESTAMP).isNull());

	pcpp::TcpOption tcpSnackOption =
	    tcpLayer.addTcpOption(pcpp::TcpOptionBuilder(pcpp::TCPOPT_SNACK, nullptr, PCPP_TCPOLEN_SNACK));
	PTF_ASSERT_TRUE(tcpSnackOption.isNotNull());
	PTF_ASSERT_TRUE(tcpSnackOption.setValue(htobe32(1000)));
}  // TcpPacketCreation2

PTF_TEST_CASE(TcpChecksumInvalidRead)
{
	uint8_t* m = new uint8_t[3];
	m[0] = 0x01;
	m[1] = 0x12;
	m[2] = 0xF3;

	pcpp::ScalarBuffer<uint16_t> vec[1];
	vec[0].buffer = reinterpret_cast<uint16_t*>(m);
	vec[0].len = 3;

	uint16_t c = pcpp::computeChecksum(vec, 1);
	PTF_ASSERT_EQUAL(c, 0xbedU);

	delete[] m;
}  // TcpChecksumInvalidRead

PTF_TEST_CASE(TcpChecksumMultiBuffer)
{
	// Taken from https://en.wikipedia.org/wiki/IPv4_header_checksum#Calculating_the_IPv4_header_checksum
	uint16_t m[4] = { 0x4500, 0x0073, 0x0000, 0x4000 };
	uint16_t n[3] = { 0x4011, 0xc0a8, 0x0001 };
	uint16_t o[2] = { 0xc0a8, 0x00c7 };
	uint16_t checksum_expected = 0xb861;

	pcpp::ScalarBuffer<uint16_t> vec[4];
	vec[0].buffer = m;
	vec[0].len = 8;
	vec[1].buffer = n;
	vec[1].len = 6;
	vec[2].buffer = o;
	vec[2].len = 4;
	vec[3].buffer = &checksum_expected;
	vec[3].len = 2;

	uint16_t c = pcpp::computeChecksum(vec, 3);
	// computeChecksum return in network byte order
	PTF_ASSERT_EQUAL(c, htobe16(checksum_expected));

	// Adding the checksum should be equal to 0x0
	c = pcpp::computeChecksum(vec, 4);
	PTF_ASSERT_EQUAL(c, 0);
}  // TcpChecksumInvalidRead
DISABLE_WARNING_POP
