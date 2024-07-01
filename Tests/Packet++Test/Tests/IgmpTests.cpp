#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "Logger.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "IgmpLayer.h"
#include "SystemUtils.h"

PTF_TEST_CASE(IgmpParsingTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/IGMPv1_1.dat");
	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/IGMPv2_1.dat");

	pcpp::Packet igmpv1Packet(&rawPacket1);
	pcpp::Packet igmpv2Packet(&rawPacket2);

	PTF_ASSERT_TRUE(igmpv1Packet.isPacketOfType(pcpp::IGMPv1));
	PTF_ASSERT_TRUE(igmpv1Packet.isPacketOfType(pcpp::IGMP));
	PTF_ASSERT_FALSE(igmpv1Packet.isPacketOfType(pcpp::IGMPv2));
	pcpp::IgmpV1Layer* igmpv1Layer = igmpv1Packet.getLayerOfType<pcpp::IgmpV1Layer>();
	PTF_ASSERT_NOT_NULL(igmpv1Layer);

	PTF_ASSERT_EQUAL(igmpv1Layer->getType(), pcpp::IgmpType_MembershipQuery, enum);
	PTF_ASSERT_EQUAL(igmpv1Layer->getGroupAddress(), pcpp::IPv4Address::Zero);
	PTF_ASSERT_EQUAL(igmpv1Layer->toString(), "IGMPv1 Layer, Membership Query message");

	PTF_ASSERT_TRUE(igmpv2Packet.isPacketOfType(pcpp::IGMPv2));
	PTF_ASSERT_TRUE(igmpv2Packet.isPacketOfType(pcpp::IGMP));
	PTF_ASSERT_FALSE(igmpv2Packet.isPacketOfType(pcpp::IGMPv1));
	pcpp::IgmpV2Layer* igmpv2Layer = igmpv2Packet.getLayerOfType<pcpp::IgmpV2Layer>();
	PTF_ASSERT_NOT_NULL(igmpv2Layer);

	PTF_ASSERT_EQUAL(igmpv2Layer->getType(), pcpp::IgmpType_MembershipReportV2, enum);
	PTF_ASSERT_EQUAL(igmpv2Layer->getGroupAddress(), pcpp::IPv4Address("239.255.255.250"));
	PTF_ASSERT_EQUAL(igmpv2Layer->toString(), "IGMPv2 Layer, Membership Report message");
}  // IgmpParsingTest

PTF_TEST_CASE(IgmpCreateAndEditTest)
{
	pcpp::MacAddress srcMac1(std::string("5c:d9:98:f9:1c:18"));
	pcpp::MacAddress dstMac1(std::string("01:00:5e:00:00:01"));
	pcpp::MacAddress srcMac2(std::string("00:15:58:dc:a8:4d"));
	pcpp::MacAddress dstMac2(std::string("01:00:5e:7f:ff:fa"));
	pcpp::EthLayer ethLayer1(srcMac1, dstMac1);
	pcpp::EthLayer ethLayer2(srcMac2, dstMac2);

	pcpp::IPv4Address srcIp1("10.0.200.151");
	pcpp::IPv4Address dstIp1("224.0.0.1");
	pcpp::IPv4Address srcIp2("10.60.2.7");
	pcpp::IPv4Address dstIp2("239.255.255.250");
	pcpp::IPv4Layer ipLayer1(srcIp1, dstIp1);
	pcpp::IPv4Layer ipLayer2(srcIp2, dstIp2);

	ipLayer1.getIPv4Header()->ipId = htobe16(2);
	ipLayer1.getIPv4Header()->timeToLive = 1;
	ipLayer2.getIPv4Header()->ipId = htobe16(3655);
	ipLayer2.getIPv4Header()->timeToLive = 1;

	pcpp::IgmpV1Layer igmpV1Layer(pcpp::IgmpType_MembershipQuery);
	pcpp::IgmpV2Layer igmpV2Layer(pcpp::IgmpType_MembershipReportV2, pcpp::IPv4Address("239.255.255.250"));

	pcpp::Packet igmpv1Packet(1);
	igmpv1Packet.addLayer(&ethLayer1);
	igmpv1Packet.addLayer(&ipLayer1);
	igmpv1Packet.addLayer(&igmpV1Layer);
	igmpv1Packet.computeCalculateFields();
	ipLayer1.getIPv4Header()->headerChecksum = 0x3d72;

	pcpp::Packet igmpv2Packet(1);
	igmpv2Packet.addLayer(&ethLayer2);
	igmpv2Packet.addLayer(&ipLayer2);
	igmpv2Packet.addLayer(&igmpV2Layer);
	igmpv2Packet.computeCalculateFields();
	ipLayer2.getIPv4Header()->headerChecksum = 0x541a;

	READ_FILE_INTO_BUFFER(1, "PacketExamples/IGMPv1_1.dat");
	READ_FILE_INTO_BUFFER(2, "PacketExamples/IGMPv2_1.dat");

	PTF_ASSERT_EQUAL(igmpv1Packet.getRawPacket()->getRawDataLen(), bufferLength1 - 14);
	PTF_ASSERT_BUF_COMPARE(igmpv1Packet.getRawPacket()->getRawData(), buffer1,
	                       igmpv1Packet.getRawPacket()->getRawDataLen());

	PTF_ASSERT_EQUAL(igmpv2Packet.getRawPacket()->getRawDataLen(), bufferLength2 - 14);
	PTF_ASSERT_BUF_COMPARE(igmpv2Packet.getRawPacket()->getRawData(), buffer2,
	                       igmpv2Packet.getRawPacket()->getRawDataLen());

	pcpp::IgmpV1Layer* igmpLayer = igmpv1Packet.getLayerOfType<pcpp::IgmpV1Layer>();
	igmpLayer->setType(pcpp::IgmpType_MembershipReportV2);
	igmpLayer->setGroupAddress(pcpp::IPv4Address("239.255.255.250"));
	igmpv1Packet.computeCalculateFields();

	PTF_ASSERT_BUF_COMPARE(igmpLayer->getData(), igmpV2Layer.getData(), igmpLayer->getHeaderLen());

	delete[] buffer1;
	delete[] buffer2;
}  // IgmpCreateAndEditTest

PTF_TEST_CASE(Igmpv3ParsingTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/igmpv3_query.dat");
	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/igmpv3_report.dat");

	pcpp::Packet igmpv3QueryPacket(&rawPacket1);
	pcpp::Packet igmpv3ReportPacket(&rawPacket2);

	PTF_ASSERT_TRUE(igmpv3QueryPacket.isPacketOfType(pcpp::IGMPv3));
	PTF_ASSERT_TRUE(igmpv3QueryPacket.isPacketOfType(pcpp::IGMP));
	PTF_ASSERT_FALSE(igmpv3QueryPacket.isPacketOfType(pcpp::IGMPv2));
	pcpp::IgmpV3QueryLayer* igmpv3QueryLayer = igmpv3QueryPacket.getLayerOfType<pcpp::IgmpV3QueryLayer>();
	PTF_ASSERT_NOT_NULL(igmpv3QueryLayer);
	PTF_ASSERT_EQUAL(igmpv3QueryLayer->getGroupAddress().toString(), "224.0.0.9");
	PTF_ASSERT_EQUAL(igmpv3QueryLayer->getIgmpV3QueryHeader()->s_qrv, 0x0f);
	PTF_ASSERT_EQUAL(igmpv3QueryLayer->getSourceAddressCount(), 1);
	PTF_ASSERT_EQUAL(igmpv3QueryLayer->getHeaderLen(), 16);
	PTF_ASSERT_EQUAL(igmpv3QueryLayer->getSourceAddressAtIndex(0).toString(), "192.168.20.222");
	PTF_ASSERT_EQUAL(igmpv3QueryLayer->getSourceAddressAtIndex(1).toString(), "0.0.0.0");
	PTF_ASSERT_EQUAL(igmpv3QueryLayer->getSourceAddressAtIndex(100).toString(), "0.0.0.0");
	PTF_ASSERT_EQUAL(igmpv3QueryLayer->getSourceAddressAtIndex(-1).toString(), "0.0.0.0");
	PTF_ASSERT_EQUAL(igmpv3QueryLayer->toString(), "IGMPv3 Layer, Membership Query message");

	igmpv3QueryLayer->getIgmpV3QueryHeader()->numOfSources = htobe16(100);

	PTF_ASSERT_EQUAL(igmpv3QueryLayer->getSourceAddressCount(), 100);
	PTF_ASSERT_EQUAL(igmpv3QueryLayer->getHeaderLen(), 16);
	PTF_ASSERT_EQUAL(igmpv3QueryLayer->getSourceAddressAtIndex(0).toString(), "192.168.20.222");
	PTF_ASSERT_EQUAL(igmpv3QueryLayer->getSourceAddressAtIndex(1).toString(), "0.0.0.0");
	PTF_ASSERT_EQUAL(igmpv3QueryLayer->getSourceAddressAtIndex(50).toString(), "0.0.0.0");
	PTF_ASSERT_EQUAL(igmpv3QueryLayer->getSourceAddressAtIndex(-1).toString(), "0.0.0.0");

	PTF_ASSERT_TRUE(igmpv3ReportPacket.isPacketOfType(pcpp::IGMPv3));
	PTF_ASSERT_TRUE(igmpv3ReportPacket.isPacketOfType(pcpp::IGMP));
	PTF_ASSERT_FALSE(igmpv3ReportPacket.isPacketOfType(pcpp::IGMPv1));
	pcpp::IgmpV3ReportLayer* igmpv3ReportLayer = igmpv3ReportPacket.getLayerOfType<pcpp::IgmpV3ReportLayer>();
	PTF_ASSERT_NOT_NULL(igmpv3ReportLayer);
	PTF_ASSERT_EQUAL(igmpv3ReportLayer->getGroupRecordCount(), 1);
	PTF_ASSERT_EQUAL(igmpv3ReportLayer->getHeaderLen(), 20);
	pcpp::igmpv3_group_record* curGroup = igmpv3ReportLayer->getFirstGroupRecord();
	PTF_ASSERT_NOT_NULL(curGroup);
	PTF_ASSERT_EQUAL(curGroup->recordType, 1);
	PTF_ASSERT_EQUAL(curGroup->getMulticastAddress().toString(), "224.0.0.9");
	PTF_ASSERT_EQUAL(curGroup->getSourceAddressCount(), 1);
	PTF_ASSERT_EQUAL(curGroup->getRecordLen(), 12);
	PTF_ASSERT_EQUAL(curGroup->getSourceAddressAtIndex(0).toString(), "192.168.20.222");
	PTF_ASSERT_EQUAL(curGroup->getSourceAddressAtIndex(-1).toString(), "0.0.0.0");
	PTF_ASSERT_EQUAL(curGroup->getSourceAddressAtIndex(1).toString(), "0.0.0.0");
	PTF_ASSERT_EQUAL(curGroup->getSourceAddressAtIndex(100).toString(), "0.0.0.0");
	curGroup = igmpv3ReportLayer->getNextGroupRecord(curGroup);
	PTF_ASSERT_NULL(curGroup);
	PTF_ASSERT_EQUAL(igmpv3ReportLayer->toString(), "IGMPv3 Layer, Membership Report message");
}  // Igmpv3ParsingTest

PTF_TEST_CASE(Igmpv3QueryCreateAndEditTest)
{
	pcpp::EthLayer ethLayer(pcpp::MacAddress("00:01:01:00:00:01"), pcpp::MacAddress("01:00:5e:00:00:09"));

	pcpp::IPv4Address srcIp("127.0.0.1");
	pcpp::IPv4Address dstIp("224.0.0.9");
	pcpp::IPv4Layer ipLayer(srcIp, dstIp);

	ipLayer.getIPv4Header()->ipId = htobe16(36760);
	ipLayer.getIPv4Header()->timeToLive = 1;

	pcpp::IPv4Address multicastAddr("224.0.0.11");
	pcpp::IgmpV3QueryLayer igmpV3QueryLayer(multicastAddr, 1, 0x0f);

	pcpp::IPv4Address srcAddr1("192.168.20.222");
	PTF_ASSERT_TRUE(igmpV3QueryLayer.addSourceAddress(srcAddr1));

	pcpp::Packet igmpv3QueryPacket(33);
	PTF_ASSERT_TRUE(igmpv3QueryPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(igmpv3QueryPacket.addLayer(&ipLayer));
	PTF_ASSERT_TRUE(igmpv3QueryPacket.addLayer(&igmpV3QueryLayer));

	pcpp::IPv4Address srcAddr2("1.2.3.4");
	PTF_ASSERT_TRUE(igmpV3QueryLayer.addSourceAddress(srcAddr2));

	pcpp::IPv4Address srcAddr3("10.20.30.40");
	PTF_ASSERT_TRUE(igmpV3QueryLayer.addSourceAddressAtIndex(srcAddr3, 0));

	pcpp::IPv4Address srcAddr4("100.200.255.255");

	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_FALSE(igmpV3QueryLayer.addSourceAddressAtIndex(srcAddr4, -1));
	PTF_ASSERT_FALSE(igmpV3QueryLayer.addSourceAddressAtIndex(srcAddr4, 4));
	igmpV3QueryLayer.getIgmpV3QueryHeader()->numOfSources = htobe16(100);
	PTF_ASSERT_FALSE(igmpV3QueryLayer.addSourceAddressAtIndex(srcAddr4, 4));
	igmpV3QueryLayer.getIgmpV3QueryHeader()->numOfSources = htobe16(3);
	pcpp::Logger::getInstance().enableLogs();

	PTF_ASSERT_TRUE(igmpV3QueryLayer.addSourceAddressAtIndex(srcAddr4, 2));

	pcpp::IPv4Address srcAddr5("11.22.33.44");
	PTF_ASSERT_TRUE(igmpV3QueryLayer.addSourceAddressAtIndex(srcAddr5, 4));

	igmpv3QueryPacket.computeCalculateFields();

	READ_FILE_INTO_BUFFER(1, "PacketExamples/igmpv3_query2.dat");

	PTF_ASSERT_EQUAL(igmpv3QueryPacket.getRawPacket()->getRawDataLen(), bufferLength1);
	PTF_ASSERT_BUF_COMPARE(igmpv3QueryPacket.getRawPacket()->getRawData(), buffer1,
	                       igmpv3QueryPacket.getRawPacket()->getRawDataLen());

	delete[] buffer1;

	PTF_ASSERT_TRUE(igmpV3QueryLayer.removeSourceAddressAtIndex(4));

	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_FALSE(igmpV3QueryLayer.removeSourceAddressAtIndex(4));
	PTF_ASSERT_FALSE(igmpV3QueryLayer.removeSourceAddressAtIndex(-1));
	igmpV3QueryLayer.getIgmpV3QueryHeader()->numOfSources = htobe16(100);
	PTF_ASSERT_FALSE(igmpV3QueryLayer.removeSourceAddressAtIndex(4));
	igmpV3QueryLayer.getIgmpV3QueryHeader()->numOfSources = htobe16(4);
	pcpp::Logger::getInstance().enableLogs();

	PTF_ASSERT_TRUE(igmpV3QueryLayer.removeSourceAddressAtIndex(0));
	PTF_ASSERT_TRUE(igmpV3QueryLayer.removeSourceAddressAtIndex(1));
	PTF_ASSERT_TRUE(igmpV3QueryLayer.removeSourceAddressAtIndex(1));

	igmpV3QueryLayer.setGroupAddress(pcpp::IPv4Address("224.0.0.9"));

	igmpv3QueryPacket.computeCalculateFields();

	ipLayer.getIPv4Header()->headerChecksum = 0x2d36;

	READ_FILE_INTO_BUFFER(2, "PacketExamples/igmpv3_query.dat");

	PTF_ASSERT_EQUAL(igmpv3QueryPacket.getRawPacket()->getRawDataLen(), bufferLength2);
	PTF_ASSERT_BUF_COMPARE(igmpv3QueryPacket.getRawPacket()->getRawData(), buffer2,
	                       igmpv3QueryPacket.getRawPacket()->getRawDataLen());

	delete[] buffer2;

	PTF_ASSERT_TRUE(igmpV3QueryLayer.removeAllSourceAddresses());
}  // Igmpv3QueryCreateAndEditTest

PTF_TEST_CASE(Igmpv3ReportCreateAndEditTest)
{
	pcpp::EthLayer ethLayer(pcpp::MacAddress("00:01:01:00:00:02"), pcpp::MacAddress("01:00:5e:00:00:16"));

	pcpp::IPv4Address srcIp("127.0.0.1");
	pcpp::IPv4Address dstIp("224.0.0.22");
	pcpp::IPv4Layer ipLayer(srcIp, dstIp);

	ipLayer.getIPv4Header()->ipId = htobe16(3941);
	ipLayer.getIPv4Header()->timeToLive = 1;

	pcpp::IgmpV3ReportLayer igmpV3ReportLayer;

	std::vector<pcpp::IPv4Address> srcAddrVec1;
	srcAddrVec1.push_back(pcpp::IPv4Address("192.168.20.222"));
	pcpp::igmpv3_group_record* groupRec =
	    igmpV3ReportLayer.addGroupRecord(1, pcpp::IPv4Address("224.0.0.9"), srcAddrVec1);
	PTF_ASSERT_NOT_NULL(groupRec);
	PTF_ASSERT_EQUAL(groupRec->getSourceAddressAtIndex(0), pcpp::IPv4Address("192.168.20.222"));

	std::vector<pcpp::IPv4Address> srcAddrVec2;
	srcAddrVec2.push_back(pcpp::IPv4Address("1.2.3.4"));
	srcAddrVec2.push_back(pcpp::IPv4Address("11.22.33.44"));
	srcAddrVec2.push_back(pcpp::IPv4Address("111.222.33.44"));
	groupRec = igmpV3ReportLayer.addGroupRecord(2, pcpp::IPv4Address("4.3.2.1"), srcAddrVec2);
	PTF_ASSERT_NOT_NULL(groupRec);
	PTF_ASSERT_EQUAL(groupRec->getSourceAddressCount(), 3);

	std::vector<pcpp::IPv4Address> srcAddrVec3;
	srcAddrVec3.push_back(pcpp::IPv4Address("12.34.56.78"));
	srcAddrVec3.push_back(pcpp::IPv4Address("88.77.66.55"));
	srcAddrVec3.push_back(pcpp::IPv4Address("44.33.22.11"));
	srcAddrVec3.push_back(pcpp::IPv4Address("255.255.255.255"));
	groupRec = igmpV3ReportLayer.addGroupRecordAtIndex(3, pcpp::IPv4Address("1.1.1.1"), srcAddrVec3, 0);
	PTF_ASSERT_NOT_NULL(groupRec);
	PTF_ASSERT_EQUAL(groupRec->getRecordLen(), 24);

	std::vector<pcpp::IPv4Address> srcAddrVec4;
	srcAddrVec4.push_back(pcpp::IPv4Address("13.24.57.68"));
	srcAddrVec4.push_back(pcpp::IPv4Address("31.42.75.86"));

	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_NULL(igmpV3ReportLayer.addGroupRecordAtIndex(4, pcpp::IPv4Address("1.3.5.7"), srcAddrVec4, -1));
	PTF_ASSERT_NULL(igmpV3ReportLayer.addGroupRecordAtIndex(4, pcpp::IPv4Address("1.3.5.7"), srcAddrVec4, 4));
	PTF_ASSERT_NULL(igmpV3ReportLayer.addGroupRecordAtIndex(4, pcpp::IPv4Address("1.3.5.7"), srcAddrVec4, 100));
	pcpp::Logger::getInstance().enableLogs();

	groupRec = igmpV3ReportLayer.addGroupRecordAtIndex(4, pcpp::IPv4Address("1.3.5.7"), srcAddrVec4, 1);
	PTF_ASSERT_NOT_NULL(groupRec);
	groupRec = igmpV3ReportLayer.addGroupRecordAtIndex(5, pcpp::IPv4Address("2.4.6.8"), srcAddrVec4, 4);
	PTF_ASSERT_NOT_NULL(groupRec);

	pcpp::Packet igmpv3ReportPacket;
	PTF_ASSERT_TRUE(igmpv3ReportPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(igmpv3ReportPacket.addLayer(&ipLayer));
	PTF_ASSERT_TRUE(igmpv3ReportPacket.addLayer(&igmpV3ReportLayer));

	igmpv3ReportPacket.computeCalculateFields();

	READ_FILE_INTO_BUFFER(1, "PacketExamples/igmpv3_report2.dat");

	PTF_ASSERT_EQUAL(igmpv3ReportPacket.getRawPacket()->getRawDataLen(), bufferLength1);
	PTF_ASSERT_BUF_COMPARE(igmpv3ReportPacket.getRawPacket()->getRawData(), buffer1,
	                       igmpv3ReportPacket.getRawPacket()->getRawDataLen());

	delete[] buffer1;

	PTF_ASSERT_TRUE(igmpV3ReportLayer.removeGroupRecordAtIndex(4));

	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_FALSE(igmpV3ReportLayer.removeGroupRecordAtIndex(4));
	PTF_ASSERT_FALSE(igmpV3ReportLayer.removeGroupRecordAtIndex(-1));
	PTF_ASSERT_FALSE(igmpV3ReportLayer.removeGroupRecordAtIndex(100));
	pcpp::Logger::getInstance().enableLogs();

	PTF_ASSERT_TRUE(igmpV3ReportLayer.removeGroupRecordAtIndex(0));
	PTF_ASSERT_TRUE(igmpV3ReportLayer.removeGroupRecordAtIndex(2));
	PTF_ASSERT_TRUE(igmpV3ReportLayer.removeGroupRecordAtIndex(0));

	READ_FILE_INTO_BUFFER(2, "PacketExamples/igmpv3_report.dat");

	PTF_ASSERT_EQUAL(igmpv3ReportPacket.getRawPacket()->getRawDataLen(), bufferLength2);

	igmpv3ReportPacket.computeCalculateFields();
	ipLayer.getIPv4Header()->headerChecksum = 0x4fb6;

	PTF_ASSERT_BUF_COMPARE(igmpv3ReportPacket.getRawPacket()->getRawData(), buffer2,
	                       igmpv3ReportPacket.getRawPacket()->getRawDataLen());

	delete[] buffer2;

	PTF_ASSERT_TRUE(igmpV3ReportLayer.removeAllGroupRecords());
}  // Igmpv3ReportCreateAndEditTest
