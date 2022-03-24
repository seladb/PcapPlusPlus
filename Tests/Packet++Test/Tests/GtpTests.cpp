#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "GtpLayer.h"
#include "UdpLayer.h"
#include "IcmpLayer.h"
#include "SystemUtils.h"


PTF_TEST_CASE(GtpLayerParsingTest)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/gtp-u1.dat");
	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/gtp-u2.dat");
	READ_FILE_AND_CREATE_PACKET(3, "PacketExamples/gtp-c1.dat");
	READ_FILE_AND_CREATE_PACKET(4, "PacketExamples/gtp-u-ipv6.dat");

	pcpp::Packet gtpPacket1(&rawPacket1);
	pcpp::Packet gtpPacket2(&rawPacket2);
	pcpp::Packet gtpPacket3(&rawPacket3);
	pcpp::Packet gtpPacket4(&rawPacket4);


	// GTP-U packet 1
	PTF_ASSERT_TRUE(gtpPacket1.isPacketOfType(pcpp::GTPv1));
	PTF_ASSERT_TRUE(gtpPacket1.isPacketOfType(pcpp::GTP));
	pcpp::GtpV1Layer* gtpLayer = gtpPacket1.getLayerOfType<pcpp::GtpV1Layer>();
	PTF_ASSERT_NOT_NULL(gtpLayer);

	PTF_ASSERT_NOT_NULL(gtpLayer->getHeader());
	PTF_ASSERT_EQUAL(gtpLayer->getHeader()->messageType, 0xff, hex);
	PTF_ASSERT_EQUAL(be16toh(gtpLayer->getHeader()->messageLength), 88);
	PTF_ASSERT_EQUAL(be32toh(gtpLayer->getHeader()->teid), 1);
	PTF_ASSERT_EQUAL(gtpLayer->getHeader()->protocolType, 1);

	uint16_t seqNum;
	PTF_ASSERT_TRUE(gtpLayer->getSequenceNumber(seqNum));
	PTF_ASSERT_EQUAL(seqNum, 10461);

	uint8_t npduNum;
	PTF_ASSERT_FALSE(gtpLayer->getNpduNumber(npduNum));

	uint8_t nextHeaderType;
	PTF_ASSERT_FALSE(gtpLayer->getNextExtensionHeaderType(nextHeaderType));

	PTF_ASSERT_EQUAL(gtpLayer->getMessageType(), pcpp::GtpV1_GPDU, enum);
	PTF_ASSERT_EQUAL(gtpLayer->getMessageTypeAsString(), "G-PDU");

	PTF_ASSERT_EQUAL(gtpLayer->getHeaderLen(), 12);
	PTF_ASSERT_EQUAL(gtpLayer->toString(), "GTP v1 Layer, GTP-U message, TEID: 1");

	PTF_ASSERT_NOT_NULL(gtpLayer->getNextLayer());
	PTF_ASSERT_EQUAL(gtpLayer->getNextLayer()->getProtocol(), pcpp::IPv4, enum);
	pcpp::IPv4Layer* ip4Layer = dynamic_cast<pcpp::IPv4Layer*>(gtpLayer->getNextLayer());
	PTF_ASSERT_EQUAL(ip4Layer->getSrcIPAddress().toString(), "202.11.40.158");
	PTF_ASSERT_NOT_NULL(ip4Layer->getNextLayer());
	PTF_ASSERT_EQUAL(ip4Layer->getNextLayer()->getProtocol(), pcpp::ICMP, enum);

	PTF_ASSERT_FALSE(gtpLayer->isGTPCMessage());
	PTF_ASSERT_TRUE(gtpLayer->isGTPUMessage());



	// GTP-U packet 2 (with GTP header extension)
	gtpLayer = gtpPacket2.getLayerOfType<pcpp::GtpV1Layer>();
	PTF_ASSERT_NOT_NULL(gtpLayer);

	PTF_ASSERT_NOT_NULL(gtpLayer->getHeader());
	PTF_ASSERT_EQUAL(be16toh(gtpLayer->getHeader()->messageLength), 1508);
	PTF_ASSERT_EQUAL(be32toh(gtpLayer->getHeader()->teid), 0x00100657);
	PTF_ASSERT_EQUAL(gtpLayer->getHeader()->protocolType, 1);

	PTF_ASSERT_EQUAL(gtpLayer->getMessageType(), pcpp::GtpV1_GPDU, enum);
	PTF_ASSERT_EQUAL(gtpLayer->getMessageTypeAsString(), "G-PDU");

	PTF_ASSERT_TRUE(gtpLayer->getSequenceNumber(seqNum));
	PTF_ASSERT_EQUAL(seqNum, 5);

	PTF_ASSERT_FALSE(gtpLayer->getNpduNumber(npduNum));

	PTF_ASSERT_TRUE(gtpLayer->getNextExtensionHeaderType(nextHeaderType));
	PTF_ASSERT_EQUAL(nextHeaderType, 0xc0, hex);

	pcpp::GtpV1Layer::GtpExtension gtpExt = gtpLayer->getNextExtension();
	PTF_ASSERT_FALSE(gtpExt.isNull());
	PTF_ASSERT_EQUAL(gtpExt.getExtensionType(), 0xc0, hex);
	PTF_ASSERT_EQUAL(gtpExt.getTotalLength(), 4);
	PTF_ASSERT_EQUAL(gtpExt.getContentLength(), 2);
	PTF_ASSERT_EQUAL(gtpExt.getNextExtensionHeaderType(), 0);
	PTF_ASSERT_TRUE(gtpExt.getNextExtension().isNull());

	PTF_ASSERT_EQUAL(gtpLayer->getHeaderLen(), 16);
	PTF_ASSERT_EQUAL(gtpLayer->toString(), "GTP v1 Layer, GTP-U message, TEID: 1050199");

	PTF_ASSERT_NOT_NULL(gtpLayer->getNextLayer());
	PTF_ASSERT_EQUAL(gtpLayer->getNextLayer()->getProtocol(), pcpp::IPv4, enum);
	ip4Layer = dynamic_cast<pcpp::IPv4Layer*>(gtpLayer->getNextLayer());
	PTF_ASSERT_EQUAL(ip4Layer->getDstIPAddress().toString(), "10.155.186.57");
	PTF_ASSERT_NOT_NULL(ip4Layer->getNextLayer());
	PTF_ASSERT_EQUAL(ip4Layer->getNextLayer()->getProtocol(), pcpp::TCP, enum);

	PTF_ASSERT_FALSE(gtpLayer->isGTPCMessage());
	PTF_ASSERT_TRUE(gtpLayer->isGTPUMessage());



	// GTP-U IPv6 packet
	gtpLayer = gtpPacket4.getLayerOfType<pcpp::GtpV1Layer>();
	PTF_ASSERT_NOT_NULL(gtpLayer);

	PTF_ASSERT_NOT_NULL(gtpLayer->getHeader());
	PTF_ASSERT_EQUAL(gtpLayer->getHeader()->messageType, 0xff, hex);
	PTF_ASSERT_EQUAL(be16toh(gtpLayer->getHeader()->messageLength), 496);
	PTF_ASSERT_EQUAL(be32toh(gtpLayer->getHeader()->teid), 2327461905U);
	PTF_ASSERT_EQUAL(gtpLayer->getHeader()->protocolType, 1);

	PTF_ASSERT_EQUAL(gtpLayer->getHeaderLen(), 8);
	PTF_ASSERT_EQUAL(gtpLayer->toString(), "GTP v1 Layer, GTP-U message, TEID: 2327461905");

	PTF_ASSERT_FALSE(gtpLayer->getSequenceNumber(seqNum));
	PTF_ASSERT_FALSE(gtpLayer->getNpduNumber(npduNum));
	PTF_ASSERT_FALSE(gtpLayer->getNextExtensionHeaderType(nextHeaderType));

	PTF_ASSERT_NOT_NULL(gtpLayer->getNextLayer());
	PTF_ASSERT_EQUAL(gtpLayer->getNextLayer()->getProtocol(), pcpp::IPv6, enum);
	pcpp::IPv6Layer* ip6Layer = dynamic_cast<pcpp::IPv6Layer*>(gtpLayer->getNextLayer());
	PTF_ASSERT_EQUAL(ip6Layer->getSrcIPAddress(), pcpp::IPv6Address("2001:507:0:1:200:8600:0:2"));
	PTF_ASSERT_NOT_NULL(ip6Layer->getNextLayer());
	PTF_ASSERT_EQUAL(ip6Layer->getNextLayer()->getProtocol(), pcpp::UDP, enum);

	PTF_ASSERT_FALSE(gtpLayer->isGTPCMessage());
	PTF_ASSERT_TRUE(gtpLayer->isGTPUMessage());



	// GTP-C packet
	PTF_ASSERT_TRUE(gtpPacket3.isPacketOfType(pcpp::GTP));
	PTF_ASSERT_TRUE(gtpPacket3.isPacketOfType(pcpp::GTPv1));
	gtpLayer = gtpPacket3.getLayerOfType<pcpp::GtpV1Layer>();
	PTF_ASSERT_NOT_NULL(gtpLayer);

	PTF_ASSERT_NOT_NULL(gtpLayer->getHeader());
	PTF_ASSERT_EQUAL(be16toh(gtpLayer->getHeader()->messageLength), 44);
	PTF_ASSERT_EQUAL(be32toh(gtpLayer->getHeader()->teid), 0x09fe4b60);
	PTF_ASSERT_EQUAL(gtpLayer->getHeader()->protocolType, 1);

	PTF_ASSERT_EQUAL(gtpLayer->getMessageType(), pcpp::GtpV1_SGSNContextResponse, enum);
	PTF_ASSERT_EQUAL(gtpLayer->getMessageTypeAsString(), "SGSN Context Response");

	PTF_ASSERT_TRUE(gtpLayer->getSequenceNumber(seqNum));
	PTF_ASSERT_EQUAL(seqNum, 34062);

	PTF_ASSERT_FALSE(gtpLayer->getNpduNumber(npduNum));

	PTF_ASSERT_FALSE(gtpLayer->getNextExtensionHeaderType(nextHeaderType));

	PTF_ASSERT_NULL(gtpLayer->getNextLayer());

	PTF_ASSERT_EQUAL(gtpLayer->getHeaderLen(), 52);
	PTF_ASSERT_EQUAL(gtpLayer->toString(), "GTP v1 Layer, GTP-C message: SGSN Context Response, TEID: 167660384");

	PTF_ASSERT_TRUE(gtpLayer->isGTPCMessage());
	PTF_ASSERT_FALSE(gtpLayer->isGTPUMessage());
} // GtpLayerParsingTest



PTF_TEST_CASE(GtpLayerCreationTest)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/gtp-u1.dat");
	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/gtp-u-1ext.dat");
	READ_FILE_AND_CREATE_PACKET(3, "PacketExamples/gtp-u-2ext.dat");

	pcpp::Packet gtpPacket1(&rawPacket1);
	pcpp::Packet newGtpPacket;

	pcpp::EthLayer ethLayer(*gtpPacket1.getLayerOfType<pcpp::EthLayer>());
	PTF_ASSERT_TRUE(newGtpPacket.addLayer(&ethLayer));

	pcpp::IPv4Layer ip4Layer(*gtpPacket1.getLayerOfType<pcpp::IPv4Layer>());
	PTF_ASSERT_TRUE(newGtpPacket.addLayer(&ip4Layer));

	pcpp::UdpLayer udpLayer(*gtpPacket1.getLayerOfType<pcpp::UdpLayer>());
	PTF_ASSERT_TRUE(newGtpPacket.addLayer(&udpLayer));

	pcpp::GtpV1Layer gtpLayer(pcpp::GtpV1_GPDU, 1, true, 10461, false, 0);
	PTF_ASSERT_TRUE(newGtpPacket.addLayer(&gtpLayer));

	pcpp::IPv4Layer ip4Layer2(*gtpPacket1.getNextLayerOfType<pcpp::IPv4Layer>(gtpPacket1.getLayerOfType<pcpp::UdpLayer>()));
	PTF_ASSERT_TRUE(newGtpPacket.addLayer(&ip4Layer2));

	pcpp::IcmpLayer icmpLayer(*gtpPacket1.getLayerOfType<pcpp::IcmpLayer>());
	PTF_ASSERT_TRUE(newGtpPacket.addLayer(&icmpLayer));

	newGtpPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(bufferLength1, newGtpPacket.getRawPacket()->getRawDataLen());
	PTF_ASSERT_BUF_COMPARE(newGtpPacket.getRawPacket()->getRawData(), buffer1, newGtpPacket.getRawPacket()->getRawDataLen());

	pcpp::GtpV1Layer* newGtpLayer = newGtpPacket.getLayerOfType<pcpp::GtpV1Layer>();

	pcpp::GtpV1Layer::GtpExtension newExt1 = newGtpLayer->addExtension(0xc0, 2308);
	PTF_ASSERT_FALSE(newExt1.isNull());
	PTF_ASSERT_EQUAL(newExt1.getExtensionType(), 0xc0);
	PTF_ASSERT_EQUAL(newExt1.getTotalLength(), 4*sizeof(uint8_t));
	PTF_ASSERT_EQUAL(newExt1.getContentLength(), 2*sizeof(uint8_t));
	uint16_t* content = (uint16_t*)newExt1.getContent();
	PTF_ASSERT_EQUAL(be16toh(content[0]), 2308);
	PTF_ASSERT_TRUE(newExt1.getNextExtension().isNull());

	newGtpPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(bufferLength2, newGtpPacket.getRawPacket()->getRawDataLen());
	PTF_ASSERT_BUF_COMPARE(newGtpPacket.getRawPacket()->getRawData(), buffer2, newGtpPacket.getRawPacket()->getRawDataLen());

	pcpp::GtpV1Layer::GtpExtension newExt2 = newGtpLayer->addExtension(0x40, 1308);
	PTF_ASSERT_FALSE(newExt2.isNull());
	PTF_ASSERT_EQUAL(newExt2.getExtensionType(), 0x40);
	PTF_ASSERT_EQUAL(newExt2.getTotalLength(), 4*sizeof(uint8_t));
	PTF_ASSERT_EQUAL(newExt2.getContentLength(), 2*sizeof(uint8_t));
	content = (uint16_t*)newExt2.getContent();
	PTF_ASSERT_EQUAL(be16toh(content[0]), 1308);
	PTF_ASSERT_TRUE(newExt2.getNextExtension().isNull());

	newGtpPacket.computeCalculateFields();

	PTF_ASSERT_FALSE(newGtpLayer->getNextExtension().isNull());
	PTF_ASSERT_FALSE(newGtpLayer->getNextExtension().getNextExtension().isNull());
	PTF_ASSERT_EQUAL(newGtpLayer->getNextExtension().getNextExtensionHeaderType(), 0x40);

	PTF_ASSERT_EQUAL(bufferLength3, newGtpPacket.getRawPacket()->getRawDataLen());
	PTF_ASSERT_BUF_COMPARE(newGtpPacket.getRawPacket()->getRawData(), buffer3, newGtpPacket.getRawPacket()->getRawDataLen());
} // GtpLayerCreationTest



PTF_TEST_CASE(GtpLayerEditTest)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/gtp-u-ipv6.dat");
	READ_FILE_INTO_BUFFER(2, "PacketExamples/gtp-u-ipv6-edited.dat");

	pcpp::Packet gtpPacket1(&rawPacket1);

	PTF_ASSERT_TRUE(gtpPacket1.isPacketOfType(pcpp::GTP));
	PTF_ASSERT_TRUE(gtpPacket1.isPacketOfType(pcpp::GTPv1));
	pcpp::GtpV1Layer* gtpLayer = gtpPacket1.getLayerOfType<pcpp::GtpV1Layer>();
	PTF_ASSERT_NOT_NULL(gtpLayer);

	pcpp::gtpv1_header* gtpHeader = gtpLayer->getHeader();
	PTF_ASSERT_NOT_NULL(gtpHeader);

	gtpHeader->teid = htobe32(10000);

	gtpLayer->setSequenceNumber(20000);
	gtpLayer->setNpduNumber(100);
	gtpLayer->addExtension(0xc0, 1000);

	uint16_t seqNum;
	PTF_ASSERT_TRUE(gtpLayer->getSequenceNumber(seqNum));
	PTF_ASSERT_EQUAL(seqNum, 20000);

	uint8_t npduNum;
	PTF_ASSERT_TRUE(gtpLayer->getNpduNumber(npduNum));
	PTF_ASSERT_EQUAL(npduNum, 100);

	uint8_t extType;
	PTF_ASSERT_TRUE(gtpLayer->getNextExtensionHeaderType(extType));
	PTF_ASSERT_EQUAL(extType, 0xc0);

	pcpp::GtpV1Layer::GtpExtension gtpExtension = gtpLayer->getNextExtension();
	PTF_ASSERT_FALSE(gtpExtension.isNull());
	uint16_t* extContent = (uint16_t*)gtpExtension.getContent();
	PTF_ASSERT_EQUAL(be16toh(extContent[0]), 1000);

	gtpHeader = gtpLayer->getHeader();
	PTF_ASSERT_EQUAL(be32toh(gtpHeader->teid), 10000);

	gtpPacket1.computeCalculateFields();

	PTF_ASSERT_EQUAL(bufferLength2, gtpPacket1.getRawPacket()->getRawDataLen());
	PTF_ASSERT_BUF_COMPARE(gtpPacket1.getRawPacket()->getRawData(), buffer2, gtpPacket1.getRawPacket()->getRawDataLen());

	delete [] buffer2;
} // GtpLayerEditTest
