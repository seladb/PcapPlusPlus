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
#include <tuple>

PTF_TEST_CASE(GtpV1LayerParsingTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

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
}  // GtpLayerParsingTest

PTF_TEST_CASE(GtpV1LayerCreationTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/gtp-u1.dat");
		READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/gtp-u-1ext.dat");
		READ_FILE_AND_CREATE_PACKET(3, "PacketExamples/gtp-u-2ext.dat");

		pcpp::Packet gtpPacket1(&rawPacket1);

		pcpp::EthLayer ethLayer(*gtpPacket1.getLayerOfType<pcpp::EthLayer>());
		pcpp::IPv4Layer ip4Layer(*gtpPacket1.getLayerOfType<pcpp::IPv4Layer>());
		pcpp::UdpLayer udpLayer(*gtpPacket1.getLayerOfType<pcpp::UdpLayer>());
		pcpp::GtpV1Layer gtpLayer(pcpp::GtpV1_GPDU, 1, true, 10461, false, 0);
		pcpp::IPv4Layer ip4Layer2(
		    *gtpPacket1.getNextLayerOfType<pcpp::IPv4Layer>(gtpPacket1.getLayerOfType<pcpp::UdpLayer>()));
		pcpp::IcmpLayer icmpLayer(*gtpPacket1.getLayerOfType<pcpp::IcmpLayer>());

		pcpp::Packet newGtpPacket;
		PTF_ASSERT_TRUE(newGtpPacket.addLayer(&ethLayer));
		PTF_ASSERT_TRUE(newGtpPacket.addLayer(&ip4Layer));
		PTF_ASSERT_TRUE(newGtpPacket.addLayer(&udpLayer));
		PTF_ASSERT_TRUE(newGtpPacket.addLayer(&gtpLayer));
		PTF_ASSERT_TRUE(newGtpPacket.addLayer(&ip4Layer2));
		PTF_ASSERT_TRUE(newGtpPacket.addLayer(&icmpLayer));
		newGtpPacket.computeCalculateFields();

		PTF_ASSERT_EQUAL(bufferLength1, newGtpPacket.getRawPacket()->getRawDataLen());
		PTF_ASSERT_BUF_COMPARE(newGtpPacket.getRawPacket()->getRawData(), buffer1,
		                       newGtpPacket.getRawPacket()->getRawDataLen());

		pcpp::GtpV1Layer* newGtpLayer = newGtpPacket.getLayerOfType<pcpp::GtpV1Layer>();

		pcpp::GtpV1Layer::GtpExtension newExt1 = newGtpLayer->addExtension(0xc0, 2308);
		PTF_ASSERT_FALSE(newExt1.isNull());
		PTF_ASSERT_EQUAL(newExt1.getExtensionType(), 0xc0);
		PTF_ASSERT_EQUAL(newExt1.getTotalLength(), 4 * sizeof(uint8_t));
		PTF_ASSERT_EQUAL(newExt1.getContentLength(), 2 * sizeof(uint8_t));
		uint16_t* content = reinterpret_cast<uint16_t*>(newExt1.getContent());
		PTF_ASSERT_EQUAL(be16toh(content[0]), 2308);
		PTF_ASSERT_TRUE(newExt1.getNextExtension().isNull());

		newGtpPacket.computeCalculateFields();

		PTF_ASSERT_EQUAL(bufferLength2, newGtpPacket.getRawPacket()->getRawDataLen());
		PTF_ASSERT_BUF_COMPARE(newGtpPacket.getRawPacket()->getRawData(), buffer2,
		                       newGtpPacket.getRawPacket()->getRawDataLen());

		pcpp::GtpV1Layer::GtpExtension newExt2 = newGtpLayer->addExtension(0x40, 1308);
		PTF_ASSERT_FALSE(newExt2.isNull());
		PTF_ASSERT_EQUAL(newExt2.getExtensionType(), 0x40);
		PTF_ASSERT_EQUAL(newExt2.getTotalLength(), 4 * sizeof(uint8_t));
		PTF_ASSERT_EQUAL(newExt2.getContentLength(), 2 * sizeof(uint8_t));
		content = reinterpret_cast<uint16_t*>(newExt2.getContent());
		PTF_ASSERT_EQUAL(be16toh(content[0]), 1308);
		PTF_ASSERT_TRUE(newExt2.getNextExtension().isNull());

		newGtpPacket.computeCalculateFields();

		PTF_ASSERT_FALSE(newGtpLayer->getNextExtension().isNull());
		PTF_ASSERT_FALSE(newGtpLayer->getNextExtension().getNextExtension().isNull());
		PTF_ASSERT_EQUAL(newGtpLayer->getNextExtension().getNextExtensionHeaderType(), 0x40);

		PTF_ASSERT_EQUAL(bufferLength3, newGtpPacket.getRawPacket()->getRawDataLen());
		PTF_ASSERT_BUF_COMPARE(newGtpPacket.getRawPacket()->getRawData(), buffer3,
		                       newGtpPacket.getRawPacket()->getRawDataLen());
	}

	{
		// Regression - issue #1711
		auto gtpLayer = std::unique_ptr<pcpp::GtpV1Layer>(
		    new pcpp::GtpV1Layer(pcpp::GtpV1MessageType::GtpV1_VersionNotSupported, 0x12345678, true, 1, false, 0));
		gtpLayer->getHeader()->messageType = 0xFF;
		gtpLayer->addExtension(0x85, 0x1234);
	}
}  // GtpLayerCreationTest

PTF_TEST_CASE(GtpV1LayerEditTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

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
	uint16_t* extContent = reinterpret_cast<uint16_t*>(gtpExtension.getContent());
	PTF_ASSERT_EQUAL(be16toh(extContent[0]), 1000);

	gtpHeader = gtpLayer->getHeader();
	PTF_ASSERT_EQUAL(be32toh(gtpHeader->teid), 10000);

	gtpPacket1.computeCalculateFields();

	PTF_ASSERT_EQUAL(bufferLength2, gtpPacket1.getRawPacket()->getRawDataLen());
	PTF_ASSERT_BUF_COMPARE(gtpPacket1.getRawPacket()->getRawData(), buffer2,
	                       gtpPacket1.getRawPacket()->getRawDataLen());

	delete[] buffer2;
}  // GtpLayerEditTest

PTF_TEST_CASE(GtpV2LayerParsingTest)
{
	timeval time{};
	gettimeofday(&time, nullptr);

	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/gtpv2-with-teid.dat");
		pcpp::Packet gtpPacket(&rawPacket1);

		PTF_ASSERT_TRUE(gtpPacket.isPacketOfType(pcpp::GTPv2));
		PTF_ASSERT_TRUE(gtpPacket.isPacketOfType(pcpp::GTP));
		auto gtpLayer = gtpPacket.getLayerOfType<pcpp::GtpV2Layer>();
		PTF_ASSERT_NOT_NULL(gtpLayer);

		PTF_ASSERT_EQUAL(gtpLayer->getMessageType(), pcpp::GtpV2MessageType::ModifyBearerRequest);
		PTF_ASSERT_EQUAL(gtpLayer->getMessageLength(), 107);
		PTF_ASSERT_FALSE(gtpLayer->isPiggybacking());
		PTF_ASSERT_EQUAL(gtpLayer->getHeaderLen(), 111);
		auto teid = gtpLayer->getTeid();
		PTF_ASSERT_TRUE(teid.first);
		PTF_ASSERT_EQUAL(teid.second, 0xd37d1590);
		PTF_ASSERT_EQUAL(gtpLayer->getSequenceNumber(), 0x1a4a43);
		PTF_ASSERT_FALSE(gtpLayer->getMessagePriority().first);
		PTF_ASSERT_EQUAL(gtpLayer->toString(), "GTPv2 Layer, Modify Bearer Request message");
		PTF_ASSERT_NULL(gtpLayer->getNextLayer());

		PTF_ASSERT_EQUAL(gtpLayer->getInformationElementCount(), 9);

		auto expectedIEValues = std::vector<
		    std::tuple<pcpp::GtpV2InformationElement::Type, size_t, size_t, uint8_t, uint8_t, uint8_t, uint8_t>>{
			{ pcpp::GtpV2InformationElement::Type::Uli,            17, 13, 0, 0, 0x18, 0x64 },
			{ pcpp::GtpV2InformationElement::Type::ServingNetwork, 7,  3,  0, 0, 0x64, 0xf6 },
			{ pcpp::GtpV2InformationElement::Type::RatType,        5,  1,  0, 0, 0x06, 0    },
			{ pcpp::GtpV2InformationElement::Type::FTeid,          13, 9,  0, 0, 0x86, 0xa4 },
			{ pcpp::GtpV2InformationElement::Type::Ambr,           12, 8,  0, 0, 0,    0    },
			{ pcpp::GtpV2InformationElement::Type::Mei,            12, 8,  0, 0, 0x53, 0x02 },
			{ pcpp::GtpV2InformationElement::Type::UeTimeZone,     6,  2,  0, 0, 0x23, 0    },
			{ pcpp::GtpV2InformationElement::Type::BearerContext,  22, 18, 0, 0, 0x49, 0    },
			{ pcpp::GtpV2InformationElement::Type::Recovery,       5,  1,  0, 0, 18,   0    },
		};

		auto infoElement = gtpLayer->getFirstInformationElement();
		for (auto expectedIEValue : expectedIEValues)
		{
			PTF_ASSERT_EQUAL(infoElement.getIEType(), std::get<0>(expectedIEValue), enumclass);
			PTF_ASSERT_EQUAL(infoElement.getTotalSize(), std::get<1>(expectedIEValue));
			PTF_ASSERT_EQUAL(infoElement.getDataSize(), std::get<2>(expectedIEValue));
			PTF_ASSERT_EQUAL(static_cast<int>(infoElement.getCRFlag()), static_cast<int>(std::get<3>(expectedIEValue)));
			PTF_ASSERT_EQUAL(static_cast<int>(infoElement.getInstance()),
			                 static_cast<int>(std::get<4>(expectedIEValue)));
			PTF_ASSERT_EQUAL(infoElement.getValueAs<uint8_t>(), std::get<5>(expectedIEValue));
			if (infoElement.getDataSize() > 1)
			{
				PTF_ASSERT_EQUAL(static_cast<int>(infoElement.getValueAs<uint8_t>(1)),
				                 static_cast<int>(std::get<6>(expectedIEValue)));
			}
			PTF_ASSERT_EQUAL(gtpLayer->getInformationElement(infoElement.getIEType()).getIEType(),
			                 std::get<0>(expectedIEValue), enumclass);
			infoElement = gtpLayer->getNextInformationElement(infoElement);
		}
		PTF_ASSERT_TRUE(infoElement.isNull());
	}

	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/gtpv2-with-piggyback.dat");
		pcpp::Packet gtpPacket(&rawPacket1);

		PTF_ASSERT_TRUE(gtpPacket.isPacketOfType(pcpp::GTPv2));
		PTF_ASSERT_TRUE(gtpPacket.isPacketOfType(pcpp::GTP));
		auto gtpLayer = gtpPacket.getLayerOfType<pcpp::GtpV2Layer>();
		PTF_ASSERT_NOT_NULL(gtpLayer);

		PTF_ASSERT_EQUAL(gtpLayer->getMessageType(), pcpp::GtpV2MessageType::EchoRequest);
		PTF_ASSERT_TRUE(gtpLayer->isPiggybacking());
		PTF_ASSERT_FALSE(gtpLayer->getTeid().first);
		PTF_ASSERT_EQUAL(gtpLayer->getSequenceNumber(), 12345);
		PTF_ASSERT_EQUAL(gtpLayer->toString(), "GTPv2 Layer, Echo Request message");
		PTF_ASSERT_EQUAL(gtpLayer->getInformationElementCount(), 1);

		gtpLayer = reinterpret_cast<pcpp::GtpV2Layer*>(gtpLayer->getNextLayer());
		PTF_ASSERT_NOT_NULL(gtpLayer);

		PTF_ASSERT_EQUAL(gtpLayer->getMessageType(), pcpp::GtpV2MessageType::CreateSessionResponse);
		PTF_ASSERT_FALSE(gtpLayer->isPiggybacking());
		auto teid = gtpLayer->getTeid();
		PTF_ASSERT_TRUE(teid.first);
		PTF_ASSERT_EQUAL(teid.second, 87654);
		PTF_ASSERT_EQUAL(gtpLayer->getSequenceNumber(), 67890);
		auto messagePriority = gtpLayer->getMessagePriority();
		PTF_ASSERT_TRUE(messagePriority.first);
		PTF_ASSERT_EQUAL(messagePriority.second, 9);
		PTF_ASSERT_EQUAL(gtpLayer->toString(), "GTPv2 Layer, Create Session Response message");
		PTF_ASSERT_NULL(gtpLayer->getNextLayer());
	}

	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/gtpv2-with-piggyback-malformed.dat");
		pcpp::Packet gtpPacket(&rawPacket1);
		PTF_ASSERT_TRUE(gtpPacket.isPacketOfType(pcpp::GTPv2));
		PTF_ASSERT_TRUE(gtpPacket.isPacketOfType(pcpp::GTP));
		auto gtpLayer = gtpPacket.getLayerOfType<pcpp::GtpV2Layer>();
		PTF_ASSERT_NOT_NULL(gtpLayer);
		PTF_ASSERT_TRUE(gtpLayer->isPiggybacking());
		PTF_ASSERT_NOT_NULL(gtpLayer->getNextLayer());
		PTF_ASSERT_EQUAL(gtpLayer->getNextLayer()->getProtocol(), pcpp::GenericPayload);
	}

	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/gtpv2-over-tcp.dat");
		pcpp::Packet gtpPacket(&rawPacket1);

		PTF_ASSERT_TRUE(gtpPacket.isPacketOfType(pcpp::GTPv2));
		PTF_ASSERT_TRUE(gtpPacket.isPacketOfType(pcpp::GTP));
		auto gtpLayer = gtpPacket.getLayerOfType<pcpp::GtpV2Layer>();
		PTF_ASSERT_NOT_NULL(gtpLayer);
		PTF_ASSERT_EQUAL(gtpLayer->getMessageType(), pcpp::GtpV2MessageType::DeleteSessionResponse);
		PTF_ASSERT_EQUAL(gtpLayer->toString(), "GTPv2 Layer, Delete Session Response message");
	}

	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/gtpv2-non-zero-cf-flag-instance.dat");
		pcpp::Packet gtpPacket(&rawPacket1);

		auto gtpLayer = gtpPacket.getLayerOfType<pcpp::GtpV2Layer>();
		PTF_ASSERT_NOT_NULL(gtpLayer);
		auto infoElement = gtpLayer->getFirstInformationElement();
		PTF_ASSERT_EQUAL(infoElement.getCRFlag(), 7);
		PTF_ASSERT_EQUAL(infoElement.getInstance(), 12);
	}
}  // GtpV2LayerParsingTest

PTF_TEST_CASE(GtpV2LayerCreationTest)
{
	timeval time{};
	gettimeofday(&time, nullptr);

	{
		pcpp::GtpV2Layer gtpLayer(pcpp::GtpV2MessageType::ModifyBearerRequest, 0x1a4a43, true, 0xd37d1590);

		// clang-format off
		std::vector<pcpp::GtpV2InformationElementBuilder> infoElementBuilders = {
			{ pcpp::GtpV2InformationElement::Type::Uli,           0, 0, { 0x18, 0x64, 0xf6, 0x29, 0x2e, 0x18, 0x64, 0xf6, 0x29, 0x01, 0xce, 0x66, 0x21 }                               },
			{ pcpp::GtpV2InformationElement::Type::RatType,       0, 0, { 0x06 }                                                                                                       },
			{ pcpp::GtpV2InformationElement::Type::FTeid,         0, 0, { 0x86, 0xa4, 0x3e, 0xd0, 0x30, 0x6f, 0x47, 0xec, 0x31 }                                                       },
			{ pcpp::GtpV2InformationElement::Type::Ambr,          0, 0, { 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x08, 0x00 }                                                             },
			{ pcpp::GtpV2InformationElement::Type::Mei,           0, 0, { 0x53, 0x02, 0x89, 0x70, 0x72, 0x61, 0x23, 0x60 }                                                             },
			{ pcpp::GtpV2InformationElement::Type::UeTimeZone,    0, 0, { 0x23, 0x00 }                                                                                                 },
			{ pcpp::GtpV2InformationElement::Type::BearerContext, 0, 0, { 0x49, 0x00, 0x01, 0x00, 0x05, 0x57, 0x00, 0x09, 0x01, 0x84, 0xa4, 0x30, 0xf3, 0xe2, 0x6f, 0x47, 0xec, 0x43 } },
		};
		// clang-format on

		for (const auto& infoElementBuilder : infoElementBuilders)
		{
			gtpLayer.addInformationElement(infoElementBuilder);
		}

		// clang-format off
		gtpLayer.addInformationElementAfter({ pcpp::GtpV2InformationElement::Type::ServingNetwork, 0, 0, { 0x64, 0xf6, 0x29 } },
		                                    pcpp::GtpV2InformationElement::Type::Uli);
		// clang-format on
		gtpLayer.addInformationElementAfter({ pcpp::GtpV2InformationElement::Type::Recovery, 0, 0, { 0x12 } },
		                                    pcpp::GtpV2InformationElement::Type::BearerContext);

		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/gtpv2-with-teid.dat");
		pcpp::Packet gtpPacket1(&rawPacket1);

		auto expectedGtpLayer = gtpPacket1.getLayerOfType<pcpp::GtpV2Layer>();
		PTF_ASSERT_NOT_NULL(expectedGtpLayer);

		PTF_ASSERT_EQUAL(gtpLayer.getDataLen(), expectedGtpLayer->getDataLen());
		PTF_ASSERT_BUF_COMPARE(gtpLayer.getData(), expectedGtpLayer->getData(), gtpLayer.getDataLen());
	}

	{
		pcpp::EthLayer ethLayer("10:5b:ad:b0:f5:07", "08:b4:b1:1a:46:ad", PCPP_ETHERTYPE_IP);
		pcpp::IPv4Layer ipLayer(pcpp::IPv4Address("192.168.1.100"), pcpp::IPv4Address("192.168.1.200"));
		ipLayer.getIPv4Header()->ipId = htobe16(1);
		ipLayer.getIPv4Header()->timeToLive = 64;
		pcpp::UdpLayer udpLayer(2123, 2123);

		pcpp::GtpV2Layer gtpLayer(pcpp::GtpV2MessageType::EchoRequest, 0x003039);
		gtpLayer.addInformationElement({ pcpp::GtpV2InformationElement::Type::Recovery, 0, 0, { 0x11 } });

		pcpp::GtpV2Layer piggybackGtpLayer(pcpp::GtpV2MessageType::CreateSessionResponse, 0x010932, true, 0x00015666,
		                                   true, 9);
		piggybackGtpLayer.addInformationElement({
		    pcpp::GtpV2InformationElement::Type::Imsi, 0, 0, { 0x33, 0x87, 0x93, 0x34, 0x49, 0x51, 0x83, 0xf6 }
        });

		pcpp::Packet newPacket;
		newPacket.addLayer(&ethLayer);
		newPacket.addLayer(&ipLayer);
		newPacket.addLayer(&udpLayer);
		newPacket.addLayer(&gtpLayer);
		newPacket.addLayer(&piggybackGtpLayer);
		newPacket.computeCalculateFields();

		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/gtpv2-with-piggyback.dat");
		pcpp::Packet expectedPacket(&rawPacket1);

		PTF_ASSERT_EQUAL(newPacket.getRawPacket()->getRawDataLen(), expectedPacket.getRawPacket()->getRawDataLen());
		PTF_ASSERT_BUF_COMPARE(newPacket.getRawPacket()->getRawData(), expectedPacket.getRawPacket()->getRawData(),
		                       newPacket.getRawPacket()->getRawDataLen());
	}

	{
		pcpp::GtpV2Layer gtpLayer(pcpp::GtpV2MessageType::ModifyBearerRequest, 0x1a4a43, true, 0xd37d1590, true, 1);
		gtpLayer.addInformationElement({
		    pcpp::GtpV2InformationElement::Type::Uli,
		    7,
		    12,
		    { 0x18, 0x64, 0xf6, 0x29, 0x2e, 0x18, 0x64, 0xf6, 0x29, 0x01, 0xce, 0x66, 0x21 }
        });

		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/gtpv2-non-zero-cf-flag-instance.dat");
		pcpp::Packet gtpPacket(&rawPacket1);

		auto expectedGtpLayer = gtpPacket.getLayerOfType<pcpp::GtpV2Layer>();
		PTF_ASSERT_NOT_NULL(expectedGtpLayer);

		PTF_ASSERT_EQUAL(gtpLayer.getDataLen(), expectedGtpLayer->getDataLen());
		PTF_ASSERT_BUF_COMPARE(gtpLayer.getData(), expectedGtpLayer->getData(), expectedGtpLayer->getDataLen());
	}
}  // GtpV2LayerCreationTest

PTF_TEST_CASE(GtpV2LayerEditTest)
{
	timeval time{};
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/gtpv2-non-zero-cf-flag-instance.dat");
	pcpp::Packet gtpPacket1(&rawPacket1);

	auto expectedGtpLayer1 = gtpPacket1.getLayerOfType<pcpp::GtpV2Layer>();
	PTF_ASSERT_NOT_NULL(expectedGtpLayer1);

	{
		pcpp::GtpV2Layer gtpLayer(pcpp::GtpV2MessageType::ISRStatus, 0x10);
		gtpLayer.addInformationElement({
		    pcpp::GtpV2InformationElement::Type::Uli,
		    7,
		    12,
		    { 0x18, 0x64, 0xf6, 0x29, 0x2e, 0x18, 0x64, 0xf6, 0x29, 0x01, 0xce, 0x66, 0x21 }
        });

		gtpLayer.setMessageType(pcpp::GtpV2MessageType::ModifyBearerRequest);
		gtpLayer.setTeid(0xd37d1590);
		gtpLayer.setMessagePriority(1);
		gtpLayer.setSequenceNumber(0x1a4a43);

		PTF_ASSERT_EQUAL(gtpLayer.getDataLen(), expectedGtpLayer1->getDataLen());
		PTF_ASSERT_BUF_COMPARE(gtpLayer.getData(), expectedGtpLayer1->getData(), expectedGtpLayer1->getDataLen());
	}

	{
		pcpp::GtpV2Layer gtpLayer(pcpp::GtpV2MessageType::ModifyBearerRequest, 0x1a4a43, true, 1, true, 2);
		gtpLayer.addInformationElement({
		    pcpp::GtpV2InformationElement::Type::Uli,
		    7,
		    12,
		    { 0x18, 0x64, 0xf6, 0x29, 0x2e, 0x18, 0x64, 0xf6, 0x29, 0x01, 0xce, 0x66, 0x21 }
        });

		gtpLayer.setTeid(0xd37d1590);
		gtpLayer.setMessagePriority(1);

		PTF_ASSERT_EQUAL(gtpLayer.getDataLen(), expectedGtpLayer1->getDataLen());
		PTF_ASSERT_BUF_COMPARE(gtpLayer.getData(), expectedGtpLayer1->getData(), expectedGtpLayer1->getDataLen());
	}

	{
		pcpp::GtpV2Layer gtpLayer(pcpp::GtpV2MessageType::EchoRequest, 12345, true, 1, true, 2);
		gtpLayer.addInformationElement({ pcpp::GtpV2InformationElement::Type::Recovery, 0, 0, { 0x11 } });

		READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/gtpv2-with-piggyback.dat");
		pcpp::Packet gtpPacket2(&rawPacket2);

		auto expectedGtpLayer2 = gtpPacket2.getLayerOfType<pcpp::GtpV2Layer>();
		PTF_ASSERT_NOT_NULL(expectedGtpLayer2);

		gtpLayer.unsetMessagePriority();
		gtpLayer.unsetTeid();

		PTF_ASSERT_EQUAL(gtpLayer.getHeaderLen(), expectedGtpLayer2->getHeaderLen());
		PTF_ASSERT_EQUAL(gtpLayer.getData()[0], 0x40);
		PTF_ASSERT_BUF_COMPARE(gtpLayer.getData() + 1, expectedGtpLayer2->getData() + 1,
		                       expectedGtpLayer2->getHeaderLen() - 1);

		gtpLayer.unsetMessagePriority();
		gtpLayer.unsetTeid();

		PTF_ASSERT_EQUAL(gtpLayer.getHeaderLen(), expectedGtpLayer2->getHeaderLen());
		PTF_ASSERT_EQUAL(gtpLayer.getData()[0], 0x40);
		PTF_ASSERT_BUF_COMPARE(gtpLayer.getData() + 1, expectedGtpLayer2->getData() + 1,
		                       expectedGtpLayer2->getHeaderLen() - 1);
	}

	{
		pcpp::GtpV2Layer gtpLayer(pcpp::GtpV2MessageType::ModifyBearerRequest, 0x1a4a43, true, 0xd37d1590, true, 1);
		gtpLayer.addInformationElement({
		    pcpp::GtpV2InformationElement::Type::Imsi, 0, 0, { 0x33, 0x87, 0x93, 0x34, 0x49, 0x51, 0x83, 0xf6 }
        });
		gtpLayer.addInformationElement({
		    pcpp::GtpV2InformationElement::Type::Uli,
		    7,
		    12,
		    { 0x18, 0x64, 0xf6, 0x29, 0x2e, 0x18, 0x64, 0xf6, 0x29, 0x01, 0xce, 0x66, 0x21 }
        });
		gtpLayer.addInformationElement({
		    pcpp::GtpV2InformationElement::Type::Imsi, 0, 0, { 0x33, 0x87, 0x93, 0x34, 0x49, 0x51, 0x83, 0xf6 }
        });
		gtpLayer.addInformationElement({ pcpp::GtpV2InformationElement::Type::Recovery, 0, 0, { 0x11 } });

		PTF_ASSERT_TRUE(gtpLayer.removeInformationElement(pcpp::GtpV2InformationElement::Type::Recovery));
		PTF_ASSERT_TRUE(gtpLayer.removeInformationElement(pcpp::GtpV2InformationElement::Type::Imsi));
		PTF_ASSERT_TRUE(gtpLayer.removeInformationElement(pcpp::GtpV2InformationElement::Type::Imsi));
		PTF_ASSERT_FALSE(gtpLayer.removeInformationElement(pcpp::GtpV2InformationElement::Type::Imsi));

		PTF_ASSERT_EQUAL(gtpLayer.getInformationElementCount(), 1);

		PTF_ASSERT_EQUAL(gtpLayer.getDataLen(), expectedGtpLayer1->getDataLen());
		PTF_ASSERT_BUF_COMPARE(gtpLayer.getData(), expectedGtpLayer1->getData(), expectedGtpLayer1->getDataLen());
	}

	{
		pcpp::GtpV2Layer gtpLayer(pcpp::GtpV2MessageType::ModifyBearerRequest, 0x1a4a43, true, 0xd37d1590, true, 1);
		gtpLayer.addInformationElement({
		    pcpp::GtpV2InformationElement::Type::Imsi, 0, 0, { 0x33, 0x87, 0x93, 0x34, 0x49, 0x51, 0x83, 0xf6 }
        });
		gtpLayer.addInformationElement({
		    pcpp::GtpV2InformationElement::Type::Uli,
		    7,
		    12,
		    { 0x18, 0x64, 0xf6, 0x29, 0x2e, 0x18, 0x64, 0xf6, 0x29, 0x01, 0xce, 0x66, 0x21 }
        });
		gtpLayer.addInformationElement({ pcpp::GtpV2InformationElement::Type::Recovery, 0, 0, { 0x11 } });

		gtpLayer.removeAllInformationElements();

		PTF_ASSERT_EQUAL(gtpLayer.getInformationElementCount(), 0);

		READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/gtpv2-no-info-elements.dat");
		pcpp::Packet gtpPacket2(&rawPacket2);

		auto expectedGtpLayer2 = gtpPacket2.getLayerOfType<pcpp::GtpV2Layer>();
		PTF_ASSERT_NOT_NULL(expectedGtpLayer2);

		PTF_ASSERT_EQUAL(gtpLayer.getDataLen(), expectedGtpLayer2->getDataLen());
		PTF_ASSERT_BUF_COMPARE(gtpLayer.getData(), expectedGtpLayer2->getData(), expectedGtpLayer2->getDataLen());
	}
}  // GtpV2LayerEditTest
