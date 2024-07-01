#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "UdpLayer.h"
#include "RadiusLayer.h"
#include "SystemUtils.h"

PTF_TEST_CASE(RadiusLayerParsingTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/radius_1.dat");
	pcpp::Packet radiusPacket(&rawPacket1);

	pcpp::RadiusLayer* radiusLayer = radiusPacket.getLayerOfType<pcpp::RadiusLayer>();
	PTF_ASSERT_NOT_NULL(radiusLayer);
	PTF_ASSERT_EQUAL(radiusLayer->getRadiusHeader()->code, 1);
	PTF_ASSERT_EQUAL(radiusLayer->getRadiusHeader()->id, 5);
	PTF_ASSERT_EQUAL(radiusLayer->getAuthenticatorValue(), "ecfe3d2fe4473ec6299095ee46aedf77");
	PTF_ASSERT_EQUAL(radiusLayer->getHeaderLen(), 139);
	PTF_ASSERT_EQUAL(pcpp::RadiusLayer::getRadiusMessageString(radiusLayer->getRadiusHeader()->code), "Access-Request");
	PTF_ASSERT_EQUAL(radiusLayer->getAttributeCount(), 10);
	uint8_t attrTypes[10] = { 4, 5, 61, 1, 30, 31, 6, 12, 79, 80 };
	size_t attrTotalSize[10] = { 6, 6, 6, 14, 19, 19, 6, 6, 19, 18 };
	size_t attrDataSize[10] = { 4, 4, 4, 12, 17, 17, 4, 4, 17, 16 };
	pcpp::RadiusAttribute radiusAttr = radiusLayer->getFirstAttribute();
	PTF_PRINT_VERBOSE("Iterating over RADIUS attributes");
	for (int i = 0; i < 10; i++)
	{
		PTF_PRINT_VERBOSE("Iteration #" << i);
		PTF_ASSERT_EQUAL(radiusAttr.getType(), attrTypes[i]);
		PTF_ASSERT_EQUAL(radiusAttr.getTotalSize(), attrTotalSize[i]);
		PTF_ASSERT_EQUAL(radiusAttr.getDataSize(), attrDataSize[i]);
		radiusAttr = radiusLayer->getNextAttribute(radiusAttr);
	}

	radiusAttr = radiusLayer->getAttribute(6);
	PTF_ASSERT_FALSE(radiusAttr.isNull());
	PTF_ASSERT_EQUAL(radiusAttr.getType(), 6);
	PTF_ASSERT_EQUAL(radiusAttr.getDataSize(), 4);
	PTF_ASSERT_EQUAL(radiusAttr.getTotalSize(), 6);
	PTF_ASSERT_EQUAL(htobe32(radiusAttr.getValueAs<int>()), 2);

	READ_FILE_AND_CREATE_PACKET_LINKTYPE(2, "PacketExamples/radius_3.dat", pcpp::LINKTYPE_NULL);
	pcpp::Packet radiusPacket2(&rawPacket2);

	radiusLayer = radiusPacket2.getLayerOfType<pcpp::RadiusLayer>();

	PTF_ASSERT_NOT_NULL(radiusLayer);
	PTF_ASSERT_EQUAL(radiusLayer->getRadiusHeader()->code, 3);
	PTF_ASSERT_EQUAL(radiusLayer->getRadiusHeader()->id, 104);
	PTF_ASSERT_EQUAL(radiusLayer->getAuthenticatorValue(), "71624da25c0b5897f70539e019a81eae");
	PTF_ASSERT_EQUAL(radiusLayer->getHeaderLen(), 44);
	PTF_ASSERT_EQUAL(pcpp::RadiusLayer::getRadiusMessageString(radiusLayer->getRadiusHeader()->code), "Access-Reject");
	PTF_ASSERT_EQUAL(radiusLayer->getAttributeCount(), 2);
	uint8_t attrTypes2[2] = { 79, 80 };
	size_t attrTotalSize2[2] = { 6, 18 };
	size_t attrDataSize2[2] = { 4, 16 };
	radiusAttr = radiusLayer->getFirstAttribute();
	PTF_PRINT_VERBOSE("Iterating over RADIUS attributes");
	for (int i = 0; i < 2; i++)
	{
		PTF_PRINT_VERBOSE("Iteration #" << i);
		PTF_ASSERT_EQUAL(radiusAttr.getType(), attrTypes2[i]);
		PTF_ASSERT_EQUAL(radiusAttr.getTotalSize(), attrTotalSize2[i]);
		PTF_ASSERT_EQUAL(radiusAttr.getDataSize(), attrDataSize2[i]);
		radiusAttr = radiusLayer->getNextAttribute(radiusAttr);
	}

	// incorrect RADIUS packet
	READ_FILE_AND_CREATE_PACKET_LINKTYPE(3, "PacketExamples/radius_wrong.dat", pcpp::LINKTYPE_NULL);
	pcpp::Packet radiusPacket3(&rawPacket3);

	radiusLayer = radiusPacket3.getLayerOfType<pcpp::RadiusLayer>();
	PTF_ASSERT_NULL(radiusLayer);
}  // RadiusLayerParsingTest

PTF_TEST_CASE(RadiusLayerCreationTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/radius_11.dat");

	pcpp::Packet radiusPacket(&rawPacket1);

	pcpp::EthLayer ethLayer(*radiusPacket.getLayerOfType<pcpp::EthLayer>());
	pcpp::IPv4Layer ip4Layer;
	ip4Layer = *(radiusPacket.getLayerOfType<pcpp::IPv4Layer>());
	pcpp::UdpLayer udpLayer(*radiusPacket.getLayerOfType<pcpp::UdpLayer>());

	pcpp::RadiusLayer radiusLayer(11, 5, "f050649184625d36f14c9075b7a48b83");
	pcpp::RadiusAttribute radiusNewAttr =
	    radiusLayer.addAttribute(pcpp::RadiusAttributeBuilder(8, pcpp::IPv4Address("255.255.255.254")));
	PTF_ASSERT_FALSE(radiusNewAttr.isNull());
	PTF_ASSERT_EQUAL(radiusNewAttr.getType(), 8);
	PTF_ASSERT_EQUAL(radiusNewAttr.getDataSize(), 4);

	radiusNewAttr = radiusLayer.addAttribute(pcpp::RadiusAttributeBuilder(12, (uint32_t)576));
	PTF_ASSERT_FALSE(radiusNewAttr.isNull());
	PTF_ASSERT_EQUAL(radiusNewAttr.getType(), 12);
	PTF_ASSERT_EQUAL(radiusNewAttr.getDataSize(), 4);
	PTF_ASSERT_EQUAL(radiusNewAttr.getValueAs<uint32_t>(), htobe32(576));

	pcpp::Packet newRadiusPacket;
	PTF_ASSERT_TRUE(newRadiusPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(newRadiusPacket.addLayer(&ip4Layer));
	PTF_ASSERT_TRUE(newRadiusPacket.addLayer(&udpLayer));
	PTF_ASSERT_TRUE(newRadiusPacket.addLayer(&radiusLayer));

	radiusNewAttr = radiusLayer.addAttribute(pcpp::RadiusAttributeBuilder(18, std::string("Hello, %u")));
	PTF_ASSERT_FALSE(radiusNewAttr.isNull());
	PTF_ASSERT_EQUAL(radiusNewAttr.getType(), 18);
	PTF_ASSERT_EQUAL(radiusNewAttr.getDataSize(), 9);

	radiusNewAttr = radiusLayer.addAttributeAfter(pcpp::RadiusAttributeBuilder(6, (uint32_t)2), 12);
	PTF_ASSERT_FALSE(radiusNewAttr.isNull());
	PTF_ASSERT_EQUAL(radiusNewAttr.getType(), 6);
	PTF_ASSERT_EQUAL(radiusNewAttr.getDataSize(), 4);

	uint8_t attrValue1[] = { 0xc6, 0xd1, 0x95, 0x03, 0x2f, 0xdc, 0x30, 0x24,
		                     0x0f, 0x73, 0x13, 0xb2, 0x31, 0xef, 0x1d, 0x77 };
	uint8_t attrValue1Len = 16;
	radiusNewAttr = radiusLayer.addAttribute(pcpp::RadiusAttributeBuilder(24, attrValue1, attrValue1Len));
	PTF_ASSERT_FALSE(radiusNewAttr.isNull());

	uint8_t attrValue2[] = { 0x01, 0x01, 0x00, 0x16, 0x04, 0x10, 0x26, 0x6b, 0x0e, 0x9a, 0x58,
		                     0x32, 0x2f, 0x4d, 0x01, 0xab, 0x25, 0xb3, 0x5f, 0x87, 0x94, 0x64 };
	uint8_t attrValue2Len = 22;
	radiusNewAttr = radiusLayer.addAttributeAfter(pcpp::RadiusAttributeBuilder(79, attrValue2, attrValue2Len), 18);
	PTF_ASSERT_FALSE(radiusNewAttr.isNull());

	uint8_t attrValue3[] = { 0x11, 0xb5, 0x04, 0x3c, 0x8a, 0x28, 0x87, 0x58,
		                     0x17, 0x31, 0x33, 0xa5, 0xe0, 0x74, 0x34, 0xcf };
	uint8_t attrValue3Len = 16;
	radiusNewAttr = radiusLayer.addAttributeAfter(pcpp::RadiusAttributeBuilder(80, attrValue3, attrValue3Len), 79);
	PTF_ASSERT_FALSE(radiusNewAttr.isNull());

	newRadiusPacket.computeCalculateFields();

	pcpp::RadiusLayer* origRadiusLayer = radiusPacket.getLayerOfType<pcpp::RadiusLayer>();
	pcpp::RadiusLayer* newRadiusLayer = newRadiusPacket.getLayerOfType<pcpp::RadiusLayer>();
	PTF_ASSERT_EQUAL(origRadiusLayer->getDataLen(), newRadiusLayer->getDataLen());
	PTF_ASSERT_BUF_COMPARE(origRadiusLayer->getData(), newRadiusLayer->getData(), origRadiusLayer->getDataLen());
}  // RadiusLayerCreationTest

PTF_TEST_CASE(RadiusLayerEditTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(11, "PacketExamples/radius_11.dat");
	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/radius_2.dat");

	pcpp::Packet radiusPacket11(&rawPacket11);
	pcpp::Packet radiusPacket2(&rawPacket2);

	pcpp::RadiusLayer* radiusLayer = radiusPacket11.getLayerOfType<pcpp::RadiusLayer>();
	PTF_ASSERT_NOT_NULL(radiusLayer);
	radiusLayer->getRadiusHeader()->code = 2;
	radiusLayer->getRadiusHeader()->id = 6;
	radiusLayer->setAuthenticatorValue("fbba6a784c7decb314caf0f27944a37b");

	PTF_ASSERT_TRUE(radiusLayer->removeAttribute(18));
	PTF_ASSERT_TRUE(radiusLayer->removeAttribute(79));
	PTF_ASSERT_TRUE(radiusLayer->removeAttribute(80));
	PTF_ASSERT_TRUE(radiusLayer->removeAttribute(24));

	pcpp::RadiusAttribute radiusNewAttr =
	    radiusLayer->addAttributeAfter(pcpp::RadiusAttributeBuilder(18, std::string("Hello, John.McGuirk")), 6);
	PTF_ASSERT_FALSE(radiusNewAttr.isNull());

	uint8_t attrValue1[] = { 0x03, 0x01, 0x00, 0x04 };
	uint8_t attrValue1Len = 4;
	radiusNewAttr = radiusLayer->addAttributeAfter(pcpp::RadiusAttributeBuilder(79, attrValue1, attrValue1Len), 18);
	PTF_ASSERT_FALSE(radiusNewAttr.isNull());

	uint8_t attrValue2[] = { 0xb9, 0xc4, 0xae, 0x62, 0x13, 0xa7, 0x1d, 0x32,
		                     0x12, 0x5e, 0xf7, 0xca, 0x4e, 0x4c, 0x63, 0x60 };
	uint8_t attrValue2Len = 16;
	radiusNewAttr = radiusLayer->addAttributeAfter(pcpp::RadiusAttributeBuilder(80, attrValue2, attrValue2Len), 79);
	PTF_ASSERT_FALSE(radiusNewAttr.isNull());

	radiusNewAttr = radiusLayer->addAttribute(pcpp::RadiusAttributeBuilder(1, std::string("John.McGuirk")));
	PTF_ASSERT_FALSE(radiusNewAttr.isNull());

	radiusPacket11.computeCalculateFields();

	pcpp::RadiusLayer* msg2OrigRadiusLayer = radiusPacket2.getLayerOfType<pcpp::RadiusLayer>();
	PTF_ASSERT_EQUAL(msg2OrigRadiusLayer->getDataLen(), radiusLayer->getDataLen());
	PTF_ASSERT_BUF_COMPARE(msg2OrigRadiusLayer->getData(), radiusLayer->getData(), msg2OrigRadiusLayer->getDataLen());

	// remove all attributes test

	PTF_ASSERT_TRUE(msg2OrigRadiusLayer->removeAllAttributes());
	radiusPacket2.computeCalculateFields();
	PTF_ASSERT_EQUAL(msg2OrigRadiusLayer->getAttributeCount(), 0);
	PTF_ASSERT_EQUAL(msg2OrigRadiusLayer->getHeaderLen(), sizeof(pcpp::radius_header));
	PTF_ASSERT_TRUE(msg2OrigRadiusLayer->getFirstAttribute().isNull());
	PTF_ASSERT_TRUE(msg2OrigRadiusLayer->getAttribute(6).isNull());
	PTF_ASSERT_TRUE(msg2OrigRadiusLayer->getAttribute(80).isNull());
}  // RadiusLayerEditTest
