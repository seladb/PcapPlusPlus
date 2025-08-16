#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "BgpLayer.h"
#include "SystemUtils.h"

PTF_TEST_CASE(BgpLayerParsingTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/Bgp_keepalive.dat");
	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/Bgp_open.dat");
	READ_FILE_AND_CREATE_PACKET(3, "PacketExamples/Bgp_notification.dat");
	READ_FILE_AND_CREATE_PACKET(4, "PacketExamples/Bgp_notification2.dat");
	READ_FILE_AND_CREATE_PACKET(5, "PacketExamples/Bgp_route-refresh.dat");
	READ_FILE_AND_CREATE_PACKET(6, "PacketExamples/Bgp_update1.dat");
	READ_FILE_AND_CREATE_PACKET(7, "PacketExamples/Bgp_update2.dat");

	// parse BGP KEEPALIVE message

	pcpp::Packet bgpKAPacket(&rawPacket1);

	PTF_ASSERT_TRUE(bgpKAPacket.isPacketOfType(pcpp::BGP));
	pcpp::BgpLayer* bgpLayer = bgpKAPacket.getLayerOfType<pcpp::BgpLayer>();
	pcpp::BgpKeepaliveMessageLayer* bgpKALayer = bgpKAPacket.getLayerOfType<pcpp::BgpKeepaliveMessageLayer>();
	PTF_ASSERT_NOT_NULL(bgpLayer);
	PTF_ASSERT_NOT_NULL(bgpKALayer);
	PTF_ASSERT_EQUAL(bgpLayer->getBgpMessageType(), pcpp::BgpLayer::Keepalive, enum);
	PTF_ASSERT_EQUAL(bgpKALayer->getBgpMessageType(), pcpp::BgpLayer::Keepalive, enum);
	PTF_ASSERT_EQUAL(bgpLayer->getHeaderLen(), 19);
	PTF_ASSERT_EQUAL(bgpKALayer->getHeaderLen(), 19);
	for (int ind = 0; ind < 16; ind++)
	{
		PTF_ASSERT_EQUAL(bgpKALayer->getKeepaliveHeader()->marker[ind], 0xff);
	}
	PTF_ASSERT_EQUAL(be16toh(bgpKALayer->getKeepaliveHeader()->length), 19);

	// parse BGP OPEN message

	pcpp::Packet bgpOpenPacket(&rawPacket2);

	PTF_ASSERT_TRUE(bgpOpenPacket.isPacketOfType(pcpp::BGP));
	bgpLayer = bgpOpenPacket.getLayerOfType<pcpp::BgpLayer>();
	pcpp::BgpOpenMessageLayer* bgpOpenLayer = bgpOpenPacket.getLayerOfType<pcpp::BgpOpenMessageLayer>();
	PTF_ASSERT_NOT_NULL(bgpLayer);
	PTF_ASSERT_NOT_NULL(bgpOpenLayer);
	PTF_ASSERT_EQUAL(bgpLayer->getBgpMessageType(), pcpp::BgpLayer::Open, enum);
	PTF_ASSERT_EQUAL(bgpOpenLayer->getBgpMessageType(), pcpp::BgpLayer::Open, enum);
	PTF_ASSERT_EQUAL(bgpLayer->getHeaderLen(), 57);
	PTF_ASSERT_EQUAL(bgpOpenLayer->getHeaderLen(), 57);
	for (int ind = 0; ind < 16; ind++)
	{
		PTF_ASSERT_EQUAL(bgpOpenLayer->getOpenMsgHeader()->marker[ind], 0xff);
	}
	PTF_ASSERT_EQUAL(be16toh(bgpOpenLayer->getOpenMsgHeader()->myAutonomousSystem), 1);
	PTF_ASSERT_EQUAL(be16toh(bgpOpenLayer->getOpenMsgHeader()->holdTime), 180);
	PTF_ASSERT_EQUAL(bgpOpenLayer->getOpenMsgHeader()->optionalParameterLength, 28);
	PTF_ASSERT_EQUAL(bgpOpenLayer->getBgpId(), pcpp::IPv4Address("1.1.1.1"));
	PTF_ASSERT_EQUAL(bgpOpenLayer->getOptionalParametersLength(), 28);
	std::vector<pcpp::BgpOpenMessageLayer::optional_parameter> optionalParams;
	bgpOpenLayer->getOptionalParameters(optionalParams);
	PTF_ASSERT_EQUAL(optionalParams.size(), 5);
	uint8_t optParamsLength[5] = { 6, 2, 2, 2, 6 };
	int optParamsDataInedx[5] = { 3, 1, 0, 0, 5 };
	uint8_t optParamsData[5] = { 1, 0, 2, 0x46, 1 };
	for (int i = 0; i < 5; i++)
	{
		pcpp::BgpOpenMessageLayer::optional_parameter optParam = optionalParams[i];
		PTF_ASSERT_EQUAL(optParam.type, 2);
		PTF_ASSERT_EQUAL(optParam.length, optParamsLength[i]);
		PTF_ASSERT_EQUAL(optParam.value[optParamsDataInedx[i]], optParamsData[i]);
	}

	// parse BGP NOTIFICATION message

	pcpp::Packet bgpNotificationPacket(&rawPacket3);

	PTF_ASSERT_TRUE(bgpNotificationPacket.isPacketOfType(pcpp::BGP));
	pcpp::BgpNotificationMessageLayer* bgpNotificationLayer =
	    bgpNotificationPacket.getLayerOfType<pcpp::BgpNotificationMessageLayer>();
	PTF_ASSERT_NOT_NULL(bgpNotificationLayer);
	PTF_ASSERT_EQUAL(bgpNotificationLayer->getBgpMessageType(), pcpp::BgpLayer::Notification, enum);
	PTF_ASSERT_EQUAL(bgpNotificationLayer->getHeaderLen(), 146);
	for (int ind = 0; ind < 16; ind++)
	{
		PTF_ASSERT_EQUAL(bgpNotificationLayer->getNotificationMsgHeader()->marker[ind], 0xff);
	}
	PTF_ASSERT_EQUAL(bgpNotificationLayer->getNotificationMsgHeader()->errorCode, 6);
	PTF_ASSERT_EQUAL(bgpNotificationLayer->getNotificationMsgHeader()->errorSubCode, 2);
	PTF_ASSERT_EQUAL(bgpNotificationLayer->getNotificationDataLen(), 125);

	std::string notificationDataAsHexString =
	    "7c4e54542077696c6c20706572666f726d206d61696e74656e616e6365206f6e207468697320726f757465722e20546869732069732074"
	    "7261636b656420696e205449434b45542d312d32343832343239342e20436f6e74616374206e6f63406e74742e6e657420666f72206d6f"
	    "726520696e666f726d6174696f6e2e";
	PTF_ASSERT_EQUAL(bgpNotificationLayer->getNotificationDataAsHexString(), notificationDataAsHexString);

	pcpp::Packet bgpNotificationNoDataPacket(&rawPacket4);

	PTF_ASSERT_TRUE(bgpNotificationNoDataPacket.isPacketOfType(pcpp::BGP));
	bgpNotificationLayer = bgpNotificationNoDataPacket.getLayerOfType<pcpp::BgpNotificationMessageLayer>();
	PTF_ASSERT_NOT_NULL(bgpNotificationLayer);
	PTF_ASSERT_EQUAL(bgpNotificationLayer->getNotificationDataLen(), 0);
	PTF_ASSERT_NULL(bgpNotificationLayer->getNotificationData());
	PTF_ASSERT_EQUAL(bgpNotificationLayer->getNotificationDataAsHexString(), "");

	// parse BGP ROUTE-REFRESH message

	pcpp::Packet bgpRRPacket(&rawPacket5);

	PTF_ASSERT_TRUE(bgpRRPacket.isPacketOfType(pcpp::BGP));
	pcpp::BgpRouteRefreshMessageLayer* bgpRRLayer = bgpRRPacket.getLayerOfType<pcpp::BgpRouteRefreshMessageLayer>();
	PTF_ASSERT_NOT_NULL(bgpRRLayer);
	PTF_ASSERT_EQUAL(bgpRRLayer->getBgpMessageType(), pcpp::BgpLayer::RouteRefresh, enum);
	PTF_ASSERT_EQUAL(bgpRRLayer->getHeaderLen(), 23);
	PTF_ASSERT_EQUAL(be16toh(bgpRRLayer->getRouteRefreshHeader()->afi), 1);
	PTF_ASSERT_EQUAL(bgpRRLayer->getRouteRefreshHeader()->safi, 1);
	PTF_ASSERT_EQUAL(bgpRRLayer->getRouteRefreshHeader()->reserved, 1);

	// parse BGP UPDATE message with Withdrawn Routes

	pcpp::Packet bgpUpdatePacket1(&rawPacket6);

	PTF_ASSERT_TRUE(bgpUpdatePacket1.isPacketOfType(pcpp::BGP));
	pcpp::BgpUpdateMessageLayer* bgpUpdateLayer = bgpUpdatePacket1.getLayerOfType<pcpp::BgpUpdateMessageLayer>();
	PTF_ASSERT_NOT_NULL(bgpUpdateLayer);
	PTF_ASSERT_EQUAL(bgpUpdateLayer->getBgpMessageType(), pcpp::BgpLayer::Update, enum);
	PTF_ASSERT_EQUAL(bgpUpdateLayer->getHeaderLen(), 38);
	PTF_ASSERT_EQUAL(bgpUpdateLayer->getWithdrawnRoutesLength(), 15);
	std::vector<pcpp::BgpUpdateMessageLayer::prefix_and_ip> withdrawnRoutes;
	bgpUpdateLayer->getWithdrawnRoutes(withdrawnRoutes);
	PTF_ASSERT_EQUAL(withdrawnRoutes.size(), 4);
	pcpp::BgpUpdateMessageLayer::prefix_and_ip wr = withdrawnRoutes[0];
	PTF_ASSERT_EQUAL(wr.prefix, 24);
	PTF_ASSERT_EQUAL(wr.ipAddr, pcpp::IPv4Address("40.1.1.0"));
	wr = withdrawnRoutes[1];
	PTF_ASSERT_EQUAL(wr.prefix, 24);
	PTF_ASSERT_EQUAL(wr.ipAddr, pcpp::IPv4Address("40.40.40.0"));
	wr = withdrawnRoutes[2];
	PTF_ASSERT_EQUAL(wr.prefix, 16);
	PTF_ASSERT_EQUAL(wr.ipAddr, pcpp::IPv4Address("103.103.0.0"));
	wr = withdrawnRoutes[3];
	PTF_ASSERT_EQUAL(wr.prefix, 24);
	PTF_ASSERT_EQUAL(wr.ipAddr, pcpp::IPv4Address("103.103.40.0"));
	PTF_ASSERT_EQUAL(bgpUpdateLayer->getPathAttributesLength(), 0);
	std::vector<pcpp::BgpUpdateMessageLayer::path_attribute> pathAttributes;
	bgpUpdateLayer->getPathAttributes(pathAttributes);
	PTF_ASSERT_EQUAL(pathAttributes.size(), 0);
	PTF_ASSERT_NOT_NULL(bgpUpdateLayer->getNextLayer());
	PTF_ASSERT_EQUAL(bgpUpdateLayer->getNextLayer()->getProtocol(), pcpp::BGP, enum);

	// parse BGP UPDATE message with Path Attributes

	pcpp::Packet bgpUpdatePacket2(&rawPacket7);

	PTF_ASSERT_TRUE(bgpUpdatePacket2.isPacketOfType(pcpp::BGP));
	bgpUpdateLayer = bgpUpdatePacket2.getLayerOfType<pcpp::BgpUpdateMessageLayer>();
	PTF_ASSERT_NOT_NULL(bgpUpdateLayer);
	PTF_ASSERT_EQUAL(bgpUpdateLayer->getBgpMessageType(), pcpp::BgpLayer::Update, enum);
	PTF_ASSERT_EQUAL(bgpUpdateLayer->getHeaderLen(), 55);
	PTF_ASSERT_EQUAL(bgpUpdateLayer->getWithdrawnRoutesLength(), 0);
	withdrawnRoutes.clear();
	bgpUpdateLayer->getWithdrawnRoutes(withdrawnRoutes);
	PTF_ASSERT_EQUAL(withdrawnRoutes.size(), 0);
	pathAttributes.clear();
	PTF_ASSERT_EQUAL(bgpUpdateLayer->getPathAttributesLength(), 28);
	bgpUpdateLayer->getPathAttributes(pathAttributes);
	PTF_ASSERT_EQUAL(pathAttributes.size(), 3);
	pcpp::BgpUpdateMessageLayer::path_attribute pathAttr;
	pathAttr = pathAttributes[0];
	PTF_ASSERT_EQUAL(pathAttr.flags, 0x40);
	PTF_ASSERT_EQUAL(pathAttr.type, 1);
	PTF_ASSERT_EQUAL(pathAttr.length, 1);
	PTF_ASSERT_EQUAL(pathAttr.data[0], 2);
	pathAttr = pathAttributes[1];
	PTF_ASSERT_EQUAL(pathAttr.flags, 0x40);
	PTF_ASSERT_EQUAL(pathAttr.type, 2);
	PTF_ASSERT_EQUAL(pathAttr.length, 14);
	PTF_ASSERT_EQUAL(pathAttr.data[5], 0x0a);
	pathAttr = pathAttributes[2];
	PTF_ASSERT_EQUAL(pathAttr.flags, 0x40);
	PTF_ASSERT_EQUAL(pathAttr.type, 3);
	PTF_ASSERT_EQUAL(pathAttr.length, 4);
	PTF_ASSERT_EQUAL(pathAttr.data[2], 0x1e);
	PTF_ASSERT_EQUAL(bgpUpdateLayer->getNetworkLayerReachabilityInfoLength(), 4);
	std::vector<pcpp::BgpUpdateMessageLayer::prefix_and_ip> nlriVec;
	bgpUpdateLayer->getNetworkLayerReachabilityInfo(nlriVec);
	PTF_ASSERT_EQUAL(nlriVec.size(), 1);
	pcpp::BgpUpdateMessageLayer::prefix_and_ip nlri = nlriVec[0];
	PTF_ASSERT_EQUAL(nlri.prefix, 24);
	PTF_ASSERT_EQUAL(nlri.ipAddr, pcpp::IPv4Address("104.104.40.0"));
	size_t pathAttrSize[3] = { 28, 24, 0 };
	for (int i = 0; i < 3; i++)
	{
		PTF_ASSERT_NOT_NULL(bgpUpdateLayer->getNextLayer());
		PTF_ASSERT_EQUAL(bgpUpdateLayer->getNextLayer()->getProtocol(), pcpp::BGP, enum);
		bgpUpdateLayer = dynamic_cast<pcpp::BgpUpdateMessageLayer*>(bgpUpdateLayer->getNextLayer());
		PTF_ASSERT_NOT_NULL(bgpUpdateLayer);
		PTF_ASSERT_EQUAL(bgpUpdateLayer->getPathAttributesLength(), pathAttrSize[i]);
	}
}  // BgpLayerParsingTest

PTF_TEST_CASE(BgpLayerCreationTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/Bgp_keepalive.dat");
	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/Bgp_route-refresh.dat");
	READ_FILE_AND_CREATE_PACKET(3, "PacketExamples/Bgp_notification.dat");
	READ_FILE_AND_CREATE_PACKET(4, "PacketExamples/Bgp_notification2.dat");
	READ_FILE_AND_CREATE_PACKET(5, "PacketExamples/Bgp_update1.dat");
	READ_FILE_AND_CREATE_PACKET(6, "PacketExamples/Bgp_update2.dat");
	READ_FILE_AND_CREATE_PACKET(7, "PacketExamples/Bgp_open.dat");

	uint8_t origBuffer[1500];

	// create BGP KEEPALIVE message

	memcpy(origBuffer, buffer1, bufferLength1);
	pcpp::BgpKeepaliveMessageLayer newKAMessage;
	pcpp::Packet bgpKAPacket(&rawPacket1);
	pcpp::BgpKeepaliveMessageLayer* origKAMessage =
	    dynamic_cast<pcpp::BgpKeepaliveMessageLayer*>(bgpKAPacket.detachLayer(pcpp::BGP));
	PTF_ASSERT_NOT_NULL(origKAMessage);
	PTF_ASSERT_EQUAL(newKAMessage.getDataLen(), origKAMessage->getDataLen());
	PTF_ASSERT_BUF_COMPARE(newKAMessage.getData(), origKAMessage->getData(), origKAMessage->getDataLen());
	PTF_ASSERT_TRUE(bgpKAPacket.addLayer(&newKAMessage));
	bgpKAPacket.computeCalculateFields();
	PTF_ASSERT_EQUAL(bgpKAPacket.getRawPacket()->getRawDataLen(), bufferLength1);
	PTF_ASSERT_BUF_COMPARE(bgpKAPacket.getRawPacket()->getRawData(), origBuffer, bufferLength1);
	delete origKAMessage;

	// create BGP ROUTE-REFRESH message

	memcpy(origBuffer, buffer2, bufferLength2);
	pcpp::BgpRouteRefreshMessageLayer newRouteRefreshMessage(1, 1);
	pcpp::Packet bgpRouteRefreshPacket(&rawPacket2);
	pcpp::BgpRouteRefreshMessageLayer* origRouteRefreshMessage =
	    dynamic_cast<pcpp::BgpRouteRefreshMessageLayer*>(bgpRouteRefreshPacket.detachLayer(pcpp::BGP));
	PTF_ASSERT_NOT_NULL(origRouteRefreshMessage);
	newRouteRefreshMessage.getRouteRefreshHeader()->reserved = 1;
	PTF_ASSERT_EQUAL(newRouteRefreshMessage.getDataLen(), origRouteRefreshMessage->getDataLen());
	PTF_ASSERT_BUF_COMPARE(newRouteRefreshMessage.getData(), origRouteRefreshMessage->getData(),
	                       origRouteRefreshMessage->getDataLen());
	PTF_ASSERT_TRUE(bgpRouteRefreshPacket.addLayer(&newRouteRefreshMessage));
	bgpRouteRefreshPacket.computeCalculateFields();
	PTF_ASSERT_EQUAL(bgpRouteRefreshPacket.getRawPacket()->getRawDataLen(), bufferLength2);
	PTF_ASSERT_BUF_COMPARE(bgpRouteRefreshPacket.getRawPacket()->getRawData(), origBuffer, bufferLength2);
	delete origRouteRefreshMessage;

	// create BGP NOTIFICATION message with notification data

	memcpy(origBuffer, buffer3, bufferLength3);
	std::string notificationData =
	    "7c4e54542077696c6c20706572666f726d206d61696e74656e616e6365206f6e207468697320726f757465722e20546869732069732074"
	    "7261636b656420696e205449434b45542d312d32343832343239342e20436f6e74616374206e6f63406e74742e6e657420666f72206d6f"
	    "726520696e666f726d6174696f6e2e";
	pcpp::BgpNotificationMessageLayer newNotificationMessage(6, 2, notificationData);
	pcpp::Packet bgpNotificationPacket(&rawPacket3);
	pcpp::BgpNotificationMessageLayer* origNotificationMessage =
	    dynamic_cast<pcpp::BgpNotificationMessageLayer*>(bgpNotificationPacket.detachLayer(pcpp::BGP));
	PTF_ASSERT_NOT_NULL(origNotificationMessage);
	PTF_ASSERT_EQUAL(newNotificationMessage.getDataLen(), origNotificationMessage->getDataLen());
	PTF_ASSERT_BUF_COMPARE(newNotificationMessage.getData(), origNotificationMessage->getData(),
	                       origNotificationMessage->getDataLen());
	PTF_ASSERT_TRUE(bgpNotificationPacket.addLayer(&newNotificationMessage));
	bgpNotificationPacket.computeCalculateFields();
	PTF_ASSERT_EQUAL(bgpNotificationPacket.getRawPacket()->getRawDataLen(), bufferLength3);
	PTF_ASSERT_BUF_COMPARE(bgpNotificationPacket.getRawPacket()->getRawData(), origBuffer, bufferLength3);
	delete origNotificationMessage;

	// create BGP NOTIFICATION message without notification data

	memcpy(origBuffer, buffer4, bufferLength4);
	pcpp::BgpNotificationMessageLayer newNotificationMessage2(6, 4);
	pcpp::Packet bgpNotificationPacket2(&rawPacket4);
	origNotificationMessage =
	    dynamic_cast<pcpp::BgpNotificationMessageLayer*>(bgpNotificationPacket2.detachLayer(pcpp::BGP));
	PTF_ASSERT_NOT_NULL(origNotificationMessage);
	PTF_ASSERT_EQUAL(newNotificationMessage2.getDataLen(), origNotificationMessage->getDataLen());
	PTF_ASSERT_BUF_COMPARE(newNotificationMessage2.getData(), origNotificationMessage->getData(),
	                       origNotificationMessage->getDataLen());
	PTF_ASSERT_TRUE(bgpNotificationPacket2.addLayer(&newNotificationMessage2));
	bgpNotificationPacket2.computeCalculateFields();
	PTF_ASSERT_EQUAL(bgpNotificationPacket2.getRawPacket()->getRawDataLen(), bufferLength4);
	PTF_ASSERT_BUF_COMPARE(bgpNotificationPacket2.getRawPacket()->getRawData(), origBuffer, bufferLength4);
	delete origNotificationMessage;

	// create BGP UPDATE message with Withdrawn Routes

	memcpy(origBuffer, buffer5, bufferLength5);
	std::vector<pcpp::BgpUpdateMessageLayer::prefix_and_ip> withdrawnRoutes;
	withdrawnRoutes.push_back(pcpp::BgpUpdateMessageLayer::prefix_and_ip(24, "40.1.1.0"));
	withdrawnRoutes.push_back(pcpp::BgpUpdateMessageLayer::prefix_and_ip(24, "40.40.40.0"));
	withdrawnRoutes.push_back(pcpp::BgpUpdateMessageLayer::prefix_and_ip(16, "103.103.0.0"));
	withdrawnRoutes.push_back(pcpp::BgpUpdateMessageLayer::prefix_and_ip(24, "103.103.40.0"));
	pcpp::BgpUpdateMessageLayer newUpdateMessage(withdrawnRoutes);
	pcpp::Packet bgpUpdatePacket1(&rawPacket5);
	pcpp::BgpUpdateMessageLayer* origUpdateMessage =
	    dynamic_cast<pcpp::BgpUpdateMessageLayer*>(bgpUpdatePacket1.detachLayer(pcpp::BGP));
	PTF_ASSERT_NOT_NULL(origUpdateMessage);
	PTF_ASSERT_EQUAL(newUpdateMessage.getDataLen(), origUpdateMessage->getDataLen());
	PTF_ASSERT_BUF_COMPARE(newUpdateMessage.getData(), origUpdateMessage->getData(), origUpdateMessage->getDataLen());
	PTF_ASSERT_TRUE(bgpUpdatePacket1.insertLayer(bgpUpdatePacket1.getLayerOfType(pcpp::TCP), &newUpdateMessage));
	bgpUpdatePacket1.computeCalculateFields();
	PTF_ASSERT_EQUAL(bgpUpdatePacket1.getRawPacket()->getRawDataLen(), bufferLength5);
	PTF_ASSERT_BUF_COMPARE(bgpUpdatePacket1.getRawPacket()->getRawData(), origBuffer, bufferLength5);
	delete origUpdateMessage;

	// create BGP UPDATE message with Path Attributes and NLRI

	memcpy(origBuffer, buffer6, bufferLength6);
	std::vector<pcpp::BgpUpdateMessageLayer::path_attribute> pathAttributes;
	pathAttributes.push_back(pcpp::BgpUpdateMessageLayer::path_attribute(0x40, 1, "02"));
	pathAttributes.push_back(pcpp::BgpUpdateMessageLayer::path_attribute(0x40, 2, "02030000000a0000001400000028"));
	pathAttributes.push_back(pcpp::BgpUpdateMessageLayer::path_attribute(0x40, 3, "1e031e03"));
	std::vector<pcpp::BgpUpdateMessageLayer::prefix_and_ip> nlri;
	nlri.push_back(pcpp::BgpUpdateMessageLayer::prefix_and_ip(24, "104.104.40.0"));
	pcpp::BgpUpdateMessageLayer newUpdateMessage2(std::vector<pcpp::BgpUpdateMessageLayer::prefix_and_ip>(),
	                                              pathAttributes, nlri);
	pcpp::Packet bgpUpdatePacket2(&rawPacket6);
	origUpdateMessage = dynamic_cast<pcpp::BgpUpdateMessageLayer*>(bgpUpdatePacket2.detachLayer(pcpp::BGP));
	PTF_ASSERT_NOT_NULL(origUpdateMessage);
	PTF_ASSERT_EQUAL(newUpdateMessage2.getDataLen(), origUpdateMessage->getDataLen());
	PTF_ASSERT_BUF_COMPARE(newUpdateMessage2.getData(), origUpdateMessage->getData(), origUpdateMessage->getDataLen());
	PTF_ASSERT_TRUE(bgpUpdatePacket2.insertLayer(bgpUpdatePacket2.getLayerOfType(pcpp::TCP), &newUpdateMessage2));
	bgpUpdatePacket2.computeCalculateFields();
	PTF_ASSERT_EQUAL(bgpUpdatePacket2.getRawPacket()->getRawDataLen(), bufferLength6);
	PTF_ASSERT_BUF_COMPARE(bgpUpdatePacket2.getRawPacket()->getRawData(), origBuffer, bufferLength6);
	delete origUpdateMessage;

	// create BGP OPEN message

	memcpy(origBuffer, buffer7, bufferLength7);
	std::vector<pcpp::BgpOpenMessageLayer::optional_parameter> optionalParams;
	optionalParams.push_back(pcpp::BgpOpenMessageLayer::optional_parameter(2, "010400010001"));
	optionalParams.push_back(pcpp::BgpOpenMessageLayer::optional_parameter(2, "8000"));
	optionalParams.push_back(pcpp::BgpOpenMessageLayer::optional_parameter(2, "0200"));
	optionalParams.push_back(pcpp::BgpOpenMessageLayer::optional_parameter(2, "4600"));
	optionalParams.push_back(pcpp::BgpOpenMessageLayer::optional_parameter(2, "410400000001"));
	pcpp::BgpOpenMessageLayer newOpenMessage(1, 180, pcpp::IPv4Address("1.1.1.1"), optionalParams);
	pcpp::Packet bgpOpenPacket(&rawPacket7);
	pcpp::BgpOpenMessageLayer* origOpenMessage =
	    dynamic_cast<pcpp::BgpOpenMessageLayer*>(bgpOpenPacket.detachLayer(pcpp::BGP));
	PTF_ASSERT_NOT_NULL(origOpenMessage);
	PTF_ASSERT_EQUAL(newOpenMessage.getDataLen(), origOpenMessage->getDataLen());
	PTF_ASSERT_BUF_COMPARE(newOpenMessage.getData(), origOpenMessage->getData(), origOpenMessage->getDataLen());
	PTF_ASSERT_TRUE(bgpOpenPacket.addLayer(&newOpenMessage));
	bgpOpenPacket.computeCalculateFields();
	PTF_ASSERT_EQUAL(bgpOpenPacket.getRawPacket()->getRawDataLen(), bufferLength7);
	PTF_ASSERT_BUF_COMPARE(bgpOpenPacket.getRawPacket()->getRawData(), origBuffer, bufferLength7);
	delete origOpenMessage;

	// create packet with multiple BGP layers

	pcpp::EthLayer ethLayer(pcpp::MacAddress("fa:16:3e:34:89:43"), pcpp::MacAddress("fa:16:3e:22:35:cf"));

	pcpp::IPv4Layer ip4Layer(pcpp::IPv4Address("30.3.30.3"), pcpp::IPv4Address("30.3.30.30"));
	ip4Layer.getIPv4Header()->typeOfService = 0xc0;
	ip4Layer.getIPv4Header()->ipId = htobe16(11890);
	ip4Layer.getIPv4Header()->timeToLive = 1;
	ip4Layer.getIPv4Header()->fragmentOffset = 0x40;

	pcpp::TcpLayer tcpLayer(20576, 179);
	tcpLayer.getTcpHeader()->sequenceNumber = htobe32(3136152551);
	tcpLayer.getTcpHeader()->ackNumber = htobe32(4120889265);
	tcpLayer.getTcpHeader()->windowSize = htobe16(16306);
	tcpLayer.getTcpHeader()->pshFlag = 1;
	tcpLayer.getTcpHeader()->ackFlag = 1;

	withdrawnRoutes.clear();
	pathAttributes.clear();
	nlri.clear();
	pathAttributes.push_back(pcpp::BgpUpdateMessageLayer::path_attribute(0x40, 1, "02"));
	pathAttributes.push_back(pcpp::BgpUpdateMessageLayer::path_attribute(0x40, 2, "02030000000a0000001400000028"));
	pathAttributes.push_back(pcpp::BgpUpdateMessageLayer::path_attribute(0x40, 3, "1e031e03"));
	nlri.push_back(pcpp::BgpUpdateMessageLayer::prefix_and_ip(24, "104.104.40.0"));
	pcpp::BgpUpdateMessageLayer newBgpUpdateMessage1(withdrawnRoutes, pathAttributes, nlri);

	pathAttributes.clear();
	pathAttributes.push_back(pcpp::BgpUpdateMessageLayer::path_attribute(0x40, 1, "00"));
	pathAttributes.push_back(pcpp::BgpUpdateMessageLayer::path_attribute(0x40, 2, "02030000000a0000001400000028"));
	pathAttributes.push_back(pcpp::BgpUpdateMessageLayer::path_attribute(0x40, 3, "1e031e03"));
	nlri.clear();
	nlri.push_back(pcpp::BgpUpdateMessageLayer::prefix_and_ip(24, "40.1.1.0"));
	nlri.push_back(pcpp::BgpUpdateMessageLayer::prefix_and_ip(24, "40.40.40.0"));
	nlri.push_back(pcpp::BgpUpdateMessageLayer::prefix_and_ip(16, "103.103.0.0"));
	nlri.push_back(pcpp::BgpUpdateMessageLayer::prefix_and_ip(24, "103.103.40.0"));
	pcpp::BgpUpdateMessageLayer newBgpUpdateMessage2(withdrawnRoutes, pathAttributes, nlri);

	pathAttributes.clear();
	pathAttributes.push_back(pcpp::BgpUpdateMessageLayer::path_attribute(0x40, 1, "00"));
	pathAttributes.push_back(pcpp::BgpUpdateMessageLayer::path_attribute(0x40, 2, "02020000000a00000014"));
	pathAttributes.push_back(pcpp::BgpUpdateMessageLayer::path_attribute(0x40, 3, "1e031e03"));
	nlri.clear();
	nlri.push_back(pcpp::BgpUpdateMessageLayer::prefix_and_ip(32, "20.100.100.20"));
	pcpp::BgpUpdateMessageLayer newBgpUpdateMessage3(withdrawnRoutes, pathAttributes, nlri);

	pcpp::BgpUpdateMessageLayer newBgpUpdateMessage4;

	pcpp::Packet newBgpMultiLayerPacket;
	PTF_ASSERT_TRUE(newBgpMultiLayerPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(newBgpMultiLayerPacket.addLayer(&ip4Layer));
	PTF_ASSERT_TRUE(newBgpMultiLayerPacket.addLayer(&tcpLayer));
	PTF_ASSERT_TRUE(newBgpMultiLayerPacket.addLayer(&newBgpUpdateMessage1));
	PTF_ASSERT_TRUE(newBgpMultiLayerPacket.addLayer(&newBgpUpdateMessage2));
	PTF_ASSERT_TRUE(newBgpMultiLayerPacket.addLayer(&newBgpUpdateMessage3));
	PTF_ASSERT_TRUE(newBgpMultiLayerPacket.addLayer(&newBgpUpdateMessage4));
	newBgpMultiLayerPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(newBgpMultiLayerPacket.getRawPacket()->getRawDataLen(),
	                 bgpUpdatePacket2.getRawPacket()->getRawDataLen());
	PTF_ASSERT_BUF_COMPARE(newBgpMultiLayerPacket.getRawPacket()->getRawData(),
	                       bgpUpdatePacket2.getRawPacket()->getRawData(),
	                       bgpUpdatePacket2.getRawPacket()->getRawDataLen());

}  // BgpLayerCreationTest

PTF_TEST_CASE(BgpLayerEditTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/Bgp_notification.dat");
	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/Bgp_notification2.dat");
	READ_FILE_AND_CREATE_PACKET(3, "PacketExamples/Bgp_open.dat");
	READ_FILE_AND_CREATE_PACKET(4, "PacketExamples/Bgp_open2.dat");
	READ_FILE_AND_CREATE_PACKET(5, "PacketExamples/Bgp_update1.dat");
	READ_FILE_AND_CREATE_PACKET(6, "PacketExamples/Bgp_update2.dat");

	uint8_t origBuffer[1500];

	// edit BGP NOTIFICATION message

	memcpy(origBuffer, buffer1, bufferLength1);
	pcpp::Packet bgpNotificationPacket1(&rawPacket1);
	pcpp::Packet bgpNotificationPacket2(&rawPacket2);
	pcpp::BgpNotificationMessageLayer* bgpNotificationMessage1 =
	    bgpNotificationPacket1.getLayerOfType<pcpp::BgpNotificationMessageLayer>();
	PTF_ASSERT_NOT_NULL(bgpNotificationMessage1);
	PTF_ASSERT_TRUE(bgpNotificationMessage1->setNotificationData(nullptr, 0));
	bgpNotificationMessage1->getNotificationMsgHeader()->errorSubCode = 4;
	bgpNotificationPacket1.computeCalculateFields();
	pcpp::BgpNotificationMessageLayer* bgpNotificationMessage2 =
	    bgpNotificationPacket2.getLayerOfType<pcpp::BgpNotificationMessageLayer>();
	PTF_ASSERT_NOT_NULL(bgpNotificationMessage2);
	PTF_ASSERT_EQUAL(bgpNotificationMessage1->getDataLen(), bgpNotificationMessage2->getDataLen());
	PTF_ASSERT_BUF_COMPARE(bgpNotificationMessage1->getData(), bgpNotificationMessage2->getData(),
	                       bgpNotificationMessage2->getDataLen());

	pcpp::RawPacket rawPacket1Tag(origBuffer, bufferLength1, time, false);
	bgpNotificationPacket1.setRawPacket(&rawPacket1Tag, false);
	bgpNotificationMessage1 = bgpNotificationPacket1.getLayerOfType<pcpp::BgpNotificationMessageLayer>();
	std::string notificationData =
	    "7c4e54542077696c6c20706572666f726d206d61696e74656e616e6365206f6e207468697320726f757465722e20546869732069732074"
	    "7261636b656420696e205449434b45542d312d32343832343239342e20436f6e74616374206e6f63406e74742e6e657420666f72206d6f"
	    "726520696e666f726d6174696f6e2e";
	PTF_ASSERT_TRUE(bgpNotificationMessage2->setNotificationData(notificationData));
	bgpNotificationMessage2->getNotificationMsgHeader()->errorSubCode = 2;
	bgpNotificationPacket2.computeCalculateFields();
	PTF_ASSERT_EQUAL(bgpNotificationMessage1->getDataLen(), bgpNotificationMessage2->getDataLen());
	PTF_ASSERT_BUF_COMPARE(bgpNotificationMessage1->getData(), bgpNotificationMessage2->getData(),
	                       bgpNotificationMessage2->getDataLen());

	// edit BGP OPEN message

	pcpp::Packet bgpOpenPacket1(&rawPacket3);
	pcpp::Packet bgpOpenPacket2(&rawPacket4);
	pcpp::BgpOpenMessageLayer* bgpOpenMessage1 = bgpOpenPacket1.getLayerOfType<pcpp::BgpOpenMessageLayer>();
	pcpp::BgpOpenMessageLayer* bgpOpenMessage2 = bgpOpenPacket2.getLayerOfType<pcpp::BgpOpenMessageLayer>();
	PTF_ASSERT_NOT_NULL(bgpOpenMessage1);
	PTF_ASSERT_NOT_NULL(bgpOpenMessage2);
	bgpOpenMessage1->getOpenMsgHeader()->myAutonomousSystem = htobe16(64512);
	bgpOpenMessage1->setBgpId(pcpp::IPv4Address("10.0.0.6"));
	std::vector<pcpp::BgpOpenMessageLayer::optional_parameter> optionalParams;
	bgpOpenMessage1->getOptionalParameters(optionalParams);
	optionalParams.insert(optionalParams.begin() + 4, pcpp::BgpOpenMessageLayer::optional_parameter(2, "450400010103"));
	optionalParams.pop_back();
	optionalParams.push_back(pcpp::BgpOpenMessageLayer::optional_parameter(2, "41040000fc00"));
	PTF_ASSERT_TRUE(bgpOpenMessage1->setOptionalParameters(optionalParams));
	bgpOpenPacket1.computeCalculateFields();
	PTF_ASSERT_EQUAL(bgpOpenMessage1->getDataLen(), bgpOpenMessage2->getDataLen());
	PTF_ASSERT_BUF_COMPARE(bgpOpenMessage1->getData(), bgpOpenMessage2->getData(), bgpOpenMessage2->getDataLen());
	PTF_ASSERT_TRUE(bgpOpenMessage2->clearOptionalParameters());
	PTF_ASSERT_EQUAL(bgpOpenMessage2->getHeaderLen(), 29);
	PTF_ASSERT_EQUAL(bgpOpenMessage2->getOptionalParametersLength(), 0);

	// edit BGP UPDATE message

	pcpp::Packet bgpUpdatePacket1(&rawPacket5);
	pcpp::Packet bgpUpdatePacket2(&rawPacket6);
	pcpp::BgpUpdateMessageLayer* bgpUpdateMessage1Packet1 =
	    bgpUpdatePacket1.getLayerOfType<pcpp::BgpUpdateMessageLayer>();
	pcpp::BgpUpdateMessageLayer* bgpUpdateMessage2Packet1 =
	    bgpUpdatePacket1.getNextLayerOfType<pcpp::BgpUpdateMessageLayer>(bgpUpdateMessage1Packet1);
	pcpp::BgpUpdateMessageLayer* bgpUpdateMessage1Packet2 =
	    bgpUpdatePacket2.getLayerOfType<pcpp::BgpUpdateMessageLayer>();
	pcpp::BgpUpdateMessageLayer* bgpUpdateMessage2Packet2 =
	    bgpUpdatePacket2.getNextLayerOfType<pcpp::BgpUpdateMessageLayer>(bgpUpdateMessage1Packet2);
	pcpp::BgpUpdateMessageLayer* bgpUpdateMessage3Packet2 =
	    bgpUpdatePacket2.getNextLayerOfType<pcpp::BgpUpdateMessageLayer>(bgpUpdateMessage2Packet2);
	pcpp::BgpUpdateMessageLayer* bgpUpdateMessage4Packet2 =
	    bgpUpdatePacket2.getNextLayerOfType<pcpp::BgpUpdateMessageLayer>(bgpUpdateMessage3Packet2);
	PTF_ASSERT_NOT_NULL(bgpUpdateMessage1Packet1);
	PTF_ASSERT_NOT_NULL(bgpUpdateMessage2Packet1);
	PTF_ASSERT_NOT_NULL(bgpUpdateMessage1Packet2);
	PTF_ASSERT_NOT_NULL(bgpUpdateMessage2Packet2);
	PTF_ASSERT_NOT_NULL(bgpUpdateMessage3Packet2);
	PTF_ASSERT_NOT_NULL(bgpUpdateMessage4Packet2);

	std::vector<pcpp::BgpUpdateMessageLayer::prefix_and_ip> withdrawnRoutes;
	withdrawnRoutes.push_back(pcpp::BgpUpdateMessageLayer::prefix_and_ip(24, "104.104.40.0"));
	PTF_ASSERT_TRUE(bgpUpdateMessage1Packet1->setWithdrawnRoutes(withdrawnRoutes));
	PTF_ASSERT_EQUAL(bgpUpdateMessage1Packet1->getHeaderLen(), bgpUpdateMessage2Packet1->getHeaderLen());
	PTF_ASSERT_BUF_COMPARE(bgpUpdateMessage1Packet1->getData(), bgpUpdateMessage2Packet1->getData(),
	                       bgpUpdateMessage2Packet1->getHeaderLen());

	PTF_ASSERT_TRUE(bgpUpdateMessage1Packet1->clearWithdrawnRoutes());
	std::vector<pcpp::BgpUpdateMessageLayer::path_attribute> pathAttributes;
	std::vector<pcpp::BgpUpdateMessageLayer::prefix_and_ip> nlri;
	pathAttributes.push_back(pcpp::BgpUpdateMessageLayer::path_attribute(0x40, 1, "02"));
	pathAttributes.push_back(pcpp::BgpUpdateMessageLayer::path_attribute(0x40, 2, "02030000000a0000001400000028"));
	pathAttributes.push_back(pcpp::BgpUpdateMessageLayer::path_attribute(0x40, 3, "1e031e03"));
	nlri.push_back(pcpp::BgpUpdateMessageLayer::prefix_and_ip(24, "104.104.40.0"));
	PTF_ASSERT_TRUE(bgpUpdateMessage1Packet1->setPathAttributes(pathAttributes));
	PTF_ASSERT_TRUE(bgpUpdateMessage1Packet1->setNetworkLayerReachabilityInfo(nlri));
	PTF_ASSERT_EQUAL(bgpUpdateMessage1Packet1->getHeaderLen(), bgpUpdateMessage1Packet2->getHeaderLen());
	PTF_ASSERT_BUF_COMPARE(bgpUpdateMessage1Packet1->getData(), bgpUpdateMessage1Packet2->getData(),
	                       bgpUpdateMessage1Packet2->getHeaderLen());

	pathAttributes.erase(pathAttributes.begin());
	pathAttributes.insert(pathAttributes.begin(), pcpp::BgpUpdateMessageLayer::path_attribute(0x40, 1, "00"));
	PTF_ASSERT_TRUE(bgpUpdateMessage1Packet1->setPathAttributes(pathAttributes));
	nlri.clear();
	nlri.push_back(pcpp::BgpUpdateMessageLayer::prefix_and_ip(24, "40.1.1.0"));
	nlri.push_back(pcpp::BgpUpdateMessageLayer::prefix_and_ip(24, "40.40.40.0"));
	nlri.push_back(pcpp::BgpUpdateMessageLayer::prefix_and_ip(16, "103.103.0.0"));
	nlri.push_back(pcpp::BgpUpdateMessageLayer::prefix_and_ip(24, "103.103.40.0"));
	PTF_ASSERT_TRUE(bgpUpdateMessage1Packet1->setNetworkLayerReachabilityInfo(nlri));
	PTF_ASSERT_EQUAL(bgpUpdateMessage1Packet1->getHeaderLen(), bgpUpdateMessage2Packet2->getHeaderLen());
	PTF_ASSERT_BUF_COMPARE(bgpUpdateMessage1Packet1->getData(), bgpUpdateMessage2Packet2->getData(),
	                       bgpUpdateMessage2Packet2->getHeaderLen());

	pathAttributes.erase(pathAttributes.begin() + 1);
	pathAttributes.insert(pathAttributes.begin() + 1,
	                      pcpp::BgpUpdateMessageLayer::path_attribute(0x40, 2, "02020000000a00000014"));
	PTF_ASSERT_TRUE(bgpUpdateMessage1Packet1->setPathAttributes(pathAttributes));
	nlri.clear();
	nlri.push_back(pcpp::BgpUpdateMessageLayer::prefix_and_ip(32, "20.100.100.20"));
	PTF_ASSERT_TRUE(bgpUpdateMessage1Packet1->setNetworkLayerReachabilityInfo(nlri));
	PTF_ASSERT_EQUAL(bgpUpdateMessage1Packet1->getHeaderLen(), bgpUpdateMessage3Packet2->getHeaderLen());
	PTF_ASSERT_BUF_COMPARE(bgpUpdateMessage1Packet1->getData(), bgpUpdateMessage3Packet2->getData(),
	                       bgpUpdateMessage3Packet2->getHeaderLen());

	PTF_ASSERT_TRUE(bgpUpdateMessage1Packet1->clearNetworkLayerReachabilityInfo());
	PTF_ASSERT_TRUE(bgpUpdateMessage1Packet1->clearPathAttributes());
	PTF_ASSERT_EQUAL(bgpUpdateMessage1Packet1->getHeaderLen(), bgpUpdateMessage4Packet2->getHeaderLen());
	PTF_ASSERT_BUF_COMPARE(bgpUpdateMessage1Packet1->getData(), bgpUpdateMessage4Packet2->getData(),
	                       bgpUpdateMessage4Packet2->getHeaderLen());

}  // BgpLayerEditTest
