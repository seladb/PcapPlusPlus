#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "Packet.h"
#include "Logger.h"
#include "EthLayer.h"
#include "IcmpLayer.h"
#include "IPv4Layer.h"
#include "UdpLayer.h"
#include "SystemUtils.h"

PTF_TEST_CASE(IcmpParsingTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/IcmpEchoRequest.dat");
	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/IcmpEchoReply.dat");
	READ_FILE_AND_CREATE_PACKET(3, "PacketExamples/IcmpTimestampRequest.dat");
	READ_FILE_AND_CREATE_PACKET(4, "PacketExamples/IcmpTimestampReply.dat");
	READ_FILE_AND_CREATE_PACKET(5, "PacketExamples/IcmpRedirect.dat");
	READ_FILE_AND_CREATE_PACKET(6, "PacketExamples/IcmpRouterAdv1.dat");
	READ_FILE_AND_CREATE_PACKET(7, "PacketExamples/IcmpRouterAdv2.dat");
	READ_FILE_AND_CREATE_PACKET(8, "PacketExamples/IcmpRouterSol.dat");
	READ_FILE_AND_CREATE_PACKET(9, "PacketExamples/IcmpTimeExceededUdp.dat");
	READ_FILE_AND_CREATE_PACKET(10, "PacketExamples/IcmpDestUnreachableUdp.dat");
	READ_FILE_AND_CREATE_PACKET(11, "PacketExamples/IcmpTimeExceededEcho.dat");
	READ_FILE_AND_CREATE_PACKET(12, "PacketExamples/IcmpDestUnreachableEcho.dat");
	READ_FILE_AND_CREATE_PACKET(13, "PacketExamples/IcmpSourceQuench.dat");
	READ_FILE_AND_CREATE_PACKET(14, "PacketExamples/IcmpAddrMaskReq.dat");
	READ_FILE_AND_CREATE_PACKET(15, "PacketExamples/IcmpAddrMaskRep.dat");

	pcpp::Packet icmpEchoRequest(&rawPacket1);
	pcpp::Packet icmpEchoReply(&rawPacket2);
	pcpp::Packet icmpTimestampReq(&rawPacket3);
	pcpp::Packet icmpTimestampReply(&rawPacket4);
	pcpp::Packet icmpRedirect(&rawPacket5);
	pcpp::Packet icmpRouterAdv1(&rawPacket6);
	pcpp::Packet icmpRouterAdv2(&rawPacket7);
	pcpp::Packet icmpRouterSol(&rawPacket8);
	pcpp::Packet icmpTimeExceededUdp(&rawPacket9);
	pcpp::Packet icmpDestUnreachableUdp(&rawPacket10);
	pcpp::Packet icmpTimeExceededEcho(&rawPacket11);
	pcpp::Packet icmpDestUnreachableEcho(&rawPacket12);
	pcpp::Packet icmpSourceQuench(&rawPacket13);
	pcpp::Packet icmpAddrMaskReq(&rawPacket14);
	pcpp::Packet icmpAddrMaskRep(&rawPacket15);

	pcpp::IcmpLayer* icmpLayer = nullptr;

	PTF_ASSERT_TRUE(icmpEchoRequest.isPacketOfType(pcpp::ICMP));
	PTF_ASSERT_TRUE(icmpEchoReply.isPacketOfType(pcpp::ICMP));
	PTF_ASSERT_TRUE(icmpTimestampReq.isPacketOfType(pcpp::ICMP));
	PTF_ASSERT_TRUE(icmpTimestampReply.isPacketOfType(pcpp::ICMP));
	PTF_ASSERT_TRUE(icmpRedirect.isPacketOfType(pcpp::ICMP));
	PTF_ASSERT_TRUE(icmpRouterAdv1.isPacketOfType(pcpp::ICMP));
	PTF_ASSERT_TRUE(icmpRouterAdv2.isPacketOfType(pcpp::ICMP));
	PTF_ASSERT_TRUE(icmpRouterSol.isPacketOfType(pcpp::ICMP));
	PTF_ASSERT_TRUE(icmpTimeExceededUdp.isPacketOfType(pcpp::ICMP));
	PTF_ASSERT_TRUE(icmpDestUnreachableUdp.isPacketOfType(pcpp::ICMP));
	PTF_ASSERT_TRUE(icmpTimeExceededEcho.isPacketOfType(pcpp::ICMP));
	PTF_ASSERT_TRUE(icmpDestUnreachableEcho.isPacketOfType(pcpp::ICMP));
	PTF_ASSERT_TRUE(icmpSourceQuench.isPacketOfType(pcpp::ICMP));
	PTF_ASSERT_TRUE(icmpAddrMaskReq.isPacketOfType(pcpp::ICMP));
	PTF_ASSERT_TRUE(icmpAddrMaskRep.isPacketOfType(pcpp::ICMP));

	// Echo request
	icmpLayer = icmpEchoRequest.getLayerOfType<pcpp::IcmpLayer>();
	PTF_ASSERT_NOT_NULL(icmpLayer);
	PTF_ASSERT_TRUE(icmpLayer->isMessageOfType(pcpp::ICMP_ECHO_REQUEST));
	PTF_ASSERT_NULL(icmpLayer->getEchoReplyData());
	pcpp::icmp_echo_request* reqData = icmpLayer->getEchoRequestData();
	PTF_ASSERT_NOT_NULL(reqData);
	PTF_ASSERT_EQUAL(reqData->header->code, 0);
	PTF_ASSERT_EQUAL(reqData->header->checksum, 0xb3bb);
	PTF_ASSERT_EQUAL(reqData->header->id, 0x3bd7);
	PTF_ASSERT_EQUAL(reqData->header->sequence, 0);
	PTF_ASSERT_EQUAL(reqData->header->timestamp, 0xE45104007DD6A751ULL);
	PTF_ASSERT_EQUAL(reqData->dataLength, 48);
	PTF_ASSERT_EQUAL(reqData->data[5], 0x0d);
	PTF_ASSERT_EQUAL(reqData->data[43], 0x33);

	// Echo reply
	icmpLayer = icmpEchoReply.getLayerOfType<pcpp::IcmpLayer>();
	PTF_ASSERT_NOT_NULL(icmpLayer);
	PTF_ASSERT_TRUE(icmpLayer->isMessageOfType(pcpp::ICMP_ECHO_REPLY));
	PTF_ASSERT_NULL(icmpLayer->getEchoRequestData());
	pcpp::icmp_echo_reply* repData = icmpLayer->getEchoReplyData();
	PTF_ASSERT_NOT_NULL(repData);
	PTF_ASSERT_EQUAL(repData->header->checksum, 0xb3c3);
	PTF_ASSERT_EQUAL(repData->dataLength, 48);
	PTF_ASSERT_EQUAL(repData->data[5], 0x0d);
	PTF_ASSERT_EQUAL(reqData->data[43], 0x33);

	// Timestamp request
	icmpLayer = icmpTimestampReq.getLayerOfType<pcpp::IcmpLayer>();
	PTF_ASSERT_NOT_NULL(icmpLayer);
	PTF_ASSERT_TRUE(icmpLayer->isMessageOfType(pcpp::ICMP_TIMESTAMP_REQUEST));
	PTF_ASSERT_NULL(icmpLayer->getEchoRequestData());
	pcpp::icmp_timestamp_request* tsReqData = icmpLayer->getTimestampRequestData();
	PTF_ASSERT_NOT_NULL(tsReqData);
	PTF_ASSERT_EQUAL(tsReqData->code, 0);
	PTF_ASSERT_EQUAL(tsReqData->originateTimestamp, 0x6324f600);
	PTF_ASSERT_EQUAL(tsReqData->transmitTimestamp, 0);

	// Timestamp reply
	icmpLayer = icmpTimestampReply.getLayerOfType<pcpp::IcmpLayer>();
	PTF_ASSERT_NOT_NULL(icmpLayer);
	PTF_ASSERT_TRUE(icmpLayer->isMessageOfType(pcpp::ICMP_TIMESTAMP_REPLY));
	PTF_ASSERT_NULL(icmpLayer->getSourceQuenchdata());
	pcpp::icmp_timestamp_reply* tsRepData = icmpLayer->getTimestampReplyData();
	PTF_ASSERT_NOT_NULL(tsRepData);
	PTF_ASSERT_EQUAL(tsRepData->checksum, 0x19e3);
	PTF_ASSERT_EQUAL(tsRepData->receiveTimestamp, 0x00f62d62);
	PTF_ASSERT_EQUAL(tsRepData->transmitTimestamp, 0x00f62d62);

	// Address mask request
	icmpLayer = icmpAddrMaskReq.getLayerOfType<pcpp::IcmpLayer>();
	PTF_ASSERT_NOT_NULL(icmpLayer);
	PTF_ASSERT_TRUE(icmpLayer->isMessageOfType(pcpp::ICMP_ADDRESS_MASK_REQUEST));
	PTF_ASSERT_NULL(icmpLayer->getRouterAdvertisementData());
	pcpp::icmp_address_mask_request* maskReqData = icmpLayer->getAddressMaskRequestData();
	PTF_ASSERT_NOT_NULL(maskReqData);
	PTF_ASSERT_EQUAL(maskReqData->id, 0x0cb0);
	PTF_ASSERT_EQUAL(maskReqData->sequence, 0x6);
	PTF_ASSERT_EQUAL(maskReqData->addressMask, 0);

	// Address mask reply
	icmpLayer = icmpAddrMaskRep.getLayerOfType<pcpp::IcmpLayer>();
	PTF_ASSERT_NOT_NULL(icmpLayer);
	PTF_ASSERT_TRUE(icmpLayer->isMessageOfType(pcpp::ICMP_ADDRESS_MASK_REPLY));
	PTF_ASSERT_NULL(icmpLayer->getSourceQuenchdata());
	PTF_ASSERT_NULL(icmpLayer->getAddressMaskRequestData());
	pcpp::icmp_address_mask_reply* maskRepData = icmpLayer->getAddressMaskReplyData();
	PTF_ASSERT_NOT_NULL(maskRepData);
	PTF_ASSERT_EQUAL(maskRepData->id, 0x0cb2);
	PTF_ASSERT_EQUAL(maskRepData->type, (uint8_t)pcpp::ICMP_ADDRESS_MASK_REPLY);
	PTF_ASSERT_EQUAL(maskRepData->addressMask, 0);

	// Router solicitation
	icmpLayer = icmpRouterSol.getLayerOfType<pcpp::IcmpLayer>();
	PTF_ASSERT_NOT_NULL(icmpLayer);
	PTF_ASSERT_TRUE(icmpLayer->isMessageOfType(pcpp::ICMP_ROUTER_SOL));
	PTF_ASSERT_NULL(icmpLayer->getSourceQuenchdata());
	PTF_ASSERT_NULL(icmpLayer->getAddressMaskRequestData());
	pcpp::icmp_router_solicitation* solData = icmpLayer->getRouterSolicitationData();
	PTF_ASSERT_NOT_NULL(solData);
	PTF_ASSERT_EQUAL(solData->checksum, 0xfff5);

	// Destination unreachable
	icmpLayer = icmpDestUnreachableUdp.getLayerOfType<pcpp::IcmpLayer>();
	PTF_ASSERT_NOT_NULL(icmpLayer);
	PTF_ASSERT_TRUE(icmpLayer->isMessageOfType(pcpp::ICMP_DEST_UNREACHABLE));
	pcpp::icmp_destination_unreachable* destUnreachData = icmpLayer->getDestUnreachableData();
	PTF_ASSERT_NOT_NULL(destUnreachData);
	PTF_ASSERT_EQUAL(destUnreachData->nextHopMTU, 0);
	PTF_ASSERT_EQUAL(destUnreachData->code, pcpp::IcmpPortUnreachable);
	PTF_ASSERT_NOT_NULL(icmpLayer->getNextLayer());
	PTF_ASSERT_EQUAL(icmpLayer->getNextLayer()->getProtocol(), pcpp::IPv4, enum);
	pcpp::IPv4Layer* ipLayer = (pcpp::IPv4Layer*)icmpLayer->getNextLayer();
	PTF_ASSERT_EQUAL(ipLayer->getSrcIPAddress(), pcpp::IPv4Address("10.0.1.2"));
	PTF_ASSERT_NOT_NULL(ipLayer->getNextLayer());
	PTF_ASSERT_EQUAL(ipLayer->getNextLayer()->getProtocol(), pcpp::UDP, enum);

	icmpLayer = icmpDestUnreachableEcho.getLayerOfType<pcpp::IcmpLayer>();
	PTF_ASSERT_NOT_NULL(icmpLayer);
	PTF_ASSERT_TRUE(icmpLayer->isMessageOfType(pcpp::ICMP_DEST_UNREACHABLE));
	destUnreachData = icmpLayer->getDestUnreachableData();
	PTF_ASSERT_NOT_NULL(destUnreachData);
	PTF_ASSERT_EQUAL(destUnreachData->nextHopMTU, 0);
	PTF_ASSERT_EQUAL(destUnreachData->code, pcpp::IcmpHostUnreachable);
	PTF_ASSERT_NOT_NULL(icmpLayer->getNextLayer());
	PTF_ASSERT_EQUAL(icmpLayer->getNextLayer()->getProtocol(), pcpp::IPv4, enum);
	ipLayer = (pcpp::IPv4Layer*)icmpLayer->getNextLayer();
	PTF_ASSERT_EQUAL(ipLayer->getDstIPAddress(), pcpp::IPv4Address("10.0.0.111"));
	PTF_ASSERT_NOT_NULL(ipLayer->getNextLayer());
	PTF_ASSERT_EQUAL(ipLayer->getNextLayer()->getProtocol(), pcpp::ICMP, enum);

	// Time exceeded
	icmpLayer = icmpTimeExceededUdp.getLayerOfType<pcpp::IcmpLayer>();
	PTF_ASSERT_NOT_NULL(icmpLayer);
	PTF_ASSERT_TRUE(icmpLayer->isMessageOfType(pcpp::ICMP_TIME_EXCEEDED));
	pcpp::icmp_time_exceeded* timeExData = icmpLayer->getTimeExceededData();
	PTF_ASSERT_NOT_NULL(timeExData);
	PTF_ASSERT_EQUAL(timeExData->checksum, 0x2dac);
	PTF_ASSERT_NOT_NULL(icmpLayer->getNextLayer());
	PTF_ASSERT_EQUAL(icmpLayer->getNextLayer()->getProtocol(), pcpp::IPv4, enum);
	ipLayer = (pcpp::IPv4Layer*)icmpLayer->getNextLayer();
	PTF_ASSERT_NOT_NULL(ipLayer->getNextLayer());
	PTF_ASSERT_EQUAL(ipLayer->getNextLayer()->getProtocol(), pcpp::UDP, enum);

	icmpLayer = icmpTimeExceededEcho.getLayerOfType<pcpp::IcmpLayer>();
	PTF_ASSERT_NOT_NULL(icmpLayer);
	PTF_ASSERT_TRUE(icmpLayer->isMessageOfType(pcpp::ICMP_TIME_EXCEEDED));
	timeExData = icmpLayer->getTimeExceededData();
	PTF_ASSERT_NOT_NULL(timeExData);
	PTF_ASSERT_EQUAL(timeExData->code, 0);
	PTF_ASSERT_NOT_NULL(icmpLayer->getNextLayer());
	PTF_ASSERT_EQUAL(icmpLayer->getNextLayer()->getProtocol(), pcpp::IPv4, enum);
	ipLayer = (pcpp::IPv4Layer*)icmpLayer->getNextLayer();
	PTF_ASSERT_NOT_NULL(ipLayer->getNextLayer());
	PTF_ASSERT_EQUAL(ipLayer->getNextLayer()->getProtocol(), pcpp::ICMP, enum);
	icmpLayer = (pcpp::IcmpLayer*)ipLayer->getNextLayer();
	PTF_ASSERT_EQUAL(icmpLayer->getMessageType(), pcpp::ICMP_ECHO_REQUEST, enum);
	PTF_ASSERT_NOT_NULL(icmpLayer->getEchoRequestData());
	PTF_ASSERT_EQUAL(icmpLayer->getEchoRequestData()->header->id, 0x670c);

	// Redirect
	icmpLayer = icmpRedirect.getLayerOfType<pcpp::IcmpLayer>();
	PTF_ASSERT_NOT_NULL(icmpLayer);
	PTF_ASSERT_TRUE(icmpLayer->isMessageOfType(pcpp::ICMP_REDIRECT));
	pcpp::icmp_redirect* redirectData = icmpLayer->getRedirectData();
	PTF_ASSERT_NOT_NULL(redirectData);
	PTF_ASSERT_NULL(icmpLayer->getEchoReplyData());
	PTF_ASSERT_NULL(icmpLayer->getInfoRequestData());
	PTF_ASSERT_NULL(icmpLayer->getParamProblemData());
	PTF_ASSERT_EQUAL(pcpp::IPv4Address(redirectData->gatewayAddress).toString(), "10.2.99.98");
	PTF_ASSERT_NOT_NULL(icmpLayer->getNextLayer());
	PTF_ASSERT_EQUAL(icmpLayer->getNextLayer()->getProtocol(), pcpp::IPv4, enum);
	ipLayer = (pcpp::IPv4Layer*)icmpLayer->getNextLayer();
	PTF_ASSERT_NOT_NULL(ipLayer);
	PTF_ASSERT_EQUAL(ipLayer->getSrcIPAddress().toString(), "10.2.10.2");
	PTF_ASSERT_NOT_NULL(ipLayer->getNextLayer());
	PTF_ASSERT_EQUAL(ipLayer->getNextLayer()->getProtocol(), pcpp::ICMP, enum);
	icmpLayer = (pcpp::IcmpLayer*)ipLayer->getNextLayer();
	PTF_ASSERT_EQUAL(icmpLayer->getMessageType(), pcpp::ICMP_ECHO_REQUEST, enum);
	PTF_ASSERT_EQUAL(icmpLayer->getEchoRequestData()->header->id, 0x2);

	// Router advertisement
	icmpLayer = icmpRouterAdv1.getLayerOfType<pcpp::IcmpLayer>();
	PTF_ASSERT_NOT_NULL(icmpLayer);
	PTF_ASSERT_TRUE(icmpLayer->isMessageOfType(pcpp::ICMP_ROUTER_ADV));
	pcpp::icmp_router_advertisement* routerAdvData = icmpLayer->getRouterAdvertisementData();
	PTF_ASSERT_NOT_NULL(routerAdvData);
	PTF_ASSERT_EQUAL(routerAdvData->header->advertisementCount, 1);
	PTF_ASSERT_EQUAL(routerAdvData->header->lifetime, htobe16(200));
	PTF_ASSERT_NULL(routerAdvData->getRouterAddress(1));
	PTF_ASSERT_NULL(routerAdvData->getRouterAddress(100));
	pcpp::icmp_router_address_structure* routerAddr = routerAdvData->getRouterAddress(0);
	PTF_ASSERT_NOT_NULL(routerAddr);
	PTF_ASSERT_EQUAL(pcpp::IPv4Address(routerAddr->routerAddress), pcpp::IPv4Address("192.168.144.2"));
	PTF_ASSERT_EQUAL(routerAddr->preferenceLevel, 0x80);

	icmpLayer = icmpRouterAdv2.getLayerOfType<pcpp::IcmpLayer>();
	PTF_ASSERT_NOT_NULL(icmpLayer);
	PTF_ASSERT_TRUE(icmpLayer->isMessageOfType(pcpp::ICMP_ROUTER_ADV));
	routerAdvData = icmpLayer->getRouterAdvertisementData();
	PTF_ASSERT_NOT_NULL(routerAdvData);
	PTF_ASSERT_EQUAL(routerAdvData->header->advertisementCount, 1);
	PTF_ASSERT_EQUAL(routerAdvData->header->addressEntrySize, 2);
	PTF_ASSERT_NULL(routerAdvData->getRouterAddress(1));
	PTF_ASSERT_NULL(routerAdvData->getRouterAddress(20));
	routerAddr = routerAdvData->getRouterAddress(0);
	PTF_ASSERT_NOT_NULL(routerAddr);
	PTF_ASSERT_EQUAL(pcpp::IPv4Address(routerAddr->routerAddress), pcpp::IPv4Address("14.80.84.66"));
	PTF_ASSERT_EQUAL(routerAddr->preferenceLevel, 0);
}  // IcmpParsingTest

PTF_TEST_CASE(IcmpCreationTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_INTO_BUFFER(1, "PacketExamples/IcmpEchoRequest.dat");
	READ_FILE_INTO_BUFFER(2, "PacketExamples/IcmpEchoReply.dat");
	READ_FILE_INTO_BUFFER(3, "PacketExamples/IcmpTimestampRequest.dat");
	READ_FILE_INTO_BUFFER(4, "PacketExamples/IcmpTimestampReply.dat");
	READ_FILE_INTO_BUFFER(5, "PacketExamples/IcmpRedirect.dat");
	READ_FILE_INTO_BUFFER(6, "PacketExamples/IcmpRouterAdv1.dat");
	READ_FILE_INTO_BUFFER(7, "PacketExamples/IcmpRouterAdv2.dat");
	READ_FILE_INTO_BUFFER(8, "PacketExamples/IcmpRouterSol.dat");
	READ_FILE_INTO_BUFFER(9, "PacketExamples/IcmpTimeExceededUdp.dat");
	READ_FILE_INTO_BUFFER(10, "PacketExamples/IcmpDestUnreachableUdp.dat");
	READ_FILE_INTO_BUFFER(11, "PacketExamples/IcmpTimeExceededEcho.dat");
	READ_FILE_INTO_BUFFER(12, "PacketExamples/IcmpDestUnreachableEcho.dat");
	READ_FILE_INTO_BUFFER(13, "PacketExamples/IcmpSourceQuench.dat");
	READ_FILE_INTO_BUFFER(14, "PacketExamples/IcmpAddrMaskReq.dat");
	READ_FILE_INTO_BUFFER(15, "PacketExamples/IcmpAddrMaskRep.dat");

	pcpp::EthLayer ethLayer(pcpp::MacAddress("11:22:33:44:55:66"), pcpp::MacAddress("66:55:44:33:22:11"));

	pcpp::IPv4Layer ipLayer(pcpp::IPv4Address("1.1.1.1"), pcpp::IPv4Address("2.2.2.2"));

	uint8_t data[48] = {
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37
	};

	// Echo request creation
	pcpp::IcmpLayer echoReqLayer;
	PTF_ASSERT_NOT_NULL(echoReqLayer.setEchoRequestData(0xd73b, 0, 0xe45104007dd6a751ULL, data, 48));
	pcpp::Packet echoRequestPacket(1);
	PTF_ASSERT_TRUE(echoRequestPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(echoRequestPacket.addLayer(&ipLayer));
	PTF_ASSERT_TRUE(echoRequestPacket.addLayer(&echoReqLayer));
	echoRequestPacket.computeCalculateFields();
	PTF_ASSERT_EQUAL(echoRequestPacket.getRawPacket()->getRawDataLen(), bufferLength1);
	PTF_ASSERT_BUF_COMPARE(echoRequestPacket.getRawPacket()->getRawData() + 34, buffer1 + 34, bufferLength1 - 34);

	// Echo reply creation
	pcpp::EthLayer ethLayer2(ethLayer);
	pcpp::IPv4Layer ipLayer2(ipLayer);
	pcpp::IcmpLayer echoRepLayer;
	pcpp::Packet echoReplyPacket(10);
	PTF_ASSERT_TRUE(echoReplyPacket.addLayer(&ethLayer2));
	PTF_ASSERT_TRUE(echoReplyPacket.addLayer(&ipLayer2));
	PTF_ASSERT_TRUE(echoReplyPacket.addLayer(&echoRepLayer));
	PTF_ASSERT_NOT_NULL(echoRepLayer.setEchoReplyData(0xd73b, 0, 0xe45104007dd6a751ULL, data, 48));
	echoReplyPacket.computeCalculateFields();
	PTF_ASSERT_EQUAL(echoReplyPacket.getRawPacket()->getRawDataLen(), bufferLength2);
	PTF_ASSERT_BUF_COMPARE(echoReplyPacket.getRawPacket()->getRawData() + 34, buffer2 + 34, bufferLength2 - 34);

	// Time exceeded creation
	pcpp::EthLayer ethLayer3(ethLayer);
	pcpp::IPv4Layer ipLayer3(ipLayer);
	pcpp::IcmpLayer timeExceededLayer;
	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_NULL(timeExceededLayer.setTimeExceededData(1, nullptr, nullptr));
	pcpp::Logger::getInstance().enableLogs();
	pcpp::IPv4Layer ipLayerForTimeExceeded(pcpp::IPv4Address("10.0.0.6"), pcpp::IPv4Address("8.8.8.8"));
	ipLayerForTimeExceeded.getIPv4Header()->fragmentOffset = 0x40;
	ipLayerForTimeExceeded.getIPv4Header()->timeToLive = 1;
	ipLayerForTimeExceeded.getIPv4Header()->ipId = be16toh(2846);
	pcpp::IcmpLayer icmpLayerForTimeExceeded;
	icmpLayerForTimeExceeded.setEchoRequestData(3175, 1, 0x00058bbd569f3d49ULL, data, 48);
	pcpp::Packet timeExceededPacket(10);
	PTF_ASSERT_TRUE(timeExceededPacket.addLayer(&ethLayer3));
	PTF_ASSERT_TRUE(timeExceededPacket.addLayer(&ipLayer3));
	PTF_ASSERT_TRUE(timeExceededPacket.addLayer(&timeExceededLayer));
	PTF_ASSERT_NOT_NULL(timeExceededLayer.setTimeExceededData(0, &ipLayerForTimeExceeded, &icmpLayerForTimeExceeded));
	timeExceededPacket.computeCalculateFields();
	PTF_ASSERT_EQUAL(timeExceededPacket.getRawPacket()->getRawDataLen(), bufferLength11);
	PTF_ASSERT_BUF_COMPARE(timeExceededPacket.getRawPacket()->getRawData() + 34, buffer11 + 34, bufferLength11 - 34);

	// Dest unreachable creation
	pcpp::EthLayer ethLayer4(ethLayer);
	pcpp::IPv4Layer ipLayer4(ipLayer);
	pcpp::IcmpLayer destUnreachableLayer;
	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_NULL(destUnreachableLayer.setDestUnreachableData(pcpp::IcmpHostUnreachable, 0, nullptr, nullptr));
	pcpp::Logger::getInstance().enableLogs();
	pcpp::UdpLayer udpLayerForDestUnreachable(49182, 33446);
	pcpp::IPv4Layer ipLayerForDestUnreachable(pcpp::IPv4Address("10.0.1.2"), pcpp::IPv4Address("172.16.0.2"));
	ipLayerForDestUnreachable.getIPv4Header()->timeToLive = 1;
	ipLayerForDestUnreachable.getIPv4Header()->ipId = be16toh(230);
	pcpp::Packet destUnreachablePacket(10);
	PTF_ASSERT_TRUE(destUnreachablePacket.addLayer(&ethLayer4));
	PTF_ASSERT_TRUE(destUnreachablePacket.addLayer(&ipLayer4));
	PTF_ASSERT_TRUE(destUnreachablePacket.addLayer(&destUnreachableLayer));
	PTF_ASSERT_NOT_NULL(destUnreachableLayer.setDestUnreachableData(
	    pcpp::IcmpPortUnreachable, 0, &ipLayerForDestUnreachable, &udpLayerForDestUnreachable));
	destUnreachablePacket.computeCalculateFields();
	PTF_ASSERT_EQUAL(destUnreachablePacket.getRawPacket()->getRawDataLen(), bufferLength10);
	PTF_ASSERT_BUF_COMPARE(destUnreachablePacket.getRawPacket()->getRawData() + 34, buffer10 + 34, bufferLength10 - 34);

	// Timestamp reply
	pcpp::EthLayer ethLayer5(ethLayer);
	pcpp::IPv4Layer ipLayer5(ipLayer);
	pcpp::IcmpLayer timestampReplyLayer;
	timeval orig = { 16131, 171000 };
	timeval recv = { 16133, 474000 };
	timeval tran = { 16133, 474000 };
	PTF_ASSERT_NOT_NULL(timestampReplyLayer.setTimestampReplyData(14640, 0, orig, recv, tran));
	pcpp::Packet timestampReplyPacket(20);
	PTF_ASSERT_TRUE(timestampReplyPacket.addLayer(&ethLayer5));
	PTF_ASSERT_TRUE(timestampReplyPacket.addLayer(&ipLayer5));
	PTF_ASSERT_TRUE(timestampReplyPacket.addLayer(&timestampReplyLayer));
	timestampReplyPacket.computeCalculateFields();
	PTF_ASSERT_EQUAL(timestampReplyPacket.getRawPacket()->getRawDataLen(), bufferLength4 - 6);

	// Address mask request
	pcpp::EthLayer ethLayer6(ethLayer);
	pcpp::IPv4Layer ipLayer6(ipLayer);
	pcpp::IcmpLayer addressMaskRequestLayer;
	PTF_ASSERT_NOT_NULL(addressMaskRequestLayer.setAddressMaskRequestData(45068, 1536, pcpp::IPv4Address::Zero));
	pcpp::Packet addressMaskRequestPacket(30);
	PTF_ASSERT_TRUE(addressMaskRequestPacket.addLayer(&ethLayer6));
	PTF_ASSERT_TRUE(addressMaskRequestPacket.addLayer(&ipLayer6));
	PTF_ASSERT_TRUE(addressMaskRequestPacket.addLayer(&addressMaskRequestLayer));
	addressMaskRequestPacket.computeCalculateFields();
	PTF_ASSERT_EQUAL(addressMaskRequestPacket.getRawPacket()->getRawDataLen(), bufferLength14 - 14);
	PTF_ASSERT_BUF_COMPARE(addressMaskRequestPacket.getRawPacket()->getRawData() + 34, buffer14 + 34,
	                       bufferLength14 - 34 - 14);

	// Redirect creation
	pcpp::EthLayer ethLayer7(ethLayer);
	pcpp::IPv4Layer ipLayer7(ipLayer);
	pcpp::IcmpLayer redirectLayer;
	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_NULL(redirectLayer.setDestUnreachableData(pcpp::IcmpHostUnreachable, 0, nullptr, nullptr));
	pcpp::Logger::getInstance().enableLogs();
	pcpp::IPv4Layer ipLayerForRedirect(pcpp::IPv4Address("10.2.10.2"), pcpp::IPv4Address("10.3.71.7"));
	ipLayerForRedirect.getIPv4Header()->ipId = be16toh(14848);
	ipLayerForRedirect.getIPv4Header()->timeToLive = 31;
	pcpp::IcmpLayer icmpLayerForRedirect;
	icmpLayerForRedirect.setEchoRequestData(512, 12544, 0, nullptr, 0);
	pcpp::Packet redirectPacket(13);
	PTF_ASSERT_TRUE(redirectPacket.addLayer(&ethLayer7));
	PTF_ASSERT_TRUE(redirectPacket.addLayer(&ipLayer7));
	PTF_ASSERT_TRUE(redirectPacket.addLayer(&redirectLayer));
	PTF_ASSERT_NOT_NULL(
	    redirectLayer.setRedirectData(1, pcpp::IPv4Address("10.2.99.98"), &ipLayerForRedirect, &icmpLayerForRedirect));
	redirectPacket.computeCalculateFields();
	PTF_ASSERT_EQUAL(redirectPacket.getRawPacket()->getRawDataLen(), bufferLength5 + 8);

	// Router advertisement creation
	pcpp::EthLayer ethLayer8(ethLayer);
	pcpp::IPv4Layer ipLayer8(ipLayer);
	pcpp::IcmpLayer routerAdvLayer;
	pcpp::Packet routerAdvPacket(23);
	PTF_ASSERT_TRUE(routerAdvPacket.addLayer(&ethLayer8));
	PTF_ASSERT_TRUE(routerAdvPacket.addLayer(&ipLayer8));
	PTF_ASSERT_TRUE(routerAdvPacket.addLayer(&routerAdvLayer));
	pcpp::icmp_router_address_structure addr1;
	addr1.setRouterAddress(pcpp::IPv4Address("192.168.144.2"), (uint32_t)0x08000000);
	pcpp::icmp_router_address_structure addr2;
	addr2.setRouterAddress(pcpp::IPv4Address("1.1.1.1"), (uint32_t)1000);
	pcpp::icmp_router_address_structure addr3;
	addr3.setRouterAddress(pcpp::IPv4Address("10.0.0.138"), (uint32_t)30000);
	std::vector<pcpp::icmp_router_address_structure> routerAddresses;
	routerAddresses.push_back(addr1);
	routerAddresses.push_back(addr2);
	routerAddresses.push_back(addr3);
	PTF_ASSERT_NOT_NULL(routerAdvLayer.setRouterAdvertisementData(16, 200, routerAddresses));
	routerAdvPacket.computeCalculateFields();
	PTF_ASSERT_EQUAL(routerAdvLayer.getHeaderLen(), 32);
	PTF_ASSERT_EQUAL(routerAdvPacket.getRawPacket()->getRawDataLen(), bufferLength6 - 18);

	delete[] buffer1;
	delete[] buffer2;
	delete[] buffer3;
	delete[] buffer4;
	delete[] buffer5;
	delete[] buffer6;
	delete[] buffer7;
	delete[] buffer8;
	delete[] buffer9;
	delete[] buffer10;
	delete[] buffer11;
	delete[] buffer12;
	delete[] buffer13;
	delete[] buffer14;
	delete[] buffer15;
}  // IcmpCreationTest

PTF_TEST_CASE(IcmpEditTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/IcmpRouterAdv1.dat");
	READ_FILE_INTO_BUFFER(2, "PacketExamples/IcmpEchoRequest.dat");
	READ_FILE_INTO_BUFFER(3, "PacketExamples/IcmpEchoReply.dat");
	READ_FILE_AND_CREATE_PACKET(4, "PacketExamples/IcmpTimeExceededUdp.dat");
	READ_FILE_INTO_BUFFER(5, "PacketExamples/IcmpDestUnreachableEcho.dat");

	// convert router adv to echo request

	pcpp::Packet icmpRouterAdv1(&rawPacket1);

	pcpp::IcmpLayer* icmpLayer = icmpRouterAdv1.getLayerOfType<pcpp::IcmpLayer>();
	PTF_ASSERT_NOT_NULL(icmpLayer);

	uint8_t data[48] = {
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37
	};

	PTF_ASSERT_NOT_NULL(icmpLayer->getRouterAdvertisementData());
	PTF_ASSERT_NULL(icmpLayer->getEchoRequestData());
	pcpp::icmp_echo_request* echoReq = icmpLayer->setEchoRequestData(55099, 0, 0xe45104007dd6a751ULL, data, 48);
	PTF_ASSERT_NOT_NULL(echoReq);
	PTF_ASSERT_EQUAL(icmpLayer->getHeaderLen(), 64);
	PTF_ASSERT_EQUAL(echoReq->header->id, htobe16(55099));
	PTF_ASSERT_EQUAL(echoReq->dataLength, 48);
	icmpRouterAdv1.computeCalculateFields();
	PTF_ASSERT_NULL(icmpLayer->getRouterAdvertisementData());
	PTF_ASSERT_BUF_COMPARE(icmpRouterAdv1.getRawPacket()->getRawData() + 34, buffer2 + 34, bufferLength2 - 34);

	// convert echo request to echo reply

	pcpp::icmp_echo_reply* echoReply = icmpLayer->setEchoReplyData(55099, 0, 0xe45104007dd6a751ULL, data, 48);
	PTF_ASSERT_NULL(icmpLayer->getEchoRequestData());
	icmpRouterAdv1.computeCalculateFields();
	PTF_ASSERT_EQUAL(echoReply->header->checksum, htobe16(0xc3b3));
	PTF_ASSERT_BUF_COMPARE(icmpRouterAdv1.getRawPacket()->getRawData() + 34, buffer3 + 34, bufferLength3 - 34);

	// convert time exceeded to echo request

	pcpp::IPv4Layer ipLayerForDestUnreachable(pcpp::IPv4Address("10.0.0.7"), pcpp::IPv4Address("10.0.0.111"));
	ipLayerForDestUnreachable.getIPv4Header()->fragmentOffset = 0x0040;
	ipLayerForDestUnreachable.getIPv4Header()->timeToLive = 64;
	ipLayerForDestUnreachable.getIPv4Header()->ipId = be16toh(10203);

	pcpp::IcmpLayer icmpLayerForDestUnreachable;
	icmpLayerForDestUnreachable.setEchoRequestData(3189, 4, 0x000809f2569f3e41ULL, data, 48);

	pcpp::Packet icmpTimeExceededUdp(&rawPacket4);

	icmpLayer = icmpTimeExceededUdp.getLayerOfType<pcpp::IcmpLayer>();
	PTF_ASSERT_NOT_NULL(icmpLayer);
	PTF_ASSERT_NOT_NULL(icmpLayer->getTimeExceededData());
	PTF_ASSERT_NULL(icmpLayer->getEchoRequestData());
	echoReq = icmpLayer->setEchoRequestData(55090, 0, 0xe45104007dd6a751ULL, data, 48);
	PTF_ASSERT_NOT_NULL(echoReq);
	PTF_ASSERT_EQUAL(icmpLayer->getHeaderLen(), 64);
	PTF_ASSERT_EQUAL(echoReq->header->id, htobe16(55090));
	echoReq->header->id = htobe16(55099);
	PTF_ASSERT_EQUAL(echoReq->header->id, htobe16(55099));
	PTF_ASSERT_EQUAL(echoReq->dataLength, 48);
	icmpTimeExceededUdp.computeCalculateFields();
	PTF_ASSERT_BUF_COMPARE(icmpTimeExceededUdp.getRawPacket()->getRawData() + 34, buffer2 + 34, bufferLength2 - 34);

	// convert echo request to dest unreachable

	pcpp::icmp_destination_unreachable* destUnreachable = icmpLayer->setDestUnreachableData(
	    pcpp::IcmpHostUnreachable, 0, &ipLayerForDestUnreachable, &icmpLayerForDestUnreachable);
	PTF_ASSERT_NOT_NULL(destUnreachable);
	PTF_ASSERT_EQUAL(icmpLayer->getHeaderLen(), 8);
	PTF_ASSERT_EQUAL(destUnreachable->code, (uint8_t)pcpp::IcmpHostUnreachable);
	PTF_ASSERT_NOT_NULL(icmpLayer->getNextLayer());
	PTF_ASSERT_EQUAL(icmpLayer->getNextLayer()->getProtocol(), pcpp::IPv4, enum);
	pcpp::IPv4Layer* ipLayer = (pcpp::IPv4Layer*)icmpLayer->getNextLayer();
	PTF_ASSERT_EQUAL(ipLayer->getDstIPAddress(), pcpp::IPv4Address("10.0.0.111"));
	PTF_ASSERT_NOT_NULL(ipLayer->getNextLayer());
	PTF_ASSERT_EQUAL(ipLayer->getNextLayer()->getProtocol(), pcpp::ICMP, enum);
	icmpLayer = (pcpp::IcmpLayer*)ipLayer->getNextLayer();
	PTF_ASSERT_TRUE(icmpLayer->isMessageOfType(pcpp::ICMP_ECHO_REQUEST));
	echoReq = icmpLayer->getEchoRequestData();
	PTF_ASSERT_NOT_NULL(echoReq);
	PTF_ASSERT_EQUAL(echoReq->header->sequence, htobe16(4));
	icmpTimeExceededUdp.computeCalculateFields();
	PTF_ASSERT_BUF_COMPARE(icmpTimeExceededUdp.getRawPacket()->getRawData() + 34, buffer5 + 34, bufferLength5 - 34);

	delete[] buffer2;
	delete[] buffer3;
	delete[] buffer5;
}  // IcmpEditTest
