#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "DhcpLayer.h"
#include "UdpLayer.h"
#include "SystemUtils.h"

PTF_TEST_CASE(DhcpParsingTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/Dhcp1.dat");

	pcpp::Packet dhcpPacket(&rawPacket1);
	PTF_ASSERT_TRUE(dhcpPacket.isPacketOfType(pcpp::DHCP));
	pcpp::DhcpLayer* dhcpLayer = dhcpPacket.getLayerOfType<pcpp::DhcpLayer>();
	PTF_ASSERT_NOT_NULL(dhcpLayer);

	PTF_ASSERT_EQUAL(dhcpLayer->getOpCode(), pcpp::DHCP_BOOTREPLY, enum);
	PTF_ASSERT_EQUAL(dhcpLayer->getDhcpHeader()->secondsElapsed, be16toh(10));
	PTF_ASSERT_EQUAL(dhcpLayer->getDhcpHeader()->hops, 1);
	PTF_ASSERT_EQUAL(dhcpLayer->getDhcpHeader()->transactionID, be32toh(0x7771cf85));
	PTF_ASSERT_EQUAL(dhcpLayer->getClientIpAddress(), pcpp::IPv4Address::Zero);
	PTF_ASSERT_EQUAL(dhcpLayer->getYourIpAddress(), pcpp::IPv4Address("10.10.8.235"));
	PTF_ASSERT_EQUAL(dhcpLayer->getServerIpAddress(), pcpp::IPv4Address("172.22.178.234"));
	PTF_ASSERT_EQUAL(dhcpLayer->getGatewayIpAddress(), pcpp::IPv4Address("10.10.8.240"));
	PTF_ASSERT_EQUAL(dhcpLayer->getClientHardwareAddress(), pcpp::MacAddress(std::string("00:0e:86:11:c0:75")));

	PTF_ASSERT_EQUAL(dhcpLayer->getOptionsCount(), 12);
	pcpp::DhcpOption opt = dhcpLayer->getFirstOptionData();
	pcpp::DhcpOptionTypes optTypeArr[] = { pcpp::DHCPOPT_DHCP_MESSAGE_TYPE,
		                                   pcpp::DHCPOPT_SUBNET_MASK,
		                                   pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER,
		                                   pcpp::DHCPOPT_DHCP_LEASE_TIME,
		                                   pcpp::DHCPOPT_ROUTERS,
		                                   pcpp::DHCPOPT_DOMAIN_NAME_SERVERS,
		                                   pcpp::DHCPOPT_TFTP_SERVER_NAME,
		                                   pcpp::DHCPOPT_SIP_SERVERS,
		                                   pcpp::DHCPOPT_DHCP_CLIENT_IDENTIFIER,
		                                   pcpp::DHCPOPT_AUTHENTICATION,
		                                   pcpp::DHCPOPT_DHCP_AGENT_OPTIONS,
		                                   pcpp::DHCPOPT_END };

	size_t optLenArr[] = { 1, 4, 4, 4, 4, 8, 14, 5, 16, 31, 22, 0 };

	for (size_t i = 0; i < dhcpLayer->getOptionsCount(); i++)
	{
		PTF_ASSERT_FALSE(opt.isNull());
		PTF_ASSERT_EQUAL(opt.getType(), optTypeArr[i]);
		PTF_ASSERT_EQUAL(opt.getDataSize(), optLenArr[i]);
		opt = dhcpLayer->getNextOptionData(opt);
	}

	PTF_ASSERT_TRUE(opt.isNull());

	PTF_PRINT_VERBOSE("Iterating over DHCP options");
	for (size_t i = 0; i < dhcpLayer->getOptionsCount(); i++)
	{
		PTF_PRINT_VERBOSE("Iteration #" << i);
		PTF_ASSERT_FALSE(dhcpLayer->getOptionData(optTypeArr[i]).isNull());
	}

	PTF_ASSERT_EQUAL(dhcpLayer->getOptionData(pcpp::DHCPOPT_SUBNET_MASK).getValueAsIpAddr(),
	                 pcpp::IPv4Address("255.255.255.0"));
	PTF_ASSERT_EQUAL(dhcpLayer->getOptionData(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER).getValueAsIpAddr(),
	                 pcpp::IPv4Address("172.22.178.234"));
	PTF_ASSERT_EQUAL(dhcpLayer->getOptionData(pcpp::DHCPOPT_DHCP_LEASE_TIME).getValueAs<uint32_t>(), htobe32(43200));
	PTF_ASSERT_EQUAL(dhcpLayer->getOptionData(pcpp::DHCPOPT_TFTP_SERVER_NAME).getValueAsString(), "172.22.178.234");

	PTF_ASSERT_EQUAL(dhcpLayer->getMessageType(), pcpp::DHCP_OFFER, enum);

	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/Dhcp2.dat");

	pcpp::Packet dhcpPacket2(&rawPacket2);

	dhcpLayer = dhcpPacket2.getLayerOfType<pcpp::DhcpLayer>();
	PTF_ASSERT_NOT_NULL(dhcpLayer);

	PTF_ASSERT_EQUAL(dhcpLayer->getOpCode(), pcpp::DHCP_BOOTREQUEST, enum);
	PTF_ASSERT_EQUAL(dhcpLayer->getDhcpHeader()->hops, 0);
	PTF_ASSERT_EQUAL(dhcpLayer->getClientIpAddress(), pcpp::IPv4Address::Zero);
	PTF_ASSERT_EQUAL(dhcpLayer->getYourIpAddress(), pcpp::IPv4Address::Zero);
	PTF_ASSERT_EQUAL(dhcpLayer->getServerIpAddress(), pcpp::IPv4Address::Zero);
	PTF_ASSERT_EQUAL(dhcpLayer->getGatewayIpAddress(), pcpp::IPv4Address::Zero);
	PTF_ASSERT_EQUAL(dhcpLayer->getClientHardwareAddress(), pcpp::MacAddress(std::string("00:00:6c:82:dc:4e")));

	PTF_ASSERT_EQUAL(dhcpLayer->getOptionsCount(), 9);
	opt = dhcpLayer->getFirstOptionData();
	pcpp::DhcpOptionTypes optTypeArr2[] = { pcpp::DHCPOPT_DHCP_MESSAGE_TYPE,
		                                    pcpp::DHCPOPT_DHCP_MAX_MESSAGE_SIZE,
		                                    pcpp::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST,
		                                    pcpp::DHCPOPT_DHCP_LEASE_TIME,
		                                    pcpp::DHCPOPT_DHCP_OPTION_OVERLOAD,
		                                    pcpp::DHCPOPT_DHCP_MESSAGE,
		                                    pcpp::DHCPOPT_PAD,
		                                    pcpp::DHCPOPT_DHCP_CLIENT_IDENTIFIER,
		                                    pcpp::DHCPOPT_END };

	size_t optLenArr2[] = { 1, 2, 4, 4, 1, 7, 0, 7, 0 };

	PTF_PRINT_VERBOSE("Iterating over DHCP options");
	for (size_t i = 0; i < dhcpLayer->getOptionsCount(); i++)
	{
		PTF_PRINT_VERBOSE("Iteration #" << i);
		PTF_ASSERT_FALSE(opt.isNull());
		PTF_ASSERT_EQUAL(opt.getType(), optTypeArr2[i]);
		PTF_ASSERT_EQUAL(opt.getDataSize(), optLenArr2[i]);
		opt = dhcpLayer->getNextOptionData(opt);
	}

	PTF_ASSERT_TRUE(opt.isNull());

	PTF_PRINT_VERBOSE("Iterating over DHCP options");
	for (size_t i = 0; i < dhcpLayer->getOptionsCount(); i++)
	{
		PTF_PRINT_VERBOSE("Iteration #" << i);
		PTF_ASSERT_FALSE(dhcpLayer->getOptionData(optTypeArr2[i]).isNull());
	}

	PTF_ASSERT_EQUAL(dhcpLayer->getMessageType(), pcpp::DHCP_DISCOVER, enum);
}  // DhcpParsingTest

PTF_TEST_CASE(DhcpCreationTest)
{
	pcpp::EthLayer ethLayer(pcpp::MacAddress("00:13:72:25:fa:cd"), pcpp::MacAddress("00:e0:b1:49:39:02"));

	pcpp::IPv4Address srcIp("172.22.178.234");
	pcpp::IPv4Address dstIp("10.10.8.240");
	pcpp::IPv4Layer ipLayer(srcIp, dstIp);
	ipLayer.getIPv4Header()->ipId = htobe16(20370);
	ipLayer.getIPv4Header()->timeToLive = 128;

	pcpp::UdpLayer udpLayer((uint16_t)67, (uint16_t)67);

	pcpp::MacAddress clientMac(std::string("00:0e:86:11:c0:75"));
	pcpp::DhcpLayer dhcpLayer(pcpp::DHCP_OFFER, clientMac);
	dhcpLayer.getDhcpHeader()->hops = 1;
	dhcpLayer.getDhcpHeader()->transactionID = htobe32(0x7771cf85);
	dhcpLayer.getDhcpHeader()->secondsElapsed = htobe16(10);
	pcpp::IPv4Address yourIP("10.10.8.235");
	pcpp::IPv4Address serverIP("172.22.178.234");
	pcpp::IPv4Address gatewayIP("10.10.8.240");
	dhcpLayer.setYourIpAddress(yourIP);
	dhcpLayer.setServerIpAddress(serverIP);
	dhcpLayer.setGatewayIpAddress(gatewayIP);

	pcpp::DhcpOption subnetMaskOpt =
	    dhcpLayer.addOption(pcpp::DhcpOptionBuilder(pcpp::DHCPOPT_SUBNET_MASK, pcpp::IPv4Address("255.255.255.0")));
	PTF_ASSERT_FALSE(subnetMaskOpt.isNull());

	uint8_t sipServersData[] = { 0x01, 0xac, 0x16, 0xb2, 0xea };
	pcpp::DhcpOption sipServersOpt =
	    dhcpLayer.addOption(pcpp::DhcpOptionBuilder(pcpp::DHCPOPT_SIP_SERVERS, sipServersData, 5));
	PTF_ASSERT_FALSE(sipServersOpt.isNull());

	uint8_t agentData[] = { 0x01, 0x14, 0x20, 0x50, 0x4f, 0x4e, 0x20, 0x31, 0x2f, 0x31, 0x2f,
		                    0x30, 0x37, 0x2f, 0x30, 0x31, 0x3a, 0x31, 0x2e, 0x30, 0x2e, 0x31 };
	pcpp::DhcpOption agentOpt =
	    dhcpLayer.addOption(pcpp::DhcpOptionBuilder(pcpp::DHCPOPT_DHCP_AGENT_OPTIONS, agentData, 22));
	PTF_ASSERT_FALSE(agentOpt.isNull());

	pcpp::DhcpOption clientIdOpt = dhcpLayer.addOptionAfter(
	    pcpp::DhcpOptionBuilder(pcpp::DHCPOPT_DHCP_CLIENT_IDENTIFIER, nullptr, 16), pcpp::DHCPOPT_SIP_SERVERS);
	clientIdOpt.setValue<uint8_t>(0);
	clientIdOpt.setValueString("nathan1clientid", 1);
	PTF_ASSERT_FALSE(clientIdOpt.isNull());

	uint8_t authOptData[] = { 0x01, 0x01, 0x00, 0xc8, 0x78, 0xc4, 0x52, 0x56, 0x40, 0x20, 0x81,
		                      0x31, 0x32, 0x33, 0x34, 0x8f, 0xe0, 0xcc, 0xe2, 0xee, 0x85, 0x96,
		                      0xab, 0xb2, 0x58, 0x17, 0xc4, 0x80, 0xb2, 0xfd, 0x30 };
	pcpp::DhcpOption authOpt = dhcpLayer.addOptionAfter(
	    pcpp::DhcpOptionBuilder(pcpp::DHCPOPT_AUTHENTICATION, authOptData, 31), pcpp::DHCPOPT_DHCP_CLIENT_IDENTIFIER);
	PTF_ASSERT_FALSE(authOpt.isNull());

	pcpp::DhcpOption dhcpServerIdOpt = dhcpLayer.addOptionAfter(
	    pcpp::DhcpOptionBuilder(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER, pcpp::IPv4Address("172.22.178.234")),
	    pcpp::DHCPOPT_SUBNET_MASK);
	PTF_ASSERT_FALSE(dhcpServerIdOpt.isNull());

	pcpp::Packet newPacket(6);
	PTF_ASSERT_TRUE(newPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(newPacket.addLayer(&ipLayer));
	PTF_ASSERT_TRUE(newPacket.addLayer(&udpLayer));
	PTF_ASSERT_TRUE(newPacket.addLayer(&dhcpLayer));

	pcpp::DhcpOption routerOpt =
	    dhcpLayer.addOptionAfter(pcpp::DhcpOptionBuilder(pcpp::DHCPOPT_ROUTERS, pcpp::IPv4Address("10.10.8.254")),
	                             pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER);
	PTF_ASSERT_FALSE(routerOpt.isNull());

	pcpp::DhcpOption tftpServerOpt = dhcpLayer.addOptionAfter(
	    pcpp::DhcpOptionBuilder(pcpp::DHCPOPT_TFTP_SERVER_NAME, std::string("172.22.178.234")), pcpp::DHCPOPT_ROUTERS);
	PTF_ASSERT_FALSE(tftpServerOpt.isNull());

	pcpp::DhcpOption dnsOpt = dhcpLayer.addOptionAfter(
	    pcpp::DhcpOptionBuilder(pcpp::DHCPOPT_DOMAIN_NAME_SERVERS, nullptr, 8), pcpp::DHCPOPT_ROUTERS);
	PTF_ASSERT_FALSE(dnsOpt.isNull());
	pcpp::IPv4Address dns1IP("143.209.4.1");
	pcpp::IPv4Address dns2IP("143.209.5.1");
	dnsOpt.setValueIpAddr(dns1IP);
	dnsOpt.setValueIpAddr(dns2IP, 4);

	pcpp::DhcpOption leaseOpt = dhcpLayer.addOptionAfter(
	    pcpp::DhcpOptionBuilder(pcpp::DHCPOPT_DHCP_LEASE_TIME, (uint32_t)43200), pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER);
	PTF_ASSERT_FALSE(leaseOpt.isNull());

	newPacket.computeCalculateFields();

	READ_FILE_INTO_BUFFER(1, "PacketExamples/Dhcp1.dat");

	PTF_ASSERT_EQUAL(newPacket.getRawPacket()->getRawDataLen(), bufferLength1);
	PTF_ASSERT_BUF_COMPARE(newPacket.getRawPacket()->getRawData(), buffer1, bufferLength1);

	delete[] buffer1;
}  // DhcpCreationTest

PTF_TEST_CASE(DhcpEditTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/Dhcp4.dat");

	pcpp::Packet dhcpPacket(&rawPacket1);

	pcpp::DhcpLayer* dhcpLayer = dhcpPacket.getLayerOfType<pcpp::DhcpLayer>();

	PTF_ASSERT_TRUE(dhcpLayer->removeOption(pcpp::DHCPOPT_TFTP_SERVER_NAME));

	PTF_ASSERT_FALSE(dhcpLayer->removeOption(pcpp::DHCPOPT_TFTP_SERVER_NAME));

	PTF_ASSERT_FALSE(dhcpLayer->removeOption(pcpp::DHCPOPT_IRC_SERVER));

	PTF_ASSERT_TRUE(dhcpLayer->removeOption(pcpp::DHCPOPT_DHCP_MAX_MESSAGE_SIZE));

	pcpp::DhcpOption opt = dhcpLayer->getOptionData(pcpp::DHCPOPT_SUBNET_MASK);
	pcpp::IPv4Address newSubnet("255.255.255.0");
	opt.setValueIpAddr(newSubnet);

	PTF_ASSERT_TRUE(dhcpLayer->setMessageType(pcpp::DHCP_ACK));

	pcpp::IPv4Address newRouter("192.168.2.1");

	opt =
	    dhcpLayer->addOptionAfter(pcpp::DhcpOptionBuilder(pcpp::DHCPOPT_ROUTERS, newRouter), pcpp::DHCPOPT_SUBNET_MASK);
	PTF_ASSERT_FALSE(opt.isNull());

	opt = dhcpLayer->addOptionAfter(pcpp::DhcpOptionBuilder(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER, newRouter),
	                                pcpp::DHCPOPT_DHCP_MESSAGE_TYPE);
	PTF_ASSERT_FALSE(opt.isNull());

	dhcpPacket.computeCalculateFields();

	READ_FILE_INTO_BUFFER(2, "PacketExamples/Dhcp3.dat");

	PTF_ASSERT_EQUAL(dhcpPacket.getRawPacket()->getRawDataLen(), bufferLength2);
	PTF_ASSERT_BUF_COMPARE(dhcpPacket.getRawPacket()->getRawData(), buffer2, bufferLength2);

	delete[] buffer2;

	PTF_ASSERT_TRUE(dhcpLayer->removeAllOptions());

	PTF_ASSERT_EQUAL(dhcpLayer->getOptionsCount(), 0);

	PTF_ASSERT_EQUAL(dhcpLayer->getDataLen(), sizeof(pcpp::dhcp_header));

	PTF_ASSERT_EQUAL(dhcpLayer->getMessageType(), pcpp::DHCP_UNKNOWN_MSG_TYPE, enum);

	PTF_ASSERT_FALSE(dhcpLayer->addOption(pcpp::DhcpOptionBuilder(pcpp::DHCPOPT_END, nullptr, 0)).isNull());

	PTF_ASSERT_FALSE(dhcpLayer->setMessageType(pcpp::DHCP_UNKNOWN_MSG_TYPE));

	PTF_ASSERT_TRUE(dhcpLayer->setMessageType(pcpp::DHCP_DISCOVER));

	PTF_ASSERT_EQUAL(dhcpLayer->getOptionsCount(), 2);

	PTF_ASSERT_EQUAL(dhcpLayer->getDataLen(), sizeof(pcpp::dhcp_header) + 4);

	PTF_ASSERT_EQUAL(dhcpLayer->getMessageType(), pcpp::DHCP_DISCOVER, enum);

	dhcpPacket.computeCalculateFields();
}  // DhcpEditTest
