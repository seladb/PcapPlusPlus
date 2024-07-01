#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include <sstream>
#include "EndianPortable.h"
#include "Logger.h"
#include "Packet.h"
#include "SomeIpSdLayer.h"
#include "SystemUtils.h"

PTF_TEST_CASE(SomeIpSdParsingTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/SomeIpSdOffer.dat");
	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/SomeIpSdOffer2.dat");
	READ_FILE_AND_CREATE_PACKET(3, "PacketExamples/SomeIpSdSubscribe.dat");

	pcpp::Packet someIpSdPacket(&rawPacket1);
	pcpp::Packet someIpSdPacket2(&rawPacket2);
	pcpp::Packet someIpSdPacket3(&rawPacket3);

	// OfferService (Entry: OfferService, Option: IPv4Endpoint)
	PTF_ASSERT_TRUE(someIpSdPacket.isPacketOfType(pcpp::SomeIP));
	pcpp::SomeIpSdLayer* someIpSdLayer = someIpSdPacket.getLayerOfType<pcpp::SomeIpSdLayer>();
	PTF_ASSERT_NOT_NULL(someIpSdLayer);
	PTF_ASSERT_EQUAL(someIpSdLayer->getHeaderLen(), 56);
	PTF_ASSERT_EQUAL(someIpSdLayer->getMessageID(), 0xffff8100);
	PTF_ASSERT_EQUAL(someIpSdLayer->getServiceID(), 0xffff);
	PTF_ASSERT_EQUAL(someIpSdLayer->getMethodID(), 0x8100);
	PTF_ASSERT_EQUAL(someIpSdLayer->getLengthField(), 48);
	PTF_ASSERT_EQUAL(someIpSdLayer->getRequestID(), 0x00000002);
	PTF_ASSERT_EQUAL(someIpSdLayer->getClientID(), 0x0);
	PTF_ASSERT_EQUAL(someIpSdLayer->getSessionID(), 0x2);
	PTF_ASSERT_EQUAL(someIpSdLayer->getProtocolVersion(), 1);
	PTF_ASSERT_EQUAL(someIpSdLayer->getInterfaceVersion(), 1);
	PTF_ASSERT_EQUAL((int)someIpSdLayer->getMessageType(), (int)pcpp::SomeIpLayer::MsgType::NOTIFICATION);
	PTF_ASSERT_EQUAL(someIpSdLayer->getMessageTypeAsInt(), (uint8_t)pcpp::SomeIpLayer::MsgType::NOTIFICATION);
	PTF_ASSERT_EQUAL(someIpSdLayer->getReturnCode(), 0);
	PTF_ASSERT_EQUAL(someIpSdLayer->getNumEntries(), 1);
	PTF_ASSERT_EQUAL(someIpSdLayer->getNumOptions(), 1);
	PTF_ASSERT_EQUAL(someIpSdLayer->toString(), "SOME/IP-SD Layer, 1 entries, 1 options");

	pcpp::SomeIpSdLayer::EntriesVec entries1 = someIpSdLayer->getEntries();
	PTF_ASSERT_EQUAL(entries1.size(), 1);
	pcpp::SomeIpSdEntry* entry = *(entries1.begin());

	PTF_ASSERT_EQUAL(entry->getLength(), 16);
	PTF_ASSERT_EQUAL(entry->getNumOptions(), 1);
	PTF_ASSERT_EQUAL((uint8_t)entry->getType(), (uint8_t)pcpp::SomeIpSdEntry::EntryType::OfferService);
	PTF_ASSERT_EQUAL(entry->getServiceId(), 0xd05f);
	PTF_ASSERT_EQUAL(entry->getInstanceId(), 0x0002);
	PTF_ASSERT_EQUAL(entry->getMajorVersion(), 1);
	PTF_ASSERT_EQUAL(entry->getTtl(), 3);
	PTF_ASSERT_EQUAL(entry->getMinorVersion(), 0);
	PTF_ASSERT_EQUAL(entry->getDataPtr()[0], 0x01);

	pcpp::SomeIpSdLayer::OptionsVec options = someIpSdLayer->getOptions();
	PTF_ASSERT_EQUAL(options.size(), 1);
	pcpp::SomeIpSdOption* option = *(options.begin());
	PTF_ASSERT_EQUAL(option->getLength(), 12);
	PTF_ASSERT_EQUAL((uint8_t)option->getType(), (uint8_t)pcpp::SomeIpSdOption::OptionType::IPv4Endpoint);
	PTF_ASSERT_EQUAL(option->getDataPtr()[1], 0x09);

	pcpp::SomeIpSdIPv4Option* ipv4Option = (pcpp::SomeIpSdIPv4Option*)option;
	PTF_ASSERT_EQUAL(ipv4Option->getIpAddress(), pcpp::IPv4Address("160.48.199.28"));
	PTF_ASSERT_EQUAL(ipv4Option->getProtocol(), pcpp::SomeIpSdProtocolType::SD_UDP);
	PTF_ASSERT_EQUAL(ipv4Option->getPort(), 30502);

	// OfferService (Entry: OfferService, Option: IPv6Endpoint, ConfigurationString)
	PTF_ASSERT_TRUE(someIpSdPacket2.isPacketOfType(pcpp::SomeIP));
	pcpp::SomeIpSdLayer* someIpSdLayer2 = someIpSdPacket2.getLayerOfType<pcpp::SomeIpSdLayer>();
	PTF_ASSERT_NOT_NULL(someIpSdLayer2);
	PTF_ASSERT_EQUAL(someIpSdLayer2->getHeaderLen(), 161);
	PTF_ASSERT_EQUAL(someIpSdLayer2->getMessageID(), 0xffff8100);
	PTF_ASSERT_EQUAL(someIpSdLayer2->getServiceID(), 0xffff);
	PTF_ASSERT_EQUAL(someIpSdLayer2->getMethodID(), 0x8100);
	PTF_ASSERT_EQUAL(someIpSdLayer2->getLengthField(), 153);
	PTF_ASSERT_EQUAL(someIpSdLayer2->getRequestID(), 0x00000002);
	PTF_ASSERT_EQUAL(someIpSdLayer2->getClientID(), 0x0);
	PTF_ASSERT_EQUAL(someIpSdLayer2->getSessionID(), 0x2);
	PTF_ASSERT_EQUAL(someIpSdLayer2->getProtocolVersion(), 1);
	PTF_ASSERT_EQUAL(someIpSdLayer2->getInterfaceVersion(), 1);
	PTF_ASSERT_EQUAL((int)someIpSdLayer2->getMessageType(), (int)pcpp::SomeIpLayer::MsgType::NOTIFICATION);
	PTF_ASSERT_EQUAL(someIpSdLayer2->getMessageTypeAsInt(), (uint8_t)pcpp::SomeIpLayer::MsgType::NOTIFICATION);
	PTF_ASSERT_EQUAL(someIpSdLayer2->getReturnCode(), 0);
	PTF_ASSERT_EQUAL(someIpSdLayer2->getNumEntries(), 1);
	PTF_ASSERT_EQUAL(someIpSdLayer2->getNumOptions(), 2);
	PTF_ASSERT_EQUAL(someIpSdLayer2->toString(), "SOME/IP-SD Layer, 1 entries, 2 options");

	pcpp::SomeIpSdLayer::EntriesVec entries2 = someIpSdLayer2->getEntries();
	PTF_ASSERT_EQUAL(entries2.size(), 1);

	pcpp::SomeIpSdEntry* entry2 = *(entries2.begin());
	PTF_ASSERT_EQUAL(entry2->getLength(), 16);
	PTF_ASSERT_EQUAL(entry2->getNumOptions(), 2);
	PTF_ASSERT_EQUAL((uint8_t)entry2->getType(), (uint8_t)pcpp::SomeIpSdEntry::EntryType::OfferService);
	PTF_ASSERT_EQUAL(entry2->getServiceId(), 0xfffe);
	PTF_ASSERT_EQUAL(entry2->getInstanceId(), 0x0001);
	PTF_ASSERT_EQUAL(entry2->getMajorVersion(), 5);
	PTF_ASSERT_EQUAL(entry2->getTtl(), 120);
	PTF_ASSERT_EQUAL(entry2->getMinorVersion(), 0);
	PTF_ASSERT_EQUAL(entry2->getDataPtr()[0], 0x01);

	pcpp::SomeIpSdLayer::OptionsVec options2 = someIpSdLayer2->getOptions();
	PTF_ASSERT_EQUAL(options2.size(), 2);

	pcpp::SomeIpSdOption* option2_1 = *(options2.begin());
	PTF_ASSERT_EQUAL(option2_1->getLength(), 24);
	PTF_ASSERT_EQUAL((uint8_t)option2_1->getType(), (uint8_t)pcpp::SomeIpSdOption::OptionType::IPv6Endpoint);
	PTF_ASSERT_EQUAL(option2_1->getDataPtr()[1], 0x15);

	pcpp::SomeIpSdIPv6Option* ipv6Option2_1 = (pcpp::SomeIpSdIPv6Option*)option2_1;
	PTF_ASSERT_EQUAL(ipv6Option2_1->getIpAddress(), pcpp::IPv6Address("fd53:7cb8:383:4::1:1e5"));
	PTF_ASSERT_EQUAL(ipv6Option2_1->getProtocol(), pcpp::SomeIpSdProtocolType::SD_TCP);
	PTF_ASSERT_EQUAL(ipv6Option2_1->getPort(), 29769);

	pcpp::SomeIpSdOption* option2_2 = *(options2.begin() + 1);
	PTF_ASSERT_EQUAL(option2_2->getLength(), 93);
	PTF_ASSERT_EQUAL((uint8_t)option2_2->getType(), (uint8_t)pcpp::SomeIpSdOption::OptionType::ConfigurationString);
	PTF_ASSERT_EQUAL(option2_2->getDataPtr()[5], 0x63);

	pcpp::SomeIpSdConfigurationOption* configurationOption = (pcpp::SomeIpSdConfigurationOption*)option2_2;
	for (int i = 0; i < 89; i++)
	{
		PTF_ASSERT_EQUAL(configurationOption->getConfigurationString()[i],
		                 someIpSdPacket2.getRawPacket()->getRawData()[138 + i]);
	}

	pcpp::SomeIpSdLayer::OptionsVec options2Entry0 = someIpSdLayer2->getOptionsFromEntry(0);
	PTF_ASSERT_EQUAL(options2Entry0.size(), 2);

	pcpp::SomeIpSdOption* options2Entry0_1 = *(options2Entry0.begin());
	PTF_ASSERT_EQUAL(options2Entry0_1->getLength(), 24);
	PTF_ASSERT_EQUAL((uint8_t)options2Entry0_1->getType(), (uint8_t)pcpp::SomeIpSdOption::OptionType::IPv6Endpoint);
	PTF_ASSERT_EQUAL(options2Entry0_1->getDataPtr()[1], 0x15);

	pcpp::SomeIpSdOption* options2Entry0_2 = *(options2Entry0.begin() + 1);
	PTF_ASSERT_EQUAL(options2Entry0_2->getLength(), 93);
	PTF_ASSERT_EQUAL((uint8_t)options2Entry0_2->getType(),
	                 (uint8_t)pcpp::SomeIpSdOption::OptionType::ConfigurationString);
	PTF_ASSERT_EQUAL(options2Entry0_2->getDataPtr()[5], 0x63);

	pcpp::SomeIpSdLayer::OptionsVec options2Entry1 = someIpSdLayer2->getOptionsFromEntry(1);
	PTF_ASSERT_EQUAL(options2Entry1.size(), 0);

	// Subscribe (Entry: 2xSubscribeEventgroup, Option: IPv4Endpoint)
	PTF_ASSERT_TRUE(someIpSdPacket3.isPacketOfType(pcpp::SomeIP));
	pcpp::SomeIpSdLayer* someIpSdLayer3 = someIpSdPacket3.getLayerOfType<pcpp::SomeIpSdLayer>();
	PTF_ASSERT_NOT_NULL(someIpSdLayer3);
	PTF_ASSERT_EQUAL(someIpSdLayer3->getHeaderLen(), 72);
	PTF_ASSERT_EQUAL(someIpSdLayer3->getMessageID(), 0xffff8100);
	PTF_ASSERT_EQUAL(someIpSdLayer3->getServiceID(), 0xffff);
	PTF_ASSERT_EQUAL(someIpSdLayer3->getMethodID(), 0x8100);
	PTF_ASSERT_EQUAL(someIpSdLayer3->getLengthField(), 64);
	PTF_ASSERT_EQUAL(someIpSdLayer3->getRequestID(), 0x00000003);
	PTF_ASSERT_EQUAL(someIpSdLayer3->getClientID(), 0x0);
	PTF_ASSERT_EQUAL(someIpSdLayer3->getSessionID(), 0x3);
	PTF_ASSERT_EQUAL(someIpSdLayer3->getProtocolVersion(), 1);
	PTF_ASSERT_EQUAL(someIpSdLayer3->getInterfaceVersion(), 1);
	PTF_ASSERT_EQUAL((int)someIpSdLayer3->getMessageType(), (int)pcpp::SomeIpLayer::MsgType::NOTIFICATION);
	PTF_ASSERT_EQUAL(someIpSdLayer3->getMessageTypeAsInt(), (uint8_t)pcpp::SomeIpLayer::MsgType::NOTIFICATION);
	PTF_ASSERT_EQUAL(someIpSdLayer3->getReturnCode(), 0);
	PTF_ASSERT_EQUAL(someIpSdLayer3->getNumEntries(), 2);
	PTF_ASSERT_EQUAL(someIpSdLayer3->getNumOptions(), 1);
	PTF_ASSERT_EQUAL(someIpSdLayer3->toString(), "SOME/IP-SD Layer, 2 entries, 1 options");

	pcpp::SomeIpSdLayer::EntriesVec entries3 = someIpSdLayer3->getEntries();
	PTF_ASSERT_EQUAL(entries3.size(), 2);

	pcpp::SomeIpSdEntry* entry3_1 = *(entries3.begin());
	PTF_ASSERT_EQUAL(entry3_1->getLength(), 16);
	PTF_ASSERT_EQUAL(entry3_1->getNumOptions(), 1);
	PTF_ASSERT_EQUAL((uint8_t)entry3_1->getType(), (uint8_t)pcpp::SomeIpSdEntry::EntryType::SubscribeEventgroup);
	PTF_ASSERT_EQUAL(entry3_1->getServiceId(), 0xd063);
	PTF_ASSERT_EQUAL(entry3_1->getInstanceId(), 0x0001);
	PTF_ASSERT_EQUAL(entry3_1->getMajorVersion(), 1);
	PTF_ASSERT_EQUAL(entry3_1->getTtl(), 3);
	PTF_ASSERT_EQUAL(entry3_1->getCounter(), 0);
	PTF_ASSERT_EQUAL(entry3_1->getEventgroupId(), 1);
	PTF_ASSERT_EQUAL(entry3_1->getDataPtr()[0], 0x06);

	pcpp::SomeIpSdEntry* entry3_2 = *(entries3.begin() + 1);
	PTF_ASSERT_EQUAL(entry3_2->getLength(), 16);
	PTF_ASSERT_EQUAL(entry3_2->getNumOptions(), 1);
	PTF_ASSERT_EQUAL((uint8_t)entry3_2->getType(), (uint8_t)pcpp::SomeIpSdEntry::EntryType::SubscribeEventgroup);
	PTF_ASSERT_EQUAL(entry3_2->getServiceId(), 0xd066);
	PTF_ASSERT_EQUAL(entry3_2->getInstanceId(), 0x0001);
	PTF_ASSERT_EQUAL(entry3_2->getMajorVersion(), 1);
	PTF_ASSERT_EQUAL(entry3_2->getTtl(), 3);
	PTF_ASSERT_EQUAL(entry3_2->getCounter(), 0);
	PTF_ASSERT_EQUAL(entry3_2->getEventgroupId(), 1);
	PTF_ASSERT_EQUAL(entry3_2->getDataPtr()[0], 0x06);

	pcpp::SomeIpSdLayer::OptionsVec options3 = someIpSdLayer3->getOptions();
	PTF_ASSERT_EQUAL(options3.size(), 1);

	pcpp::SomeIpSdOption* option3 = *(options3.begin());
	PTF_ASSERT_EQUAL(option3->getLength(), 12);
	PTF_ASSERT_EQUAL((uint8_t)option3->getType(), (uint8_t)pcpp::SomeIpSdOption::OptionType::IPv4Endpoint);
	PTF_ASSERT_EQUAL(option3->getDataPtr()[1], 0x09);

	delete entry;
	delete option;
	entries1.clear();
	options.clear();

	delete entry2;
	delete option2_1;
	delete option2_2;
	delete options2Entry0_1;
	delete options2Entry0_2;
	entries2.clear();
	options2.clear();
	options2Entry0.clear();

	delete entry3_1;
	delete entry3_2;
	delete option3;
	entries3.clear();
	options3.clear();
}

PTF_TEST_CASE(SomeIpSdCreationTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_INTO_BUFFER(1, "PacketExamples/SomeIpSdOffer.dat");
	READ_FILE_INTO_BUFFER(2, "PacketExamples/SomeIpSdSubscribe.dat");

	// OfferService (Entry: OfferService, Option: IPv4Endpoint)
	pcpp::SomeIpSdLayer someIpSdLayer(0xffff, 0x8100, 0, 0x2, 0x1, pcpp::SomeIpLayer::MsgType::NOTIFICATION, 0, 0xc0);
	auto pEntry = std::unique_ptr<pcpp::SomeIpSdEntry>(
	    new pcpp::SomeIpSdEntry(pcpp::SomeIpSdEntry::EntryType::OfferService, 0xd05f, 2, 1, 3, 0));
	auto pOption = std::unique_ptr<pcpp::SomeIpSdIPv4Option>(
	    new pcpp::SomeIpSdIPv4Option(pcpp::SomeIpSdIPv4Option::IPv4OptionType::IPv4Endpoint,
	                                 pcpp::IPv4Address("160.48.199.28"), 30502, pcpp::SomeIpSdProtocolType::SD_UDP));
	auto offsetEntry = someIpSdLayer.addEntry(*pEntry);
	someIpSdLayer.addOptionTo(offsetEntry, *pOption);

	pcpp::Packet someIpSdPacket(100);
	PTF_ASSERT_TRUE(someIpSdPacket.addLayer(&someIpSdLayer));
	someIpSdPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(someIpSdPacket.getRawPacket()->getRawDataLen(), bufferLength1 - 46);
	PTF_ASSERT_BUF_COMPARE(someIpSdPacket.getRawPacket()->getRawData(), buffer1 + 46, bufferLength1 - 46);

	// Subscribe (Entry: 2xSubscribeEventgroup, Option: IPv4Endpoint)
	pcpp::SomeIpSdLayer someIpSdLayer2(0xffff, 0x8100, 0, 0x3, 0x1, pcpp::SomeIpLayer::MsgType::NOTIFICATION, 0, 0xc0);
	auto pEntry2_1 = std::unique_ptr<pcpp::SomeIpSdEntry>(
	    new pcpp::SomeIpSdEntry(pcpp::SomeIpSdEntry::EntryType::SubscribeEventgroup, 0xd063, 1, 1, 3, 0, 1));
	auto pEntry2_2 = std::unique_ptr<pcpp::SomeIpSdEntry>(
	    new pcpp::SomeIpSdEntry(pcpp::SomeIpSdEntry::EntryType::SubscribeEventgroup, 0xd066, 1, 1, 3, 0, 1));
	auto pOption2 = std::unique_ptr<pcpp::SomeIpSdIPv4Option>(
	    new pcpp::SomeIpSdIPv4Option(pcpp::SomeIpSdIPv4Option::IPv4OptionType::IPv4Endpoint,
	                                 pcpp::IPv4Address("160.48.199.101"), 58358, pcpp::SomeIpSdProtocolType::SD_UDP));
	auto offsetEntry2_1 = someIpSdLayer2.addEntry(*pEntry2_1);
	someIpSdLayer2.addOptionTo(offsetEntry2_1, *pOption2);
	auto offsetEntry2_2 = someIpSdLayer2.addEntry(*pEntry2_2);
	someIpSdLayer2.addOptionTo(offsetEntry2_2, *pOption2);

	pcpp::Packet someIpSdPacket2(100);
	PTF_ASSERT_TRUE(someIpSdPacket2.addLayer(&someIpSdLayer2));
	someIpSdPacket2.computeCalculateFields();

	PTF_ASSERT_EQUAL(someIpSdPacket2.getRawPacket()->getRawDataLen(), bufferLength2 - 46);
	PTF_ASSERT_BUF_COMPARE(someIpSdPacket2.getRawPacket()->getRawData(), buffer2 + 46, bufferLength2 - 46);

	delete[] buffer1;
	delete[] buffer2;
}
