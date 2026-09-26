#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "Packet.h"
#include "BluetoothHciLayer.h"
#include "PayloadLayer.h"

namespace
{
	std::string directionToString(pcpp::BluetoothHciDirection direction)
	{
		switch (direction)
		{
		case pcpp::BluetoothHciDirection::HostToController:
			return "HostToController";
		case pcpp::BluetoothHciDirection::ControllerToHost:
			return "ControllerToHost";
		default:
			return "Unknown";
		}
	}

	void printEventLayer(const pcpp::BluetoothHciEventLayer* eventLayer, bool printVerbose)
	{
		PTF_PRINT_VERBOSE("  getProtocol():             " << static_cast<int>(eventLayer->getProtocol()));
		PTF_PRINT_VERBOSE("  hasDirectionHeader():      " << (eventLayer->hasDirectionHeader() ? "true" : "false"));
		PTF_PRINT_VERBOSE("  getDirection():            " << directionToString(eventLayer->getDirection()));
		PTF_PRINT_VERBOSE("  getHeaderLen():            " << eventLayer->getHeaderLen());
		PTF_PRINT_VERBOSE("  getPacketIndicator():      0x"
		                  << std::hex << static_cast<int>(eventLayer->getPacketIndicator()) << std::dec);
		PTF_PRINT_VERBOSE("  getEventCode():            0x" << std::hex << static_cast<int>(eventLayer->getEventCode())
		                                                    << std::dec);
		PTF_PRINT_VERBOSE("  getParameterTotalLength(): " << static_cast<int>(eventLayer->getParameterTotalLength()));
		PTF_PRINT_VERBOSE("  getLayerPayloadSize():     " << eventLayer->getLayerPayloadSize());
		PTF_PRINT_VERBOSE("  getParameters()[0]:        0x"
		                  << std::hex << static_cast<int>(eventLayer->getParameters()[0]) << std::dec);
		PTF_PRINT_VERBOSE("  getInquiryCompleteParameters(): "
		                  << (eventLayer->getInquiryCompleteParameters() == nullptr ? "nullptr" : "non-null"));
		PTF_PRINT_VERBOSE("  toString():                " << eventLayer->toString());
	}
}  // namespace

PTF_TEST_CASE(BluetoothHciEventInquiryCompleteTest)
{
	// LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR: 4-byte direction header followed by the H4 packet
	{
		auto rawPacket = pcpp_tests::utils::createPacketFromHexResource(
		    "PacketExamples/bluetoothHciInquiryCompleteWithPhdr.dat",
		    pcpp_tests::utils::PacketFactory(pcpp::LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR));

		pcpp::Packet packet(rawPacket.get());

		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::BluetoothHci));
		PTF_ASSERT_EQUAL(packet.getFirstLayer()->getProtocol(), pcpp::BluetoothHci, enum);

		auto* hciLayer = packet.getLayerOfType<pcpp::BluetoothHciLayer>();
		PTF_ASSERT_NOT_NULL(hciLayer);
		PTF_ASSERT_EQUAL(hciLayer->getPacketType(), pcpp::BluetoothHciPacketType::Event, enumclass);
		PTF_ASSERT_EQUAL(hciLayer->getPacketIndicator(), 0x04);

		auto* eventLayer = hciLayer->asEventLayer();
		PTF_ASSERT_NOT_NULL(eventLayer);
		PTF_ASSERT_NULL(eventLayer->getNextLayer());

		PTF_PRINT_VERBOSE("Inquiry Complete (LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR):");
		printEventLayer(eventLayer, printVerbose);

		PTF_ASSERT_EQUAL(eventLayer->getOsiModelLayer(), pcpp::OsiModelDataLinkLayer, enum);
		PTF_ASSERT_TRUE(eventLayer->hasDirectionHeader());
		PTF_ASSERT_EQUAL(eventLayer->getDirection(), pcpp::BluetoothHciDirection::ControllerToHost, enumclass);
		PTF_ASSERT_EQUAL(eventLayer->getHeaderLen(), 7);
		PTF_ASSERT_EQUAL(eventLayer->getLayerPayloadSize(), 1);

		auto* header = eventLayer->getEventHeader();
		PTF_ASSERT_NOT_NULL(header);
		PTF_ASSERT_EQUAL(header->eventCode, pcpp::BluetoothHciInquiryCompleteEventCode);
		PTF_ASSERT_EQUAL(header->parameterTotalLength, 1);

		PTF_ASSERT_EQUAL(eventLayer->getEventCode(), pcpp::BluetoothHciInquiryCompleteEventCode);
		PTF_ASSERT_TRUE(eventLayer->isEventOfType(pcpp::BluetoothHciInquiryCompleteEventCode));
		PTF_ASSERT_FALSE(eventLayer->isEventOfType(0x0f));
		PTF_ASSERT_EQUAL(eventLayer->getParameterTotalLength(), 1);
		PTF_ASSERT_EQUAL(eventLayer->getParameters()[0], 0);

		auto* inquiryComplete = eventLayer->getInquiryCompleteParameters();
		PTF_ASSERT_NOT_NULL(inquiryComplete);
		PTF_ASSERT_EQUAL(inquiryComplete->status, 0);

		PTF_ASSERT_EQUAL(eventLayer->toString(), "Bluetooth HCI Event - Inquiry Complete, Status: Success (0x00)");
	}

	// LINKTYPE_BLUETOOTH_HCI_H4: H4 packet with no direction header
	{
		auto rawPacket = pcpp_tests::utils::createPacketFromHexResource(
		    "PacketExamples/bluetoothHciInquiryComplete.dat",
		    pcpp_tests::utils::PacketFactory(pcpp::LINKTYPE_BLUETOOTH_HCI_H4));

		pcpp::Packet packet(rawPacket.get());

		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::BluetoothHci));

		auto* hciLayer = packet.getLayerOfType<pcpp::BluetoothHciLayer>();
		PTF_ASSERT_NOT_NULL(hciLayer);
		PTF_ASSERT_EQUAL(hciLayer->getPacketType(), pcpp::BluetoothHciPacketType::Event, enumclass);
		PTF_ASSERT_EQUAL(hciLayer->getPacketIndicator(), 0x04);

		auto* eventLayer = hciLayer->asEventLayer();
		PTF_ASSERT_NOT_NULL(eventLayer);
		PTF_ASSERT_NULL(eventLayer->getNextLayer());

		PTF_PRINT_VERBOSE("Inquiry Complete (LINKTYPE_BLUETOOTH_HCI_H4):");
		printEventLayer(eventLayer, printVerbose);

		PTF_ASSERT_FALSE(eventLayer->hasDirectionHeader());
		PTF_ASSERT_EQUAL(eventLayer->getDirection(), pcpp::BluetoothHciDirection::Unknown, enumclass);
		PTF_ASSERT_EQUAL(eventLayer->getHeaderLen(), 3);
		PTF_ASSERT_EQUAL(eventLayer->getLayerPayloadSize(), 1);
		PTF_ASSERT_EQUAL(eventLayer->getEventCode(), pcpp::BluetoothHciInquiryCompleteEventCode);
		PTF_ASSERT_EQUAL(eventLayer->getParameterTotalLength(), 1);

		auto* inquiryComplete = eventLayer->getInquiryCompleteParameters();
		PTF_ASSERT_NOT_NULL(inquiryComplete);
		PTF_ASSERT_EQUAL(inquiryComplete->status, 0);

		PTF_ASSERT_EQUAL(eventLayer->toString(), "Bluetooth HCI Event - Inquiry Complete, Status: Success (0x00)");
	}
}

PTF_TEST_CASE(BluetoothHciEventGenericTest)
{
	// Command Status (0x0f) is not decoded yet: the layer must still identify it as an Event and expose the raw
	// parameters, but the Inquiry Complete accessor must return nullptr
	auto rawPacket = pcpp_tests::utils::createPacketFromHexResource(
	    "PacketExamples/bluetoothHciCommandStatusWithPhdr.dat",
	    pcpp_tests::utils::PacketFactory(pcpp::LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR));

	pcpp::Packet packet(rawPacket.get());

	PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::BluetoothHci));

	auto* hciLayer = packet.getLayerOfType<pcpp::BluetoothHciLayer>();
	PTF_ASSERT_NOT_NULL(hciLayer);
	PTF_ASSERT_EQUAL(hciLayer->getPacketType(), pcpp::BluetoothHciPacketType::Event, enumclass);

	auto* eventLayer = hciLayer->asEventLayer();
	PTF_ASSERT_NOT_NULL(eventLayer);

	PTF_PRINT_VERBOSE("Command Status (LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR):");
	printEventLayer(eventLayer, printVerbose);

	PTF_ASSERT_TRUE(eventLayer->hasDirectionHeader());
	PTF_ASSERT_EQUAL(eventLayer->getDirection(), pcpp::BluetoothHciDirection::ControllerToHost, enumclass);
	PTF_ASSERT_EQUAL(eventLayer->getHeaderLen(), 7);
	PTF_ASSERT_EQUAL(eventLayer->getEventCode(), 0x0f);
	PTF_ASSERT_FALSE(eventLayer->isEventOfType(pcpp::BluetoothHciInquiryCompleteEventCode));
	PTF_ASSERT_EQUAL(eventLayer->getParameterTotalLength(), 4);
	PTF_ASSERT_EQUAL(eventLayer->getLayerPayloadSize(), 4);

	const uint8_t* parameters = eventLayer->getParameters();
	PTF_ASSERT_EQUAL(parameters[0], 0x00);
	PTF_ASSERT_EQUAL(parameters[1], 0x01);
	PTF_ASSERT_EQUAL(parameters[2], 0x01);
	PTF_ASSERT_EQUAL(parameters[3], 0x04);

	PTF_ASSERT_NULL(eventLayer->getInquiryCompleteParameters());
	PTF_ASSERT_EQUAL(eventLayer->toString(), "Bluetooth HCI Event, Event Code: 0x0f");
}

PTF_TEST_CASE(BluetoothHciEventInvalidDataTest)
{
	// An HCI Command packet (indicator 0x01) must not be parsed as an Event
	{
		uint8_t commandPacket[] = { 0x01, 0x01, 0x04, 0x05, 0x33, 0x8b, 0x9e, 0x06, 0x00 };
		pcpp::RawPacket rawPacket(commandPacket, sizeof(commandPacket), timeval{ 0, 0 }, false,
		                          pcpp::LINKTYPE_BLUETOOTH_HCI_H4);

		pcpp::Packet packet(&rawPacket);

		PTF_PRINT_VERBOSE("Command packet (indicator 0x01) parsed as: " << packet.getFirstLayer()->toString());

		PTF_ASSERT_FALSE(packet.isPacketOfType(pcpp::BluetoothHci));
		PTF_ASSERT_NOT_NULL(packet.getLayerOfType<pcpp::PayloadLayer>());
	}

	// Direction header present but the indicator after it is not 0x04
	{
		uint8_t commandPacketWithPhdr[] = {
			0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x04, 0x05, 0x33, 0x8b, 0x9e, 0x06, 0x00
		};
		PTF_ASSERT_FALSE(
		    pcpp::BluetoothHciEventLayer::isDataValid(commandPacketWithPhdr, sizeof(commandPacketWithPhdr), true));
	}

	// Too short to hold an Event header
	{
		uint8_t truncated[] = { 0x04, 0x01 };
		PTF_ASSERT_FALSE(pcpp::BluetoothHciEventLayer::isDataValid(truncated, sizeof(truncated), false));

		uint8_t truncatedWithPhdr[] = { 0x00, 0x00, 0x00, 0x01, 0x04, 0x01 };
		PTF_ASSERT_FALSE(pcpp::BluetoothHciEventLayer::isDataValid(truncatedWithPhdr, sizeof(truncatedWithPhdr), true));

		PTF_ASSERT_FALSE(pcpp::BluetoothHciEventLayer::isDataValid(nullptr, 0, false));
	}

	// Inquiry Complete header but the status byte is missing: layer is valid, but the typed accessor must refuse
	{
		uint8_t missingStatus[] = { 0x04, 0x01, 0x01 };
		PTF_ASSERT_TRUE(pcpp::BluetoothHciEventLayer::isDataValid(missingStatus, sizeof(missingStatus), false));

		pcpp::RawPacket rawPacket(missingStatus, sizeof(missingStatus), timeval{ 0, 0 }, false,
		                          pcpp::LINKTYPE_BLUETOOTH_HCI_H4);
		pcpp::Packet packet(&rawPacket);

		auto* hciLayer = packet.getLayerOfType<pcpp::BluetoothHciLayer>();
		PTF_ASSERT_NOT_NULL(hciLayer);
		PTF_ASSERT_EQUAL(hciLayer->getPacketType(), pcpp::BluetoothHciPacketType::Event, enumclass);
		PTF_ASSERT_EQUAL(hciLayer->getPacketIndicator(), 0x04);

		auto* eventLayer = hciLayer->asEventLayer();
		PTF_ASSERT_NOT_NULL(eventLayer);
		PTF_ASSERT_NULL(eventLayer->getInquiryCompleteParameters());
		PTF_ASSERT_EQUAL(eventLayer->toString(), "Bluetooth HCI Event, Event Code: 0x01");
	}
}

PTF_TEST_CASE(BluetoothHciPacketTypeTest)
{
	// Every known H4 packet indicator maps to its packet type
	PTF_ASSERT_EQUAL(pcpp::BluetoothHciLayer::packetTypeFromIndicator(0x01), pcpp::BluetoothHciPacketType::Command,
	                 enumclass);
	PTF_ASSERT_EQUAL(pcpp::BluetoothHciLayer::packetTypeFromIndicator(0x02), pcpp::BluetoothHciPacketType::AclData,
	                 enumclass);
	PTF_ASSERT_EQUAL(pcpp::BluetoothHciLayer::packetTypeFromIndicator(0x03), pcpp::BluetoothHciPacketType::ScoData,
	                 enumclass);
	PTF_ASSERT_EQUAL(pcpp::BluetoothHciLayer::packetTypeFromIndicator(0x04), pcpp::BluetoothHciPacketType::Event,
	                 enumclass);
	PTF_ASSERT_EQUAL(pcpp::BluetoothHciLayer::packetTypeFromIndicator(0x05), pcpp::BluetoothHciPacketType::IsoData,
	                 enumclass);

	// Anything else is reported as Unknown rather than becoming an out-of-range enum value
	PTF_ASSERT_EQUAL(pcpp::BluetoothHciLayer::packetTypeFromIndicator(0x00), pcpp::BluetoothHciPacketType::Unknown,
	                 enumclass);
	PTF_ASSERT_EQUAL(pcpp::BluetoothHciLayer::packetTypeFromIndicator(0x06), pcpp::BluetoothHciPacketType::Unknown,
	                 enumclass);
	PTF_ASSERT_EQUAL(pcpp::BluetoothHciLayer::packetTypeFromIndicator(0x42), pcpp::BluetoothHciPacketType::Unknown,
	                 enumclass);
	PTF_ASSERT_EQUAL(pcpp::BluetoothHciLayer::packetTypeFromIndicator(0xff), pcpp::BluetoothHciPacketType::Unknown,
	                 enumclass);

	// A packet whose indicator is not a known packet type isn't parsed as an HCI layer at all
	{
		uint8_t unknownIndicator[] = { 0x42, 0x01, 0x01, 0x00 };
		PTF_ASSERT_FALSE(pcpp::BluetoothHciEventLayer::isDataValid(unknownIndicator, sizeof(unknownIndicator), false));

		pcpp::RawPacket rawPacket(unknownIndicator, sizeof(unknownIndicator), timeval{ 0, 0 }, false,
		                          pcpp::LINKTYPE_BLUETOOTH_HCI_H4);
		pcpp::Packet packet(&rawPacket);

		PTF_ASSERT_FALSE(packet.isPacketOfType(pcpp::BluetoothHci));
		PTF_ASSERT_NOT_NULL(packet.getLayerOfType<pcpp::PayloadLayer>());
	}

	// A direction value that is neither host-to-controller nor controller-to-host is reported as Unknown
	{
		uint8_t unknownDirection[] = { 0x00, 0x00, 0x00, 0x07, 0x04, 0x01, 0x01, 0x00 };
		pcpp::RawPacket rawPacket(unknownDirection, sizeof(unknownDirection), timeval{ 0, 0 }, false,
		                          pcpp::LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR);
		pcpp::Packet packet(&rawPacket);

		auto* hciLayer = packet.getLayerOfType<pcpp::BluetoothHciLayer>();
		PTF_ASSERT_NOT_NULL(hciLayer);

		PTF_PRINT_VERBOSE("Unknown direction value parsed as: " << directionToString(hciLayer->getDirection()));

		PTF_ASSERT_TRUE(hciLayer->hasDirectionHeader());
		PTF_ASSERT_EQUAL(hciLayer->getDirection(), pcpp::BluetoothHciDirection::Unknown, enumclass);
		PTF_ASSERT_EQUAL(hciLayer->getPacketType(), pcpp::BluetoothHciPacketType::Event, enumclass);
		PTF_ASSERT_NOT_NULL(hciLayer->asEventLayer());
	}

	// A host-to-controller direction value is read correctly. Events are always sent by the controller, so real
	// captures don't contain this, but the direction field must still be read correctly
	{
		uint8_t hostToController[] = { 0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x01, 0x00 };
		pcpp::RawPacket rawPacket(hostToController, sizeof(hostToController), timeval{ 0, 0 }, false,
		                          pcpp::LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR);
		pcpp::Packet packet(&rawPacket);

		auto* hciLayer = packet.getLayerOfType<pcpp::BluetoothHciLayer>();
		PTF_ASSERT_NOT_NULL(hciLayer);
		PTF_ASSERT_EQUAL(hciLayer->getDirection(), pcpp::BluetoothHciDirection::HostToController, enumclass);

		auto* eventLayer = hciLayer->asEventLayer();
		PTF_ASSERT_NOT_NULL(eventLayer);
		PTF_ASSERT_EQUAL(eventLayer->toString(), "Bluetooth HCI Event - Inquiry Complete, Status: Success (0x00)");
	}
}
