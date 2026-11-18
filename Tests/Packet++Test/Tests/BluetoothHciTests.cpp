#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "Packet.h"
#include "BluetoothHciLayer.h"
#include "PayloadLayer.h"
#include "Serializers.h"

#include <sstream>

namespace
{
	std::string directionToString(pcpp::BluetoothHciLayer::BluetoothHciDirection direction)
	{
		switch (direction)
		{
		case pcpp::BluetoothHciLayer::BluetoothHciDirection::HostToController:
			return "HostToController";
		case pcpp::BluetoothHciLayer::BluetoothHciDirection::ControllerToHost:
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
		PTF_PRINT_VERBOSE("  getEventCode():            0x" << std::hex << static_cast<int>(eventLayer->getEventCode())
		                                                    << std::dec);
		PTF_PRINT_VERBOSE("  getParameterTotalLength(): " << static_cast<int>(eventLayer->getParameterTotalLength()));
		PTF_PRINT_VERBOSE("  getLayerPayloadSize():     " << eventLayer->getLayerPayloadSize());
		PTF_PRINT_VERBOSE("  getParameters()[0]:        0x"
		                  << std::hex << static_cast<int>(eventLayer->getParameters()[0]) << std::dec);
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

		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::BluetoothHCI));
		PTF_ASSERT_EQUAL(packet.getFirstLayer()->getProtocol(), pcpp::BluetoothHCI, enum);

		auto* hciLayer = packet.getLayerOfType<pcpp::BluetoothHciLayer>();
		PTF_ASSERT_NOT_NULL(hciLayer);
		PTF_ASSERT_EQUAL(hciLayer->getPacketType(), pcpp::BluetoothHciLayer::BluetoothHciPacketType::Event, enumclass);

		auto* eventLayer = packet.getLayerOfType<pcpp::BluetoothHciEventLayer>();
		PTF_ASSERT_NOT_NULL(eventLayer);
		PTF_ASSERT_NULL(eventLayer->getNextLayer());

		PTF_PRINT_VERBOSE("Inquiry Complete (LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR):");
		printEventLayer(eventLayer, printVerbose);

		PTF_ASSERT_EQUAL(eventLayer->getOsiModelLayer(), pcpp::OsiModelDataLinkLayer, enum);
		PTF_ASSERT_TRUE(eventLayer->hasDirectionHeader());
		PTF_ASSERT_EQUAL(eventLayer->getDirection(), pcpp::BluetoothHciLayer::BluetoothHciDirection::ControllerToHost,
		                 enumclass);
		PTF_ASSERT_EQUAL(eventLayer->getHeaderLen(), 8);
		PTF_ASSERT_EQUAL(eventLayer->getLayerPayloadSize(), 0);

		PTF_ASSERT_EQUAL(eventLayer->getEventCode(), 0x01);
		PTF_ASSERT_EQUAL(eventLayer->getParameterTotalLength(), 1);
		PTF_ASSERT_EQUAL(eventLayer->getParameters()[0], 0);

		PTF_ASSERT_EQUAL(eventLayer->toString(), "Bluetooth HCI Event, Event Code: 0x01");

		{
			std::ostringstream oss;
			pcpp::JsonSerializer serializer(oss);
			eventLayer->serialize(serializer);
			PTF_ASSERT_EQUAL(
			    oss.str(),
			    R"({"protocolName":"BluetoothHCI","protocolId":67,"length":8,"direction":"ControllerToHost","eventCode":1,"parameterTotalLength":1})");
		}
	}

	// LINKTYPE_BLUETOOTH_HCI_H4: H4 packet with no direction header
	{
		auto rawPacket = pcpp_tests::utils::createPacketFromHexResource(
		    "PacketExamples/bluetoothHciInquiryComplete.dat",
		    pcpp_tests::utils::PacketFactory(pcpp::LINKTYPE_BLUETOOTH_HCI_H4));

		pcpp::Packet packet(rawPacket.get());

		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::BluetoothHCI));

		auto* hciLayer = packet.getLayerOfType<pcpp::BluetoothHciLayer>();
		PTF_ASSERT_NOT_NULL(hciLayer);
		PTF_ASSERT_EQUAL(hciLayer->getPacketType(), pcpp::BluetoothHciLayer::BluetoothHciPacketType::Event, enumclass);

		auto* eventLayer = packet.getLayerOfType<pcpp::BluetoothHciEventLayer>();
		PTF_ASSERT_NOT_NULL(eventLayer);
		PTF_ASSERT_NULL(eventLayer->getNextLayer());

		PTF_PRINT_VERBOSE("Inquiry Complete (LINKTYPE_BLUETOOTH_HCI_H4):");
		printEventLayer(eventLayer, printVerbose);

		PTF_ASSERT_FALSE(eventLayer->hasDirectionHeader());
		PTF_ASSERT_EQUAL(eventLayer->getDirection(), pcpp::BluetoothHciLayer::BluetoothHciDirection::Unknown,
		                 enumclass);
		PTF_ASSERT_EQUAL(eventLayer->getHeaderLen(), 4);
		PTF_ASSERT_EQUAL(eventLayer->getLayerPayloadSize(), 0);
		PTF_ASSERT_EQUAL(eventLayer->getEventCode(), 0x01);
		PTF_ASSERT_EQUAL(eventLayer->getParameterTotalLength(), 1);

		PTF_ASSERT_EQUAL(eventLayer->toString(), "Bluetooth HCI Event, Event Code: 0x01");
	}
}

PTF_TEST_CASE(BluetoothHciEventGenericTest)
{
	// Command Status (0x0f) is not decoded yet: the layer must still identify it as an Event and expose the raw
	// parameters
	auto rawPacket = pcpp_tests::utils::createPacketFromHexResource(
	    "PacketExamples/bluetoothHciCommandStatusWithPhdr.dat",
	    pcpp_tests::utils::PacketFactory(pcpp::LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR));

	pcpp::Packet packet(rawPacket.get());

	PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::BluetoothHCI));

	auto* hciLayer = packet.getLayerOfType<pcpp::BluetoothHciLayer>();
	PTF_ASSERT_NOT_NULL(hciLayer);
	PTF_ASSERT_EQUAL(hciLayer->getPacketType(), pcpp::BluetoothHciLayer::BluetoothHciPacketType::Event, enumclass);

	auto* eventLayer = packet.getLayerOfType<pcpp::BluetoothHciEventLayer>();
	PTF_ASSERT_NOT_NULL(eventLayer);

	PTF_PRINT_VERBOSE("Command Status (LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR):");
	printEventLayer(eventLayer, printVerbose);

	PTF_ASSERT_TRUE(eventLayer->hasDirectionHeader());
	PTF_ASSERT_EQUAL(eventLayer->getDirection(), pcpp::BluetoothHciLayer::BluetoothHciDirection::ControllerToHost,
	                 enumclass);
	PTF_ASSERT_EQUAL(eventLayer->getHeaderLen(), 11);
	PTF_ASSERT_EQUAL(eventLayer->getEventCode(), 0x0f);
	PTF_ASSERT_EQUAL(eventLayer->getParameterTotalLength(), 4);
	PTF_ASSERT_EQUAL(eventLayer->getLayerPayloadSize(), 0);

	const uint8_t* parameters = eventLayer->getParameters();
	PTF_ASSERT_EQUAL(parameters[0], 0x00);
	PTF_ASSERT_EQUAL(parameters[1], 0x01);
	PTF_ASSERT_EQUAL(parameters[2], 0x01);
	PTF_ASSERT_EQUAL(parameters[3], 0x04);

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

		PTF_ASSERT_FALSE(packet.isPacketOfType(pcpp::BluetoothHCI));
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
}

PTF_TEST_CASE(BluetoothHciPacketTypeTest)
{
	// A packet whose indicator is not a known packet type isn't parsed as an HCI layer at all
	{
		uint8_t unknownIndicator[] = { 0x42, 0x01, 0x01, 0x00 };
		PTF_ASSERT_FALSE(pcpp::BluetoothHciEventLayer::isDataValid(unknownIndicator, sizeof(unknownIndicator), false));

		pcpp::RawPacket rawPacket(unknownIndicator, sizeof(unknownIndicator), timeval{ 0, 0 }, false,
		                          pcpp::LINKTYPE_BLUETOOTH_HCI_H4);
		pcpp::Packet packet(&rawPacket);

		PTF_ASSERT_FALSE(packet.isPacketOfType(pcpp::BluetoothHCI));
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
		PTF_ASSERT_EQUAL(hciLayer->getDirection(), pcpp::BluetoothHciLayer::BluetoothHciDirection::Unknown, enumclass);
		PTF_ASSERT_EQUAL(hciLayer->getPacketType(), pcpp::BluetoothHciLayer::BluetoothHciPacketType::Event, enumclass);
		PTF_ASSERT_NOT_NULL(packet.getLayerOfType<pcpp::BluetoothHciEventLayer>());
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
		PTF_ASSERT_EQUAL(hciLayer->getDirection(), pcpp::BluetoothHciLayer::BluetoothHciDirection::HostToController,
		                 enumclass);

		auto* eventLayer = packet.getLayerOfType<pcpp::BluetoothHciEventLayer>();
		PTF_ASSERT_NOT_NULL(eventLayer);
		PTF_ASSERT_EQUAL(eventLayer->toString(), "Bluetooth HCI Event, Event Code: 0x01");
	}
}

PTF_TEST_CASE(BluetoothHciEventCreationTest)
{
	std::vector<uint8_t> statusParam = { 0x00 };

	// No direction header: 0x04 indicator + event header + 1 parameter byte = 4 bytes total
	{
		pcpp::BluetoothHciEventLayer eventLayer(0x01, statusParam);

		PTF_ASSERT_FALSE(eventLayer.hasDirectionHeader());
		PTF_ASSERT_EQUAL(eventLayer.getDirection(), pcpp::BluetoothHciLayer::BluetoothHciDirection::Unknown, enumclass);
		PTF_ASSERT_EQUAL(eventLayer.getPacketType(), pcpp::BluetoothHciLayer::BluetoothHciPacketType::Event, enumclass);
		PTF_ASSERT_EQUAL(eventLayer.getHeaderLen(), 4);
		PTF_ASSERT_EQUAL(eventLayer.getDataLen(), 4);
		PTF_ASSERT_EQUAL(eventLayer.getEventCode(), 0x01);
		PTF_ASSERT_EQUAL(eventLayer.getParameterTotalLength(), 1);
		PTF_ASSERT_EQUAL(eventLayer.getParameters()[0], 0x00);
	}

	// With direction header: 4 (phdr) + 1 (indicator) + 2 (event header) + 1 (param) = 8 bytes total
	{
		pcpp::BluetoothHciEventLayer eventLayer(pcpp::BluetoothHciLayer::BluetoothHciDirection::ControllerToHost, 0x01,
		                                        statusParam);

		PTF_ASSERT_TRUE(eventLayer.hasDirectionHeader());
		PTF_ASSERT_EQUAL(eventLayer.getDirection(), pcpp::BluetoothHciLayer::BluetoothHciDirection::ControllerToHost,
		                 enumclass);
		PTF_ASSERT_EQUAL(eventLayer.getHeaderLen(), 8);
		PTF_ASSERT_EQUAL(eventLayer.getDataLen(), 8);
		PTF_ASSERT_EQUAL(eventLayer.getEventCode(), 0x01);
		PTF_ASSERT_EQUAL(eventLayer.getParameterTotalLength(), 1);
		PTF_ASSERT_EQUAL(eventLayer.getParameters()[0], 0x00);

		// Round-trip the created buffer back through parseLayer and confirm it decodes identically.
		// RawPacket does not take ownership of eventLayer's buffer (`false` on the 4th arg).
		pcpp::RawPacket rawPacket(eventLayer.getData(), eventLayer.getDataLen(), timeval{ 0, 0 }, false,
		                          pcpp::LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR);
		pcpp::Packet packet(&rawPacket);
		auto* parsed = packet.getLayerOfType<pcpp::BluetoothHciEventLayer>();
		PTF_ASSERT_NOT_NULL(parsed);
		PTF_ASSERT_EQUAL(parsed->getPacketType(), pcpp::BluetoothHciLayer::BluetoothHciPacketType::Event, enumclass);
		PTF_ASSERT_EQUAL(parsed->getDirection(), pcpp::BluetoothHciLayer::BluetoothHciDirection::ControllerToHost,
		                 enumclass);
		PTF_ASSERT_EQUAL(parsed->getEventCode(), 0x01);
		PTF_ASSERT_EQUAL(parsed->getParameterTotalLength(), 1);
		PTF_ASSERT_EQUAL(parsed->getParameters()[0], 0x00);
	}

	// Zero-length parameters are valid: event header + 1 (indicator) = 3 bytes total
	{
		pcpp::BluetoothHciEventLayer eventLayer(0x0f);

		PTF_ASSERT_EQUAL(eventLayer.getHeaderLen(), 3);
		PTF_ASSERT_EQUAL(eventLayer.getDataLen(), 3);
		PTF_ASSERT_EQUAL(eventLayer.getEventCode(), 0x0f);
		PTF_ASSERT_EQUAL(eventLayer.getParameterTotalLength(), 0);
	}
}

PTF_TEST_CASE(BluetoothHciEventEditTest)
{
	// setEventCode() on a parsed packet
	{
		auto rawPacket = pcpp_tests::utils::createPacketFromHexResource(
		    "PacketExamples/bluetoothHciCommandStatusWithPhdr.dat",
		    pcpp_tests::utils::PacketFactory(pcpp::LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR));
		pcpp::Packet packet(rawPacket.get());

		auto* eventLayer = packet.getLayerOfType<pcpp::BluetoothHciEventLayer>();
		PTF_ASSERT_NOT_NULL(eventLayer);
		PTF_ASSERT_EQUAL(eventLayer->getEventCode(), 0x0f);

		eventLayer->setEventCode(0x0e);
		PTF_ASSERT_EQUAL(eventLayer->getEventCode(), 0x0e);
		PTF_ASSERT_EQUAL(eventLayer->getParameterTotalLength(), 4);
		PTF_ASSERT_EQUAL(eventLayer->toString(), "Bluetooth HCI Event, Event Code: 0x0e");
	}

	// setParameters() on a parsed packet: extend, shorten, same size and empty
	{
		auto rawPacket = pcpp_tests::utils::createPacketFromHexResource(
		    "PacketExamples/bluetoothHciCommandStatusWithPhdr.dat",
		    pcpp_tests::utils::PacketFactory(pcpp::LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR));
		pcpp::Packet packet(rawPacket.get());

		auto* eventLayer = packet.getLayerOfType<pcpp::BluetoothHciEventLayer>();
		PTF_ASSERT_NOT_NULL(eventLayer);
		PTF_ASSERT_EQUAL(eventLayer->getParameterTotalLength(), 4);

		// Extend: 4 -> 6 parameter bytes
		std::vector<uint8_t> longerParams = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
		eventLayer->setParameters(longerParams);
		PTF_ASSERT_EQUAL(eventLayer->getParameterTotalLength(), 6);
		PTF_ASSERT_EQUAL(eventLayer->getHeaderLen(), 13);
		PTF_ASSERT_EQUAL(packet.getRawPacket()->getRawDataLen(), 13);
		PTF_ASSERT_BUF_COMPARE(eventLayer->getParameters(), longerParams.data(), longerParams.size());
		PTF_ASSERT_EQUAL(eventLayer->getEventCode(), 0x0f);
		PTF_ASSERT_EQUAL(eventLayer->getDirection(), pcpp::BluetoothHciLayer::BluetoothHciDirection::ControllerToHost,
		                 enumclass);

		// Shorten: 6 -> 2 parameter bytes
		std::vector<uint8_t> shorterParams = { 0xaa, 0xbb };
		eventLayer->setParameters(shorterParams);
		PTF_ASSERT_EQUAL(eventLayer->getParameterTotalLength(), 2);
		PTF_ASSERT_EQUAL(eventLayer->getHeaderLen(), 9);
		PTF_ASSERT_EQUAL(packet.getRawPacket()->getRawDataLen(), 9);
		PTF_ASSERT_BUF_COMPARE(eventLayer->getParameters(), shorterParams.data(), shorterParams.size());

		// Same size: 2 -> 2 parameter bytes
		std::vector<uint8_t> sameSizeParams = { 0xcc, 0xdd };
		eventLayer->setParameters(sameSizeParams);
		PTF_ASSERT_EQUAL(eventLayer->getParameterTotalLength(), 2);
		PTF_ASSERT_EQUAL(eventLayer->getHeaderLen(), 9);
		PTF_ASSERT_BUF_COMPARE(eventLayer->getParameters(), sameSizeParams.data(), sameSizeParams.size());

		// Empty parameters
		eventLayer->setParameters({});
		PTF_ASSERT_EQUAL(eventLayer->getParameterTotalLength(), 0);
		PTF_ASSERT_EQUAL(eventLayer->getHeaderLen(), 7);
		PTF_ASSERT_EQUAL(packet.getRawPacket()->getRawDataLen(), 7);
		PTF_ASSERT_EQUAL(eventLayer->getEventCode(), 0x0f);
	}

	// setParameters() on a standalone layer with no direction header
	{
		std::vector<uint8_t> statusParam = { 0x00 };
		pcpp::BluetoothHciEventLayer eventLayer(0x01, statusParam);

		eventLayer.setEventCode(0x0f);
		PTF_ASSERT_EQUAL(eventLayer.getEventCode(), 0x0f);

		std::vector<uint8_t> newParams = { 0x00, 0x01, 0x01, 0x04 };
		eventLayer.setParameters(newParams);
		PTF_ASSERT_EQUAL(eventLayer.getParameterTotalLength(), 4);
		PTF_ASSERT_EQUAL(eventLayer.getDataLen(), 7);
		PTF_ASSERT_BUF_COMPARE(eventLayer.getParameters(), newParams.data(), newParams.size());
		PTF_ASSERT_EQUAL(eventLayer.getPacketType(), pcpp::BluetoothHciLayer::BluetoothHciPacketType::Event, enumclass);
	}

	// setParameters() with more than 255 bytes throws and leaves the layer unchanged
	{
		std::vector<uint8_t> statusParam = { 0x00 };
		pcpp::BluetoothHciEventLayer eventLayer(0x01, statusParam);

		std::vector<uint8_t> tooLong(256, 0xab);
		PTF_ASSERT_RAISES(eventLayer.setParameters(tooLong), std::invalid_argument,
		                  "Parameters length is greater than 255 bytes");
		PTF_ASSERT_EQUAL(eventLayer.getParameterTotalLength(), 1);
		PTF_ASSERT_EQUAL(eventLayer.getDataLen(), 4);
	}

	// setParameters() throws if the layer can't be extended, e.g. when the packet buffer is pre-allocated and full
	{
		uint8_t buffer[4];
		pcpp::Packet packet(buffer, sizeof(buffer), pcpp::LINKTYPE_BLUETOOTH_HCI_H4);

		std::vector<uint8_t> statusParam = { 0x00 };
		auto* eventLayer = new pcpp::BluetoothHciEventLayer(0x01, statusParam);
		PTF_ASSERT_TRUE(packet.addLayer(eventLayer, true));

		std::vector<uint8_t> longerParams = { 0x01, 0x02 };
		SuppressLogs suppressLogs;
		PTF_ASSERT_RAISES(eventLayer->setParameters(longerParams), std::runtime_error,
		                  "Could not extend the Bluetooth HCI Event layer to fit the new parameters");
		PTF_ASSERT_EQUAL(eventLayer->getParameterTotalLength(), 1);
	}
}

PTF_TEST_CASE(BluetoothHciEventEdgeCasesTest)
{
	// Creating a layer with a direction header requires a valid direction
	{
		std::vector<uint8_t> statusParam = { 0x00 };
		PTF_ASSERT_RAISES(
		    pcpp::BluetoothHciEventLayer(pcpp::BluetoothHciLayer::BluetoothHciDirection::Unknown, 0x01, statusParam),
		    std::invalid_argument, "Direction must be HostToController or ControllerToHost");
	}

	// Creating a layer with more than 255 parameter bytes throws
	{
		std::vector<uint8_t> tooLong(256, 0xab);
		PTF_ASSERT_RAISES(pcpp::BluetoothHciEventLayer(0x01, tooLong), std::invalid_argument,
		                  "Parameters length is greater than 255 bytes");
		PTF_ASSERT_RAISES(pcpp::BluetoothHciEventLayer(pcpp::BluetoothHciLayer::BluetoothHciDirection::ControllerToHost,
		                                               0x01, tooLong),
		                  std::invalid_argument, "Parameters length is greater than 255 bytes");
	}

	// parameterTotalLength larger than the available bytes: the available length is returned
	{
		uint8_t truncated[] = { 0x04, 0x0f, 0x04, 0x00, 0x01 };
		pcpp::RawPacket rawPacket(truncated, sizeof(truncated), timeval{ 0, 0 }, false,
		                          pcpp::LINKTYPE_BLUETOOTH_HCI_H4);
		pcpp::Packet packet(&rawPacket);

		auto* eventLayer = packet.getLayerOfType<pcpp::BluetoothHciEventLayer>();
		PTF_ASSERT_NOT_NULL(eventLayer);
		PTF_ASSERT_EQUAL(eventLayer->getParameterTotalLength(), 2);
	}

	// More than 255 bytes available after the event header: the available length must not be truncated to 8 bits,
	// so the parameterTotalLength field (255) is returned
	{
		std::vector<uint8_t> data(4 + 1 + 2 + 256, 0x00);
		data[3] = 0x01;  // ControllerToHost
		data[4] = 0x04;  // Event indicator
		data[5] = 0x0f;  // Event code
		data[6] = 0xff;  // Parameter total length
		pcpp::RawPacket rawPacket(data.data(), static_cast<int>(data.size()), timeval{ 0, 0 }, false,
		                          pcpp::LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR);
		pcpp::Packet packet(&rawPacket);

		auto* eventLayer = packet.getLayerOfType<pcpp::BluetoothHciEventLayer>();
		PTF_ASSERT_NOT_NULL(eventLayer);
		PTF_ASSERT_EQUAL(eventLayer->getParameterTotalLength(), 255);
	}
}
