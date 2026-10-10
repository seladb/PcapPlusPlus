#include "BluetoothHciLayer.h"
#include "SystemUtils.h"

#include <iomanip>
#include <sstream>

namespace pcpp
{
	// ~~~~~~~~~~~~~~~~~
	// BluetoothHciLayer
	// ~~~~~~~~~~~~~~~~~

	BluetoothHciLayer::BluetoothHciPacketType BluetoothHciLayer::packetTypeFromIndicator(uint8_t packetIndicator)
	{
		switch (packetIndicator)
		{
		case static_cast<uint8_t>(BluetoothHciPacketType::Command):
			return BluetoothHciPacketType::Command;
		case static_cast<uint8_t>(BluetoothHciPacketType::AclData):
			return BluetoothHciPacketType::AclData;
		case static_cast<uint8_t>(BluetoothHciPacketType::ScoData):
			return BluetoothHciPacketType::ScoData;
		case static_cast<uint8_t>(BluetoothHciPacketType::Event):
			return BluetoothHciPacketType::Event;
		case static_cast<uint8_t>(BluetoothHciPacketType::IsoData):
			return BluetoothHciPacketType::IsoData;
		default:
			return BluetoothHciPacketType::Unknown;
		}
	}

	BluetoothHciLayer* BluetoothHciLayer::parseLayer(uint8_t* data, size_t dataLen, Packet* packet,
	                                                 bool hasDirectionHeader)
	{
		if (!isDataValid(data, dataLen, hasDirectionHeader))
		{
			return nullptr;
		}

		size_t directionHeaderLen = hasDirectionHeader ? directionHeaderSize : 0;
		switch (packetTypeFromIndicator(data[directionHeaderLen]))
		{
		case BluetoothHciPacketType::Event:
		{
			if (!BluetoothHciEventLayer::isDataValid(data, dataLen, hasDirectionHeader))
			{
				return nullptr;
			}
			return new BluetoothHciEventLayer(data, dataLen, packet, hasDirectionHeader);
		}
		default:
		{
			// Command, ACL data, SCO data and ISO data packets are not supported yet
			return nullptr;
		}
		}
	}

	BluetoothHciLayer::BluetoothHciDirection BluetoothHciLayer::getDirection() const
	{
		if (!hasDirectionHeader())
		{
			return BluetoothHciDirection::Unknown;
		}

		auto* directionHeader = reinterpret_cast<bluetooth_hci_direction_header*>(m_Data);
		switch (netToHost32(directionHeader->direction))
		{
		case static_cast<uint32_t>(BluetoothHciDirection::HostToController):
			return BluetoothHciDirection::HostToController;
		case static_cast<uint32_t>(BluetoothHciDirection::ControllerToHost):
			return BluetoothHciDirection::ControllerToHost;
		default:
			return BluetoothHciDirection::Unknown;
		}
	}

	bool BluetoothHciLayer::isDataValid(const uint8_t* data, size_t dataLen, bool hasDirectionHeader)
	{
		if (data == nullptr)
		{
			return false;
		}

		size_t directionHeaderLen = hasDirectionHeader ? directionHeaderSize : 0;
		return dataLen >= directionHeaderLen + sizeof(uint8_t);
	}

	// ~~~~~~~~~~~~~~~~~~~~~~
	// BluetoothHciEventLayer
	// ~~~~~~~~~~~~~~~~~~~~~~

	std::string BluetoothHciEventLayer::toString() const
	{
		std::ostringstream stream;
		stream << "Bluetooth HCI Event, Event Code: 0x" << std::hex << std::setw(2) << std::setfill('0')
		       << static_cast<int>(getEventCode());
		return stream.str();
	}

	bool BluetoothHciEventLayer::isDataValid(const uint8_t* data, size_t dataLen, bool hasDirectionHeader)
	{
		if (data == nullptr)
		{
			return false;
		}

		size_t directionHeaderLen = hasDirectionHeader ? directionHeaderSize : 0;
		if (dataLen < directionHeaderLen + sizeof(uint8_t) + sizeof(bluetooth_hci_event_header))
		{
			return false;
		}

		return data[directionHeaderLen] == static_cast<uint8_t>(BluetoothHciPacketType::Event);
	}

}  // namespace pcpp
