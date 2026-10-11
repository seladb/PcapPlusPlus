#include "BluetoothHciLayer.h"
#include "GeneralUtils.h"
#include "Serializers.h"
#include "SystemUtils.h"

#include <cstring>
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

	BluetoothHciEventLayer::BluetoothHciEventLayer(uint8_t eventCode, const uint8_t* parameters, uint8_t paramLen)
	    : BluetoothHciLayer(false)
	{
		size_t len = sizeof(uint8_t) + sizeof(bluetooth_hci_event_header) + paramLen;
		allocData(len);
		m_Data[0] = static_cast<uint8_t>(BluetoothHciPacketType::Event);
		auto* header = getEventHeader();
		header->eventCode = eventCode;
		header->parameterTotalLength = paramLen;
		if (paramLen > 0 && parameters != nullptr)
		{
			std::memcpy(m_Data + getHeaderLen(), parameters, paramLen);
		}
	}

	BluetoothHciEventLayer::BluetoothHciEventLayer(BluetoothHciDirection direction, uint8_t eventCode,
	                                                const uint8_t* parameters, uint8_t paramLen)
	    : BluetoothHciLayer(true)
	{
		size_t len = directionHeaderSize + sizeof(uint8_t) + sizeof(bluetooth_hci_event_header) + paramLen;
		allocData(len);
		uint32_t netDirection = hostToNet32(static_cast<uint32_t>(direction));
		std::memcpy(m_Data, &netDirection, directionHeaderSize);
		m_Data[directionHeaderSize] = static_cast<uint8_t>(BluetoothHciPacketType::Event);
		auto* header = getEventHeader();
		header->eventCode = eventCode;
		header->parameterTotalLength = paramLen;
		if (paramLen > 0 && parameters != nullptr)
		{
			std::memcpy(m_Data + getHeaderLen(), parameters, paramLen);
		}
	}

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

	const FieldDescriptor BluetoothHciEventLayer::SerializedFields::Direction{ Layer::SerializedFields::MaxID + 1,
		                                                                       "direction" };
	const FieldDescriptor BluetoothHciEventLayer::SerializedFields::EventCode{ Layer::SerializedFields::MaxID + 2,
		                                                                       "eventCode" };
	const FieldDescriptor BluetoothHciEventLayer::SerializedFields::ParameterTotalLength{
		Layer::SerializedFields::MaxID + 3, "parameterTotalLength"
	};
	const FieldDescriptor BluetoothHciEventLayer::SerializedFields::Parameters{ Layer::SerializedFields::MaxID + 4,
		                                                                        "parameters" };

	void BluetoothHciEventLayer::serializeLayer(ObjectScope& serializer) const
	{
		const char* directionStr;
		switch (getDirection())
		{
		case BluetoothHciDirection::HostToController:
			directionStr = "HostToController";
			break;
		case BluetoothHciDirection::ControllerToHost:
			directionStr = "ControllerToHost";
			break;
		default:
			directionStr = "Unknown";
			break;
		}
		serializer.writeField(SerializedFields::Direction, directionStr);
		serializer.writeField(SerializedFields::EventCode, static_cast<uint64_t>(getEventCode()));
		serializer.writeField(SerializedFields::ParameterTotalLength,
		                      static_cast<uint64_t>(getParameterTotalLength()));
		serializer.writeField(SerializedFields::Parameters,
		                      byteArrayToHexString(getParameters(), getParameterTotalLength()));
	}

}  // namespace pcpp
