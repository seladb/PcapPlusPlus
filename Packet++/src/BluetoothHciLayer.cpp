#include "BluetoothHciLayer.h"
#include "Serializers.h"
#include "SystemUtils.h"

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>

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

		const auto* directionHeader = reinterpret_cast<const bluetooth_hci_direction_header*>(m_Data);
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

	BluetoothHciEventLayer::BluetoothHciEventLayer(uint8_t eventCode, const std::vector<uint8_t>& parameters)
	    : BluetoothHciLayer(false)
	{
		initLayer(eventCode, parameters);
	}

	BluetoothHciEventLayer::BluetoothHciEventLayer(BluetoothHciDirection direction, uint8_t eventCode,
	                                               const std::vector<uint8_t>& parameters)
	    : BluetoothHciLayer(true)
	{
		if (direction != BluetoothHciDirection::HostToController &&
		    direction != BluetoothHciDirection::ControllerToHost)
		{
			throw std::invalid_argument("Direction must be HostToController or ControllerToHost");
		}

		initLayer(eventCode, parameters);
		uint32_t netDirection = hostToNet32(static_cast<uint32_t>(direction));
		std::memcpy(m_Data, &netDirection, directionHeaderSize);
	}

	void BluetoothHciEventLayer::initLayer(uint8_t eventCode, const std::vector<uint8_t>& parameters)
	{
		if (parameters.size() > std::numeric_limits<uint8_t>::max())
		{
			throw std::invalid_argument("Parameters length is greater than 255 bytes");
		}

		size_t paramOffset = getDirectionHeaderLen() + sizeof(uint8_t) + sizeof(bluetooth_hci_event_header);
		allocData(paramOffset + parameters.size());
		m_Data[getDirectionHeaderLen()] = static_cast<uint8_t>(BluetoothHciPacketType::Event);
		auto* header = getEventHeader();
		header->eventCode = eventCode;
		header->parameterTotalLength = static_cast<uint8_t>(parameters.size());
		if (!parameters.empty())
		{
			std::memcpy(m_Data + paramOffset, parameters.data(), parameters.size());
		}
	}

	uint8_t BluetoothHciEventLayer::getParameterTotalLength() const
	{
		// Compute the available length as size_t so that it isn't truncated to 8 bits before the comparison
		size_t availableLen =
		    m_DataLen - getDirectionHeaderLen() - sizeof(uint8_t) - sizeof(bluetooth_hci_event_header);
		size_t declaredLen = getEventHeader()->parameterTotalLength;
		return static_cast<uint8_t>(std::min(declaredLen, availableLen));
	}

	void BluetoothHciEventLayer::setParameters(const std::vector<uint8_t>& parameters)
	{
		if (parameters.size() > std::numeric_limits<uint8_t>::max())
		{
			throw std::invalid_argument("Parameters length is greater than 255 bytes");
		}

		size_t paramOffset = getDirectionHeaderLen() + sizeof(uint8_t) + sizeof(bluetooth_hci_event_header);
		size_t currentParamLen = getParameterTotalLength();
		size_t newParamLen = parameters.size();

		if (newParamLen > currentParamLen)
		{
			if (!extendLayer(static_cast<int>(paramOffset + currentParamLen), newParamLen - currentParamLen))
			{
				throw std::runtime_error("Could not extend the Bluetooth HCI Event layer to fit the new parameters");
			}
		}
		else if (newParamLen < currentParamLen)
		{
			if (!shortenLayer(static_cast<int>(paramOffset + newParamLen), currentParamLen - newParamLen))
			{
				throw std::runtime_error("Could not shorten the Bluetooth HCI Event layer to fit the new parameters");
			}
		}

		getEventHeader()->parameterTotalLength = static_cast<uint8_t>(newParamLen);
		if (newParamLen > 0)
		{
			std::memcpy(m_Data + paramOffset, parameters.data(), newParamLen);
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
		serializer.writeField(SerializedFields::EventCode, getEventCode());
		serializer.writeField(SerializedFields::ParameterTotalLength, getParameterTotalLength());
	}

}  // namespace pcpp
