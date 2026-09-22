#include "BluetoothHciLayer.h"
#include "EndianPortable.h"

#include <iomanip>
#include <sstream>

namespace pcpp
{
	// ~~~~~~~~~~~~~~~~~
	// BluetoothHciLayer
	// ~~~~~~~~~~~~~~~~~

	BluetoothHciLayer* BluetoothHciLayer::parseLayer(uint8_t* data, size_t dataLen, Packet* packet,
	                                                 bool hasDirectionHeader)
	{
		if (!isDataValid(data, dataLen, hasDirectionHeader))
		{
			return nullptr;
		}

		size_t directionHeaderLen = hasDirectionHeader ? sizeof(bluetooth_hci_direction_header) : 0;
		switch (static_cast<BluetoothHciPacketType>(data[directionHeaderLen]))
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

	BluetoothHciDirection BluetoothHciLayer::getDirection() const
	{
		if (!hasDirectionHeader())
		{
			return BluetoothHciDirection::Unknown;
		}

		auto* directionHeader = reinterpret_cast<bluetooth_hci_direction_header*>(m_Data);
		return static_cast<BluetoothHciDirection>(be32toh(directionHeader->direction));
	}

	BluetoothHciEventLayer* BluetoothHciLayer::asEventLayer()
	{
		return getPacketType() == BluetoothHciPacketType::Event ? static_cast<BluetoothHciEventLayer*>(this) : nullptr;
	}

	bool BluetoothHciLayer::isDataValid(const uint8_t* data, size_t dataLen, bool hasDirectionHeader)
	{
		if (data == nullptr)
		{
			return false;
		}

		size_t directionHeaderLen = hasDirectionHeader ? sizeof(bluetooth_hci_direction_header) : 0;
		return dataLen >= directionHeaderLen + sizeof(uint8_t);
	}

	// ~~~~~~~~~~~~~~~~~~~~~~
	// BluetoothHciEventLayer
	// ~~~~~~~~~~~~~~~~~~~~~~

	bluetooth_hci_inquiry_complete_parameters* BluetoothHciEventLayer::getInquiryCompleteParameters() const
	{
		if (!isEventOfType(BluetoothHciInquiryCompleteEventCode))
		{
			return nullptr;
		}

		if (m_DataLen < getHeaderLen() + sizeof(bluetooth_hci_inquiry_complete_parameters))
		{
			return nullptr;
		}

		return reinterpret_cast<bluetooth_hci_inquiry_complete_parameters*>(getParameters());
	}

	std::string BluetoothHciEventLayer::toString() const
	{
		std::ostringstream stream;
		stream << "Bluetooth HCI Event";

		auto* inquiryComplete = getInquiryCompleteParameters();
		if (inquiryComplete != nullptr)
		{
			stream << " - Inquiry Complete, Status: " << (inquiryComplete->status == 0 ? "Success" : "Error") << " (0x"
			       << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(inquiryComplete->status) << ")";
			return stream.str();
		}

		stream << ", Event Code: 0x" << std::hex << std::setw(2) << std::setfill('0')
		       << static_cast<int>(getEventCode());
		return stream.str();
	}

	bool BluetoothHciEventLayer::isDataValid(const uint8_t* data, size_t dataLen, bool hasDirectionHeader)
	{
		if (!BluetoothHciLayer::isDataValid(data, dataLen, hasDirectionHeader))
		{
			return false;
		}

		size_t directionHeaderLen = hasDirectionHeader ? sizeof(bluetooth_hci_direction_header) : 0;
		if (dataLen < directionHeaderLen + sizeof(uint8_t) + sizeof(bluetooth_hci_event_header))
		{
			return false;
		}

		return static_cast<BluetoothHciPacketType>(data[directionHeaderLen]) == BluetoothHciPacketType::Event;
	}

}  // namespace pcpp
