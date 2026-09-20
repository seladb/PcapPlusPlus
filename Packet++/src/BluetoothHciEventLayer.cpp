#include "BluetoothHciEventLayer.h"
#include "EndianPortable.h"

#include <iomanip>
#include <sstream>

namespace pcpp
{
	BluetoothHciDirection BluetoothHciEventLayer::getDirection() const
	{
		if (!m_HasDirectionHeader)
		{
			return BluetoothHciDirection::Unknown;
		}

		auto* directionHeader = reinterpret_cast<bluetooth_hci_direction_header*>(m_Data);
		return static_cast<BluetoothHciDirection>(be32toh(directionHeader->direction));
	}

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
		if (data == nullptr)
		{
			return false;
		}

		size_t directionHeaderLen = hasDirectionHeader ? sizeof(bluetooth_hci_direction_header) : 0;
		if (dataLen < directionHeaderLen + sizeof(bluetooth_hci_event_header))
		{
			return false;
		}

		return data[directionHeaderLen] == BluetoothHciEventPacketIndicator;
	}

}  // namespace pcpp
