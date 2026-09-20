#pragma once

#include "Layer.h"

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	/// H4 packet indicator value marking an HCI Event packet
	constexpr uint8_t BluetoothHciEventPacketIndicator = 0x04;

	/// Event Code for the Inquiry Complete event
	constexpr uint8_t BluetoothHciInquiryCompleteEventCode = 0x01;

	/// @enum BluetoothHciDirection
	/// The direction of an HCI packet, taken from the pseudo-header present in LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR
	/// captures
	enum class BluetoothHciDirection : uint32_t
	{
		/// Sent from the host to the controller
		HostToController = 0,
		/// Received by the host from the controller
		ControllerToHost = 1,
		/// The capture has no direction pseudo-header (LINKTYPE_BLUETOOTH_HCI_H4)
		Unknown = 0xffffffff
	};

	/// @struct bluetooth_hci_direction_header
	/// Represents the 4-byte direction pseudo-header that precedes the H4 packet in
	/// LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR captures
#pragma pack(push, 1)
	struct bluetooth_hci_direction_header
	{
		/// The packet direction, in network byte order (big-endian)
		uint32_t direction;
	};
#pragma pack(pop)
	static_assert(sizeof(bluetooth_hci_direction_header) == 4, "bluetooth_hci_direction_header size is not 4 bytes");

	/// @struct bluetooth_hci_event_header
	/// Represents a Bluetooth HCI Event packet header
#pragma pack(push, 1)
	struct bluetooth_hci_event_header
	{
		/// H4 packet indicator byte (always 0x04 for Event packets)
		uint8_t packetIndicator;
		/// The event code identifying the event type
		uint8_t eventCode;
		/// The total length of the parameters that follow
		uint8_t parameterTotalLength;
	};
#pragma pack(pop)
	static_assert(sizeof(bluetooth_hci_event_header) == 3, "bluetooth_hci_event_header size is not 3 bytes");

	/// @struct bluetooth_hci_inquiry_complete_parameters
	/// Represents the parameters of a Bluetooth HCI Inquiry Complete event
#pragma pack(push, 1)
	struct bluetooth_hci_inquiry_complete_parameters
	{
		/// 0x00 means success, any other value is an error code
		uint8_t status;
	};
#pragma pack(pop)
	static_assert(sizeof(bluetooth_hci_inquiry_complete_parameters) == 1,
	              "bluetooth_hci_inquiry_complete_parameters size is not 1 byte");

	/// @class BluetoothHciEventLayer
	/// Represents a Bluetooth HCI Event packet (identified by the H4 packet indicator byte 0x04). Supports both
	/// LINKTYPE_BLUETOOTH_HCI_H4 (raw H4 packet) and LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR (H4 packet preceded by a
	/// 4-byte direction pseudo-header)
	class BluetoothHciEventLayer : public Layer
	{
	public:
		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		/// @param[in] hasDirectionHeader True if the data starts with a 4-byte direction pseudo-header
		/// (LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR), false if it starts directly with the H4 packet indicator
		/// (LINKTYPE_BLUETOOTH_HCI_H4)
		BluetoothHciEventLayer(uint8_t* data, size_t dataLen, Packet* packet, bool hasDirectionHeader)
		    : Layer(data, dataLen, nullptr, packet, BluetoothHciEvent), m_HasDirectionHeader(hasDirectionHeader)
		{}

		~BluetoothHciEventLayer() override = default;

		/// @return True if this packet has a direction pseudo-header, false otherwise
		bool hasDirectionHeader() const
		{
			return m_HasDirectionHeader;
		}

		/// Get the direction of this packet
		/// @return The packet direction, or BluetoothHciDirection::Unknown if the capture has no direction
		/// pseudo-header
		BluetoothHciDirection getDirection() const;

		/// Get a pointer to the Bluetooth HCI Event header
		/// @return A pointer to the bluetooth_hci_event_header
		bluetooth_hci_event_header* getEventHeader() const
		{
			return reinterpret_cast<bluetooth_hci_event_header*>(m_Data + getDirectionHeaderLen());
		}

		/// Get the event code of this packet
		/// @return The event code
		uint8_t getEventCode() const
		{
			return getEventHeader()->eventCode;
		}

		/// Get the parameter total length field
		/// @return The parameter total length, in bytes
		uint8_t getParameterTotalLength() const
		{
			return getEventHeader()->parameterTotalLength;
		}

		/// Get a pointer to the raw event parameters
		/// @return A pointer to the raw parameter bytes
		uint8_t* getParameters() const
		{
			return m_Data + getHeaderLen();
		}

		/// Check if this packet is a specific event type
		/// @param[in] eventCode The event code to check against
		/// @return True if the packet's event code matches the given one, false otherwise
		bool isEventOfType(uint8_t eventCode) const
		{
			return getEventCode() == eventCode;
		}

		/// Get a pointer to the Inquiry Complete event parameters
		/// @return A pointer to the bluetooth_hci_inquiry_complete_parameters, or nullptr if this packet is not an
		/// Inquiry Complete event or the parameters are truncated
		bluetooth_hci_inquiry_complete_parameters* getInquiryCompleteParameters() const;

		// implement abstract methods

		/// This is a terminal layer, it doesn't parse any next layer
		void parseNextLayer() override
		{}

		/// @return Size of the direction pseudo-header (if present) plus bluetooth_hci_event_header
		size_t getHeaderLen() const override
		{
			return getDirectionHeaderLen() + sizeof(bluetooth_hci_event_header);
		}

		/// Does nothing for this layer
		void computeCalculateFields() override
		{}

		std::string toString() const override;

		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelDataLinkLayer;
		}

		/// A static method that validates the input data
		/// @param[in] data The pointer to the beginning of a byte stream of a Bluetooth HCI Event packet
		/// @param[in] dataLen The length of the byte stream
		/// @param[in] hasDirectionHeader True if the data is expected to start with a 4-byte direction pseudo-header
		/// @return True if the data is valid and can represent a Bluetooth HCI Event packet
		static bool isDataValid(const uint8_t* data, size_t dataLen, bool hasDirectionHeader);

	private:
		bool m_HasDirectionHeader;

		size_t getDirectionHeaderLen() const
		{
			return m_HasDirectionHeader ? sizeof(bluetooth_hci_direction_header) : 0;
		}
	};

}  // namespace pcpp
