#pragma once

#include "Layer.h"

/// @file
/// This file contains classes for parsing Bluetooth Host Controller Interface (HCI) packets.
/// It contains an abstract class named BluetoothHciLayer which has common functionality.
/// It contains inherited classes that represent the different HCI packet types, identified by the H4 packet indicator
/// octet. These types of packets are Command, ACL data, SCO data, Event and ISO data.
/// **Currently** only Event packets are implemented, by BluetoothHciEventLayer.
/// Instances are created through the BluetoothHciLayer::parseLayer() factory, which identifies the packet type and
/// constructs the matching class.

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	/// @enum BluetoothHciPacketType
	/// The HCI packet type, taken from the H4 packet indicator octet
	enum class BluetoothHciPacketType : uint8_t
	{
		/// A command sent from the host to the controller
		Command = 0x01,
		/// ACL data
		AclData = 0x02,
		/// Synchronous (SCO) data
		ScoData = 0x03,
		/// An event sent from the controller to the host
		Event = 0x04,
		/// Isochronous (ISO) data
		IsoData = 0x05
	};

	/// @enum BluetoothHciDirection
	/// The direction of an HCI packet, taken from the pseudo-header present in
	/// LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR captures
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

	class BluetoothHciEventLayer;

	/// @class BluetoothHciLayer
	/// An abstract base class for all Bluetooth HCI packet types. It handles the parts common to every HCI packet:
	/// the optional direction pseudo-header and the H4 packet indicator octet. Concrete subclasses parse a specific
	/// packet type and are created through BluetoothHciLayer::parseLayer()
	class BluetoothHciLayer : public Layer
	{
	public:
		~BluetoothHciLayer() override = default;

		/// A static factory that identifies the HCI packet type and creates the matching layer
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		/// @param[in] hasDirectionHeader True if the data starts with a 4-byte direction pseudo-header
		/// (LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR), false if it starts directly with the H4 packet indicator
		/// (LINKTYPE_BLUETOOTH_HCI_H4)
		/// @return An instance of a BluetoothHciLayer subclass, or nullptr if the data is invalid or the packet type
		/// is not supported yet
		static BluetoothHciLayer* parseLayer(uint8_t* data, size_t dataLen, Packet* packet, bool hasDirectionHeader);

		/// @return True if this packet is preceded by a direction pseudo-header, false otherwise
		bool hasDirectionHeader() const
		{
			return m_HasDirectionHeader;
		}

		/// Get the direction of this packet
		/// @return The packet direction, or BluetoothHciDirection::Unknown if the capture has no direction
		/// pseudo-header
		BluetoothHciDirection getDirection() const;

		/// @return The H4 packet indicator octet
		uint8_t getPacketIndicator() const
		{
			return m_Data[getDirectionHeaderLen()];
		}

		/// @return The HCI packet type this layer represents
		BluetoothHciPacketType getPacketType() const
		{
			return static_cast<BluetoothHciPacketType>(getPacketIndicator());
		}

		/// Get this layer as a Bluetooth HCI Event layer. As instances are only created by parseLayer(), the packet
		/// indicator octet is a reliable indication of the concrete type, so no dynamic cast is needed
		/// @return A pointer to this layer as a BluetoothHciEventLayer, or nullptr if this is not an Event packet
		BluetoothHciEventLayer* asEventLayer();

		// implement abstract methods

		/// HCI packets don't encapsulate another protocol, so no next layer is parsed. Subclasses that do encapsulate
		/// another protocol override this method
		void parseNextLayer() override
		{}

		/// Does nothing for this layer
		void computeCalculateFields() override
		{}

		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelDataLinkLayer;
		}

		/// A static method that validates the part of the input data common to all HCI packet types
		/// @param[in] data The pointer to the beginning of a byte stream of a Bluetooth HCI packet
		/// @param[in] dataLen The length of the byte stream
		/// @param[in] hasDirectionHeader True if the data is expected to start with a 4-byte direction pseudo-header
		/// @return True if the data is long enough to hold the direction pseudo-header, if one is expected, followed
		/// by a packet indicator octet
		static bool isDataValid(const uint8_t* data, size_t dataLen, bool hasDirectionHeader);

	protected:
		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		/// @param[in] hasDirectionHeader True if the data starts with a 4-byte direction pseudo-header
		BluetoothHciLayer(uint8_t* data, size_t dataLen, Packet* packet, bool hasDirectionHeader)
		    : Layer(data, dataLen, nullptr, packet, BluetoothHci), m_HasDirectionHeader(hasDirectionHeader)
		{}

		/// @return Size of the direction pseudo-header, or 0 if this packet has none
		size_t getDirectionHeaderLen() const
		{
			return m_HasDirectionHeader ? sizeof(bluetooth_hci_direction_header) : 0;
		}

	private:
		bool m_HasDirectionHeader;
	};

	/// Event Code for the Inquiry Complete event
	constexpr uint8_t BluetoothHciInquiryCompleteEventCode = 0x01;

	/// @struct bluetooth_hci_event_header
	/// Represents a Bluetooth HCI Event packet header, excluding the direction pseudo-header and the packet indicator
#pragma pack(push, 1)
	struct bluetooth_hci_event_header
	{
		/// The event code identifying the event type
		uint8_t eventCode;
		/// The total length of the parameters that follow
		uint8_t parameterTotalLength;
	};
#pragma pack(pop)
	static_assert(sizeof(bluetooth_hci_event_header) == 2, "bluetooth_hci_event_header size is not 2 bytes");

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
	/// Represents a Bluetooth HCI Event packet, identified by the H4 packet indicator octet 0x04
	class BluetoothHciEventLayer : public BluetoothHciLayer
	{
		friend BluetoothHciLayer* BluetoothHciLayer::parseLayer(uint8_t* data, size_t dataLen, Packet* packet,
		                                                        bool hasDirectionHeader);

	public:
		~BluetoothHciEventLayer() override = default;

		/// Get a pointer to the Bluetooth HCI Event header
		/// @return A pointer to the bluetooth_hci_event_header
		bluetooth_hci_event_header* getEventHeader() const
		{
			return reinterpret_cast<bluetooth_hci_event_header*>(m_Data + getDirectionHeaderLen() + sizeof(uint8_t));
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

		/// @return Size of the direction pseudo-header (if present), the packet indicator octet and
		/// bluetooth_hci_event_header
		size_t getHeaderLen() const override
		{
			return getDirectionHeaderLen() + sizeof(uint8_t) + sizeof(bluetooth_hci_event_header);
		}

		std::string toString() const override;

		/// A static method that validates the input data
		/// @param[in] data The pointer to the beginning of a byte stream of a Bluetooth HCI Event packet
		/// @param[in] dataLen The length of the byte stream
		/// @param[in] hasDirectionHeader True if the data is expected to start with a 4-byte direction pseudo-header
		/// @return True if the data is valid and can represent a Bluetooth HCI Event packet
		static bool isDataValid(const uint8_t* data, size_t dataLen, bool hasDirectionHeader);

	private:
		/// A constructor that creates the layer from an existing packet raw data. Instances are only created through
		/// BluetoothHciLayer::parseLayer()
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		/// @param[in] hasDirectionHeader True if the data starts with a 4-byte direction pseudo-header
		BluetoothHciEventLayer(uint8_t* data, size_t dataLen, Packet* packet, bool hasDirectionHeader)
		    : BluetoothHciLayer(data, dataLen, packet, hasDirectionHeader)
		{}
	};

}  // namespace pcpp
