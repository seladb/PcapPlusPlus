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
	/// @class BluetoothHciLayer
	/// An abstract base class for all Bluetooth HCI packet types. It handles the parts common to every HCI packet:
	/// the optional direction pseudo-header and the H4 packet indicator octet. Concrete subclasses parse a specific
	/// packet type and are created through BluetoothHciLayer::parseLayer()
	class BluetoothHciLayer : public Layer
	{
	public:
		/// @enum BluetoothHciPacketType
		/// The HCI packet type, taken from the H4 packet indicator octet
		enum class BluetoothHciPacketType : uint8_t
		{
			/// Not a recognized HCI packet type. 0x00 is not a valid H4 packet indicator value
			Unknown = 0x00,
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

		/// @return The HCI packet type this layer represents, or BluetoothHciPacketType::Unknown if the packet
		/// indicator octet doesn't match a known packet type
		BluetoothHciPacketType getPacketType() const
		{
			return packetTypeFromIndicator(m_Data[getDirectionHeaderLen()]);
		}

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
		/// Size of the direction pseudo-header on the wire. Exposed to derived classes so their static
		/// validators can size-check the raw buffer without needing the struct definition itself
		static constexpr size_t directionHeaderSize = 4;

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
			return m_HasDirectionHeader ? directionHeaderSize : 0;
		}

	private:
#pragma pack(push, 1)
		struct bluetooth_hci_direction_header
		{
			uint32_t direction;
		};
#pragma pack(pop)
		static_assert(sizeof(bluetooth_hci_direction_header) == directionHeaderSize,
		              "bluetooth_hci_direction_header size does not match directionHeaderSize");

		static BluetoothHciPacketType packetTypeFromIndicator(uint8_t packetIndicator);

		bool m_HasDirectionHeader;
	};

	/// @class BluetoothHciEventLayer
	/// Represents a Bluetooth HCI Event packet, identified by the H4 packet indicator octet 0x04
	class BluetoothHciEventLayer : public BluetoothHciLayer
	{
		friend BluetoothHciLayer* BluetoothHciLayer::parseLayer(uint8_t* data, size_t dataLen, Packet* packet,
		                                                        bool hasDirectionHeader);

	public:
		~BluetoothHciEventLayer() override = default;

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
#pragma pack(push, 1)
		struct bluetooth_hci_event_header
		{
			uint8_t eventCode;
			uint8_t parameterTotalLength;
		};
#pragma pack(pop)
		static_assert(sizeof(bluetooth_hci_event_header) == 2, "bluetooth_hci_event_header size is not 2 bytes");

		/// A constructor that creates the layer from an existing packet raw data. Instances are only created through
		/// BluetoothHciLayer::parseLayer()
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		/// @param[in] hasDirectionHeader True if the data starts with a 4-byte direction pseudo-header
		BluetoothHciEventLayer(uint8_t* data, size_t dataLen, Packet* packet, bool hasDirectionHeader)
		    : BluetoothHciLayer(data, dataLen, packet, hasDirectionHeader)
		{}

		bluetooth_hci_event_header* getEventHeader() const
		{
			return reinterpret_cast<bluetooth_hci_event_header*>(m_Data + getDirectionHeaderLen() + sizeof(uint8_t));
		}
	};

}  // namespace pcpp
