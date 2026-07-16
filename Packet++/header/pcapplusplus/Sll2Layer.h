#pragma once

#include "MacAddress.h"
#include "Layer.h"

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	/// @struct sll2_header
	/// Represents SLL2 header
#pragma pack(push, 1)
	struct sll2_header
	{
		/// Contains an Ethernet protocol type of the next layer
		uint16_t protocol_type;
		/// The "Reserved (MBZ)" field is reserved, and must be set to zero
		uint16_t reserved;
		/// The interface index field is a signed integer in network byte
		/// order and contains the 1-based index of the interface on which the packet was observed
		uint32_t interface_index;
		/// Contains a Linux ARPHRD_ value for the link-layer device type
		uint16_t ARPHRD_type;
		/// Specifies whether packet was: specifically sent to us by somebody else (value=0);
		/// broadcast by somebody else (value=1); multicast, but not broadcast, by somebody else (value=2);
		/// sent to somebody else by somebody else (value=3); sent by us (value=4)
		uint8_t packet_type;
		/// Contains the length of the link-layer address of the sender of the packet. That length could be zero
		uint8_t link_layer_addr_len;
		/// Contains the link-layer address of the sender of the packet; the number of bytes of that field that are
		///  meaningful is specified by the link-layer address length field
		uint8_t link_layer_addr[8];
	};
#pragma pack(pop)
	static_assert(sizeof(sll2_header) == 20, "sll2_header size is not 20 bytes");

	/// @class Sll2Layer
	/// Represents an SLL2 (Linux cooked capture) protocol layer
	class Sll2Layer : public Layer
	{
	public:
		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data (will be casted to ether_header)
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		Sll2Layer(uint8_t* data, size_t dataLen, Packet* packet) : Layer(data, dataLen, nullptr, packet, SLL2)
		{}

		/// A constructor that creates a new SLL2 header and allocates the data
		/// @param[in] interfaceIndex The interface index
		/// @param[in] ARPHRDType The ARPHRD type
		/// @param[in] packetType The packet type
		Sll2Layer(uint32_t interfaceIndex, uint16_t ARPHRDType, uint8_t packetType);

		~Sll2Layer() override = default;

		/// Get a pointer to the Sll header. Notice this points directly to the data, so every change will change the
		/// actual packet data
		/// @return A pointer to the sll2_header
		sll2_header* getSll2Header() const
		{
			return reinterpret_cast<sll2_header*>(m_Data);
		}

		/// A static method that validates the input data
		/// @param[in] data The pointer to the beginning of a byte stream of an IEEE 802.3 Eth packet
		/// @param[in] dataLen The length of the byte stream
		/// @return True if the data is valid and can represent an IEEE 802.3 Eth packet
		static bool isDataValid(const uint8_t* data, size_t dataLen);

		/// Get a protocol type of this layer
		/// @return protocol type
		uint16_t getProtocolType() const;

		/// Set protocol type of this layer
		/// @param[in] protocolType type to set
		void setProtocolType(uint16_t protocolType);

		/// Get interface index of this layer
		/// @return interface index
		uint32_t getInterfaceIndex() const;

		/// Set interface index of this layer
		/// @param[in] interfaceIndex interface index to set
		void setInterfaceIndex(uint32_t interfaceIndex);

		/// Get arphrd type of this layer
		/// @return arphrd type
		uint16_t getArphrdType() const;

		/// Set arphrd type of this layer
		/// @param[in] arphrdType arphrd type to set
		void setArphrdType(uint16_t arphrdType);

		/// Get packet type of this layer
		/// @return packet type
		uint8_t getPacketType() const;

		/// Set packet type of this layer
		/// @param[in] packetType packet type to set
		void setPacketType(uint8_t packetType);

		/// Get link layer address length
		/// @return link layer address length
		uint8_t getLinkLayerAddrLen() const;

		/// Get link layer address data pointer
		/// @return link layer address data pointer
		const uint8_t* getLinkLayerAddr() const;

		/// A setter for the link layer address field
		/// @param[in] addr The address to set. Memory will be copied to packet
		/// @param[in] addrLength Address length, must be lower or equal to 8 (which is max length for SLL2 address)
		/// @return True if address was set successfully, or false of addrLength is out of bounds (0 or larger than 8)
		bool setLinkLayerAddr(const uint8_t* addr, size_t addrLength);

		/// Get a MAC address in the link layer address field
		/// @return return macAddress pointer was set successfully, null pointer if d MAC address isn't valid or if set
		/// failed
		MacAddress getLinkLayerAsMacAddress();

		/// Set a MAC address in the link layer address field
		/// @param[in] macAddr MAC address to set
		/// @return True if address was set successfully, false if MAC address isn't valid or if set failed
		bool setMacAddressAsLinkLayer(const MacAddress& macAddr);

		// implement abstract methods

		/// Currently identifies the following next layers: IPv4Layer, IPv6Layer, ArpLayer, VlanLayer,
		/// PPPoESessionLayer, PPPoEDiscoveryLayer, MplsLayer. Otherwise sets PayloadLayer
		void parseNextLayer() override;

		/// Calculate the next protocol type for known protocols: IPv4, IPv6, ARP, VLAN
		void computeCalculateFields() override;

		/// @return Size of sll2_header
		size_t getHeaderLen() const override
		{
			return sizeof(sll2_header);
		}

		std::string toString() const override;

		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelDataLinkLayer;
		}
	};

}  // namespace pcpp
