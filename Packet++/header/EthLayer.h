#pragma once

#include "Layer.h"
#include "MacAddress.h"

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{

	/// @struct ether_header
	/// Represents an Ethernet II header
#pragma pack(push, 1)
	struct ether_header
	{
		/// Destination MAC
		uint8_t dstMac[6];
		/// Source MAC
		uint8_t srcMac[6];
		/// EtherType
		uint16_t etherType;
	};
#pragma pack(pop)
	static_assert(sizeof(ether_header) == 14, "ether_header size is not 14 bytes");

	// Ethernet protocol ID's

	/// IP
#define PCPP_ETHERTYPE_IP 0x0800
	/// Address resolution
#define PCPP_ETHERTYPE_ARP 0x0806
	/// Transparent Ethernet Bridging
#define PCPP_ETHERTYPE_ETHBRIDGE 0x6558
	/// Reverse ARP
#define PCPP_ETHERTYPE_REVARP 0x8035
	/// AppleTalk protocol
#define PCPP_ETHERTYPE_AT 0x809B
	/// AppleTalk ARP
#define PCPP_ETHERTYPE_AARP 0x80F3
	/// IEEE 802.1Q VLAN tagging
#define PCPP_ETHERTYPE_VLAN 0x8100
	/// IPX
#define PCPP_ETHERTYPE_IPX 0x8137
	/// IP protocol version 6
#define PCPP_ETHERTYPE_IPV6 0x86dd
	/// used to test interfaces
#define PCPP_ETHERTYPE_LOOPBACK 0x9000
	/// PPPoE discovery
#define PCPP_ETHERTYPE_PPPOED 0x8863
	/// PPPoE session
#define PCPP_ETHERTYPE_PPPOES 0x8864
	/// MPLS
#define PCPP_ETHERTYPE_MPLS 0x8847
	/// Point-to-point protocol (PPP)
#define PCPP_ETHERTYPE_PPP 0x880B
	/// RDMA over Converged Ethernet (RoCEv1)
#define PCPP_ETHERTYPE_ROCEV1 0x8915
	/// IEEE 802.1ad Provider Bridge, Q-in-Q
#define PCPP_ETHERTYPE_IEEE_802_1AD 0x88A8
	/// Wake on LAN
#define PCPP_ETHERTYPE_WAKE_ON_LAN 0x0842

	/// @class EthLayer
	/// Represents an Ethernet II protocol layer
	class EthLayer : public Layer
	{
	public:
		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data (will be casted to ether_header)
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		EthLayer(uint8_t* data, size_t dataLen, Packet* packet) : Layer(data, dataLen, nullptr, packet, Ethernet)
		{}

		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data (will be casted to ether_header)
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		EthLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, Ethernet)
		{}

		/// A constructor that creates a new Ethernet header and allocates the data
		/// @param[in] sourceMac The source MAC address
		/// @param[in] destMac The destination MAC address
		/// @param[in] etherType The EtherType to be used. It's an optional parameter, a value of 0 will be set if not
		/// provided
		EthLayer(const MacAddress& sourceMac, const MacAddress& destMac, uint16_t etherType = 0);

		~EthLayer() override = default;

		/// Get a pointer to the Ethernet header. Notice this points directly to the data, so every change will change
		/// the actual packet data
		/// @return A pointer to the ether_header
		inline ether_header* getEthHeader() const
		{
			return reinterpret_cast<ether_header*>(m_Data);
		}

		/// Get the source MAC address
		/// @return The source MAC address
		inline MacAddress getSourceMac() const
		{
			return MacAddress(getEthHeader()->srcMac);
		}

		/// Set source MAC address
		/// @param sourceMac Source MAC to set
		inline void setSourceMac(const MacAddress& sourceMac)
		{
			sourceMac.copyTo(getEthHeader()->srcMac);
		}

		/// Get the destination MAC address
		/// @return The destination MAC address
		inline MacAddress getDestMac() const
		{
			return MacAddress(getEthHeader()->dstMac);
		}

		/// Set destination MAC address
		/// @param destMac Destination MAC to set
		inline void setDestMac(const MacAddress& destMac)
		{
			destMac.copyTo(getEthHeader()->dstMac);
		}

		// implement abstract methods

		/// Currently identifies the following next layers: IPv4Layer, IPv6Layer, ArpLayer, VlanLayer,
		/// PPPoESessionLayer, PPPoEDiscoveryLayer, MplsLayer. Otherwise sets PayloadLayer
		void parseNextLayer() override;

		/// @return Size of ether_header
		size_t getHeaderLen() const override
		{
			return sizeof(ether_header);
		}

		/// Calculate ether_header#etherType for known protocols: IPv4, IPv6, ARP, VLAN
		void computeCalculateFields() override;

		std::string toString() const override;

		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelDataLinkLayer;
		}

		/// A static method that validates the input data
		/// @param[in] data The pointer to the beginning of a byte stream of an Ethernet II packet
		/// @param[in] dataLen The length of the byte stream
		/// @return True if the data is valid and can represent an Ethernet II packet
		static bool isDataValid(const uint8_t* data, size_t dataLen);
	};

}  // namespace pcpp
