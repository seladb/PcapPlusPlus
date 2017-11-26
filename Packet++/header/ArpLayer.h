#ifndef PACKETPP_ARP_LAYER
#define PACKETPP_ARP_LAYER

#include "Layer.h"
#include "IpAddress.h"
#include "MacAddress.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * @struct arphdr
	 * Represents an ARP protocol header
	 */
#pragma pack(push, 1)
	struct arphdr {
		/** Hardware type (HTYPE) */
		uint16_t hardwareType;
		/** Protocol type (PTYPE). The permitted PTYPE values share a numbering space with those for EtherType */
		uint16_t protocolType;
		/** Hardware address length (HLEN). For IPv4, this has the value 0x0800 */
		uint8_t	hardwareSize;
		/** Protocol length (PLEN). Length (in octets) of addresses used in the upper layer protocol. (The upper layer protocol specified in PTYPE.) IPv4 address size is 4 */
		uint8_t	protocolSize;
		/** Specifies the operation that the sender is performing: 1 (::ARP_REQUEST) for request, 2 (::ARP_REPLY) for reply */
		uint16_t opcode;
		/** Sender hardware address (SHA) */
		uint8_t senderMacAddr[6];
		/** Sender protocol address (SPA) */
		uint32_t senderIpAddr;
		/** Target hardware address (THA) */
		uint8_t targetMacAddr[6];
		/** Target protocol address (TPA) */
		uint32_t targetIpAddr;
	};
#pragma pack(pop)

	/**
	 * An enum for ARP message type
	 */
	enum ArpOpcode
	{
		ARP_REQUEST = 0x0001, ///< ARP request
		ARP_REPLY   = 0x0002  ///< ARP reply (response)
	};

	/**
	 * @class ArpLayer
	 * Represents an ARP protocol layer. Currently only IPv4 ARP messages are supported
	 */
	class ArpLayer : public Layer
	{
	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to @ref arphdr)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		ArpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet) { m_Protocol = ARP; }

		/**
		 * A constructor that allocates a new ARP header
		 * @param[in] opCode ARP message type (ARP request or ARP reply)
		 * @param[in] senderMacAddr The sender MAC address (will be put in arphdr#senderMacAddr)
		 * @param[in] targetMacAddr The target MAC address (will be put in arphdr#targetMacAddr)
		 * @param[in] senderIpAddr The sender IP address (will be put in arphdr#senderIpAddr)
		 * @param[in] targetIpAddr The target IP address (will be put in arphdr#targetIpAddr)
		 */
		ArpLayer(ArpOpcode opCode, const MacAddress& senderMacAddr, const MacAddress& targetMacAddr, const IPv4Address senderIpAddr, const IPv4Address& targetIpAddr);

		~ArpLayer() {}

		/**
		 * Get a pointer to the ARP header. Notice this points directly to the data, so every change will change the actual packet data
		 * @return A pointer to the @ref arphdr
		 */
		inline arphdr* getArpHeader() { return (arphdr*)m_Data; };

		/**
		 * Get the sender hardware address (SHA) in the form of MacAddress
		 * @return A MacAddress containing the sender hardware address (SHA)
		 */
		inline MacAddress getSenderMacAddress() { return MacAddress(getArpHeader()->senderMacAddr); }

		/**
		 * Get the target hardware address (THA) in the form of MacAddress
		 * @return A MacAddress containing the target hardware address (THA)
		 */
		inline MacAddress getTargetMacAddress() { return MacAddress(getArpHeader()->targetMacAddr); }

		/**
		 * Get the sender protocol address (SPA) in the form of IPv4Address
		 * @return An IPv4Address containing the sender protocol address (SPA)
		 */
		inline IPv4Address getSenderIpAddr() { return IPv4Address(getArpHeader()->senderIpAddr); }

		/**
		 * Get the target protocol address (TPA) in the form of IPv4Address
		 * @return An IPv4Address containing the target protocol address (TPA)
		 */
		inline IPv4Address getTargetIpAddr() { return IPv4Address(getArpHeader()->targetIpAddr); }


		// implement abstract methods

		/**
		 * Does nothing for this layer (ArpLayer is always last)
		 */
		void parseNextLayer() {}

		/**
		 * @return The size of @ref arphdr
		 */
		inline size_t getHeaderLen() { return sizeof(arphdr); }

		/**
		 * Calculate the following fields:
		 * - @ref arphdr#hardwareType = Ethernet (1)
		 * - @ref arphdr#hardwareSize = 6
		 * - @ref arphdr#protocolType = ETHERTYPE_IP (assume IPv4 over ARP)
		 * - @ref arphdr#protocolSize = 4 (assume IPv4 over ARP)
		 * - if it's an ARP requst: @ref arphdr#targetMacAddr = MacAddress("00:00:00:00:00:00")
		 */
		void computeCalculateFields();

		std::string toString();

		OsiModelLayer getOsiModelLayer() { return OsiModelNetworkLayer; }
	};

} // namespace pcpp
#endif /* PACKETPP_ARP_LAYER */
