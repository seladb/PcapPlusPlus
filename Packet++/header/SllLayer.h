#ifndef PACKETPP_SLL_LAYER
#define PACKETPP_SLL_LAYER

#include "MacAddress.h"
#include "Layer.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * @struct sll_header
	 * Represents SLL header
	 */
#pragma pack(push, 1)
	struct sll_header
	{
		/** Specifies whether packet was: specifically sent to us by somebody else (value=0);
		 *  broadcast by somebody else (value=1); multicast, but not broadcast, by somebody else (value=2);
		 *  sent to somebody else by somebody else (value=3); sent by us (value=4)
		 **/
		uint16_t packet_type;
		/** Contains a Linux ARPHRD_ value for the link-layer device type */
		uint16_t ARPHRD_type;
		/** Contains the length of the link-layer address of the sender of the packet. That length could be zero */
		uint16_t link_layer_addr_len;
		/** contains the link-layer address of the sender of the packet; the number of bytes of that field that are
		 *  meaningful is specified by the link-layer address length field
		 **/
		uint8_t link_layer_addr[8];
		/** Contains an Ethernet protocol type of the next layer */
		uint16_t protocol_type;
	};
#pragma pack(pop)

	/**
	 * @class SllLayer
	 * Represents an SLL (Linux cooked capture) protocol layer
	 */
	class SllLayer : public Layer
	{
	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to ether_header)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		SllLayer(uint8_t* data, size_t dataLen, Packet* packet) : Layer(data, dataLen, NULL, packet) { m_Protocol = SLL; }

		/**
		 * A constructor that creates a new SLL header and allocates the data
		 * @param[in] packetType The packet type
		 * @param[in] ARPHRDType The ARPHRD type
		 */
		SllLayer(uint16_t packetType, uint16_t ARPHRDType);

		~SllLayer() {}

		/**
		 * Get a pointer to the Sll header. Notice this points directly to the data, so every change will change the actual packet data
		 * @return A pointer to the sll_header
		 */
		inline sll_header* getSllHeader() { return (sll_header*)m_Data; }

		/**
		 * A setter for the link layer address field
		 * @param[in] addr The address to set. Memory will be copied to packet
		 * @param[in] addrLength Address length, must be lower or equal to 8 (which is max length for SLL address)
		 * @return True if address was set successfully, or false of addrLength is out of bounds (0 or larger than 8)
		 */
		bool setLinkLayerAddr(uint8_t* addr, size_t addrLength);

		/**
		 * Set a MAC address in the link layer address field
		 * @param[in] macAddr MAC address to set
		 * @return True if address was set successfully, false if MAC address isn't valid or if set failed
		 */
		bool setMacAddressAsLinkLayer(MacAddress macAddr);

		/**
		 * Currently identifies the following next layers: IPv4Layer, IPv6Layer, ArpLayer, VlanLayer, PPPoESessionLayer, PPPoEDiscoveryLayer,
		 * MplsLayer.
		 * Otherwise sets PayloadLayer
		 */
		void parseNextLayer();

		/**
		 * @return Size of sll_header
		 */
		inline size_t getHeaderLen() { return sizeof(sll_header); }

		/**
		 * Calculate the next protocol type for known protocols: IPv4, IPv6, ARP, VLAN
		 */
		void computeCalculateFields();

		std::string toString();

		OsiModelLayer getOsiModelLayer() { return OsiModelDataLinkLayer; }
	};

} // namespace pcpp

#endif /* PACKETPP_SLL_LAYER */

