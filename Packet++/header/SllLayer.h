#ifndef PACKETPP_SLL_LAYER
#define PACKETPP_SLL_LAYER

#include <MacAddress.h>
#include <Layer.h>

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * @struct sll_header
	 * Represents an special ssl header
	 */
#pragma pack(push, 1)
	struct sll_header
	{
		uint16_t packet_type;
		uint16_t ARPHRD_type;
		uint16_t link_layer_addr_len;
		uint8_t link_layer_addr[8];
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
		 * @param[in] packetType Packet type
		 * @param[in] ARPHRDType ARPHRD type
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
		 * @return Size of ether_header
		 */
		inline size_t getHeaderLen() { return sizeof(sll_header); }

		/**
		 * Calculate ether_header#etherType for known protocols: IPv4, IPv6, ARP, VLAN
		 */
		void computeCalculateFields();

		std::string toString();
	};

} // namespace pcpp

#endif /* PACKETPP_SLL_LAYER */

