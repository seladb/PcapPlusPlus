#ifndef PACKETPP_ETH_DOT3_LAYER
#define PACKETPP_ETH_DOT3_LAYER

#include "Layer.h"
#include "MacAddress.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * @struct ether_dot3_header
	 * Represents an IEEE 802.3 Ethernet header
	 */
#pragma pack(push, 1)
	struct ether_dot3_header
	{
		/** Destination MAC */
		uint8_t dstMac[6];
		/** Source MAC */
		uint8_t srcMac[6];
		/** EtherType */
		uint16_t length;
	};
#pragma pack(pop)

	/**
	 * @class EthDot3Layer
	 * Represents an IEEE 802.3 Ethernet protocol layer
	 */
	class EthDot3Layer : public Layer
	{
	public:

		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to ether_dot3_header)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		EthDot3Layer(uint8_t* data, size_t dataLen, Packet* packet) : Layer(data, dataLen, NULL, packet) { m_Protocol = EthernetDot3; }

		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to ether_header)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		EthDot3Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet) { m_Protocol = EthernetDot3; }

		/**
		 * A constructor that creates a new IEEE 802.3 Ethernet header and allocates the data
		 * @param[in] sourceMac The source MAC address
		 * @param[in] destMac The destination MAC address
		 * @param[in] length The frame length
		 */
		EthDot3Layer(const MacAddress& sourceMac, const MacAddress& destMac, uint16_t length);

		~EthDot3Layer() {}

		/**
		 * Get a pointer to the Ethernet header. Notice this points directly to the data, so every change will change the actual packet data
		 * @return A pointer to the ether_header
		 */
		ether_dot3_header* getEthHeader() const { return (ether_dot3_header*)m_Data; }

		/**
		 * Get the source MAC address
		 * @return The source MAC address
		 */
		MacAddress getSourceMac() const { return MacAddress(getEthHeader()->srcMac); }

		/**
		 * Set source MAC address
		 * @param sourceMac Source MAC to set
		 */
		void setSourceMac(const MacAddress& sourceMac) { sourceMac.copyTo(getEthHeader()->srcMac); }

		/**
		 * Get the destination MAC address
		 * @return The destination MAC address
		 */
		MacAddress getDestMac() const { return MacAddress(getEthHeader()->dstMac); }

		/**
		 * Set destination MAC address
		 * @param destMac Destination MAC to set
		 */
		void setDestMac(const MacAddress& destMac) { destMac.copyTo(getEthHeader()->dstMac); }

		// implement abstract methods

		/**
		 * Currently doesn't identify any particular layer (because LLC is not supported yet) so the payload will always be of type PayloadLayer.
		 */
		void parseNextLayer();

		/**
		 * @return Size of ether_dot3_header
		 */
		size_t getHeaderLen() const { return sizeof(ether_dot3_header); }

		/**
		 * Does nothing for this layer
		 */
		void computeCalculateFields() {}

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const { return OsiModelDataLinkLayer; }

		/**
		 * A static method that validates the input data
		 * @param[in] data The pointer to the beginning of a byte stream of an IEEE 802.3 Eth packet
		 * @param[in] dataLen The length of the byte stream
		 * @return True if the data is valid and can represent an IEEE 802.3 Eth packet
		 */
		static bool isDataValid(const uint8_t* data, size_t dataLen);
	};

} // namespace pcpp

#endif // PACKETPP_ETH_DOT3_LAYER
