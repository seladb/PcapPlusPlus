#ifndef PACKETPP_UDP_LAYER
#define PACKETPP_UDP_LAYER

#include "Layer.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * @struct udphdr
	 * Represents an UDP protocol header
	 */
#pragma pack(push,1)
	struct udphdr {
		/** Source port */
		uint16_t portSrc;
		/** Destination port */
		uint16_t portDst;
		/** Length of header and payload in bytes */
		uint16_t length;
		/**  Error-checking of the header and data */
		uint16_t headerChecksum;
	};
#pragma pack(pop)


	/**
	 * @class UdpLayer
	 * Represents an UDP (User Datagram Protocol) protocol layer
	 */
	class UdpLayer : public Layer
	{
	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to @ref udphdr)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		UdpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet) { m_Protocol = UDP; }

		/**
		 * A constructor that allocates a new UDP header with source and destination ports
		 * @param[in] portSrc Source UDP port address
		 * @param[in] portDst Destination UDP port
		 */
		UdpLayer(uint16_t portSrc, uint16_t portDst);

		/**
		 * Get a pointer to the UDP header. Notice this points directly to the data, so every change will change the actual packet data
		 * @return A pointer to the @ref udphdr
		 */
		inline udphdr* getUdpHeader() { return (udphdr*)m_Data; };

		/**
		 * Calculate the checksum from header and data and possibly write the result to @ref udphdr#headerChecksum
		 * @param[in] writeResultToPacket If set to true then checksum result will be written to @ref udphdr#headerChecksum
		 * @return The checksum result
		 */
		uint16_t calculateChecksum(bool writeResultToPacket);

		// implement abstract methods

		/**
		 * Currently identifies the following next layers: DnsLayer, DhcpLayer, VxlanLayer, SipRequestLayer, SipResponseLayer.
		 * Otherwise sets PayloadLayer
		 */
		void parseNextLayer();

		/**
		 * @return Size of @ref udphdr
		 */
		inline size_t getHeaderLen() { return sizeof(udphdr); }

		/**
		 * Calculate @ref udphdr#headerChecksum field
		 */
		void computeCalculateFields();

		std::string toString();

		OsiModelLayer getOsiModelLayer() { return OsiModelTransportLayer; }
	};

} // namespace pcpp

#endif /* PACKETPP_UDP_LAYER */
