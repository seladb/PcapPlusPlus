#ifndef PACKETPP_TPKT_LAYER
#define PACKETPP_TPKT_LAYER

#include "EthLayer.h"
#include "Layer.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * @struct tpkthdr
	 * Represents a TPKT protocol header
	 */
#pragma pack(push, 1)
	typedef struct
	{
		/** message vrsn */
		uint8_t vrsn;
		/** message reserved */
		uint8_t reserved;
		/** message length */
		uint16_t length;
	} tpkthdr;
#pragma pack(pop)

	/**
	 * @class TpktLayer
	 * Represents a TPKT (Transport Service on top of the TCP) protocol layer
	 */
	class TpktLayer : public Layer
	{
	  public:
		/**
		 * Get a pointer to the TPKT header. Data can be retrieved through the
		 * other methods of this layer. Notice the return value points directly to the data, so every change will change the actual packet data
		 * @return A pointer to the @ref tpkthdr
		 */
		tpkthdr *getTpktHeader() const { return (tpkthdr *)m_Data; }

		/**
		 * @return TPKT reserved
		 */
		uint8_t getReserved() const;

		/**
		 * @return TPKT version
		 */
		uint8_t getVrsn() const;

		/**
		 * @return TPKT length
		 */
		uint16_t getLength() const;

		/**
		 * @return Size of @ref tpkthdr
		 */
		size_t getHeaderLen() const override { return sizeof(tpkthdr); }

		/**
		 * Does nothing for this layer
		 */
		void computeCalculateFields() {}

		/**
		 * Currently identifies the following next layer: CotpLayer
		 */
		void parseNextLayer();

		/**
		 * A static method that checks whether a source or dest port match those associated with the TPKT protocol
		 * @param[in] portSrc Source port number to check
	 	 * @param[in] portDst Dest port number to check
	 	 * @return True if the source or dest port match those associated with the TPKT protocol
		 */
		static bool isTpktPort(uint16_t portSrc, uint16_t portDst) { return portSrc == 102 || portDst == 102; }

		/**
		 * A method that creates a TPKT layer from packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored
		 * @return A newly allocated TPKT layer
		 */
		static TpktLayer *parseTpktLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet);

		/**
		 * A static method that takes a byte array and detects whether it is a TPKT message
		 * @param[in] data A byte array
		 * @param[in] dataSize The byte array size (in bytes)
		 * @return True if the data is identified as TPKT message
		 */
		static bool isDataValid(const uint8_t *data, size_t dataSize) {	return data && dataSize; }

		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to @ref tpkthdr)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		TpktLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet) : Layer(data, dataLen, prevLayer, packet)
		{
			m_Protocol = TPKT;
		}

		virtual ~TpktLayer() {}

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const override { return OsiModelTransportLayer; }
	};

} // namespace pcpp
#endif // PACKETPP_TPKT_LAYER
