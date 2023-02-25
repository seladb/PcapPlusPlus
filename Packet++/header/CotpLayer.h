#ifndef PCAPPLUSPLUS_COTPLAYER_H
#define PCAPPLUSPLUS_COTPLAYER_H

#include "Layer.h"
#include "EthLayer.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp {

	/**
	 * @struct cotphdr
	 * Represents a COTP protocol header
	 */
#pragma pack(push, 1)
	typedef struct {
		/** length */
		uint8_t length;
		/** PDU type */
		uint8_t pdu_type;
		/** TPDU number */
		uint8_t tpdu_number;
	} cotphdr;
#pragma pack(pop)

	/**
     * @class CotpLayer
     * * Represents a COTP (Connection Oriented Transport Protocol, ISO 8073) protocol header
	 */
	class CotpLayer : public Layer {
	  public:
		/**
		 * Get a pointer to the COTP header. Data can be retrieved through the
		 * other methods of this layer. Notice the return value points directly to the data, so every change will change the actual packet data
		 * @return A pointer to the @ref cotphdr
		 */
		cotphdr *getCotpHeader() const { return (cotphdr *) m_Data; }

		/**
		 * @return COTP length
		 */
		uint8_t getLength() const;

		/**
		 * @return COTP PDU type
		 */
		uint8_t getPdu_type() const;

		/**
		 * @return COTP TPDU number
		 */
		uint8_t getTpdu_number() const;

		/**
		 * @return Size of @ref cotphdr
		 */
		size_t getHeaderLen() const override {
			return sizeof(cotphdr);
		}

		/**
		 * Does nothing for this layer
		 */
		void computeCalculateFields() {}

		/**
		* Currently identifies the following next layer: S7commLayer
		*/
		void parseNextLayer();

		/**
		 * A static method that takes a byte array and detects whether it is a COTP message
		 * @param[in] data A byte array
		 * @param[in] dataSize The byte array size (in bytes)
		 * @return True if the data is identified as COTP message
		 */
		static bool isDataValid(const uint8_t *data, size_t dataSize) {	return data && dataSize; }

		/**
		 * A static method that checks whether a source or dest port match those associated with the COTP protocol
		 * @param[in] portSrc Source port number to check
	 	 * @param[in] portDst Dest port number to check
	 	 * @return True if the source or dest port match those associated with the COTP protocol
		 */
		static bool isCotpPort(uint8_t cotpType) { return cotpType == 0x06 || cotpType == 0xf0; }

		/**
		 * A method that creates a COTP layer from packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored
		 * @return A newly allocated COTP layer
		 */
		static CotpLayer *parseCotpLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet);

		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to @ref cotphdr)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		CotpLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet) : Layer(data, dataLen, prevLayer, packet) { m_Protocol = COTP; }

		virtual ~CotpLayer() {}

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const override { return OsiModelSesionLayer; }
	};


}

#endif //PCAPPLUSPLUS_COTPLAYER_H
