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
		virtual ~CotpLayer() {}

		CotpLayer(uint8_t length, uint8_t pdu_type, uint8_t tpdu_number);

		cotphdr *getCotpHeader() const { return (cotphdr *) m_Data; }

		uint8_t getLength() const;

		uint8_t getPdu_type() const;

		uint8_t getTpdu_number() const;

		size_t getHeaderLen() const override {
			return sizeof(cotphdr);
		}

		void computeCalculateFields() override;

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const override { return OsiModelSesionLayer; }

		void parseNextLayer() override;

		static bool isCotpPort(uint8_t cotpType) { return cotpType == 0x06 || cotpType == 0xf0; }

		static CotpLayer *parseCotpLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet);

		CotpLayer();

		CotpLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet) : Layer(data, dataLen, prevLayer,
																						   packet) { m_Protocol = COTP; }
	};


}

#endif //PCAPPLUSPLUS_COTPLAYER_H
