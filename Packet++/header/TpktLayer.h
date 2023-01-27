#ifndef PACKETPP_TPKT_LAYER
#define PACKETPP_TPKT_LAYER

#include "Layer.h"
#include "EthLayer.h"


namespace pcpp {


#pragma pack(push, 1)
	typedef struct {
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
	 */
	class TpktLayer : public Layer {
	  public:
		virtual ~TpktLayer() {}

		TpktLayer(uint8_t vrsn, uint8_t reserved, uint16_t length);

		tpkthdr *getTpktHeader() const { return (tpkthdr *) m_Data; }

		uint8_t getReserved() const;

		uint8_t getVrsn() const;

		uint16_t getLength() const;


		/**
         * @return Size of @ref tpkthdr
		 */
		size_t getHeaderLen() const override {
			return sizeof(tpkthdr);
		}

		void computeCalculateFields() override;

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const override { return OsiModelTransportLayer; }

		void parseNextLayer() override;

		static bool isTpktPort(uint16_t portSrc, uint16_t portDst) { return portSrc == 102 || portDst == 102; }

		static TpktLayer *parseTpktLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet);

		TpktLayer();

		TpktLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet) : Layer(data, dataLen, prevLayer,
																						   packet) { m_Protocol = TPKT; }
	};


}
#endif //PACKETPP_TPKT_LAYER
