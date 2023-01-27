#ifndef PCAPPLUSPLUS_S7COMMLAYER_H
#define PCAPPLUSPLUS_S7COMMLAYER_H

#include "Layer.h"
#include "EthLayer.h"


namespace pcpp {


#pragma pack(push, 1)
	typedef struct {
		/** protocol id */
		uint8_t protocol_id;
		/** message type */
		uint8_t msg_type;
		/** redundancy identification (reserved) */
		uint16_t reserved;
		/** protocol data unit reference */
		uint16_t pdu_ref;
		/** parameter length */
		uint16_t param_length;
		/** data length */
		uint16_t data_length;
	} s7commhdr;
#pragma pack(pop)


	/**
     * @class S7commLayer
	 */
	class S7commLayer : public Layer {
	  public:
		virtual ~S7commLayer() {}

		S7commLayer(uint8_t protocol_id, uint8_t msg_type, uint16_t reserved, uint16_t pdu_ref,
					uint16_t param_length,
					uint16_t data_length);

		s7commhdr *getS7commHeader() const { return (s7commhdr *) m_Data; }

		uint8_t getProtocolId() const;

		uint8_t getMsgType() const;

		uint16_t getReserved() const;

		uint16_t getPduRef() const;

		uint16_t getParamLength() const;

		uint16_t getDataLength() const;


		/**
         * @return Size of @ref s7commhdr
		 */
		size_t getHeaderLen() const override {
			return sizeof(s7commhdr);
		}

		void computeCalculateFields() override;

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const override { return OsiModelApplicationLayer; }

		void parseNextLayer() override;

		static bool isS7commPort(uint8_t type) { return type == 0x32; }

		static S7commLayer *parseS7commLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet);

		S7commLayer();

		S7commLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet) : Layer(data, dataLen, prevLayer,
																							 packet) { m_Protocol = S7COMM; }
	};


}
#endif //PCAPPLUSPLUS_S7COMMLAYER_H
