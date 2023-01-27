#ifndef PCAPPLUSPLUS_NBNSLAYER_H
#define PCAPPLUSPLUS_NBNSLAYER_H

#include "Layer.h"
#include "EthLayer.h"


namespace pcpp {


#pragma pack(push, 1)
	typedef struct {
		/** transaction id*/
		uint16_t transaction_id;
		/** flags */
		uint16_t flags;
		/** questions */
		uint16_t question;
		/** answer RRS */
		uint16_t answer;
		/** authority RRS */
		uint16_t authority;
		/** additional RRS */
		uint16_t additional;
		/** queries */
		uint16_t queries_name[17];
		/** queries type */
		uint16_t queries_type;
		/** queries class */
		uint16_t queries_class;
		/** queries records vista */
		uint8_t additional_records_vista;
		/** queries records name */
		uint8_t additional_records_name;
		/** queries records type */
		uint16_t additional_records_type;
		/** queries records class */
		uint16_t additional_records_class;
		/** queries records time to live */
		uint32_t additional_records_time_to_live;
		/** queries records data length */
		uint16_t additional_records_data_length;
		/** queries records flags */
		uint16_t additional_records_flags;
		/** queries records address*/
		uint32_t additional_records_address;

	} nbnshdr;
#pragma pack(pop)


	class NbnsLayer : public Layer {
	  public:
		virtual ~NbnsLayer() {}

		NbnsLayer(
			uint16_t transaction_id,
			uint16_t flags,
			uint16_t question,
			uint16_t answer,
			uint16_t authority,
			uint16_t additional,
			uint16_t queries_name[17],
			uint16_t queries_type,
			uint16_t queries_class,
			uint8_t additional_records_vista,
			uint8_t additional_records_name,
			uint16_t additional_records_type,
			uint16_t additional_records_class,
			uint32_t additional_records_time_to_live,
			uint16_t additional_records_data_length,
			uint16_t additional_records_flags,
			uint32_t additional_records_address
		);

		nbnshdr *getNbnsHeader() const { return (nbnshdr *) m_Data; }


		size_t getHeaderLen() const override {
			return sizeof(nbnshdr);
		}

		void computeCalculateFields() override;

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const override { return OsiModelSesionLayer; }

		void parseNextLayer() override;

		static bool isNbnsPort(uint16_t portSrc, uint16_t portDst) { return portSrc == 137 || portDst == 137; }

		static NbnsLayer *parseNbnsLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet);

		NbnsLayer();

		NbnsLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet) : Layer(data, dataLen, prevLayer,
																						   packet) { m_Protocol = NBNS; }


		uint16_t getTransactionId() const;

		uint16_t getFlags() const;

		uint16_t getQuestion() const;

		uint16_t getAnswer() const;

		uint16_t getAuthority() const;

		uint16_t getAdditional() const;

		uint16_t *getQueriesName() const;

		uint16_t getQueriesType() const;

		uint16_t getQueriesClass() const;

		uint8_t getAdditionalRecordsVista() const;

		uint8_t getAdditionalRecordsName() const;

		uint16_t getAdditionalRecordsType() const;

		uint16_t getAdditionalRecordsClass() const;

		uint32_t getAdditionalRecordsTimeToLive() const;

		uint16_t getAdditionalRecordsDataLength() const;

		uint16_t getAdditionalRecordsFlags() const;

		uint32_t getAdditionalRecordsAddress() const;

	};


}
#endif //PCAPPLUSPLUS_NBNSLAYER_H

