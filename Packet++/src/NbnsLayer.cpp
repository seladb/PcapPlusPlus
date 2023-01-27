#include "../header/NbnsLayer.h"
#include <string.h>
#include <sstream>
#include "NbnsLayer.h"
#include <iostream>

namespace pcpp {
	void NbnsLayer::computeCalculateFields() {
	}

	std::string NbnsLayer::toString() const {

		std::ostringstream transactionIdStream;
		transactionIdStream << getTransactionId();

		std::ostringstream flagsStream;
		flagsStream << getFlags();
		std::ostringstream questionStream;
		questionStream << getQuestion();
		std::ostringstream answerStream;
		answerStream << getAnswer();
		std::ostringstream authorityStream;
		authorityStream << getAuthority();
		std::ostringstream additionalStream;
		additionalStream << getAdditional();

		std::ostringstream queriesNameStream0;
		queriesNameStream0 << getQueriesName()[0];
		std::ostringstream queriesNameStream1;
		queriesNameStream1 << getQueriesName()[1];
		std::ostringstream queriesNameStream2;
		queriesNameStream2 << getQueriesName()[2];
		std::ostringstream queriesNameStream3;
		queriesNameStream3 << getQueriesName()[3];
		std::ostringstream queriesNameStream4;
		queriesNameStream4 << getQueriesName()[4];
		std::ostringstream queriesNameStream5;
		queriesNameStream5 << getQueriesName()[5];
		std::ostringstream queriesNameStream6;
		queriesNameStream6 << getQueriesName()[6];
		std::ostringstream queriesNameStream7;
		queriesNameStream7 << getQueriesName()[7];
		std::ostringstream queriesNameStream8;
		queriesNameStream8 << getQueriesName()[8];
		std::ostringstream queriesNameStream9;
		queriesNameStream9 << getQueriesName()[9];
		std::ostringstream queriesNameStream10;
		queriesNameStream10 << getQueriesName()[10];
		std::ostringstream queriesNameStream11;
		queriesNameStream11 << getQueriesName()[11];
		std::ostringstream queriesNameStream12;
		queriesNameStream12 << getQueriesName()[12];
		std::ostringstream queriesNameStream13;
		queriesNameStream13 << getQueriesName()[13];
		std::ostringstream queriesNameStream14;
		queriesNameStream14 << getQueriesName()[14];
		std::ostringstream queriesNameStream15;
		queriesNameStream15 << getQueriesName()[15];
		std::ostringstream queriesNameStream16;
		queriesNameStream16 << getQueriesName()[16];

		std::ostringstream queriesTypeStream;
		queriesTypeStream << getQueriesType();
		std::ostringstream queriesClassStream;
		queriesClassStream << getQueriesClass();

		std::ostringstream additionalRecordsNameStream;
		additionalRecordsNameStream << getAdditionalRecordsName();
		std::ostringstream additionalRecordsVistaStream;
		additionalRecordsVistaStream << getAdditionalRecordsVista();
		std::ostringstream additionalRecordTypeStream;
		additionalRecordTypeStream << getAdditionalRecordsType();
		std::ostringstream additionalRecordClassStream;
		additionalRecordClassStream << getAdditionalRecordsClass();
		std::ostringstream additionalRecordTimeToLiveStream;
		additionalRecordTimeToLiveStream << getAdditionalRecordsTimeToLive();
		std::ostringstream additionalRecordDataLengthStream;
		additionalRecordDataLengthStream << getAdditionalRecordsDataLength();
		std::ostringstream additionalRecordFlagsStream;
		additionalRecordFlagsStream << getAdditionalRecordsFlags();
		std::ostringstream additionalRecordAddressStream;
		additionalRecordAddressStream << getAdditionalRecordsFlags();


		return "NBNS Layer, flags: " + flagsStream.str() +
			   ", question: " + questionStream.str() +
			   ", answer: " + answerStream.str() +
			   ", authority: " + authorityStream.str() +
			   ", additional: " + additionalStream.str() +
			   ", queries_name[0]: " + queriesNameStream0.str() +
			   ", queries_name[1]: " + queriesNameStream1.str() +
			   ", queries_name[2]: " + queriesNameStream2.str() +
			   ", queries_name[3]: " + queriesNameStream3.str() +
			   ", queries_name[4]: " + queriesNameStream4.str() +
			   ", queries_name[5]: " + queriesNameStream5.str() +
			   ", queries_name[6]: " + queriesNameStream6.str() +
			   ", queries_name[7]: " + queriesNameStream7.str() +
			   ", queries_name[8]: " + queriesNameStream8.str() +
			   ", queries_name[9]: " + queriesNameStream9.str() +
			   ", queries_name[10]: " + queriesNameStream10.str() +
			   ", queries_name[11]: " + queriesNameStream11.str() +
			   ", queries_name[12]: " + queriesNameStream12.str() +
			   ", queries_name[13]: " + queriesNameStream13.str() +
			   ", queries_name[14]: " + queriesNameStream14.str() +
			   ", queries_name[15]: " + queriesNameStream15.str() +
			   ", queries_type: " + queriesTypeStream.str() +
			   ", queries_class: " + queriesClassStream.str() +
			   ", additional_records_vista: " + additionalRecordsVistaStream.str() +
			   ", additional_records_name: " + additionalRecordsNameStream.str() +
			   ", additional_records_type: " + queriesTypeStream.str() +
			   ", additional_records_class: " + additionalRecordClassStream.str() +
			   ", additional_records_time_to_live: " + additionalRecordTimeToLiveStream.str() +
			   ", additional_records_data_length: " + additionalRecordDataLengthStream.str() +
			   ", additional_records_flags: " + additionalRecordFlagsStream.str() +
			   ", additional_records_address: " + additionalRecordAddressStream.str();

	}

	void NbnsLayer::parseNextLayer() {

	}

	NbnsLayer *NbnsLayer::parseNbnsLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet) {
		if (dataLen < sizeof(nbnshdr))
			return NULL;

		return new NbnsLayer(data, dataLen, prevLayer, packet);
	}

	NbnsLayer::NbnsLayer() {
		const size_t headerLen = sizeof(nbnshdr);
		m_DataLen = headerLen;
		m_Data = new uint8_t[headerLen];
		memset(m_Data, 0, headerLen);
		m_Protocol = NBNS;
	}

	pcpp::NbnsLayer::NbnsLayer(uint16_t transaction_id, uint16_t flags, uint16_t question, uint16_t answer,
							   uint16_t authority, uint16_t additional, uint16_t *queries_name,
							   uint16_t queries_type,
							   uint16_t queries_class,
							   uint8_t additional_records_vista,
							   uint8_t additional_records_name,
							   uint16_t additional_records_type,
							   uint16_t additional_records_class,
							   uint32_t additional_records_time_to_live,
							   uint16_t additional_records_data_length,
							   uint16_t additional_records_flags,
							   uint32_t additional_records_address) {

		const size_t headerLen = sizeof(nbnshdr);
		m_DataLen = headerLen;
		m_Data = new uint8_t[headerLen];
		memset(m_Data, 0, headerLen);
		nbnshdr *nbnsHdr = (nbnshdr *) m_Data;
		nbnsHdr->transaction_id = transaction_id;
		nbnsHdr->flags = flags;
		nbnsHdr->question = question;
		nbnsHdr->answer = answer;
		nbnsHdr->authority = authority;
		nbnsHdr->additional = additional;
		for (int i = 0; i < 17; i++) {
			nbnsHdr->queries_name[i] = queries_name[i];
		}
		nbnsHdr->queries_type = queries_type;
		nbnsHdr->queries_class = queries_class;
		nbnsHdr->additional_records_vista = additional_records_vista;
		nbnsHdr->additional_records_name = additional_records_name;
		nbnsHdr->additional_records_type = additional_records_type;
		nbnsHdr->additional_records_class = additional_records_class;
		nbnsHdr->additional_records_time_to_live = additional_records_time_to_live;
		nbnsHdr->additional_records_data_length = additional_records_data_length;
		nbnsHdr->additional_records_flags = additional_records_flags;
		nbnsHdr->additional_records_address = additional_records_address;
		m_Protocol = NBNS;
	}

	uint16_t NbnsLayer::getTransactionId() const {
		return htobe16(getNbnsHeader()->transaction_id);
	}

	uint16_t NbnsLayer::getFlags() const {
		return htobe16(getNbnsHeader()->flags);
	}

	uint16_t NbnsLayer::getQuestion() const {
		return htobe16(getNbnsHeader()->question);
	}

	uint16_t NbnsLayer::getAnswer() const {
		return htobe16(getNbnsHeader()->answer);
	}

	uint16_t NbnsLayer::getAuthority() const {
		return htobe16(getNbnsHeader()->authority);
	}

	uint16_t *NbnsLayer::getQueriesName() const {
		return getNbnsHeader()->queries_name;
	}

	uint16_t NbnsLayer::getAdditional() const {
		return htobe16(getNbnsHeader()->additional);
	}

	uint16_t NbnsLayer::getQueriesType() const {
		return htobe16(getNbnsHeader()->queries_type);
	}

	uint16_t NbnsLayer::getQueriesClass() const {
		return htobe16(getNbnsHeader()->queries_class);
	}

	uint8_t NbnsLayer::getAdditionalRecordsVista() const {
		return getNbnsHeader()->additional_records_vista;
	}

	uint8_t NbnsLayer::getAdditionalRecordsName() const {
		return getNbnsHeader()->additional_records_name;
	}

	uint16_t NbnsLayer::getAdditionalRecordsType() const {
		return htobe16(getNbnsHeader()->additional_records_type);
	}

	uint32_t NbnsLayer::getAdditionalRecordsTimeToLive() const {
		return htobe32(getNbnsHeader()->additional_records_time_to_live);
	}

	uint16_t NbnsLayer::getAdditionalRecordsFlags() const {
		return htobe16(getNbnsHeader()->additional_records_flags);
	}

	uint32_t NbnsLayer::getAdditionalRecordsAddress() const {
		return htobe32(getNbnsHeader()->additional_records_address);
	}

	uint16_t NbnsLayer::getAdditionalRecordsDataLength() const {
		return htobe16(getNbnsHeader()->additional_records_data_length);
	}

	uint16_t NbnsLayer::getAdditionalRecordsClass() const {
		return htobe16(getNbnsHeader()->additional_records_class);
	}
}
