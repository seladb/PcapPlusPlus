#ifndef PCAPPLUSPLUS_S7COMMLAYER_H
#define PCAPPLUSPLUS_S7COMMLAYER_H

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
	 * @struct s7commhdr
	 * Represents a S7COMM (S7 Communication) protocol header
	 */
#pragma pack(push, 1)
	typedef struct
	{
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
	 * * Represents a S7COMM protocol header
	 */
	class S7commLayer : public Layer
	{
	  public:
		/**
		 * Get a pointer to the S7COMM header. Data can be retrieved through the
		 * other methods of this layer. Notice the return value points directly to the data, so every change will change
		 * the actual packet data
		 * @return A pointer to the @ref s7commhdr
		 */
		s7commhdr *getS7commHeader() const { return (s7commhdr *)m_Data; }

		/**
		 * @return S7COMM protocol id
		 */
		uint8_t getProtocolId() const;

		/**
		 * @return S7COMM message type
		 */
		uint8_t getMsgType() const;

		/**
		 * @return S7COMM reserved
		 */
		uint16_t getReserved() const;

		/**
		 * @return S7COMM PDU reference
		 */
		uint16_t getPduRef() const;

		/**
		 * @return S7COMM param length
		 */
		uint16_t getParamLength() const;

		/**
		 * @return S7COMM data length
		 */
		uint16_t getDataLength() const;

		/**
		 * @return Size of @ref s7commhdr
		 */
		size_t getHeaderLen() const override { return sizeof(s7commhdr); }

		/**
		 * Does nothing for this layer
		 */
		void computeCalculateFields() {}

		/**
		 * A static method that takes a byte array and detects whether it is a S7COMM message
		 * @param[in] data A byte array
		 * @param[in] dataSize The byte array size (in bytes)
		 * @return True if the data is identified as S7COMM message
		 */
		static bool isDataValid(const uint8_t *data, size_t dataSize) { return data && dataSize; }

		/**
		 * Does nothing for this layer
		 */
		void parseNextLayer();

		/**
		 * A static method that checks whether a source or dest port match those associated with the S7COMM protocol
		 * @param[in] value of the number to check
		 * @return True if the source or dest port match those associated with the S7COMM protocol
		 */
		static bool isS7commPort(uint8_t type) { return type == 0x32; }

		/**
		 * A method that creates a S7COMM layer from packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored
		 * @return A newly allocated S7COMM layer
		 */
		static S7commLayer *parseS7commLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet);

		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to @ref s7commhdr)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		S7commLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet)
			: Layer(data, dataLen, prevLayer, packet)
		{
			m_Protocol = S7COMM;
		}

		virtual ~S7commLayer() {}

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const override { return OsiModelApplicationLayer; }
	};

} // namespace pcpp
#endif // PCAPPLUSPLUS_S7COMMLAYER_H
