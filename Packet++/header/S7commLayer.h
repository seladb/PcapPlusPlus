#ifndef PCAPPLUSPLUS_S7COMMLAYER_H
#define PCAPPLUSPLUS_S7COMMLAYER_H

#include "EthLayer.h"
#include "Layer.h"

namespace pcpp
{
/**
 * @struct s7commhdr
 * Represents a S7COMM protocol header
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
 * @struct s7comm_ack_data_hdr
 * Represents a S7COMM protocol with Ack-Data header
 */
#pragma pack(push, 1)
	struct s7comm_ack_data_hdr : s7commhdr
	{
		/** error class */
		uint8_t error_class;
		/** error code */
		uint8_t error_code;
	};
#pragma pack(pop)

	/**
	 * @class S7commLayer
	 * Represents a S7COMM (S7 Communication7) protocol
	 */
	class S7commLayer : public Layer
	{
	  public:
		/**
		 * A constructor that allocates a new S7comm header
		 * @param[in] msg_type The general type of the message
		 * @param[in] pdu_ref Link responses to their requests
		 * @param[in] param_length The length of the parameter field
		 * @param[in] data_length The length of the data field
		 */
		S7commLayer(uint8_t msg_type, uint16_t pdu_ref, uint16_t param_length, uint16_t data_length,
					uint8_t error_class = 0, uint8_t error_code = 0);

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

		/**
		 * @return S7comm protocol id
		 */
		uint8_t getProtocolId() const;

		/**
		 * @return S7comm message type
		 */
		uint8_t getMsgType() const;

		/**
		 * @return S7comm reserved
		 */
		uint16_t getReserved() const;

		/**
		 * @return S7comm PDU ref
		 */
		uint16_t getPduRef() const;

		/**
		 * @return S7comm parameter length
		 */
		uint16_t getParamLength() const;

		/**
		 * @return S7comm data length
		 */
		uint16_t getDataLength() const;

		/**
		 * @return S7comm error code
		 */
		uint8_t getErrorCode() const;
		/**
		 * @return S7comm error class
		 */
		uint8_t getErrorClass() const;

		/**
		 * Set the value of the message type
		 * @param[in] msg_type The value of the message type
		 */
		void setMsgType(uint8_t msg_type) const;

		/**
		 * Set the value of the PDU ref
		 * @param[in] pdu_ref The value of the PDU ref
		 */
		void setPduRef(uint16_t pdu_ref) const;

		/**
		 * Set the value of the parameter length
		 * @param[in] param_length The value of the parameter length
		 */
		void setParamLength(uint16_t param_length) const;

		/**
		 * Set the value of the data length
		 * @param[in] data_length The value of the data length
		 */
		void setDataLength(uint16_t data_length) const;

		/**
		 * Set the value of the error code
		 * @param[in] error_code The value of the error code
		 */
		void setErrorCode(uint8_t error_code) const;
		/**
		 * Set the value of the error class
		 * @param[in] error_class The value of the error class
		 */
		void setErrorClass(uint8_t error_class) const;

		/**
		 * @return Size of @ref s7commhdr
		 */
		size_t getHeaderLen() const override { return sizeof(s7commhdr); }

		/**
		 * Does nothing for this layer
		 */
		void computeCalculateFields() override {}

		/**
		 * Does nothing for this layer
		 */
		void parseNextLayer() override {}

		/**
		 * A static method that takes a byte array and detects whether it is a S7COMM
		 * @param[in] data A byte array
		 * @param[in] dataSize The byte array size (in bytes)
		 * @return True if the data looks like a valid S7COMM layer
		 */
		static bool isDataValid(const uint8_t *data, size_t dataSize);

		std::string toString() const override;

		OsiModelLayer getOsiModelLayer() const override { return OsiModelApplicationLayer; }

	  private:
		s7commhdr *getS7commHeader() const { return (s7commhdr *)m_Data; }

		s7comm_ack_data_hdr *getS7commAckDataHeader() const
		{
			if (getS7commHeader()->msg_type == 0x03)
			{
				return (s7comm_ack_data_hdr *)m_Data;
			}
			return nullptr;
		}
	};
	class S7CommParameter
	{
		friend class S7commLayer;

	  public:
		S7CommParameter() {}
		uint8_t *getData() { return m_Data; }
		size_t getDataLength() const { return m_DataLen; }
		S7CommParameter *getParameter() const;

	  private:
		S7CommParameter(uint8_t *data, size_t dataLen) : m_Data(data), m_DataLen(dataLen) {}
		uint8_t *m_Data;
		size_t m_DataLen;
	};

}; // namespace pcpp
#endif // PCAPPLUSPLUS_S7COMMLAYER_H
