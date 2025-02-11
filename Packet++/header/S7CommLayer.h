#pragma once

#include "EthLayer.h"
#include "Layer.h"

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	/// @struct s7commhdr
	/// Represents a S7COMM protocol header
#pragma pack(push, 1)
	typedef struct
	{
		/// protocol id
		uint8_t protocolId;
		/// message type
		uint8_t msgType;
		/// redundancy identification (reserved)
		uint16_t reserved;
		/// protocol data unit reference
		uint16_t pduRef;
		/// parameter length
		uint16_t paramLength;
		/// data length
		uint16_t dataLength;
	} s7commhdr;
#pragma pack(pop)
	static_assert(sizeof(s7commhdr) == 10, "s7commhdr size is not 10 bytes");

	/// @struct s7comm_ack_data_hdr
	/// Represents a S7COMM protocol header with Ack-Data header
#pragma pack(push, 1)
	struct s7comm_ack_data_hdr : s7commhdr
	{
		/// error class
		uint8_t errorClass;
		/// error code
		uint8_t errorCode;
	};
#pragma pack(pop)
	static_assert(sizeof(s7comm_ack_data_hdr) == 12, "s7comm_ack_data_hdr size is not 12 bytes");

	/// @class S7CommParameter
	/// Represents a S7COMM (S7 Communication) protocol Parameter
	class S7CommParameter
	{
		friend class S7CommLayer;

	public:
		S7CommParameter()
		{}

		virtual ~S7CommParameter() = default;

		/// @return The data of the Parameter
		uint8_t* getData() const
		{
			return m_Data;
		}
		/// @return The length of the Parameter data
		size_t getDataLength() const
		{
			return m_DataLen;
		}

	private:
		S7CommParameter(uint8_t* data, size_t dataLen) : m_Data(data), m_DataLen(dataLen)
		{}
		uint8_t* m_Data;
		size_t m_DataLen;
	};
	/// @class S7CommLayer
	/// Represents a S7COMM (S7 Communication) protocol
	class S7CommLayer : public Layer
	{
	public:
		/// A constructor that allocates a new S7comm header
		/// @param[in] msgType The general type of the message
		/// @param[in] pduRef Link responses to their requests
		/// @param[in] paramLength The length of the parameter field
		/// @param[in] dataLength The length of the data field
		/// @param[in] errorClass The value of the error class
		/// @param[in] errorCode The value of the error code
		S7CommLayer(uint8_t msgType, uint16_t pduRef, uint16_t paramLength, uint16_t dataLength, uint8_t errorClass = 0,
		            uint8_t errorCode = 0);

		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data (will be casted to @ref s7commhdr)
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		S7CommLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, S7COMM)
		{
			m_Parameter = nullptr;
		}

		~S7CommLayer() override
		{
			if (m_Parameter)
				delete m_Parameter;
		}

		/// @return S7comm protocol id
		uint8_t getProtocolId() const;

		/// @return S7comm message type
		uint8_t getMsgType() const;

		/// @return S7comm PDU ref
		uint16_t getPduRef() const;

		/// @return S7comm parameter length
		uint16_t getParamLength() const;

		/// @return S7comm data length
		uint16_t getDataLength() const;

		/// @return S7comm error code
		uint8_t getErrorCode() const;

		/// @return S7comm error class
		uint8_t getErrorClass() const;

		/// @return S7comm parameter
		const S7CommParameter* getParameter();

		/// Set the value of the message type
		/// @param[in] msgType The value of the message type
		void setMsgType(uint8_t msgType) const;

		/// Set the value of the PDU ref
		/// @param[in] pduRef The value of the PDU ref
		void setPduRef(uint16_t pduRef) const;

		/// Set the value of the error code
		/// @param[in] errorCode The value of the error code
		void setErrorCode(uint8_t errorCode) const;
		/// Set the value of the error class
		/// @param[in] errorClass The value of the error class
		void setErrorClass(uint8_t errorClass) const;

		/// @return Size of S7CommLayer
		size_t getHeaderLen() const override
		{
			return m_DataLen;
		}

		/// Does nothing for this layer (S7CommLayer is always last)
		void computeCalculateFields() override
		{}

		/// Does nothing for this layer (S7CommLayer is always last)
		void parseNextLayer() override
		{}

		/// A static method that takes a byte array and detects whether it is a S7COMM
		/// @param[in] data A byte array
		/// @param[in] dataSize The byte array size (in bytes)
		/// @return True if the data looks like a valid S7COMM layer
		static bool isDataValid(const uint8_t* data, size_t dataSize);

		std::string toString() const override;

		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelApplicationLayer;
		}

	private:
		s7commhdr* getS7commHeader() const
		{
			return reinterpret_cast<s7commhdr*>(m_Data);
		}

		s7comm_ack_data_hdr* getS7commAckDataHeader() const
		{
			if (getS7commHeader()->msgType == 0x03)
			{
				return reinterpret_cast<s7comm_ack_data_hdr*>(m_Data);
			}
			return nullptr;
		}

		size_t getS7commHeaderLength() const;

		S7CommParameter* m_Parameter;
	};

}  // namespace pcpp
