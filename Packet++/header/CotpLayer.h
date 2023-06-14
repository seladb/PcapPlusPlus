#ifndef PCAPPLUSPLUS_COTPLAYER_H
#define PCAPPLUSPLUS_COTPLAYER_H

#include "EthLayer.h"
#include "Layer.h"

namespace pcpp
{

/**
 * @struct cotphdr
 * Represents a COTP protocol header
 */
#pragma pack(push, 1)
	typedef struct
	{
		/** length */
		uint8_t length;
		/** PDU type identifier */
		uint8_t pdu_type;
		/** TPDU number sequence*/
		uint8_t tpdu_number;
	} cotphdr;
#pragma pack(pop)

	class CotpLayer : public Layer
	{
	  public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to @ref cotphdr)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		CotpLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet)
			: Layer(data, dataLen, prevLayer, packet)
		{
			m_Protocol = COTP;
		}

		/**
		 * A constructor that allocates a new COTP header
		 * @param[in] length Packet length
		 * @param[in] pdu_type Protocol PDU type number
		 * @param[in] pdu_type Protocol TPDU number
		 */
		CotpLayer(uint8_t length, uint8_t pdu_type, uint8_t tpdu_number);

		virtual ~CotpLayer() {}

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
		size_t getHeaderLen() const override { return sizeof(cotphdr); }

		/**
		 * Set the value of the length
		 * @param[in] length The value of the length
		 */
		void setLength(uint8_t length) const;

		/**
		 * Set the value of the version
		 * @param[in] pdu_type The number of the PDU type
		 */
		void setPdu_type(uint8_t pdu_type) const;

		/**
		 * Set the value of the version
		 * @param[in] tpdu_number The value of the TPDU number
		 */
		void setTpdu_number(uint8_t tpdu_number) const;

		/**
		 * Does nothing for this layer
		 */
		void computeCalculateFields() override;

		/**
		 * Currently parses the rest of the packet as a generic payload (PayloadLayer)
		 */
		void parseNextLayer() override;

		/**
		 * A static method that checks whether a source or dest port match those associated with the COTP protocol
		 * @param[in] cotpType data type with special numbers to check
		 * @return True if the number match that associated with the COTP protocol
		 */
		static bool isCotpPort(uint8_t cotpType) { return cotpType == 0x06 || cotpType == 0xf0; }

		static CotpLayer *parseCotpLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet);

		/**
		 * A static method that takes a byte array and detects whether it is a COTP
		 * @param[in] data A byte array
		 * @param[in] dataSize The byte array size (in bytes)
		 * @return True if the data size is greater or equal than the size of cotphdr
		 */
		static bool isDataValid(const uint8_t *data, size_t dataSize) { return data && dataSize >= sizeof(cotphdr); }

		std::string toString() const override;

		OsiModelLayer getOsiModelLayer() const override { return OsiModelSesionLayer; }

	  private:
		/**
		 * Get a pointer to the COTP header. Data can be retrieved through the
		 * other methods of this layer. Notice the return value points directly to the data, so every change will change
		 * the actual packet data
		 * @return A pointer to the @ref cotphdr
		 */
		cotphdr *getCotpHeader() const { return (cotphdr *)m_Data; }
	};

} // namespace pcpp

#endif // PCAPPLUSPLUS_COTPLAYER_H
