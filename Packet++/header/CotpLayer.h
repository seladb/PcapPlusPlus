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
		uint8_t pduType ;
		/** TPDU number sequence*/
		uint8_t tpduNumber;
	} cotphdr;
#pragma pack(pop)

	/**
	 * @class CotpLayer
	 * Represents a COTP (Connection Oriented Transport Protocol)
	 */
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
		 * @param[in] tpduNumber Protocol TPDU number
		 */
		explicit CotpLayer(uint8_t tpduNumber);

		virtual ~CotpLayer() {}

		/**
		 * @return COTP length
		 */
		uint8_t getLength() const;

		/**
		 * @return COTP PDU type
		 */
		uint8_t getPduType() const;

		/**
		 * @return COTP TPDU number
		 */
		uint8_t getTpduNumber() const;

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
		 * @param[in] pduType The number of the PDU type
		 */
		void setPduType(uint8_t pduType) const;

		/**
		 * Set the value of the version
		 * @param[in] tpduNumber The value of the TPDU number
		 */
		void setTpduNumber(uint8_t tpduNumber) const;

		/**
		 * Does nothing for this layer
		 */
		void computeCalculateFields() override;

		/**
		 * Currently parses the rest of the packet as a generic payload (PayloadLayer)
		 */
		void parseNextLayer() override;

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
		 * A static method that takes a byte array and detects whether it is a COTP
		 * @param[in] data A byte array
		 * @param[in] dataSize The byte array size (in bytes)
		 * @param[in] cotpType The type of the COTP
		 * @param[in] length The length of the COTP
		 * @return True if the data size is greater or equal than the size of cotphdr
		 */
		static bool isDataValid(const uint8_t *data, size_t dataSize, uint8_t cotpType, uint8_t length) { return data && dataSize >= sizeof(cotphdr) && cotpType == 0xf0 && length == 2; }

		std::string toString() const override;

		OsiModelLayer getOsiModelLayer() const override { return OsiModelTransportLayer; }

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