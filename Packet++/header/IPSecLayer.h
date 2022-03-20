#ifndef PACKETPP_IPSEC_LAYER
#define PACKETPP_IPSEC_LAYER

/// @file

#include "Layer.h"

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
	/**
	 * @struct ipsec_authentication_header
	 * Represents IPSec AuthenticationHeader (AH) structure
	 */
#pragma pack(push, 1)
	struct ipsec_authentication_header
	{
		/** Type of the next header */
		uint8_t nextHeader;
		/** The length of the Authentication Header in 4-octet units, minus 2 */
		uint8_t payloadLen;
		/** Reserved */
		uint16_t reserved;
		/** Security Parameters Index */
		uint32_t spi;
		/** Sequence Number */
		uint32_t sequenceNumber;
	};
#pragma pack(pop)

	/**
	 * @struct ipsec_esp
	 * Represents IPSec Encapsulating Security Payload (ESP) structure
	 */
#pragma pack(push, 1)
	struct ipsec_esp
	{
		/** Security Parameters Index */
		uint32_t spi;
		/** Sequence Number */
		uint32_t sequenceNumber;
	};
#pragma pack(pop)

	/**
	 * @class AuthenticationHeaderLayer
	 * Represents an IPSec AuthenticationHeader (AH) layer
	 */
	class AuthenticationHeaderLayer : public Layer
	{
	public:
		 /** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		AuthenticationHeaderLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet) { m_Protocol = AuthenticationHeader; }

		/**
		 * Get a pointer to the raw AH header. Notice this points directly to the data, so every change will change the actual packet data
		 * @return A pointer to the ipsec_authentication_header
		 */
		ipsec_authentication_header* getAHHeader() const { return (ipsec_authentication_header*)m_Data; }

		/**
		 * @return The Security Parameters Index (SPI) field value
		 */
		uint32_t getSPI() const;

		/**
		 * @return The sequence number value
		 */
		uint32_t getSequenceNumber() const;

		/**
		 * @return The size of the Integrity Check Value (ICV)
		 */
		size_t getICVLength() const;

		/**
		 * @return A pointer to the raw data of the Integrity Check Value (ICV)
		 */
		uint8_t* getICVBytes() const;

		/**
		 * @return The value of the Integrity Check Value (ICV) as a hex string
		 */
		std::string getICVHexStream() const;

		/**
		 * A static method that validates the input data
		 * @param[in] data The pointer to the beginning of a byte stream of a AuthenticationHeader layer
		 * @param[in] dataLen The length of byte stream
		 * @return True if the data is valid and can represent an AuthenticationHeader layer
		 */
		static inline bool isDataValid(const uint8_t* data, size_t dataLen);

		// implement abstract methods

		/**
		 * @return The size of the AH header
		 */
		size_t getHeaderLen() const { return 4*(getAHHeader()->payloadLen + 2); }

		/**
		 * Currently identifies the following next layers: UdpLayer, TcpLayer, IPv4Layer, IPv6Layer and ESPLayer. Otherwise sets PayloadLayer
		 */
		void parseNextLayer();

		/**
		 * Does nothing for this layer
		 */
		void computeCalculateFields() {}

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const { return OsiModelNetworkLayer; }

	private:
		// this layer supports parsing only
		AuthenticationHeaderLayer() {}
	};



	/**
	 * @class ESPLayer
	 * Represents an IPSec Encapsulating Security Payload (ESP) layer
	 */
	class ESPLayer : public Layer
	{
	public:
		 /** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		ESPLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet) { m_Protocol = ESP; }

		ipsec_esp* getESPHeader() const { return (ipsec_esp*)m_Data; }

		/**
		 * @return The Security Parameters Index (SPI) field value
		 */
		uint32_t getSPI() const;

		/**
		 * @return The sequence number value
		 */
		uint32_t getSequenceNumber() const;

		/**
		 * A static method that validates the input data
		 * @param[in] data The pointer to the beginning of a byte stream of a ESP layer
		 * @param[in] dataLen The length of byte stream
		 * @return True if the data is valid and can represent an ESP layer
		 */
		static inline bool isDataValid(const uint8_t* data, size_t dataLen);

		// implement abstract methods

		/**
		 * @return The size of the ESP header (8 bytes)
		 */
		size_t getHeaderLen() const { return sizeof(ipsec_esp); }

		/**
		 * The payload of an ESP layer is encrypted, hence the next layer is always a generic payload (PayloadLayer)
		 */
		void parseNextLayer();

		/**
		 * Does nothing for this layer
		 */
		void computeCalculateFields() {}

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const { return OsiModelTransportLayer; }

	private:
		// this layer supports parsing only
		ESPLayer() {}
	};


	// implementation of inline methods

	bool AuthenticationHeaderLayer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		if (dataLen < sizeof(ipsec_authentication_header))
			return false;

		size_t payloadLen = 4 * (data[1] + 2);
		if (payloadLen < sizeof(ipsec_authentication_header) || payloadLen > dataLen)
			return false;

		return true;
	}

	bool ESPLayer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		return dataLen >= sizeof(ipsec_esp);
	}
}

#endif // PACKETPP_IPSEC_LAYER
