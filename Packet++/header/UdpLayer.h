#pragma once

#include "Layer.h"

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	/// @struct udphdr
	/// Represents an UDP protocol header
#pragma pack(push, 1)
	struct udphdr
	{
		/// Source port
		uint16_t portSrc;
		/// Destination port
		uint16_t portDst;
		/// Length of header and payload in bytes
		uint16_t length;
		///  Error-checking of the header and data
		uint16_t headerChecksum;
	};
#pragma pack(pop)
	static_assert(sizeof(udphdr) == 8, "udphdr size is not 8 bytes");

	/// @class UdpLayer
	/// Represents an UDP (User Datagram Protocol) protocol layer
	class UdpLayer : public Layer
	{
	public:
		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data (will be casted to @ref udphdr)
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		UdpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, UDP)
		{}

		/// A constructor that allocates a new UDP header with source and destination ports
		/// @param[in] portSrc Source UDP port address
		/// @param[in] portDst Destination UDP port
		UdpLayer(uint16_t portSrc, uint16_t portDst);

		/// Get a pointer to the UDP header. Notice this points directly to the data, so every change will change the
		/// actual packet data
		/// @return A pointer to the @ref udphdr
		udphdr* getUdpHeader() const
		{
			return reinterpret_cast<udphdr*>(m_Data);
		}

		/// @return UDP source port
		uint16_t getSrcPort() const;

		/// @return UDP destination port
		uint16_t getDstPort() const;

		/// Calculate the checksum from header and data and possibly write the result to @ref udphdr#headerChecksum
		/// @param[in] writeResultToPacket If set to true then checksum result will be written to @ref
		/// udphdr#headerChecksum
		/// @return The checksum result
		uint16_t calculateChecksum(bool writeResultToPacket);

		/// A static method that validates the input data
		/// @param[in] data The pointer to the beginning of a byte stream of an UDP packet
		/// @param[in] dataLen The length of the byte stream
		/// @return True if the data is valid and can represent a UDP packet
		static inline bool isDataValid(const uint8_t* data, size_t dataLen);

		// implement abstract methods

		/// Currently identifies the following next layers: DnsLayer, DhcpLayer, VxlanLayer, SipRequestLayer,
		/// SipResponseLayer, RadiusLayer. Otherwise sets PayloadLayer
		void parseNextLayer() override;

		/// @return Size of @ref udphdr
		size_t getHeaderLen() const override
		{
			return sizeof(udphdr);
		}

		/// Calculate @ref udphdr#headerChecksum field
		void computeCalculateFields() override;

		std::string toString() const override;

		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelTransportLayer;
		}
	};

	bool UdpLayer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		return data && dataLen >= sizeof(udphdr);
	}
}  // namespace pcpp
