#pragma once

#include "EthLayer.h"
#include "Layer.h"

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	/// @struct tpkthdr
	/// Represents a TPKT protocol header
#pragma pack(push, 1)
	struct tpkthdr
	{
		/// message version
		uint8_t version;
		/// message reserved
		uint8_t reserved;
		/// message length
		uint16_t length;
	};
#pragma pack(pop)
	static_assert(sizeof(tpkthdr) == 4, "tpkthdr size is not 4 bytes");

	/// @class TpktLayer
	/// Represents a TPKT (Transport Service on top of the TCP) protocol layer
	class TpktLayer : public Layer
	{
	public:
		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data (will be casted to @ref tpkthdr)
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		TpktLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, TPKT)
		{}

		/// A constructor that allocates a new TPKT header
		/// @param[in] version Protocol version number
		/// @param[in] length Packet length
		TpktLayer(uint8_t version, uint16_t length);

		~TpktLayer() override = default;

		/// @return TPKT reserved
		uint8_t getReserved() const;

		/// @return TPKT version
		uint8_t getVersion() const;

		/// @return TPKT length
		uint16_t getLength() const;

		/// Set the value of the version
		/// @param[in] version The value of the version
		void setVersion(uint8_t version) const;

		/// Set the value of the length
		/// @param[in] length The value of the length
		void setLength(uint16_t length) const;

		/// @return Size of @ref tpkthdr
		size_t getHeaderLen() const override
		{
			return sizeof(tpkthdr);
		}

		/// Does nothing for this layer
		void computeCalculateFields() override
		{}

		/// Currently parses the rest of the packet as a COTP protocol or generic payload (PayloadLayer)
		void parseNextLayer() override;

		/// A static method that checks whether a source or dest port match those associated with the TPKT protocol
		/// @param[in] portSrc Source port number to check
		/// @param[in] portDst Dest port number to check
		/// @return True if the source or dest port match those associated with the TPKT protocol
		static bool isTpktPort(uint16_t portSrc, uint16_t portDst)
		{
			return portSrc == 102 || portDst == 102;
		}

		/// A static method that takes a byte array and detects whether it is a TPKT message
		/// @param[in] data A byte array
		/// @param[in] dataSize The byte array size (in bytes)
		/// @return True if the data size is greater or equal than the size of tpkthdr
		static bool isDataValid(const uint8_t* data, size_t dataSize)
		{
			return canReinterpretAs<tpkthdr>(data, dataSize);
		}

		std::string toString() const override;

		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelTransportLayer;
		}

	private:
		/// Get a pointer to the TPKT header. Data can be retrieved through the
		/// other methods of this layer. Notice the return value points directly to the data, so every change will
		/// change the actual packet data
		/// @return A pointer to the @ref tpkthdr
		tpkthdr* getTpktHeader() const
		{
			return reinterpret_cast<tpkthdr*>(m_Data);
		}
	};

}  // namespace pcpp
