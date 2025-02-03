#pragma once

#include "Layer.h"

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	/// @class PacketTrailerLayer
	/// A class for representing packet trailer (a.k.a footer or padding) which refers to supplemental data placed at
	/// the end of a block of data being stored or transmitted, which may contain information for the handling of the
	/// data block, or just mark its end (taken from Wikipedia: https://en.wikipedia.org/wiki/Trailer_(computing) )
	///
	/// There are various reasons for adding a packet trailer, one of the most famous is FCS (Frame check sequence)
	/// which refers to the extra error-detecting code added to a frame. Another usage is padding which means adding
	/// data to reach a minimum required packet length.
	///
	/// Although this layer inherits from the Layer class, it is not a standard layer in the sense that it can't be
	/// constructed by the user. This layer may be only be constructed in the Packet class, in the process of parsing
	/// the packet and creating the layers; if at the end of the parsing process there is data left that is not
	/// allocated to any layer, it's assumed to be the packet trailer and an instance of this class is created. This
	/// means this layer can only exist as the last layer in a packet, if a packet trailer indeed exists.
	///
	/// No layer can be added by the user after this layer (trying to do that will result with an error).
	///
	/// This layer can be removed by the user or extended/shortened, as any layer.
	///
	/// It also contains method to extract the trailer data
	class PacketTrailerLayer : public Layer
	{
	public:
		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		PacketTrailerLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, PacketTrailer)
		{}

		~PacketTrailerLayer() override = default;

		/// Get a pointer to the trailer data
		/// @return A pointer to the trailer data
		uint8_t* getTrailerData() const
		{
			return m_Data;
		}

		/// @return Trailer data as hex string
		std::string getTrailerDataAsHexString() const;

		/// Get the trailer data length
		/// @return The trailer data length in bytes
		size_t getTrailerLen() const
		{
			return m_DataLen;
		}

		// implement abstract methods

		/// Does nothing for this layer (PacketTrailerLayer is always last)
		void parseNextLayer() override
		{}

		/// @return trailer data length in bytes
		size_t getHeaderLen() const override
		{
			return m_DataLen;
		}

		/// Does nothing for this layer
		void computeCalculateFields() override
		{}

		std::string toString() const override;

		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelDataLinkLayer;
		}
	};

}  // namespace pcpp
