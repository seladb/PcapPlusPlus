#pragma once

#include "EthLayer.h"
#include "Layer.h"

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	/// @struct cotphdr
	/// Represents a COTP protocol header
#pragma pack(push, 1)
	struct cotphdr
	{
		/// length
		uint8_t length;
		/// PDU type identifier
		uint8_t pduType;
		/// TPDU number sequence
		uint8_t tpduNumber;
	};
#pragma pack(pop)
	static_assert(sizeof(cotphdr) == 3, "cotphdr size is not 3 bytes");

	/// @class CotpLayer
	/// Represents a COTP (Connection Oriented Transport Protocol)
	class CotpLayer : public Layer
	{
	public:
		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data (will be casted to @ref cotphdr)
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		CotpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, COTP)
		{}

		/// A constructor that allocates a new COTP header
		/// @param[in] tpduNumber Protocol TPDU number
		explicit CotpLayer(uint8_t tpduNumber);

		~CotpLayer() override = default;

		/// @return COTP length
		uint8_t getLength() const;

		/// @return COTP PDU type
		uint8_t getPduType() const;

		/// @return COTP TPDU number
		uint8_t getTpduNumber() const;

		/// @return Size of @ref cotphdr
		size_t getHeaderLen() const override
		{
			return sizeof(cotphdr);
		}

		/// Set the value of the length
		/// @param[in] length The value of the length
		void setLength(uint8_t length) const;

		/// Set the value of the version
		/// @param[in] pduType The number of the PDU type
		void setPduType(uint8_t pduType) const;

		/// Set the value of the version
		/// @param[in] tpduNumber The value of the TPDU number
		void setTpduNumber(uint8_t tpduNumber) const;

		/// Does nothing for this layer
		void computeCalculateFields() override
		{}

		/// Currently parses the rest of the packet as a S7COMM or generic payload (PayloadLayer)
		void parseNextLayer() override;

		/// A static method that takes a byte array and detects whether it is a COTP
		/// @param[in] data A byte array
		/// @param[in] dataSize The byte array size (in bytes)
		/// @return True if the data looks like a valid COTP layer
		static bool isDataValid(const uint8_t* data, size_t dataSize);

		std::string toString() const override;

		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelTransportLayer;
		}

		/// @struct SerializedFields
		/// Fields written by CotpLayer's serializeLayer(), in addition to
		/// Layer::SerializedFields.
		struct SerializedFields : Layer::SerializedFields
		{
			/// @return All field descriptors for CotpLayer
			static std::vector<FieldDescriptor> all()
			{
				auto result = Layer::SerializedFields::all();
				std::initializer_list<FieldDescriptor> extra{ PduType, TpduNumber };
				std::copy(extra.begin(), extra.end(), std::back_inserter(result));
				return result;
			}

			/// @brief Field descriptor for the COTP PDU type, written as a number.
			static const FieldDescriptor PduType;

			/// @brief Field descriptor for the COTP TPDU number, written as a number.
			static const FieldDescriptor TpduNumber;
		};

	protected:
		void serializeLayer(ObjectScope& serializer) const override;

	private:
		cotphdr* getCotpHeader() const
		{
			return reinterpret_cast<cotphdr*>(m_Data);
		}
	};

}  // namespace pcpp
