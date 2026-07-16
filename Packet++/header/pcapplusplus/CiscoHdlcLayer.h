#pragma once

#include "Layer.h"

namespace pcpp
{
	/// @class CiscoHdlcLayer
	/// Represents a Cisco HDLC protocol layer
	class CiscoHdlcLayer : public Layer
	{
	public:
		/// @enum AddressType
		/// Represents Cisco HDLC address types
		enum class AddressType
		{
			/// Unicast
			Unicast = 0x0f,
			/// Multicast
			Multicast = 0x8f,
			/// Unknown address type
			Unknown
		};

		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] packet A pointer to the Packet instance where layer will be stored
		CiscoHdlcLayer(uint8_t* data, size_t dataLen, Packet* packet) : Layer(data, dataLen, nullptr, packet, CiscoHDLC)
		{}

		/// A constructor that creates a new Cisco HDLC layer
		/// @param[in] address The address field value
		explicit CiscoHdlcLayer(AddressType address);

		/// Default destructor for this layer
		~CiscoHdlcLayer() override = default;

		/// @return The address field enum value
		AddressType getAddress() const;

		/// @return The address field raw value
		uint8_t getAddressValue() const;

		/// Set the address field enum value
		/// @param[in] address The address enum value to set
		void setAddress(AddressType address);

		/// Set the address field value
		/// @param[in] address The address value to set
		void setAddressValue(uint8_t address);

		/// @return The protocol type value
		uint16_t getNextProtocol() const;

		/// A static method that validates the input data
		/// @param[in] data The pointer to the beginning of a byte stream of a Cisco HDLC packet
		/// @param[in] dataLen The length of the byte stream
		/// @return True if the data is valid and can represent a Cisco HDLC packet
		static bool isDataValid(const uint8_t* data, size_t dataLen)
		{
			return data && dataLen >= sizeof(cisco_hdlc_header);
		}

		// Overridden methods

		/// @return The size of the HDLC header which is 4 bytes
		size_t getHeaderLen() const override
		{
			return sizeof(cisco_hdlc_header);
		}

		/// Calculate the Next Protocol when possible
		void computeCalculateFields() override;

		/// Parses the next layer. Currently, supports IPv4 and IPv6
		void parseNextLayer() override;

		std::string toString() const override;

		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelDataLinkLayer;
		}

	private:
#pragma pack(push, 1)
		struct cisco_hdlc_header
		{
			uint8_t address;
			uint8_t control;
			uint16_t protocol;
		};
#pragma pack(pop)
		static_assert(sizeof(cisco_hdlc_header) == 4, "cisco_hdlc_header size is not 4 bytes");

		cisco_hdlc_header* getCiscoHdlcHeader() const
		{
			return reinterpret_cast<cisco_hdlc_header*>(m_Data);
		}

		void setNextProtocol(uint16_t protocol);
	};

}  // namespace pcpp
