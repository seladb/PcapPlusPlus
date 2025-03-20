#pragma once

#include "IpAddress.h"
#include "Layer.h"
#include "MacAddress.h"

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	/// Class for representing the Wake on LAN Layer
	class WakeOnLanLayer : public Layer
	{
	private:
		void init(uint16_t len);

	public:
		/// @struct wol_header
		/// Wake On LAN protocol header
#pragma pack(push, 1)
		struct wol_header
		{
			/// Sync stream (FF FF FF FF FF FF)
			uint8_t sync[6];
			/// Target MAC address repeated 16 times
			uint8_t addrBody[6 * 16];
		};
#pragma pack(pop)
		static_assert(sizeof(wol_header) == 102, "wol_header size is not 102 bytes");

		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		WakeOnLanLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, WakeOnLan)
		{}

		/// Construct a new Wake On Lan Layer with provided values
		/// @param[in] targetAddr Target MAC address
		explicit WakeOnLanLayer(const pcpp::MacAddress& targetAddr);

		/// Construct a new Wake On Lan Layer with provided values
		/// @param[in] targetAddr Target MAC address
		/// @param[in] password Password as array
		/// @param[in] len Length of the password array, length of the password should be less than 6 bytes
		WakeOnLanLayer(const pcpp::MacAddress& targetAddr, uint8_t* password, uint8_t len);

		/// Construct a new Wake On Lan Layer with provided values
		/// @param[in] targetAddr Target MAC address
		/// @param[in] password Password as MAC address
		WakeOnLanLayer(const pcpp::MacAddress& targetAddr, const pcpp::MacAddress& password);

		/// Construct a new Wake On Lan Layer with provided values
		/// @param[in] targetAddr Target MAC address
		/// @param[in] password Password as IPv4 address
		WakeOnLanLayer(const pcpp::MacAddress& targetAddr, const IPv4Address& password);

		/// Get a pointer to the Wake On LAN header. Notice this points directly to the data, so every change will
		/// change the actual packet data
		/// @return A pointer to the wol_header
		inline wol_header* getWakeOnLanHeader() const
		{
			return reinterpret_cast<wol_header*>(m_Data);
		}

		/// Get the target MAC address of the command
		/// @return MAC address of the target
		pcpp::MacAddress getTargetAddr() const;

		/// Set the target MAC address
		/// @param[in] targetAddr MAC address of the target
		void setTargetAddr(const pcpp::MacAddress& targetAddr);

		/// Get the password of the command
		/// @return Returns the password if exists, empty string otherwise
		std::string getPassword() const;

		/// Set the password of the command
		/// @param[in] password Password as array
		/// @param[in] len Length of the password array, length of the password should be less than 6 bytes
		/// @return True if operation successful, false otherwise
		bool setPassword(const uint8_t* password, uint8_t len);

		/// Set the password of the command
		/// @param[in] password Password as string. Length of the password should be less than 6 bytes
		/// @return True if operation successful, false otherwise
		bool setPassword(const std::string& password);

		/// Set the password of the command
		/// @param[in] addr Password as MAC address
		/// @return True if operation successful, false otherwise
		bool setPassword(const MacAddress& addr);

		/// Set the password of the command
		/// @param addr Password as IPv4 address
		/// @return True if operation successful, false otherwise
		bool setPassword(const IPv4Address& addr);

		/// A static method that checks whether the port is considered as Wake on LAN
		/// @param[in] port The port number to be checked
		static bool isWakeOnLanPort(uint16_t port)
		{
			return (port == 0) || (port == 7) || (port == 9);
		}

		/// A static method that takes a byte array and detects whether it is a Wake on LAN message
		/// @param[in] data A byte array
		/// @param[in] dataSize The byte array size (in bytes)
		/// @return True if the data is identified as Wake on LAN message
		static bool isDataValid(const uint8_t* data, size_t dataSize);

		// overridden methods

		/// Parses the next layer. Wake on LAN is the always last so does nothing for this layer
		void parseNextLayer() override
		{}

		/// @return Get the size of the layer
		size_t getHeaderLen() const override
		{
			return m_DataLen;
		}

		/// Does nothing for this layer
		void computeCalculateFields() override
		{}

		/// @return The OSI layer level of Wake on LAN (Data Link Layer)
		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelDataLinkLayer;
		}

		/// @return Returns the protocol info as readable string
		std::string toString() const override;
	};
}  // namespace pcpp
