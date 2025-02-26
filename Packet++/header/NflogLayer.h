#pragma once

#include "Layer.h"
#include "TLVData.h"
#include "GeneralUtils.h"

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	/// @struct nflog_header
	/// Represents Nflog header
#pragma pack(push, 1)
	struct nflog_header
	{
		/// A Linux AF_ value, so it's 2 for IPv4 and 10 for IPv6
		uint8_t addressFamily;
		/// The version field is 0 for the current version of the pseudo-header
		uint8_t version;
		/// The network byte order (big-endian)
		uint16_t resourceId;
	};
#pragma pack(pop)
	static_assert(sizeof(nflog_header) == 4, "nflog_header size is not 4 bytes");

	/// @enum NflogTlvType
	/// Represents TLV types of NFLOG packets
	enum class NflogTlvType
	{
		/// the packet header structure
		NFULA_PACKET_HDR = 1,
		/// packet mark from skbuff
		NFULA_MARK = 2,
		/// nflog_timestamp_t for skbuff's time stamp
		NFULA_TIMESTAMP = 3,
		/// ifindex of device on which packet received (possibly bridge group)
		NFULA_IFINDEX_INDEV = 4,
		/// ifindex of device on which packet transmitted (possibly bridge group)
		NFULA_IFINDEX_OUTDEV = 5,
		/// ifindex of physical device on which packet received (not bridge group)
		NFULA_IFINDEX_PHYSINDEV = 6,
		/// ifindex of physical device on which packet transmitted (not bridge group)
		NFULA_IFINDEX_PHYSOUTDEV = 7,
		/// nflog_hwaddr_t for hardware address
		NFULA_HWADDR = 8,
		/// packet payload
		NFULA_PAYLOAD = 9,
		/// text string - null-terminated, count includes NUL
		NFULA_PREFIX = 10,
		/// UID owning socket on which packet was sent/received
		NFULA_UID = 11,
		/// sequence number of packets on this NFLOG socket
		NFULA_SEQ = 12,
		/// sequence number of packets on all NFLOG sockets
		NFULA_SEQ_GLOBAL = 13,
		/// GID owning socket on which packet was sent/received
		NFULA_GID = 14,
		/// ARPHRD_ type of skbuff's device
		NFULA_HWTYPE = 15,
		/// skbuff's MAC-layer header
		NFULA_HWHEADER = 16,
		/// length of skbuff's MAC-layer header
		NFULA_HWLEN = 17,
	};

	/// @class NflogTlv
	/// A wrapper class for NFLOG TLV fields. This class does not create or modify TLVs related to NFLOG, but rather
	/// serves as a wrapper and provides useful methods for setting and retrieving data to/from them
	class NflogTlv
	{
	private:
		struct NflogTLVRawData
		{
			/// Record length in bytes
			uint16_t recordLen;
			/// Record type
			uint16_t recordType;
			/// Record value (variable size)
			uint8_t recordValue[];
		};
		NflogTLVRawData* m_Data;

	public:
		/// A c'tor for this class that gets a pointer to the option raw data (byte array)
		/// @param[in] recordRawData A pointer to the option raw data
		explicit NflogTlv(uint8_t* recordRawData)
		{
			assign(recordRawData);
		}

		/// @return recordLen attribute in NflogTLVRawData
		size_t getTotalSize() const
		{
			// as in
			// https://github.com/the-tcpdump-group/libpcap/blob/766b607d60d8038087b49fc4cf433dac3dcdb49c/pcap-util.c#L371-L374
			return align<4>(m_Data->recordLen);
		}

		/// Assign a pointer to the TLV record raw data (byte array)
		/// @param[in] recordRawData A pointer to the TLV record raw data
		void assign(uint8_t* recordRawData)
		{
			m_Data = reinterpret_cast<NflogTLVRawData*>(recordRawData);
		}

		/// Check if a pointer can be assigned to the TLV record data
		/// @param[in] recordRawData A pointer to the TLV record raw data
		/// @param[in] tlvDataLen The size of the TLV record raw data
		/// * @return True if data is valid and can be assigned
		static bool canAssign(const uint8_t* recordRawData, size_t tlvDataLen)
		{
			return recordRawData != nullptr && tlvDataLen >= sizeof(NflogTLVRawData::recordLen);
		}

		/// @return True if the TLV record raw data is nullptr, false otherwise
		bool isNull() const
		{
			return (m_Data == nullptr);
		}

		/// @return The type field of the record (the 'T' in __Type__-Length-Value)
		uint16_t getType() const
		{
			return m_Data->recordType;
		}

		/// @return A pointer to the TLV record raw data byte stream
		uint8_t* getRecordBasePtr() const
		{
			return reinterpret_cast<uint8_t*>(m_Data);
		}

		/// @return A pointer to the value of the record as byte array (the 'V' in Type-Length- __Value__)
		uint8_t* getValue() const
		{
			return m_Data->recordValue;
		}
	};

	/// @class NflogLayer
	/// Represents an NFLOG protocol layer
	class NflogLayer : public Layer
	{
	public:
		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data (will be casted to ether_header)
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		NflogLayer(uint8_t* data, size_t dataLen, Packet* packet) : Layer(data, dataLen, nullptr, packet, NFLOG)
		{}

		~NflogLayer() override = default;

		/// Get a pointer to the Nflog header.
		/// @return A pointer to the nflog_header
		nflog_header* getNflogHeader() const
		{
			return reinterpret_cast<nflog_header*>(m_Data);
		}

		/// Get address family of the packet. e.g. 2 for ipv4 and 10 for ipv6
		/// @return an unsigned char of address family
		uint8_t getFamily();

		/// Get Version number inside packet header
		/// The version field is 0 for the current version of the pseudo-header
		/// @return an unsigned char for version
		uint8_t getVersion();

		/// Get Resource Id in packet header
		/// On one netlink socket it's possible to listen to several nflog groups; the resource ID is the nflog group
		/// for the packet
		uint16_t getResourceId();

		/// Get a TLV object found with the input type. if no tlv is found, the internal value of the object will set to
		/// nullptr
		/// @param[in] type type of tlv by using enum class defined as NflogTlvType
		/// @return NflogTlv obtained by type
		NflogTlv getTlvByType(NflogTlvType type) const;

		// implement abstract methods

		/// Currently identifies the following next layers: IPv4Layer, IPv6Layer using address family
		/// Otherwise sets PayloadLayer
		void parseNextLayer() override;

		/// @return Size of nflog_header
		size_t getHeaderLen() const override;

		/// Does nothing for this layer
		void computeCalculateFields() override {};

		std::string toString() const override;

		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelDataLinkLayer;
		}

		/// A static method that validates the input data
		/// @param[in] data The pointer to the beginning of a byte stream of an NFLOG packet
		/// @param[in] dataLen The length of the byte stream
		/// @return True if the data is valid and can represent an NFLOG packet
		static bool isDataValid(const uint8_t* data, size_t dataLen);

	private:
		uint8_t* getTlvsBasePtr() const
		{
			return m_Data + sizeof(nflog_header);
		}

		TLVRecordReader<NflogTlv> m_TlvReader;
	};

}  // namespace pcpp
