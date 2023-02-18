#ifndef PACKETPP_NFLOG_LAYER
#define PACKETPP_NFLOG_LAYER

#include "Layer.h"
#include "TLVData.h"
#include "GeneralUtils.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/** IPv4 protocol */
	#define PCPP_WS_NFPROTO_IPV4		2
	/** IPv6 protocol */
	#define PCPP_WS_NFPROTO_IPV6		10

	/**
	 * @struct nflog_header
	 * Represents Nflog header
	 */
#pragma pack(push, 1)
	struct nflog_header
	{
		uint8_t addressFamily;
		uint8_t version;
		uint16_t resourceId;
	};
#pragma pack(pop)

	/**
	 * @struct nflog_tlv
	 * Represents Nflog tlv structure
	 */
#pragma pack(push, 1)
	struct nflog_tlv
	{
		/** tlv length */
		uint16_t tlvLength;

		/** tlv type */
		uint16_t tlvType;
	};
#pragma pack(pop)

	/**
	 * @struct nflog_packet_header
	 * represents data of the first tlv by tlv type 1
	*/
#pragma pack(push, 1)
	struct nflog_packet_header
	{
		/** e.g. ipv4, unknown, etc */
		uint16_t hardwareProtocol;

		/** local-in, local-out, post-routing, etc */
		uint8_t netfilterHook;

		/** one byte padding */
		uint8_t padding;
	};

	/**
	 * @enum NflogTlvType
	 * Represents TLV types of NFLOG packets
	*/
#pragma pack(pop)

	enum class NflogTlvType
	{
		/** the packet header structure */
		NFULA_PACKET_HDR			= 1,
		/** packet mark from skbuff */
		NFULA_MARK					= 2,
		/** nflog_timestamp_t for skbuff's time stamp */
 		NFULA_TIMESTAMP				= 3,
		/** ifindex of device on which packet received (possibly bridge group) */
 		NFULA_IFINDEX_INDEV			= 4,
		/** ifindex of device on which packet transmitted (possibly bridge group) */
 		NFULA_IFINDEX_OUTDEV		= 5,
		/** ifindex of physical device on which packet received (not bridge group) */
 		NFULA_IFINDEX_PHYSINDEV		= 6,
		/** ifindex of physical device on which packet transmitted (not bridge group) */
 		NFULA_IFINDEX_PHYSOUTDEV	= 7,
		/** nflog_hwaddr_t for hardware address */
 		NFULA_HWADDR				= 8,
		/** packet payload */
 		NFULA_PAYLOAD				= 9,
		/** text string - null-terminated, count includes NUL */
 		NFULA_PREFIX				= 10,
		/** UID owning socket on which packet was sent/received */
 		NFULA_UID					= 11,
		/** sequence number of packets on this NFLOG socket */
 		NFULA_SEQ					= 12,
		/** sequence number of pakets on all NFLOG sockets */
 		NFULA_SEQ_GLOBAL			= 13,
		/** GID owning socket on which packet was sent/received */
 		NFULA_GID					= 14,
		/** ARPHRD_ type of skbuff's device */
 		NFULA_HWTYPE				= 15,
		/** skbuff's MAC-layer header */
 		NFULA_HWHEADER				= 16,
		/** length of skbuff's MAC-layer header */
 		NFULA_HWLEN					= 17,
	};

	/**
	 * @class NflogTlv
	 * A wrapper class for NFLOG TLV fields. This class does not create or modify TLVs related to NFLOG, but rather
	 * serves as a wrapper and provides useful methods for setting and retrieving data to/from them
	 */
	class NflogTlv
	{
	private:
		struct NflogTLVRawData
		{
			/** Record length in bytes */
			uint16_t recordLen;
			/** Record type */
			uint16_t recordType;
			/** Record value (variable size) */
			uint8_t recordValue[];
		};
		NflogTLVRawData* m_Data;
	public:
		/**
		 * A c'tor for this class that gets a pointer to the option raw data (byte array)
		 * @param[in] recordRawData A pointer to the option raw data
		 */
		explicit NflogTlv(uint8_t* recordRawData)
		{
			assign(recordRawData);
		}

		/**
		 * @return recordLen attribute in NflogTLVRawData
		 */
		size_t getTotalSize() const { return m_Data->recordLen; }

		/**
		 * Assign a pointer to the TLV record raw data (byte array)
		 * @param[in] recordRawData A pointer to the TLV record raw data
		 */
		void assign(uint8_t* recordRawData)
		{
			if(recordRawData == nullptr)
				m_Data = nullptr;
			else
			{
				// to pass from some unknown paddings after tlv with type NFULA_PREFIX
				while (*recordRawData == 0)
					recordRawData += 1;
				m_Data = (NflogTLVRawData*)recordRawData;
			}
		}

		/**
		 * @return True if the TLV record raw data is nullptr, false otherwise
		 */
		bool isNull() const
		{
			return (m_Data == nullptr);
		}

		/**
		 * @return The type field of the record (the 'T' in __Type__-Length-Value)
		 */
		uint16_t getType() const { return m_Data->recordType; }

		/**
		 * @return A pointer to the TLV record raw data byte stream
		 */
		uint8_t* getRecordBasePtr() const { return (uint8_t*)m_Data; }

		/**
		 * @return A pointer to the value of the record as byte array (the 'V' in Type-Length- __Value__)
		 */
		uint8_t* getValue() const { return m_Data->recordValue; }
	};

	/**
	 * @class NflogLayer
	 * Represents an NFLOG protocol layer
	 */
	class NflogLayer : public Layer
	{
	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to ether_header)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		NflogLayer(uint8_t* data, size_t dataLen, Packet* packet) : Layer(data, dataLen, NULL, packet) { m_Protocol = NFLOG; }

		~NflogLayer() {}

		/**
		 * Get a pointer to the Nflog header.
		 * @return A pointer to the nflog_header
		 */
		nflog_header* getNflogHeader() const { return (nflog_header*)m_Data; }

		/**
		 * Get address family of the packet. e.g. 2 for ipv4 and 10 for ipv6
		 * @return an unsigned char of address family
		*/
		uint8_t getFamily();

		/**
		 * Get Version number inside packet header
		 * The version field is 0 for the current version of the pseudo-header
		 * @return an unsigned char for version
		*/
		uint8_t getVersion();

		/**
		 * Get Resource Id in packet header
		 * On one netlink socket it's possible to listen to several nflog groups; the resource ID is the nflog group for the packet
		*/
		uint16_t getResourceId();

		/**
		 * returns a pair of pointer to tlv data and the length of the tlv
		 * @param[in] type type of tlv by using enum class defined as NflogTlvType
		 * @return NflogTlv obtained by type
		*/
		NflogTlv getTlvByType(NflogTlvType type) const;

		// implement abstract methods

		/**
		 * Currently identifies the following next layers: IPv4Layer, IPv6Layer using address family
		 * Otherwise sets PayloadLayer
		 */
		void parseNextLayer();

		/**
		 * @return Size of nflog_header
		 */
		size_t getHeaderLen() const;

		/**
		 * nothing to do for now
		*/
		void computeCalculateFields() {};

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const { return OsiModelDataLinkLayer; }

	private:
		uint8_t* getTlvsBasePtr() const { return m_Data + sizeof(nflog_header); }

		TLVRecordReader<NflogTlv> m_TlvReader;
	};

} // namespace pcpp

#endif /* PACKETPP_NFLOG_LAYER */
