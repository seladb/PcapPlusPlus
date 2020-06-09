#ifndef PACKETPP_IPV4_LAYER
#define PACKETPP_IPV4_LAYER

#include "Layer.h"
#include "TLVData.h"
#include "IpAddress.h"
#include <string.h>
#include <vector>

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * @struct iphdr
	 * Represents an IPv4 protocol header
	 */
#pragma pack(push, 1)
	struct iphdr {
#if (BYTE_ORDER == LITTLE_ENDIAN)
		/** IP header length, has the value of 5 for IPv4 */
		uint8_t internetHeaderLength:4,
		/** IP version number, has the value of 4 for IPv4 */
		ipVersion:4;
#else
		/** IP version number, has the value of 4 for IPv4 */
		uint8_t ipVersion:4,
		/** IP header length, has the value of 5 for IPv4 */
		internetHeaderLength:4;
#endif
		/** type of service, same as Differentiated Services Code Point (DSCP)*/
		uint8_t typeOfService;
		/** Entire packet (fragment) size, including header and data, in bytes */
		uint16_t totalLength;
		/** Identification field. Primarily used for uniquely identifying the group of fragments of a single IP datagram*/
		uint16_t ipId;
		 /** Fragment offset field, measured in units of eight-byte blocks (64 bits) */
		uint16_t fragmentOffset;
		/** An eight-bit time to live field helps prevent datagrams from persisting (e.g. going in circles) on an internet.  In practice, the field has become a hop count */
		uint8_t timeToLive;
		/** Defines the protocol used in the data portion of the IP datagram. Must be one of ::IPProtocolTypes */
		uint8_t protocol;
		/** Error-checking of the header */
		uint16_t headerChecksum;
		/** IPv4 address of the sender of the packet */
		uint32_t ipSrc;
		/** IPv4 address of the receiver of the packet */
		uint32_t ipDst;
		/*The options start here. */
	};
#pragma pack(pop)

	/**
	 * An enum for all possible IPv4 and IPv6 protocol types
	 */
	enum IPProtocolTypes
	{
		/** Dummy protocol for TCP		*/
		PACKETPP_IPPROTO_IP = 0,
		/** IPv6 Hop-by-Hop options		*/
		PACKETPP_IPPROTO_HOPOPTS = 0,
		/** Internet Control Message Protocol	*/
		PACKETPP_IPPROTO_ICMP = 1,
		/** Internet Gateway Management Protocol */
		PACKETPP_IPPROTO_IGMP = 2,
		/** IPIP tunnels (older KA9Q tunnels use 94) */
		PACKETPP_IPPROTO_IPIP = 4,
		/** Transmission Control Protocol	*/
		PACKETPP_IPPROTO_TCP = 6,
		/** Exterior Gateway Protocol		*/
		PACKETPP_IPPROTO_EGP = 8,
		/** PUP protocol				*/
		PACKETPP_IPPROTO_PUP = 12,
		/** User Datagram Protocol		*/
		PACKETPP_IPPROTO_UDP = 17,
		/** XNS IDP protocol			*/
		PACKETPP_IPPROTO_IDP = 22,
		/** IPv6 header				*/
		PACKETPP_IPPROTO_IPV6 = 41,
		/** IPv6 Routing header			*/
		PACKETPP_IPPROTO_ROUTING = 43,
		/** IPv6 fragmentation header		*/
		PACKETPP_IPPROTO_FRAGMENT = 44,
		/** GRE protocol */
		PACKETPP_IPPROTO_GRE = 47,
		/** encapsulating security payload	*/
		PACKETPP_IPPROTO_ESP = 50,
		/** authentication header		*/
		PACKETPP_IPPROTO_AH = 51,
		/** ICMPv6				*/
		PACKETPP_IPPROTO_ICMPV6 = 58,
		/** IPv6 no next header			*/
		PACKETPP_IPPROTO_NONE = 59,
		/** IPv6 Destination options		*/
		PACKETPP_IPPROTO_DSTOPTS = 60,
		/** Raw IP packets			*/
		PACKETPP_IPPROTO_RAW = 255,
		/** Maximum value */
		PACKETPP_IPPROTO_MAX
	};


	/**
	 * An enum for supported IPv4 option types
	 */
	enum IPv4OptionTypes
	{
		/** End of Options List */
		IPV4OPT_EndOfOptionsList = 0,
		/** No Operation */
		IPV4OPT_NOP = 1,
		/** Record Route */
		IPV4OPT_RecordRoute = 7,
		/** MTU Probe */
		IPV4OPT_MTUProbe = 11,
		/** MTU Reply */
		IPV4OPT_MTUReply = 12,
		/** Quick-Start */
		IPV4OPT_QuickStart = 25,
		/** Timestamp */
		IPV4OPT_Timestamp = 68,
		/** Traceroute */
		IPV4OPT_Traceroute = 82,
		/** Security */
		IPV4OPT_Security = 130,
		/** Loose Source Route */
		IPV4OPT_LooseSourceRoute = 131,
		/** Extended Security */
		IPV4OPT_ExtendedSecurity = 133,
		/** Commercial Security */
		IPV4OPT_CommercialSecurity = 134,
		/** Stream ID */
		IPV4OPT_StreamID = 136,
		/** Strict Source Route */
		IPV4OPT_StrictSourceRoute = 137,
		/** Extended Internet Protocol */
		IPV4OPT_ExtendedInternetProtocol = 145,
		/** Address Extension */
		IPV4OPT_AddressExtension = 147,
		/** Router Alert */
		IPV4OPT_RouterAlert = 148,
		/** Selective Directed Broadcast */
		IPV4OPT_SelectiveDirectedBroadcast = 149,
		/** Dynamic Packet State */
		IPV4OPT_DynamicPacketState = 151,
		/** Upstream Multicast Pkt. */
		IPV4OPT_UpstreamMulticastPkt = 152,
		/** Unknown IPv4 option */
		IPV4OPT_Unknown
	};

#define PCPP_IP_DONT_FRAGMENT  0x40
#define PCPP_IP_MORE_FRAGMENTS 0x20

	/**
	 * @struct IPv4TimestampOptionValue
	 * A struct representing a parsed value of the IPv4 timestamp option. This struct is used returned in IPv4OptionData#getTimestampOptionValue() method
	 */
	struct IPv4TimestampOptionValue
	{
		/**
		 * An enum for IPv4 timestamp option types
		 */
		enum TimestampType
		{
			/** Value containing only timestamps */
			TimestampOnly = 0,
			/** Value containing both timestamps and IPv4 addresses */
			TimestampAndIP = 1,
			/** The IPv4 addresses are prespecified */
			TimestampsForPrespecifiedIPs = 2,
			/** Invalid or unknown value type */
			Unknown = 3
		};

		/** The timestamp value type */
		TimestampType type;

		/** A list of timestamps parsed from the IPv4 timestamp option value */
		std::vector<uint32_t> timestamps;

		/** A list of IPv4 addresses parsed from the IPv4 timestamp option value */
		std::vector<IPv4Address> ipAddresses;

		/** The default constructor */
		IPv4TimestampOptionValue() : type(IPv4TimestampOptionValue::Unknown) {}

		/**
		 * Clear the structure. Clean the timestamps and IP addresses vectors and set the type as IPv4TimestampOptionValue#Unknown
		 */
		void clear()
		{
			type = IPv4TimestampOptionValue::Unknown;
			timestamps.clear();
			ipAddresses.clear();
		}
	};


	/**
	 * @class IPv4Option
	 * A wrapper class for IPv4 options. This class does not create or modify IPv4 option records, but rather
	 * serves as a wrapper and provides useful methods for retrieving data from them
	 */
	class IPv4Option : public TLVRecord
	{
	public:

		/**
		 * A c'tor for this class that gets a pointer to the option raw data (byte array)
		 * @param[in] optionRawData A pointer to the IPv4 option raw data
		 */
		IPv4Option(uint8_t* optionRawData) : TLVRecord(optionRawData) { }

		/**
		 * A d'tor for this class, currently does nothing
		 */
		~IPv4Option() { }

		/**
		 * A method for parsing the IPv4 option value as a list of IPv4 addresses. This method is relevant only for certain types of IPv4 options which their value is a list of IPv4 addresses
		 * such as ::IPV4OPT_RecordRoute, ::IPV4OPT_StrictSourceRoute, ::IPV4OPT_LooseSourceRoute, etc. This method returns a vector of the IPv4 addresses. Blank IP addresses
		 * (meaning zeroed addresses - 0.0.0.0) will not be added to the returned list. If some error occurs during the parsing or the value is invalid an empty vector is returned
		 * @return A vector of IPv4 addresses parsed from the IPv4 option value
		 */
		std::vector<IPv4Address> getValueAsIpList() const
		{
			std::vector<IPv4Address> res;

			if (m_Data == NULL)
				return res;

			size_t dataSize = getDataSize();
			if (dataSize < 2)
				return res;

			uint8_t valueOffset = (uint8_t)(1);

			while ((size_t)valueOffset < dataSize)
			{
				uint32_t curValue;
				memcpy(&curValue, m_Data->recordValue + valueOffset, sizeof(uint32_t));
				if (curValue == 0)
					break;

				res.push_back(IPv4Address(curValue));

				valueOffset += (uint8_t)(4);
			}

			return res;
		}

		/**
		 * A method for parsing the IPv4 timestamp option value. This method is relevant only for IPv4 timestamp option. For other option types an empty result will be returned.
		 * The returned structure contains the timestamp value type (timestamp only, timestamp + IP addresses, etc.) as well as 2 vectors containing the list of timestamps and the list
		 * of IP addresses (if applicable for the timestamp value type). Blank timestamps or IP addresses (meaning zeroed values - timestamp=0 or IP address=0.0.0.0) will not be added to
		 * the lists. If some error occurs during the parsing or the value is invalid an empty result is returned
		 * @return A structured containing the IPv4 timestamp value
		 */
		IPv4TimestampOptionValue getTimestampOptionValue() const
		{
			IPv4TimestampOptionValue res;
			res.clear();

			if (m_Data == NULL)
				return res;

			if (getIPv4OptionType() != IPV4OPT_Timestamp)
				return res;

			size_t dataSize =  getDataSize();
			if (dataSize < 2)
				return res;

			res.type = (IPv4TimestampOptionValue::TimestampType)m_Data->recordValue[1];

			uint8_t valueOffset = (uint8_t)(2);
			bool readIPAddr = (res.type == IPv4TimestampOptionValue::TimestampAndIP);

			while ((size_t)valueOffset < dataSize)
			{
				uint32_t curValue;
				memcpy(&curValue, m_Data->recordValue + valueOffset, sizeof(uint32_t));
				if (curValue == 0)
					break;

				if (readIPAddr)
					res.ipAddresses.push_back(IPv4Address(curValue));
				else
					res.timestamps.push_back(curValue);

				if (res.type == IPv4TimestampOptionValue::TimestampAndIP)
					readIPAddr = !readIPAddr;

				valueOffset += (uint8_t)(4);
			}

			return res;
		}

		/**
		 * @return IPv4 option type casted as pcpp::IPv4OptionTypes enum
		 */
		IPv4OptionTypes getIPv4OptionType() const
		{
			if (m_Data == NULL)
				return IPV4OPT_Unknown;

			return (IPv4OptionTypes)m_Data->recordType;
		}


		// implement abstract methods

		size_t getTotalSize() const
		{
			if (m_Data == NULL)
				return 0;

			if (getIPv4OptionType() == (uint8_t)IPV4OPT_EndOfOptionsList || m_Data->recordType == (uint8_t)IPV4OPT_NOP)
				return sizeof(uint8_t);

			return (size_t)m_Data->recordLen;
		}

		size_t getDataSize() const
		{
			if (m_Data == NULL)
				return 0;

			if (getIPv4OptionType() == (uint8_t)IPV4OPT_EndOfOptionsList || m_Data->recordType == (uint8_t)IPV4OPT_NOP)
				return (size_t)0;

			return (size_t)m_Data->recordLen - (2*sizeof(uint8_t));
		}
	};


	/**
	 * @class IPv4OptionBuilder
	 * A class for building IPv4 option records. This builder receives the IPv4 option parameters in its c'tor,
	 * builds the IPv4 option raw buffer and provides a build() method to get a IPv4Option object out of it
	 */
	class IPv4OptionBuilder : public TLVRecordBuilder
	{
	private:
		bool m_BuilderParamsValid;

	public:
		
		/**
		 * A c'tor for building IPv4 options which their value is a byte array. The IPv4Option object can be later
		 * retrieved by calling build()
		 * @param[in] optionType IPv4 option type
		 * @param[in] optionValue A buffer containing the option value. This buffer is read-only and isn't modified in any way.
		 * For option types ::IPV4OPT_NOP and ::IPV4OPT_EndOfOptionsList this parameter is ignored (expected to be NULL) as these
		 * option types don't contain any data
		 * @param[in] optionValueLen Option value length in bytes
		 */
		IPv4OptionBuilder(IPv4OptionTypes optionType, const uint8_t* optionValue, uint8_t optionValueLen) :
			TLVRecordBuilder((uint8_t)optionType, optionValue, optionValueLen) { m_BuilderParamsValid = true; }

		/**
		 * A c'tor for building IPv4 options which have a 2-byte value. The IPv4Option object can be later retrieved
		 * by calling build()
		 * @param[in] optionType IPv4 option type
		 * @param[in] optionValue A 2-byte option value
		 */
		IPv4OptionBuilder(IPv4OptionTypes optionType, uint16_t optionValue) :
			TLVRecordBuilder((uint8_t)optionType, optionValue) { m_BuilderParamsValid = true; }

		/**
		 * A c'tor for building IPv4 options which their value is a list of IPv4 addresses, for example: 
		 * ::IPV4OPT_RecordRoute, ::IPV4OPT_StrictSourceRoute, ::IPV4OPT_LooseSourceRoute. The IPv4Option object can be later retrieved
		 * by calling build()
		 * @param[in] optionType IPv4 option type
		 * @param[in] ipList A vector of IPv4 addresses that will be used as the option value
		 */
		IPv4OptionBuilder(IPv4OptionTypes optionType, const std::vector<IPv4Address>& ipList);

		/**
		 * A c'tor for building IPv4 timestamp option (::IPV4OPT_Timestamp). The IPv4Option object can be later retrieved by calling build()
		 * @param[in] timestampValue The timestamp value to build the IPv4 option with
		 */
		IPv4OptionBuilder(const IPv4TimestampOptionValue& timestampValue);

		/**
		 * Build the IPv4Option object out of the parameters defined in the c'tor
		 * @return The IPv4Option object
		 */
		IPv4Option build() const;
	};


	/**
	 * @class IPv4Layer
	 * Represents an IPv4 protocol layer
	 */
	class IPv4Layer : public Layer
	{
	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to @ref iphdr)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		IPv4Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to @ref iphdr)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 * @param[in] setTotalLenAsDataLen When setting this value to "true" or when using the other c'tor, the layer data length is calculated
		 * from iphdr#totalLength field. When setting to "false" the data length is set as the value of dataLen parameter. Please notice that
		 * if iphdr#totalLength is equal to zero (which can happen in TCP Segmentation Offloading), this flag is ignored and the layer data
		 * length is calculated by the actual data captured on the wire
		 */
		IPv4Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet, bool setTotalLenAsDataLen);


		/**
		 * A constructor that allocates a new IPv4 header with empty fields
		 */
		IPv4Layer();

		/**
		 * A constructor that allocates a new IPv4 header with source and destination IPv4 addresses
		 * @param[in] srcIP Source IPv4 address
		 * @param[in] dstIP Destination IPv4 address
		 */
		IPv4Layer(const IPv4Address& srcIP, const IPv4Address& dstIP);

		/**
		 * A copy constructor that copy the entire header from the other IPv4Layer (including IPv4 options)
		 */
		IPv4Layer(const IPv4Layer& other);

		/**
		 * An assignment operator that first delete all data from current layer and then copy the entire header from the other IPv4Layer (including IPv4 options)
		 */
		IPv4Layer& operator=(const IPv4Layer& other);

		/**
		 * Get a pointer to the IPv4 header. Notice this points directly to the data, so every change will change the actual packet data
		 * @return A pointer to the @ref iphdr
		 */
		iphdr* getIPv4Header() const { return (iphdr*)m_Data; }

		/**
		 * Get the source IP address in the form of IPv4Address
		 * @return An IPv4Address containing the source address
		 */
		IPv4Address getSrcIpAddress() const { return getIPv4Header()->ipSrc; }

		/**
		 * Set the source IP address
		 * @param[in] ipAddr The IP address to set
		 */
		void setSrcIpAddress(const IPv4Address& ipAddr) { getIPv4Header()->ipSrc = ipAddr.toInt(); }

		/**
		 * Get the destination IP address in the form of IPv4Address
		 * @return An IPv4Address containing the destination address
		 */
		IPv4Address getDstIpAddress() const { return getIPv4Header()->ipDst; }

		/**
		 * Set the dest IP address
		 * @param[in] ipAddr The IP address to set
		 */
		void setDstIpAddress(const IPv4Address& ipAddr) { getIPv4Header()->ipDst = ipAddr.toInt(); }

		/**
		 * @return True if this packet is a fragment (in sense of IP fragmentation), false otherwise
		 */
		bool isFragment() const;

		/**
		 * @return True if this packet is a fragment (in sense of IP fragmentation) and is the first fragment
		 * (which usually contains the L4 header). Return false otherwise (not a fragment or not the first fragment)
		 */
		bool isFirstFragment() const;

		/**
		 * @return True if this packet is a fragment (in sense of IP fragmentation) and is the last fragment.
		 * Return false otherwise (not a fragment or not the last fragment)
		 */
		bool isLastFragment() const;

		/**
		 * @return A bitmask containing the fragmentation flags (e.g IP_DONT_FRAGMENT or IP_MORE_FRAGMENTS)
		 */
		uint8_t getFragmentFlags() const;

		/**
		 * @return The fragment offset in case this packet is a fragment, 0 otherwise
		 */
		uint16_t getFragmentOffset() const;

		/**
		 * Get an IPv4 option by type.
		 * @param[in] option IPv4 option type
		 * @return An IPv4Option object that contains the first option that matches this type, or logical NULL
		 * (IPv4Option#isNull() == true) if no such option found
		 */
		IPv4Option getOption(IPv4OptionTypes option) const;

		/**
		 * @return The first IPv4 option in the packet. If the current layer contains no options the returned value will contain
		 * a logical NULL (IPv4Option#isNull() == true)
		 */
		IPv4Option getFirstOption() const;

		/**
		 * Get the IPv4 option that comes after a given option. If the given option was the last one, the
		 * returned value will contain a logical NULL (IPv4Option#isNull() == true)
		 * @param[in] option An IPv4 option object that exists in the current layer
		 * @return A IPv4Option object that contains the IPv4 option data that comes next, or logical NULL if the given
		 * IPv4 option: (1) was the last one; or (2) contains a logical NULL; or (3) doesn't belong to this packet
		 */
		IPv4Option getNextOption(IPv4Option& option) const;

		/**
		 * @return The number of IPv4 options in this layer
		 */
		size_t getOptionCount() const;

		/**
		 * Add a new IPv4 option at the end of the layer (after the last IPv4 option)
		 * @param[in] optionBuilder An IPv4OptionBuilder object that contains the IPv4 option data to be added
		 * @return A IPv4Option object that contains the newly added IPv4 option data or logical NULL
		 * (IPv4Option#isNull() == true) if addition failed. In case of a failure a corresponding error message will be
		 * printed to log
		 */
		IPv4Option addOption(const IPv4OptionBuilder& optionBuilder);

		/**
		 * Add a new IPv4 option after an existing one
		 * @param[in] optionBuilder An IPv4OptionBuilder object that contains the requested IPv4 option data to be added
		 * @param[in] prevOptionType The IPv4 option which the newly added option should come after. This is an optional parameter which
		 * gets a default value of ::IPV4OPT_Unknown if omitted, which means the new option will be added as the first option in the layer
		 * @return A IPv4Option object containing the newly added IPv4 option data or logical NULL
		 * (IPv4Option#isNull() == true) if addition failed. In case of a failure a corresponding error message will be
		 * printed to log
		 */
		IPv4Option addOptionAfter(const IPv4OptionBuilder& optionBuilder, IPv4OptionTypes prevOptionType = IPV4OPT_Unknown);

		/**
		 * Remove an IPv4 option
		 * @param[in] option The option type to remove
		 * @return True if option was removed successfully or false if option type wasn't found or failed to shorten the layer. If an option appears twice in the layer, its first instance
		 * will be removed
		 */
		bool removeOption(IPv4OptionTypes option);

		/**
		 * Remove all IPv4 options from the layer
		 * @return True if options removed successfully or false if some error occurred (an appropriate error message will be printed to log)
		 */
		bool removeAllOptions();


		// implement abstract methods

		/**
		 * Currently identifies the following next layers: UdpLayer, TcpLayer. Otherwise sets PayloadLayer
		 */
		void parseNextLayer();

		/**
		 * @return Size of IPv4 header (including IPv4 options if exist)
		 */
		size_t getHeaderLen() const { return (size_t)((uint16_t)(getIPv4Header()->internetHeaderLength) * 4) + m_TempHeaderExtension; }

		/**
		 * Calculate the following fields:
		 * - iphdr#ipVersion = 4;
		 * - iphdr#totalLength = total packet length
		 * - iphdr#headerChecksum = calculated
		 * - iphdr#protocol = calculated if next layer is known: ::PACKETPP_IPPROTO_TCP for TCP, ::PACKETPP_IPPROTO_UDP for UDP, ::PACKETPP_IPPROTO_ICMP for ICMP
		 */
		void computeCalculateFields();

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const { return OsiModelNetworkLayer; }

		/**
		 * The static method makes validation of input data
		 * @param[in] data The pointer to the beginning of byte stream of IP packet
		 * @param[in] dataLen The length of byte stream
		 * @return True if the data is valid and can represent the IPv4 packet
		 */
		static inline bool isDataValid(const uint8_t* data, size_t dataLen);

	private:
		int m_NumOfTrailingBytes;
		int m_TempHeaderExtension;
		TLVRecordReader<IPv4Option> m_OptionReader;

		void copyLayerData(const IPv4Layer& other);
		uint8_t* getOptionsBasePtr() const { return m_Data + sizeof(iphdr); }
		IPv4Option addOptionAt(const IPv4OptionBuilder& optionBuilder, int offset);
		void adjustOptionsTrailer(size_t totalOptSize);
		void initLayer();
		void initLayerInPacket(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet, bool setTotalLenAsDataLen);
	};


	// implementation of inline methods

	bool IPv4Layer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		const iphdr* hdr = reinterpret_cast<const iphdr*>(data);
		return dataLen >= sizeof(iphdr) && hdr->ipVersion == 4 && hdr->internetHeaderLength >= 5;
	}

} // namespace pcpp

#endif /* PACKETPP_IPV4_LAYER */
