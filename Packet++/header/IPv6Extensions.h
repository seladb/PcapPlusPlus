#ifndef PACKETPP_IPV6_EXTENSION
#define PACKETPP_IPV6_EXTENSION

#include <vector>
#include "IpAddress.h"
#include "Layer.h"
#include "TLVData.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * @class IPv6Extension
	 * A base class for all supported IPv6 extensions. This class is abstract, meaning it cannot be instantiated or copied
	 * (has private c'tor and copy c'tor)
	 */
	class IPv6Extension
	{
		friend class IPv6Layer;

	public:

		/**
		 * An enum representing all supported IPv6 extension types
		 */
		enum IPv6ExtensionType
		{
			/** Hop-By-Hop extension type */
			IPv6HopByHop = 0,
			/** Routing extension type */
			IPv6Routing = 43,
			/** IPv6 fragmentation extension type */
			IPv6Fragmentation = 44,
			/** Authentication Header extension type */
			IPv6AuthenticationHdr = 51,
			/** Destination extension type */
			IPv6Destination = 60,
			/** Unknown or unsupported extension type */
			IPv6ExtensionUnknown = 255
		};

		/**
		 * @return The size of extension in bytes, meaning (for most extensions): 8 * ([headerLen field] + 1)
		 */
		virtual size_t getExtensionLen() const { return 8 * (getBaseHeader()->headerLen+1); }

		/**
		 * @return The type of the extension
		 */
		IPv6ExtensionType getExtensionType() const { return m_ExtType; }

		/**
		 * A destructor for this class
		 */
		virtual ~IPv6Extension();

		/**
		 * @return A pointer to the next header or NULL if the extension is the last one
		 */
		IPv6Extension* getNextHeader() const { return m_NextHeader; }

	protected:

		struct ipv6_ext_base_header
		{
			uint8_t nextHeader;
			uint8_t headerLen;
		};

		// protected c'tor
		IPv6Extension(IDataContainer* dataContainer, size_t offset) :
			m_NextHeader(NULL), m_ExtType(IPv6ExtensionUnknown), m_DataContainer(dataContainer), m_Offset(offset), m_ShadowData(NULL) {}

		// protected empty c'tor
		IPv6Extension() :
			m_NextHeader(NULL), m_ExtType(IPv6ExtensionUnknown), m_DataContainer(NULL), m_Offset(0), m_ShadowData(NULL) {}

		// protected assignment operator
		IPv6Extension& operator=(const IPv6Extension& other);

		uint8_t* getDataPtr() const;

		void initShadowPtr(size_t size);

		ipv6_ext_base_header* getBaseHeader() const { return (ipv6_ext_base_header*)getDataPtr(); }

		void setNextHeader(IPv6Extension* nextHeader) { m_NextHeader = nextHeader; }

		IPv6Extension* m_NextHeader;
		IPv6ExtensionType m_ExtType;

	private:
		IDataContainer* m_DataContainer;
		size_t m_Offset;
		uint8_t* m_ShadowData;

	};



	/**
	 * @class IPv6FragmentationHeader
	 * Represents an IPv6 fragmentation extension header and allows easy access to all fragmentation parameters
	 */
	class IPv6FragmentationHeader : public IPv6Extension
	{
		friend class IPv6Layer;

	public:

		/**
		 * @struct ipv6_frag_header
		 * A struct representing IPv6 fragmentation header
		 */
		struct ipv6_frag_header
		{
			/** Next header type */
			uint8_t nextHeader;
			/** Fragmentation header size is fixed 8 bytes, so len is always zero */
			uint8_t headerLen;
			/** Offset, in 8-octet units, relative to the start of the fragmentable part of the original packet
			 * plus 1-bit indicating if more fragments will follow */
			uint16_t fragOffsetAndFlags;
			/** packet identification value. Needed for reassembly of the original packet */
			uint32_t id;
		};

		/**
		 * A c'tor for creating a new IPv6 fragmentation extension object not bounded to a packet. Useful for adding new extensions to an
		 * IPv6 layer with IPv6Layer#addExtension()
		 * @param[in] fragId Fragmentation ID
		 * @param[in] fragOffset Fragmentation offset
		 * @param[in] lastFragment Indicates whether this fragment is the last one
		 */
		IPv6FragmentationHeader(uint32_t fragId, uint16_t fragOffset, bool lastFragment);

		/**
		 * Get a pointer to the fragmentation header. Notice the returned pointer points directly to the data, so every change will modify
		 * the actual packet data
		 * @return A pointer to the @ref ipv6_frag_header
		 */
		ipv6_frag_header* getFragHeader() const { return (ipv6_frag_header*)getDataPtr(); }

		/**
		 * @return True if this is the first fragment (which usually contains the L4 header), false otherwise
		 */
		bool isFirstFragment() const;

		/**
		 * @return True if this is the last fragment, false otherwise
		 */
		bool isLastFragment() const;

		/**
		 * @return True if the "more fragments" bit is set, meaning more fragments are expected to follow this fragment
		 */
		bool isMoreFragments() const;

		/**
		 * @return The fragment offset
		 */
		uint16_t getFragmentOffset() const;

	private:

		IPv6FragmentationHeader(IDataContainer* dataContainer, size_t offset) : IPv6Extension(dataContainer, offset)
		{
			m_ExtType = IPv6Fragmentation;
		}

	};


	/**
	 * An abstract base class for Hop-By-Hop and Destination IPv6 extensions which their structure contains Type-Length-Value (TLV) options.
	 * This class provides access to these options and their data as well as methods to create new options. Notice this class is abstract
	 * and cannot be instantiated
	 */
	class IPv6TLVOptionHeader : public IPv6Extension
	{
		friend class IPv6Layer;

	public:

		/**
		 * @class IPv6Option
		 * A class representing a Type-Length-Value (TLV) options that are used inside Hop-By-Hop and Destinations IPv6
		 * extensions. This class does not create or modify IPv6 option records, but rather serves as a wrapper and
		 * provides useful methods for retrieving data from them
		 */
		class IPv6Option : public TLVRecord<uint8_t, uint8_t>
		{
		public:

			static const uint8_t Pad0OptionType = 0;
			static const uint8_t PadNOptionType = 1;

			/**
			 * A c'tor for this class that gets a pointer to the option raw data (byte array)
			 * @param[in] optionRawData A pointer to the attribute raw data
			 */
			IPv6Option(uint8_t* optionRawData) : TLVRecord(optionRawData) { }

			/**
			 * A d'tor for this class, currently does nothing
			 */
			~IPv6Option() { }

			// implement abstract methods

			size_t getTotalSize() const
			{
				if (m_Data->recordType == Pad0OptionType)
					return sizeof(uint8_t);

				return (size_t)(m_Data->recordLen + sizeof(uint16_t));
			}

			size_t getDataSize() const
			{
				if (m_Data->recordType == Pad0OptionType)
					return (size_t)0;

				return (size_t)m_Data->recordLen;
			}
		};


		/**
		 * @class IPv6TLVOptionBuilder
		 * A class for building IPv6 Type-Length-Value (TLV) options. This builder receives the option parameters in its c'tor,
		 * builds the option raw buffer and provides a method to build a IPv6Option object out of it
		 */
		class IPv6TLVOptionBuilder : public TLVRecordBuilder
		{
		public:

			/**
			 * A c'tor for building IPv6 TLV options which their value is a byte array. The IPv6Option object can later
			 * be retrieved by calling build()
			 * @param[in] optType IPv6 option type
			 * @param[in] optValue A buffer containing the option value. This buffer is read-only and isn't modified in any way
			 * @param[in] optValueLen Option value length in bytes
			 */
			IPv6TLVOptionBuilder(uint8_t optType, const uint8_t* optValue, uint8_t optValueLen) :
				TLVRecordBuilder(optType, optValue, optValueLen) { }

			/**
			 * A c'tor for building IPv6 TLV options which have a 1-byte value. The IPv6Option object can later be retrieved
			 * by calling build()
			 * @param[in] optType IPv6 option type
			 * @param[in] optValue A 1-byte option value
			 */
			IPv6TLVOptionBuilder(uint8_t optType, uint8_t optValue) :
				TLVRecordBuilder(optType, optValue) { }

			/**
			 * A c'tor for building IPv6 TLV options which have a 2-byte value. The IPv6Option object can later be retrieved
			 * by calling build()
			 * @param[in] optType IPv6 option type
			 * @param[in] optValue A 2-byte option value
			 */
			IPv6TLVOptionBuilder(uint8_t optType, uint16_t optValue) :
				TLVRecordBuilder(optType, optValue) { }

			/**
			 * A copy c'tor that creates an instance of this class out of another instance and copies all the data from it
			 * @param[in] other The instance to copy data from
			 */
			IPv6TLVOptionBuilder(const IPv6TLVOptionBuilder& other) :
				TLVRecordBuilder(other) {}

			/**
			 * Assignment operator that copies all data from another instance of IPv6TLVOptionBuilder
			 * @param[in] other The instance to assign from
			 */
			IPv6TLVOptionBuilder& operator=(const IPv6TLVOptionBuilder& other)
			{
				TLVRecordBuilder::operator=(other);
				return *this;
			}

			/**
			 * Build the IPv6Option object out of the parameters defined in the c'tor
			 * @return The IPv6Option object
			 */
			IPv6Option build() const;
		};

		/**
		 * Retrieve an option by its type
		 * @param[in] optionType Option type
		 * @return An IPv6Option object that wraps the option data. If option isn't found a logical NULL is returned
		 * (IPv6Option#isNull() == true)
		 */
		IPv6Option getOption(uint8_t optionType) const;

		/**
		 * @return An IPv6Option that wraps the first option data or logical NULL (IPv6Option#isNull() == true) if no options exist
		 */
		IPv6Option getFirstOption() const;

		/**
		 * Returns a pointer to the option that comes after the option given as the parameter
		 * @param[in] option A pointer to an option instance
		 * @return An IPv6Option object that wraps the option data. In the following cases logical NULL (IPv6Option#isNull() == true)
		 * is returned:
		 * (1) input parameter is out-of-bounds for this extension or
		 * (2) the next option doesn't exist or
		 * (3) the input option is NULL
		 */
		IPv6Option getNextOption(IPv6Option& option) const;

		/**
		 * @returns The number of options this IPv6 extension contains
		 */
		size_t getOptionCount() const;

	protected:

		/** A private c'tor to keep this object from being constructed */
		IPv6TLVOptionHeader(const std::vector<IPv6TLVOptionBuilder>& options);

		IPv6TLVOptionHeader(IDataContainer* dataContainer, size_t offset);

	private:

		TLVRecordReader<IPv6Option> m_OptionReader;
	};



	/**
	 * @class IPv6HopByHopHeader
	 * Represents IPv6 Hop-By-Hop extension header and allows easy access to all of its data including the TLV options stored
	 */
	class IPv6HopByHopHeader : public IPv6TLVOptionHeader
	{
		friend class IPv6Layer;

	public:

		/**
		 * A c'tor for creating a new IPv6 Hop-By-Hop extension object not bounded to a packet. Useful for adding new extensions to an
		 * IPv6 layer with IPv6Layer#addExtension()
		 * @param[in] options A vector of IPv6TLVOptionHeader#TLVOptionBuilder instances which define the options that will be stored in the
		 * extension data. Notice this vector is read-only and its content won't be modified
		 */
		IPv6HopByHopHeader(const std::vector<IPv6TLVOptionBuilder>& options) : IPv6TLVOptionHeader(options) { m_ExtType = IPv6HopByHop; }

	private:

		IPv6HopByHopHeader(IDataContainer* dataContainer, size_t offset) : IPv6TLVOptionHeader(dataContainer, offset) { m_ExtType = IPv6HopByHop; }
	};



	/**
	 * @class IPv6DestinationHeader
	 * Represents IPv6 destination extension header and allows easy access to all of its data including the TLV options stored in it
	 */
	class IPv6DestinationHeader : public IPv6TLVOptionHeader
	{
		friend class IPv6Layer;

	public:

		/**
		 * A c'tor for creating a new IPv6 destination extension object not bounded to a packet. Useful for adding new extensions to an
		 * IPv6 layer with IPv6Layer#addExtension()
		 * @param[in] options A vector of IPv6TLVOptionHeader#TLVOptionBuilder instances which define the options that will be stored in the
		 * extension data. Notice this vector is read-only and its content won't be modified
		 */
		IPv6DestinationHeader(const std::vector<IPv6TLVOptionBuilder>& options) : IPv6TLVOptionHeader(options) { m_ExtType = IPv6Destination; }

	private:

		IPv6DestinationHeader(IDataContainer* dataContainer, size_t offset) : IPv6TLVOptionHeader(dataContainer, offset) { m_ExtType = IPv6Destination; }
	};



	/**
	 * @class IPv6RoutingHeader
	 * Represents IPv6 routing extension header and allows easy access to all of its data
	 */
	class IPv6RoutingHeader : public IPv6Extension
	{
		friend class IPv6Layer;

	public:

		/**
		 * @struct ipv6_routing_header
		 * A struct representing the fixed part of the IPv6 routing extension header
		 */
		struct ipv6_routing_header
		{
			/** Next header type */
			uint8_t nextHeader;
			/** The length of this header, in multiples of 8 octets, not including the first 8 octets */
			uint8_t headerLen;
			/** A value representing the routing type */
			uint8_t routingType;
			/** Number of nodes this packet still has to visit before reaching its final destination */
			uint8_t segmentsLeft;
		};

		/**
		 * A c'tor for creating a new IPv6 routing extension object not bounded to a packet. Useful for adding new extensions to an
		 * IPv6 layer with IPv6Layer#addExtension()
		 * @param[in] routingType Routing type value (will be written to ipv6_routing_header#routingType field)
		 * @param[in] segmentsLeft Segments left value (will be written to ipv6_routing_header#segmentsLeft field)
		 * @param[in] additionalRoutingData A pointer to a buffer containing the additional routing data for this extension. Notice this
		 * buffer is read-only and its content isn't modified
		 * @param[in] additionalRoutingDataLen The length of the additional routing data buffer
		 */
		IPv6RoutingHeader(uint8_t routingType, uint8_t segmentsLeft, const uint8_t* additionalRoutingData, size_t additionalRoutingDataLen);

		/**
		 * Get a pointer to the fixed part of the routing header. Notice the return pointer points directly to the data, so every change will modify
		 * the actual packet data
		 * @return A pointer to the @ref ipv6_routing_header
		 */
		ipv6_routing_header* getRoutingHeader() const { return (ipv6_routing_header*)getDataPtr(); }

		/**
		 * @return A pointer to the buffer containing the additional routing data for this extension. Notice that any change in this buffer
		 * will lead to a change in the extension data
		 */
		uint8_t* getRoutingAdditionalData() const;

		/**
		 * @return The length of the additional routing parameters buffer
		 */
		size_t getRoutingAdditionalDataLength() const;

		/**
		 * In many cases the additional routing data is actually IPv6 address(es). This method converts the raw buffer data into an IPv6 address
		 * @param[in] offset An offset in the additional routing buffer pointing to where the IPv6 address begins. In some cases there are
		 * multiple IPv6 addresses in the additional routing data buffer so this offset points to where the request IPv6 address begins. Also,
		 * even if there is only one IPv6 address in this buffer, sometimes it isn't written in the beginning of the buffer, so the offset points
		 * to where the IPv6 address begins. This is an optional parameter and the default offset is 0
		 * @return The IPv6 address stored in the additional routing data buffer from the offset defined by the user. If offset is out-of-bounds
		 * of the extension of doesn't have 16 bytes (== the length of IPv6 address) until the end of the buffer - IPv6Address#Zero is returned
		 */
		IPv6Address getRoutingAdditionalDataAsIPv6Address(size_t offset = 0) const;

	private:

		IPv6RoutingHeader(IDataContainer* dataContainer, size_t offset) : IPv6Extension(dataContainer, offset) { m_ExtType = IPv6Routing; }

	};


	/**
	 * @class IPv6AuthenticationHeader
	 * Represents IPv6 authentication header extension (used in IPSec protocol) and allows easy access to all of its data
	 */
	class IPv6AuthenticationHeader : public IPv6Extension
	{
		friend class IPv6Layer;

	public:

		/**
		 * @struct ipv6_authentication_header
		 * A struct representing the fixed part of the IPv6 authentication header extension
		 */
		struct ipv6_authentication_header
		{
			/** Next header type */
			uint8_t nextHeader;
			/** The length of this Authentication Header in 4-octet units, minus 2. For example, an AH value of 4
			 * equals: [ 3×(32-bit fixed-length AH fields) + 3×(32-bit ICV fields) − 2 ] and thus an AH value of 4 means 24 octets */
			uint8_t headerLen;
			/** Reserved bytes, all zeros */
			uint16_t reserved;
			/** Arbitrary value which is used (together with the destination IP address) to identify the security association of the receiving party */
			uint32_t securityParametersIndex;
			/** A monotonic strictly increasing sequence number (incremented by 1 for every packet sent) */
			uint32_t sequenceNumber;
		};

		/**
		 * A c'tor for creating a new IPv6 authentication header extension object not bounded to a packet. Useful for adding new extensions to an
		 * IPv6 layer with IPv6Layer#addExtension()
		 * @param[in] securityParametersIndex Security Parameters Index (SPI) value (will be written to ipv6_authentication_header#securityParametersIndex field)
		 * @param[in] sequenceNumber Sequence number value (will be written to ipv6_authentication_header#sequenceNumber field)
		 * @param[in] integrityCheckValue A pointer to a buffer containing the integrity check value (ICV) data for this extension. Notice this
		 * pointer is read-only and its content isn't modified in any way
		 * @param[in] integrityCheckValueLen The length of the integrity check value (ICV) buffer
		 */
		IPv6AuthenticationHeader(uint32_t securityParametersIndex, uint32_t sequenceNumber, const uint8_t* integrityCheckValue, size_t integrityCheckValueLen);

		/**
		 * Get a pointer to the fixed part of the authentication header. Notice the return pointer points directly to the data, so every change
		 * will modify the actual packet data
		 * @return A pointer to the @ref ipv6_authentication_header
		 */
		ipv6_authentication_header* getAuthHeader() const { return (ipv6_authentication_header*)getDataPtr(); }

		/**
		 * @return A pointer to the buffer containing the integrity check value (ICV) for this extension. Notice that any change in this buffer
		 * will lead to a change in the extension data
		 */
		uint8_t* getIntegrityCheckValue() const;

		/**
		 * @return The length of the integrity check value (ICV) buffer
		 */
		size_t getIntegrityCheckValueLength() const;

		// overridden methods

		/**
		 * In the authentication header the extension length is calculated in a different way than other extensions. The
		 * calculation is: [ 4 * (ipv6_authentication_header#headerLen + 2) ]
		 * @return The length of this extension
		 */
		size_t getExtensionLen() const { return 4 * (getBaseHeader()->headerLen+2); }

	private:

		IPv6AuthenticationHeader(IDataContainer* dataContainer, size_t offset) : IPv6Extension(dataContainer, offset) { m_ExtType = IPv6AuthenticationHdr; }
	};

}

#endif // PACKETPP_IPV6_EXTENSION
