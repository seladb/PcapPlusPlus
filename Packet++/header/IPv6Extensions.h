#ifndef PACKETPP_IPV6_EXTENSION
#define PACKETPP_IPV6_EXTENSION

#include <vector>
#include "IpAddress.h"
#include "Layer.h"

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
		virtual inline size_t getExtensionLen() const { return 8 * (getBaseHeader()->headerLen+1); }

		/**
		 * @return The type of the extension
		 */
		inline IPv6ExtensionType getExtensionType() { return m_ExtType; }

		/**
		 * A destructor for this class
		 */
		virtual ~IPv6Extension();

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

		inline void setNextHeader(IPv6Extension* nextHeader) { m_NextHeader = nextHeader; }

		inline IPv6Extension* getNextHeader() { return m_NextHeader; }

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
		ipv6_frag_header* getFragHeader() { return (ipv6_frag_header*)getDataPtr(); }

		/**
		 * @return True if this is the first fragment (which usually contains the L4 header), false otherwise
		 */
		bool isFirstFragment();

		/**
		 * @return True if this is the last fragment, false otherwise
		 */
		bool isLastFragment();

		/**
		 * @return True if the "more fragments" bit is set, meaning more fragments are expected to follow this fragment
		 */
		bool isMoreFragments();

		/**
		 * @return The fragment offset
		 */
		uint16_t getFragmentOffset();

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
		 * @struct TLVOption
		 * A struct representing a Type-Length-Value (TLV) option. These type of options are used inside Hop-By-Hop and Destinations IPv6
		 * extensions
		 */
		struct TLVOption
		{
		public:
			/** Option type */
			uint8_t optionType;
			/** Option length in bytes, not including TLVOption#optionType field and this field */
			uint8_t optionLen;
			/** Option data (variable size) */
			uint8_t optionData[];

			static const uint8_t Pad0OptionType = 0;
			static const uint8_t PadNOptionType = 1;

			/**
			 * A templated method to retrieve the option data as a certain type T. For example, if option data is 4B long
			 * (integer) then this method should be used as getValueAs<int>() and it will return the option data as an integer.<BR>
			 * Notice this return value is a copy of the data, not a pointer to the actual data
			 * @return The option data as type T
			 */
			template<typename T>
			T getValueAs()
			{
				if (getDataSize() < sizeof(T))
					return 0;

				T result;
				memcpy(&result, optionData, sizeof(T));
				return result;
			}

			/**
			 * @return The total size of this option (in bytes)
			 */
			size_t getTotalSize() const
			{
				if (optionType == Pad0OptionType)
					return sizeof(uint8_t);

				return (size_t)(optionLen + sizeof(uint16_t));
			}

			/**
			 * @return The size of the option data
			 */
			size_t getDataSize()
			{
				if (optionType == Pad0OptionType)
					return (size_t)0;

				return (size_t)optionLen;
			}
		};


		/**
		 * A class for building Type-Length-Value (TLV) options of type TLVOption. This builder gets the option parameters in its c'tor,
		 * builds the option raw buffer and provides a method to build a TLVOption object out of it
		 */
		class TLVOptionBuilder
		{
		public:

			/**
			 * A c'tor which gets the option type, option length and a buffer containing the option value and builds
			 * the option raw buffer which can later be casted to TLVOption object using the build() method
			 * @param[in] optType Option type
			 * @param[in] optDataLen Option length in bytes
			 * @param[in] optValue A buffer containing the option data. This buffer is read-only and isn't modified in any way
			 */
			TLVOptionBuilder(uint8_t optType, uint8_t optDataLen, const uint8_t* optValue);

			/**
			 * A c'tor which gets the option type, a 1-byte option value (which length is 1) and builds
			 * the option raw buffer which can later be casted to TLVOption object using the build() method
			 * @param[in] optType Option type
			 * @param[in] optValue A 1-byte option value
			 */
			TLVOptionBuilder(uint8_t optType, uint8_t optValue);

			/**
			 * A c'tor which gets the option type, a 2-byte option value (which length is 2) and builds
			 * the option raw buffer which can later be casted to TLVOption object using the build() method
			 * @param[in] optType Option type
			 * @param[in] optValue A 2-byte option value
			 */
			TLVOptionBuilder(uint8_t optType, uint16_t optValue);

			/**
			 * A copy c'tor which copies all the data from another instance of TLVOptionBuilder
			 * @param[in] other The instance to copy from
			 */
			TLVOptionBuilder(const TLVOptionBuilder& other);

			/**
			 * A d'tor for this class, frees all allocated memory
			 */
			~TLVOptionBuilder() { delete [] m_OptionBuffer; }

			/**
			 * A method that returns a pointer to TLVOption object containing option parameters. Notice the return value is just a
			 * TLVOption-pointer cast of the raw buffer that is stored inside this class so modifying it will modify the internal raw buffer
			 * @return A pointer to a TLVOption object
			 */
			TLVOption* build() const { return (TLVOption*)m_OptionBuffer; }

			/**
			 * @return A pointer to the raw buffer stored as a private member of this class
			 */
			uint8_t* getRawBuffer() const { return m_OptionBuffer; }

		private:

			void init(uint8_t optType, uint8_t optDataLen, const uint8_t* optValue);
			uint8_t* m_OptionBuffer;
		};

		/**
		 * Retrieve an option by its type
		 * @param[in] optionType Option type
		 * @return A pointer to the option data or NULL if option cannot be found
		 */
		TLVOption* getOption(uint8_t optionType);

		/**
		 * @return A pointer to the first option or NULL if option cannot be found
		 */
		TLVOption* getFirstOption();

		/**
		 * Returns a pointer to the option that comes after the option given as the parameter
		 * @param[in] option A pointer to an option instance
		 * @return A pointer to the option that comes next or NULL if: (1) input parameter is out-of-bounds for this extension or
		 * (2) if the next option doesn't exist or (3) if input option is NULL
		 */
		TLVOption* getNextOption(TLVOption* option);

		/**
		 * @returns The number of options this IPv6 extension contains
		 */
		size_t getOptionCount();

	protected:

		/** A private c'tor to keep this object from being constructed */
		IPv6TLVOptionHeader(const std::vector<TLVOptionBuilder>& options);

		IPv6TLVOptionHeader(IDataContainer* dataContainer, size_t offset);

	private:

		size_t m_OptionCount;
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
		IPv6HopByHopHeader(const std::vector<TLVOptionBuilder>& options) : IPv6TLVOptionHeader(options) { m_ExtType = IPv6HopByHop; }

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
		IPv6DestinationHeader(const std::vector<TLVOptionBuilder>& options) : IPv6TLVOptionHeader(options) { m_ExtType = IPv6Destination; }

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
		ipv6_routing_header* getRoutingHeader() { return (ipv6_routing_header*)getDataPtr(); }

		/**
		 * @return A pointer to the buffer containing the additional routing data for this extension. Notice that any change in this buffer
		 * will lead to a change in the extension data
		 */
		uint8_t* getRoutingAdditionalData();

		/**
		 * @return The length of the additional routing parameters buffer
		 */
		size_t getRoutingAdditionalDataLength();

		/**
		 * In many cases the additional routing data is actually IPv6 address(es). This method converts the raw buffer data into an IPv6 address
		 * @param[in] offset An offset in the additional routing buffer pointing to where the IPv6 address begins. In some cases there are
		 * multiple IPv6 addresses in the additional routing data buffer so this offset points to where the request IPv6 address begins. Also,
		 * even if there is only one IPv6 address in this buffer, sometimes it isn't written in the beginning of the buffer, so the offset points
		 * to where the IPv6 address begins. This is an optional parameter and the default offset is 0
		 * @return The IPv6 address stored in the additional routing data buffer from the offset defined by the user. If offset is out-of-bounds
		 * of the extension of doesn't have 16 bytes (== the length of IPv6 address) until the end of the buffer - IPv6Address#Zero is returned
		 */
		IPv6Address getRoutingAdditionalDataAsIPv6Address(size_t offset = 0);

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
		ipv6_authentication_header* getAuthHeader() { return (ipv6_authentication_header*)getDataPtr(); }

		/**
		 * @return A pointer to the buffer containing the integrity check value (ICV) for this extension. Notice that any change in this buffer
		 * will lead to a change in the extension data
		 */
		uint8_t* getIntegrityCheckValue();

		/**
		 * @return The length of the integrity check value (ICV) buffer
		 */
		size_t getIntegrityCheckValueLength();

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
