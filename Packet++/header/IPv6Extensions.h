#ifndef PACKETPP_IPV6_EXTENSION
#define PACKETPP_IPV6_EXTENSION

#include <vector>
#include "IpAddress.h"
#include "Layer.h"

namespace pcpp
{
	class IPv6Extension
	{
		friend class IPv6Layer;

	public:

		enum IPv6ExtensionType
		{
			IPv6HopByHop = 0,
			IPv6Routing = 43,
			IPv6Fragmentation = 44,
			IPv6AuthenticationHdr = 51,
			IPv6Destination = 60,
			IPv6ExtensionUnknown = 255
		};

		/**
		 * @return Size of 8 * (ipv6_ext_base_header#headerLen + 1)
		 */
		virtual inline size_t getExtensionLen() const { return 8 * (getBaseHeader()->headerLen+1); }

		inline IPv6ExtensionType getExtensionType() { return m_ExtType; }

		virtual ~IPv6Extension();

	protected:

		struct ipv6_ext_base_header
		{
			uint8_t nextHeader;
			uint8_t headerLen;
		};

		// private c'tor
		IPv6Extension(IDataContainer* dataContainer, size_t offset) :
			m_NextHeader(NULL), m_ExtType(IPv6ExtensionUnknown), m_DataContainer(dataContainer), m_Offset(offset), m_ShadowData(NULL) {}

		// private empty c'tor
		IPv6Extension() :
			m_NextHeader(NULL), m_ExtType(IPv6ExtensionUnknown), m_DataContainer(NULL), m_Offset(0), m_ShadowData(NULL) {}

		// private assignment operator
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



	class IPv6FragmentationHeader : public IPv6Extension
	{
		friend class IPv6Layer;

	public:

		struct ipv6_frag_header
		{
			uint8_t nextHeader;
			uint8_t headerLen;
			uint16_t fragOffsetAndFlags;
			uint32_t id;
		};

		/**
		 * Fragmentation header c'tor
		 * @param[in] fragId Fragmentation ID
		 * @param[in] fragOffset Fragmentation offset
		 * @param[in] nextHeader Next header
		 * @param[in] lastFragment Indicates whether this fragment is the last one
		 */
		IPv6FragmentationHeader(uint32_t fragId, uint16_t fragOffset, bool lastFragment);

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
		 * @return A bitmask containing the fragmentation flags (e.g IP_DONT_FRAGMENT or IP_MORE_FRAGMENTS)
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


	class IPv6TLVOptionHeader : public IPv6Extension
	{
		friend class IPv6Layer;

	public:

		struct TLVOption
		{
		public:
			uint8_t optionType;
			uint8_t optionLen;
			uint8_t optionData[];

			static const uint8_t Pad0OptionType = 0;
			static const uint8_t PadNOptionType = 1;

			template<typename T>
			T getValueAs()
			{
				if (getDataSize() < sizeof(T))
					return 0;

				T result;
				memcpy(&result, optionData, sizeof(T));
				return result;
			}

			size_t getTotalSize() const
			{
				if (optionType == Pad0OptionType)
					return sizeof(uint8_t);

				return (size_t)(optionLen + sizeof(uint16_t));
			}

			size_t getDataSize()
			{
				if (optionType == Pad0OptionType)
					return (size_t)0;

				return (size_t)optionLen;
			}
		};

		class TLVOptionBuilder
		{
		public:

			TLVOptionBuilder(uint8_t optType, uint8_t optDataLen, const uint8_t* optValue);

			TLVOptionBuilder(uint8_t optType, uint8_t optValue);

			TLVOptionBuilder(uint8_t optType, uint16_t optValue);

			TLVOptionBuilder(const TLVOptionBuilder& other);

			~TLVOptionBuilder() { delete [] m_OptionBuffer; }

			TLVOption* build() const { return (TLVOption*)m_OptionBuffer; }

			uint8_t* getRawBuffer() const { return m_OptionBuffer; }

		private:

			void init(uint8_t optType, uint8_t optDataLen, const uint8_t* optValue);
			uint8_t* m_OptionBuffer;
		};

		TLVOption* getOption(uint8_t optionType);

		TLVOption* getFirstOption();

		TLVOption* getNextOption(TLVOption* option);

		size_t getOptionCount();

	protected:

		IPv6TLVOptionHeader(const std::vector<TLVOptionBuilder>& options);

		IPv6TLVOptionHeader(IDataContainer* dataContainer, size_t offset);

	private:

		size_t m_OptionCount;
	};


	class IPv6HopByHopHeader : public IPv6TLVOptionHeader
	{
		friend class IPv6Layer;

	public:

		IPv6HopByHopHeader(const std::vector<TLVOptionBuilder>& options) : IPv6TLVOptionHeader(options) { m_ExtType = IPv6HopByHop; }

	private:

		IPv6HopByHopHeader(IDataContainer* dataContainer, size_t offset) : IPv6TLVOptionHeader(dataContainer, offset) { m_ExtType = IPv6HopByHop; }
	};


	class IPv6DestinationHeader : public IPv6TLVOptionHeader
	{
		friend class IPv6Layer;

	public:

		IPv6DestinationHeader(const std::vector<TLVOptionBuilder>& options) : IPv6TLVOptionHeader(options) { m_ExtType = IPv6Destination; }

	private:

		IPv6DestinationHeader(IDataContainer* dataContainer, size_t offset) : IPv6TLVOptionHeader(dataContainer, offset) { m_ExtType = IPv6Destination; }
	};


	class IPv6RoutingHeader : public IPv6Extension
	{
		friend class IPv6Layer;

	public:

		struct ipv6_routing_header
		{
			uint8_t nextHeader;
			uint8_t headerLen;
			uint8_t routingType;
			uint8_t segmentsLeft;
		};

		IPv6RoutingHeader(uint8_t routingType, uint8_t segmentsLeft, const uint8_t* additionalRoutingData, size_t additionalRoutingDataLen);

		ipv6_routing_header* getRoutingHeader() { return (ipv6_routing_header*)getDataPtr(); }

		uint8_t* getRoutingAdditionalData();

		size_t getRoutingAdditionalDataLength();

		IPv6Address getRoutingAdditionalDataAsIPv6Address(size_t offset = 0);

	private:

		IPv6RoutingHeader(IDataContainer* dataContainer, size_t offset) : IPv6Extension(dataContainer, offset) { m_ExtType = IPv6Routing; }

	};


	class IPv6AuthenticationHeader : public IPv6Extension
	{
		friend class IPv6Layer;

	public:

		struct ipv6_authentication_header
		{
			uint8_t nextHeader;
			uint8_t headerLen;
			uint16_t reserved;
			uint32_t securityParametersIndex;
			uint32_t sequenceNumber;
		};

		IPv6AuthenticationHeader(uint32_t securityParametersIndex, uint32_t sequenceNumber, const uint8_t* integrityCheckValue, size_t integrityCheckValueLen);

		ipv6_authentication_header* getAuthHeader() { return (ipv6_authentication_header*)getDataPtr(); }

		uint8_t* getIntegrityCheckValue();

		size_t getIntegrityCheckValueLength();

		// overridden methods

		size_t getExtensionLen() const { return 4 * (getBaseHeader()->headerLen+2); }

	private:

		IPv6AuthenticationHeader(IDataContainer* dataContainer, size_t offset) : IPv6Extension(dataContainer, offset) { m_ExtType = IPv6AuthenticationHdr; }
	};

}

#endif // PACKETPP_IPV6_EXTENSION
