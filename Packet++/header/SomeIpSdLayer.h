#pragma once

#include "IpAddress.h"
#include "Layer.h"
#include "SomeIpLayer.h"
#include <cstring>
#include <iterator>
#include <unordered_map>
#include <memory>
#include <stdexcept>
#include <vector>

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	/// Types of protocols that can be referenced in SOME/IP-SD
	enum SomeIpSdProtocolType : uint8_t
	{
		/// TCP
		SD_TCP = 0x06,
		/// UDP
		SD_UDP = 0x11
	};

	class SomeIpSdLayer;

	/// @class SomeIpSdOption
	/// Base class of the SOME/IP-SD options. Cannot be instantiated.
	class SomeIpSdOption
	{
	public:
		friend class SomeIpSdLayer;

		/// Types of options currently available for the SOME/IP-SD protocol
		enum class OptionType : uint8_t
		{
			/// Unknown Option Type
			Unknown = 0x00,
			/// Configuration Option
			ConfigurationString = 0x01,
			/// Load Balancing Option
			LoadBalancing = 0x02,
			/// IPv4 Endpoint Option
			IPv4Endpoint = 0x04,
			/// IPv6 Endpoint Option
			IPv6Endpoint = 0x06,
			/// IPv4 Multicast Option
			IPv4Multicast = 0x14,
			/// IPv6 Multicast Option
			IPv6Multicast = 0x16,
			/// IPv4 SD Endpoint Option
			IPv4SdEndpoint = 0x24,
			/// IPv6 SD Endpoint Option
			IPv6SdEndpoint = 0x26
		};

		/// @struct someipsdhdroptionsbase
		/// Represents the common base for SOME/IP-SD header options
#pragma pack(push, 1)
		struct someipsdhdroptionsbase
		{
			/// Length - excluding the 16 bit Length field and the 8 bit type flag
			uint16_t length;
			/// Type
			uint8_t type;
			/// Reserved
			uint8_t reserved;
		};
#pragma pack(pop)
		static_assert(sizeof(someipsdhdroptionsbase) == 4, "someipsdhdroptionsbase size is not 4 bytes");

		/// Destroy the SOME/IP-SD Option object and delete allocated data if it has been allocated by a constructor
		virtual ~SomeIpSdOption();

		/// Get the Option Type
		/// @return OptionType
		OptionType getType() const;

		/// Get the Length of the SOME/IP-SD option
		/// @return size_t
		size_t getLength() const
		{
			return m_DataLen;
		}

		/// Get the internal data of the SOME/IP-SD Option
		/// @return uint8_t*
		uint8_t* getDataPtr() const;

		/// Get a pointer to the SOME/IP-SD Option base header
		/// @return someipsdhdroptionsbase*
		someipsdhdroptionsbase* getSomeIpSdOptionHeader() const;

	protected:
		const IDataContainer* m_DataContainer;
		size_t m_Offset;
		uint8_t* m_ShadowData;
		size_t m_DataLen;

		SomeIpSdOption() : m_DataContainer(nullptr), m_Offset(0), m_ShadowData(nullptr), m_DataLen(0)
		{}

		SomeIpSdOption(const IDataContainer* dataContainer, size_t offset)
		    : m_DataContainer(dataContainer), m_Offset(offset), m_ShadowData(nullptr), m_DataLen(0)
		{}

		void initStdFields(OptionType type);

		SomeIpSdOption(const SomeIpSdOption&) = delete;
		SomeIpSdOption& operator=(const SomeIpSdOption&) = delete;
	};

	/// @class SomeIpSdIPv4Option
	/// Implements the following SOME/IP-SD Options: IPv4 Endpoint, IPv4 Multicast, IPv4 SD Endpoint
	class SomeIpSdIPv4Option : public SomeIpSdOption
	{
	public:
		friend class SomeIpSdLayer;

		/// Types of options which are implemented with this class
		enum IPv4OptionType
		{
			/// IPv4 Endpoint Option
			IPv4Endpoint,
			/// IPv4 Multicast Option
			IPv4Multicast,
			/// IPv4 SD Endpoint Option
			IPv4SdEndpoint,
		};

		/// Construct a new SomeIpSdIPv4 Option object
		/// @param[in] type IPv4 Option type
		/// @param[in] ipAddress Ipv4 address to use
		/// @param[in] port Port to use
		/// @param[in] l4Protocol Protocol to use
		SomeIpSdIPv4Option(IPv4OptionType type, IPv4Address ipAddress, uint16_t port, SomeIpSdProtocolType l4Protocol);

		/// Construct a new SomeIpSdIPv4 Option object from already existing memory
		/// @param[in] dataContainer Data containing the SomeIpSdIPv4 Option object
		/// @param[in] offset Offset for dataContainer
		SomeIpSdIPv4Option(const IDataContainer* dataContainer, size_t offset);

		/// Get the Ip Address
		/// @return IPv4Address
		IPv4Address getIpAddress() const;

		/// Get the Port
		/// @return uint16_t
		uint16_t getPort() const;

		/// Get the Protocol
		/// @return SomeIpSdProtocolType
		SomeIpSdProtocolType getProtocol() const;

	private:
		/// @struct someipsdhdroptionsipv4
		/// Represents the IPv4 option types for the SOME/IP-SD header
#pragma pack(push, 1)
		struct someipsdhdroptionsipv4 : someipsdhdroptionsbase
		{
			/// IPv4-Address field
			uint32_t ipv4Address;
			// cppcheck-suppress duplInheritedMember
			/// Reserved
			uint8_t reserved;
			/// Layer 4 Protocol field (L4-Proto) - Either UDP or TCP
			SomeIpSdProtocolType l4Protocol;
			/// Port number of UDP or TCP
			uint16_t portNumber;
		};
#pragma pack(pop)
		static_assert(sizeof(someipsdhdroptionsipv4) == 12, "someipsdhdroptionsipv4 size is not 12 bytes");
	};

	/// @class SomeIpSdIPv6Option
	/// Implements the following SOME/IP-SD Options: IPv6 Endpoint, IPv6 Multicast, IPv6 SD Endpoint
	class SomeIpSdIPv6Option : public SomeIpSdOption
	{
	public:
		friend class SomeIpSdLayer;

		/// Types of options which are implemented with this class
		enum IPv6OptionType
		{
			/// IPv6 Endpoint Option
			IPv6Endpoint,
			/// IPv6 Multicast Option
			IPv6Multicast,
			/// IPv6 SD Endpoint Option
			IPv6SdEndpoint,
		};

		/// Construct a new SomeIpSdIPv6 Option object
		/// @param[in] type IPv6 Option type
		/// @param[in] ipAddress Ipv6 address to use
		/// @param[in] port Port to use
		/// @param[in] l4Protocol Protocol to use
		SomeIpSdIPv6Option(IPv6OptionType type, IPv6Address ipAddress, uint16_t port, SomeIpSdProtocolType l4Protocol);

		/// Construct a new SomeIpSdIPv6 Option object from already existing memory
		/// @param[in] dataContainer Data containing the SomeIpSdIPv6 Option object
		/// @param[in] offset Offset for dataContainer
		SomeIpSdIPv6Option(const IDataContainer* dataContainer, size_t offset);

		/// Get the Ip Address
		/// @return IPv6Address
		IPv6Address getIpAddress() const;

		/// Get the Port
		/// @return uint16_t
		uint16_t getPort() const;

		/// Get the Protocol
		/// @return SomeIpSdProtocolType
		SomeIpSdProtocolType getProtocol() const;

	private:
		/// @struct someipsdhdroptionsipv6
		/// Represents the IPv6 option types for the SOME/IP-SD header
#pragma pack(push, 1)
		struct someipsdhdroptionsipv6 : someipsdhdroptionsbase
		{
			/// IPv6-Address field
			uint8_t ipv6Address[16];
			// cppcheck-suppress duplInheritedMember
			/// Reserved
			uint8_t reserved;
			/// Layer 4 Protocol field (L4-Proto) - Either UDP or TCP
			SomeIpSdProtocolType l4Protocol;
			/// Port number of UDP or TCP
			uint16_t portNumber;
		};
#pragma pack(pop)
		static_assert(sizeof(someipsdhdroptionsipv6) == 24, "someipsdhdroptionsipv6 size is not 24 bytes");
	};

	/// @class SomeIpSdConfigurationOption
	/// Implements the Configuration option of SOME/IP-SD protocol
	class SomeIpSdConfigurationOption : public SomeIpSdOption
	{
	public:
		friend class SomeIpSdLayer;

		/// Construct a new Configuration Option object
		/// @param[in] configurationString the configuration string
		explicit SomeIpSdConfigurationOption(const std::string& configurationString);

		/// Construct a new Configuration Option object from already existing memory
		/// @param[in] dataContainer Data containing the Configuration Option object
		/// @param[in] offset Offset for dataContainer
		SomeIpSdConfigurationOption(const IDataContainer* dataContainer, size_t offset);

		/// Get the configuration string
		/// @return std::string
		std::string getConfigurationString() const;
	};

	/// @class SomeIpSdLoadBalancingOption
	/// Implements the Load Balancing option of SOME/IP-SD protocol
	class SomeIpSdLoadBalancingOption : public SomeIpSdOption
	{
	public:
		friend class SomeIpSdLayer;

		/// Construct a new Load Balancing object
		/// @param[in] priority Priority of this instance
		/// @param[in] weight Weight of this instance
		SomeIpSdLoadBalancingOption(uint16_t priority, uint16_t weight);

		/// Construct a new Option object from already existing memory
		/// @param[in] dataContainer Data containing the option object
		/// @param[in] offset Offset for dataContainer
		SomeIpSdLoadBalancingOption(const IDataContainer* dataContainer, size_t offset);

		/// Get the priority fild
		/// @return uint16_t
		uint16_t getPriority() const;

		/// Get the weight field
		/// @return uint16_t
		uint16_t getWeight() const;

	private:
		/// @struct someipsdhdroptionsload
		/// Represents the Load Balancing option header for SOME/IP-SD
#pragma pack(push, 1)
		struct someipsdhdroptionsload : someipsdhdroptionsbase
		{
			/// Priority field
			uint16_t priority;
			/// Weight field
			uint16_t weight;
		};
#pragma pack(pop)
		static_assert(sizeof(someipsdhdroptionsload) == 8, "someipsdhdroptionsload size is not 8 bytes");
	};

	/// @class SomeIpSdEntry
	/// Implementation of the SOME/IP-SD Service Entry and Eventgroup Entry Type
	class SomeIpSdEntry
	{
	public:
		friend class SomeIpSdLayer;

		/// Types of entries that can occur in SOME/IP-SD
		enum class EntryType : uint8_t
		{
			/// Find Service
			FindService,
			/// Offer Service
			OfferService,
			/// Stop Offer Service
			StopOfferService,
			/// Subscribe Eventgroup
			SubscribeEventgroup,
			/// Stop Subscribe Eventgroup
			StopSubscribeEventgroup,
			/// Subscribe Eventgroup Acknowledgment
			SubscribeEventgroupAck,
			/// Subscribe Eventgroup Negative Acknowledgement
			SubscribeEventgroupNack,
			/// Unknown Entry Type
			UnknownEntryType
		};

		/// @struct someipsdhdrentry
		/// Represents the Service Entry Type and Eventgroup Entry Type
#pragma pack(push, 1)
		struct someipsdhdrentry
		{
			/// Type
			uint8_t type;
			/// Index 1st option
			uint8_t indexFirstOption;
			/// Index 2nd option
			uint8_t indexSecondOption;
#if (BYTE_ORDER == LITTLE_ENDIAN)
			uint8_t
			    /// Numbers of Option #2 (4bit)
			    nrOpt2 : 4,
			    /// Numbers of Option #1 (4bit)
			    nrOpt1 : 4;
#else
			uint8_t
			    /// Numbers of Option #1 (4bit)
			    nrOpt1 : 4,
			    /// Numbers of Option #2 (4bit)
			    nrOpt2 : 4;
#endif
			/// Service ID
			uint16_t serviceID;
			/// Instance ID
			uint16_t instanceID;
			/// Major Version (8 bit) + TTL (24 bit)
			uint32_t majorVersion_ttl;
			/// Minor Version (Service Entry Type) or Counter + Eventgroup ID (Eventgroup Entry Type)
			uint32_t data;
		};
#pragma pack(pop)
		static_assert(sizeof(someipsdhdrentry) == 16, "someipsdhdrentry size is not 16 bytes");

		/// Construct a new SOME/IP-SD Service Entry Type
		/// @param[in] type Type to create
		/// @param[in] serviceID ServiceID to use
		/// @param[in] instanceID InstanceID to use
		/// @param[in] majorVersion MajorVersion to use
		/// @param[in] TTL TTL to use. Has to be 0 for all Stop* entry types
		/// @param[in] minorVersion MinorVersion to use
		SomeIpSdEntry(EntryType type, uint16_t serviceID, uint16_t instanceID, uint8_t majorVersion, uint32_t TTL,
		              uint32_t minorVersion);

		/// Construct a new SOME/IP-SD Eventgroup Entry Type
		/// @param[in] type Type to create
		/// @param[in] serviceID ServiceID to use
		/// @param[in] instanceID InstanceID to use
		/// @param[in] majorVersion MajorVersion to use
		/// @param[in] TTL TTL to use. Has to be 0 for all Stop* entry types
		/// @param[in] counter Counter value to use
		/// @param[in] eventGroupID EventgroupId to use
		SomeIpSdEntry(EntryType type, uint16_t serviceID, uint16_t instanceID, uint8_t majorVersion, uint32_t TTL,
		              uint8_t counter, uint16_t eventGroupID);

		/// Construct a new SomeIpSdEntry object from existing data
		/// @param[in] pSomeIpSdLayer Layer that this entry is created for
		/// @param[in] offset Offset for pSomeIpSdLayer
		SomeIpSdEntry(const SomeIpSdLayer* pSomeIpSdLayer, size_t offset);

		/// Destroy the SomeIpSd Entry object and delete allocated data if it has been allocated by a constructor
		~SomeIpSdEntry();

		/// Get the internal data of the SOME/IP-SD Entry
		/// @return uint8_t*
		uint8_t* getDataPtr() const;

		/// Get a pointer to the SOME/IP-SD Entry header
		/// @return someipsdhdrentry*
		someipsdhdrentry* getSomeIpSdEntryHeader() const;

		/// Get the Entry Type
		/// @return EntryType
		EntryType getType() const
		{
			return m_EntryType;
		}

		/// Get the Length of the SomeIpSd Entry
		/// @return size_t
		size_t getLength() const
		{
			return sizeof(someipsdhdrentry);
		}

		/// Get the number of Options of this Entry
		/// @return uint32_t
		uint32_t getNumOptions() const;

		/// Get the Service Id in host endianness
		/// @return uint16_t
		uint16_t getServiceId() const;

		/// Set the Service Id
		/// @param[in] serviceId
		void setServiceId(uint16_t serviceId);

		/// Get the Instance Id in host endianness
		/// @return uint16_t
		uint16_t getInstanceId() const;

		/// Set the Instance Id
		/// @param[in] instanceId
		void setInstanceId(uint16_t instanceId);

		/// Get the Major version field in host endianness
		/// @return uint16_t
		uint8_t getMajorVersion() const;

		/// Set the Major Version
		/// @param[in] majorVersion
		void setMajorVersion(uint8_t majorVersion);

		/// Get the Ttl field
		/// @return uint32_t
		uint32_t getTtl() const;

		/// Set the Ttl field
		/// @param[in] ttl
		void setTtl(uint32_t ttl);

		/// Get the minor version
		/// @return uint32_t
		uint32_t getMinorVersion() const;

		/// Set the minor version
		/// @param[in] minorVersion
		void setMinorVersion(uint32_t minorVersion);

		/// Get the counter value
		/// @return uint32_t
		uint8_t getCounter() const;

		/// Set the counter value
		/// @param[in] counter
		void setCounter(uint8_t counter);

		/// Get the eventgroup id
		/// @return uint32_t
		uint16_t getEventgroupId() const;

		/// Set the eventgroup id
		/// @param[in] eventgroupID
		void setEventgroupId(uint16_t eventgroupID);

	private:
		/// These are the entry types used by SOME/IP-SD. They cannot be used for parameter passing since the values
		/// are not unique.
		enum class TypeInternal : uint8_t
		{
			/// Find Service
			FindService_Internal = 0x00,
			/// Offer Service / Stop Offer Service
			OfferService_Internal = 0x01,
			/// Subscribe Eventgroup & Stop Subscribe Eventgroup
			SubscribeEventgroup_Internal = 0x06,
			/// Subscribe Eventgroup Acknowledgment / Negative Acknowledgement
			SubscribeEventgroupAck_Internal = 0x07,
		};

		EntryType m_EntryType;
		const SomeIpSdLayer* m_Layer;
		size_t m_Offset;
		uint8_t* m_ShadowData;

		void initStdFields(EntryType type, uint16_t serviceID, uint16_t instanceID, uint8_t majorVersion, uint32_t TTL);

		SomeIpSdEntry(const SomeIpSdEntry&) = delete;
		SomeIpSdEntry& operator=(const SomeIpSdEntry&) = delete;

		static const uint32_t SOMEIPSD_HDR_ENTRY_MASK_TTL = 0x00FFFFFF;
	};

	/// @class SomeIpSdLayer
	/// Implementation of the SOME/IP-SD protocol
	class SomeIpSdLayer : public SomeIpLayer
	{
	public:
		friend class SomeIpSdEntry;

		typedef SomeIpSdEntry* EntryPtr;
		typedef std::vector<EntryPtr> EntriesVec;
		typedef SomeIpSdOption* OptionPtr;
		typedef std::vector<OptionPtr> OptionsVec;

		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		SomeIpSdLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/// Construct a new SomeIpSdLayer object
		/// @param[in] serviceID Service ID
		/// @param[in] methodID Method ID
		/// @param[in] clientID Client ID
		/// @param[in] sessionID Session ID
		/// @param[in] interfaceVersion Interface Version
		/// @param[in] type Type of the message
		/// @param[in] returnCode Return Code
		/// @param[in] flags Flags that shall be used in the header
		SomeIpSdLayer(uint16_t serviceID, uint16_t methodID, uint16_t clientID, uint16_t sessionID,
		              uint8_t interfaceVersion, MsgType type, uint8_t returnCode, uint8_t flags);

		/// Destroy the layer object
		~SomeIpSdLayer() override = default;

		/// Checks if given port is a SOME/IP-SD protocol port
		/// @param[in] port Port to check
		/// @return true if SOME/IP-SD protocol port, false if not
		static bool isSomeIpSdPort(uint16_t port)
		{
			return port == 30490;
		}

		/// The static method makes validation of input data
		/// @param[in] data The pointer to the beginning of byte stream of IP packet
		/// @param[in] dataLen The length of byte stream
		/// @return True if the data is valid and can represent the packet
		static bool isDataValid(const uint8_t* data, size_t dataLen);

		/// Get the Flags of the layer
		/// @return uint8_t Flags
		uint8_t getFlags() const;

		/// Set the Flags of the layer
		/// @param[in] flags Flags to set
		void setFlags(uint8_t flags);

		/// Get the number of entries in this layer
		/// @return uint32_t
		uint32_t getNumEntries() const;

		/// Get the number of options in this layer
		/// @return uint32_t
		uint32_t getNumOptions() const;

		/// Get the Entries from this layer
		/// @return EntriesVec Vector holding pointers to the options
		const EntriesVec getEntries() const;

		/// Get the Options from this layer
		/// @return OptionsVec Vector holding pointers to the options
		const OptionsVec getOptions() const;

		/// Get the Options from a specific Entry
		/// @param[in] index Index of the Entry, starting with 0.
		/// @return OptionsVec Vector holding pointers to the options
		const OptionsVec getOptionsFromEntry(uint32_t index) const;

		/// Adds a given entry to the layer and returns the index of the entry
		/// @param[in] entry Pointer to the entry that shall be added to the layer
		/// @return uint32_t Returns the index of the entry starting with 0
		uint32_t addEntry(const SomeIpSdEntry& entry);

		/// Adds an option to an entry that has already been added to the layer by using addEntry(). The option
		/// is also added to the layer itself. If the option cannot by assigned to the entry, the option is not
		/// copied into the layer.
		/// @param[in] indexEntry Index of the entry where the option shall be added. First Entry has index 0
		/// @param[in] option Pointer to the option that shall be added
		/// @return True if the option could be assigned to the entry and was copied into the layer, false otherwise
		bool addOptionTo(uint32_t indexEntry, const SomeIpSdOption& option);

		/// Does nothing for this layer
		void computeCalculateFields() override {};

		/// @return The string representation of the SOME/IP-SD layer
		std::string toString() const override;

	private:
		/// @struct someipsdhdr
		/// Represents an SOME/IP-SD protocol header
#pragma pack(push, 1)
		struct someipsdhdr : someiphdr
		{
			/// Flags (8 bit)
			uint8_t flags;
			/// Reserved1 field (Bits 0-7 of 24-bits reserved field)
			uint8_t reserved1;
			/// Reserved2 field (Bits 8-15 of 24-bits reserved field)
			uint8_t reserved2;
			/// Reserved3 field (Bits 16-23 of 24-bits reserved field)
			uint8_t reserved3;
		};
#pragma pack(pop)
		static_assert(sizeof(someipsdhdr) == 20, "someipsdhdr size is not 20 bytes");

		uint32_t m_NumOptions;

		static bool countOptions(uint32_t& count, const uint8_t* data);
		uint32_t findOption(const SomeIpSdOption& option);
		void addOption(const SomeIpSdOption& option);
		bool addOptionIndex(uint32_t indexEntry, uint32_t indexOffset);
		OptionPtr parseOption(SomeIpSdOption::OptionType type, size_t offset) const;

		static size_t getLenEntries(const uint8_t* data);
		size_t getLenEntries() const;
		static size_t getLenOptions(const uint8_t* data);
		size_t getLenOptions() const;
		void setLenEntries(uint32_t length);
		void setLenOptions(uint32_t length);
	};
}  // namespace pcpp
