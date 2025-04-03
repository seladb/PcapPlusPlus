#pragma once

#include "Layer.h"
#include "TLVData.h"
#include "IpAddress.h"
#include "MacAddress.h"
#include <string.h>

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	/// @struct dhcp_header
	/// Represents a DHCP protocol header
#pragma pack(push, 1)
	struct dhcp_header
	{
		/// BootP opcode
		uint8_t opCode;
		/// Hardware type, set to 1 (Ethernet) by default
		uint8_t hardwareType;
		/// Hardware address length, set to 6 (MAC address length) by default
		uint8_t hardwareAddressLength;
		/// Hop count
		uint8_t hops;
		/// DHCP/BootP transaction ID
		uint32_t transactionID;
		/// The elapsed time, in seconds since the client sent its first BOOTREQUEST message
		uint16_t secondsElapsed;
		/// BootP flags
		uint16_t flags;
		/// Client IPv4 address
		uint32_t clientIpAddress;
		/// Your IPv4 address
		uint32_t yourIpAddress;
		/// Server IPv4 address
		uint32_t serverIpAddress;
		/// Gateway IPv4 address
		uint32_t gatewayIpAddress;
		/// Client hardware address, by default contains the MAC address (only 6 first bytes are used)
		uint8_t clientHardwareAddress[16];
		/// BootP server name
		uint8_t serverName[64];
		/// BootP boot file name
		uint8_t bootFilename[128];
		/// DHCP magic number (set to the default value of 0x63538263)
		uint32_t magicNumber;
	};
#pragma pack(pop)
	static_assert(sizeof(dhcp_header) == 240, "dhcp_header size is not 240 bytes");

	/// BootP opcodes
	enum BootpOpCodes
	{
		/// BootP request
		DHCP_BOOTREQUEST = 1,
		/// BootP reply
		DHCP_BOOTREPLY = 2
	};

	/// DHCP message types
	enum DhcpMessageType
	{
		/// Unknown message type
		DHCP_UNKNOWN_MSG_TYPE = 0,
		/// Discover message type
		DHCP_DISCOVER = 1,
		/// Offer message type
		DHCP_OFFER = 2,
		/// Request message type
		DHCP_REQUEST = 3,
		/// Decline message type
		DHCP_DECLINE = 4,
		/// Acknowledge message type
		DHCP_ACK = 5,
		/// Non-acknowledge message type
		DHCP_NAK = 6,
		/// Release message type
		DHCP_RELEASE = 7,
		/// Inform message type
		DHCP_INFORM = 8
	};

	/// DHCP option types.
	enum DhcpOptionTypes
	{
		/// Unknown option type
		DHCPOPT_UNKNOWN = -1,
		/// Pad
		DHCPOPT_PAD = 0,
		/// Subnet Mask Value
		DHCPOPT_SUBNET_MASK = 1,
		/// Time Offset in Seconds from UTC
		DHCPOPT_TIME_OFFSET = 2,
		/// N/4 Router addresses
		DHCPOPT_ROUTERS = 3,
		/// N/4 Timeserver addresses
		DHCPOPT_TIME_SERVERS = 4,
		/// N/4 IEN-116 Server addresses
		DHCPOPT_NAME_SERVERS = 5,
		/// N/4 DNS Server addresses
		DHCPOPT_DOMAIN_NAME_SERVERS = 6,
		/// N/4 Logging Server addresses
		DHCPOPT_LOG_SERVERS = 7,
		/// N/4 Quotes Server addresses
		DHCPOPT_QUOTES_SERVERS = 8,
		/// N/4 Quotes Server addresses
		DHCPOPT_LPR_SERVERS = 9,
		/// N/4 Quotes Server addresses
		DHCPOPT_IMPRESS_SERVERS = 10,
		/// N/4 RLP Server addresses
		DHCPOPT_RESOURCE_LOCATION_SERVERS = 11,
		/// Hostname string
		DHCPOPT_HOST_NAME = 12,
		/// Size of boot file in 512 byte chunks
		DHCPOPT_BOOT_SIZE = 13,
		/// Client to dump and name the file to dump it to
		DHCPOPT_MERIT_DUMP = 14,
		/// The DNS domain name of the client
		DHCPOPT_DOMAIN_NAME = 15,
		/// Swap Server address
		DHCPOPT_SWAP_SERVER = 16,
		/// Path name for root disk
		DHCPOPT_ROOT_PATH = 17,
		/// Path name for more BOOTP info
		DHCPOPT_EXTENSIONS_PATH = 18,
		/// Enable/Disable IP Forwarding
		DHCPOPT_IP_FORWARDING = 19,
		/// Enable/Disable Source Routing
		DHCPOPT_NON_LOCAL_SOURCE_ROUTING = 20,
		/// Routing Policy Filters
		DHCPOPT_POLICY_FILTER = 21,
		/// Max Datagram Reassembly Size
		DHCPOPT_MAX_DGRAM_REASSEMBLY = 22,
		/// Default IP Time to Live
		DEFAULT_IP_TTL = 23,
		/// Path MTU Aging Timeout
		DHCPOPT_PATH_MTU_AGING_TIMEOUT = 24,
		/// Path MTU Plateau Table
		PATH_MTU_PLATEAU_TABLE = 25,
		/// Interface MTU Size
		DHCPOPT_INTERFACE_MTU = 26,
		/// All Subnets are Local
		DHCPOPT_ALL_SUBNETS_LOCAL = 27,
		/// Broadcast Address
		DHCPOPT_BROADCAST_ADDRESS = 28,
		/// Perform Mask Discovery
		DHCPOPT_PERFORM_MASK_DISCOVERY = 29,
		/// Provide Mask to Others
		DHCPOPT_MASK_SUPPLIER = 30,
		/// Perform Router Discovery
		DHCPOPT_ROUTER_DISCOVERY = 31,
		/// Router Solicitation Address
		DHCPOPT_ROUTER_SOLICITATION_ADDRESS = 32,
		/// Static Routing Table
		DHCPOPT_STATIC_ROUTES = 33,
		/// Trailer Encapsulation
		DHCPOPT_TRAILER_ENCAPSULATION = 34,
		/// ARP Cache Timeout
		DHCPOPT_ARP_CACHE_TIMEOUT = 35,
		/// IEEE802.3 Encapsulation
		DHCPOPT_IEEE802_3_ENCAPSULATION = 36,
		/// Default TCP Time to Live
		DHCPOPT_DEFAULT_TCP_TTL = 37,
		/// TCP Keepalive Interval
		DHCPOPT_TCP_KEEPALIVE_INTERVAL = 38,
		/// TCP Keepalive Garbage
		DHCPOPT_TCP_KEEPALIVE_GARBAGE = 39,
		/// NIS Domain Name
		DHCPOPT_NIS_DOMAIN = 40,
		/// NIS Server Addresses
		DHCPOPT_NIS_SERVERS = 41,
		/// NTP Server Addresses
		DHCPOPT_NTP_SERVERS = 42,
		/// Vendor Specific Information
		DHCPOPT_VENDOR_ENCAPSULATED_OPTIONS = 43,
		/// NETBIOS Name Servers
		DHCPOPT_NETBIOS_NAME_SERVERS = 44,
		/// NETBIOS Datagram Distribution
		DHCPOPT_NETBIOS_DD_SERVER = 45,
		/// NETBIOS Node Type
		DHCPOPT_NETBIOS_NODE_TYPE = 46,
		/// NETBIOS Scope
		DHCPOPT_NETBIOS_SCOPE = 47,
		/// X Window Font Server
		DHCPOPT_FONT_SERVERS = 48,
		/// X Window Display Manager
		DHCPOPT_X_DISPLAY_MANAGER = 49,
		/// Requested IP Address
		DHCPOPT_DHCP_REQUESTED_ADDRESS = 50,
		/// IP Address Lease Time
		DHCPOPT_DHCP_LEASE_TIME = 51,
		/// Overload "sname" or "file"
		DHCPOPT_DHCP_OPTION_OVERLOAD = 52,
		/// DHCP Message Type
		DHCPOPT_DHCP_MESSAGE_TYPE = 53,
		/// DHCP Server Identification
		DHCPOPT_DHCP_SERVER_IDENTIFIER = 54,
		/// Parameter Request List
		DHCPOPT_DHCP_PARAMETER_REQUEST_LIST = 55,
		/// DHCP Error Message
		DHCPOPT_DHCP_MESSAGE = 56,
		/// DHCP Maximum Message Size
		DHCPOPT_DHCP_MAX_MESSAGE_SIZE = 57,
		/// DHCP Renewal (T1) Time
		DHCPOPT_DHCP_RENEWAL_TIME = 58,
		/// DHCP Rebinding (T2) Time
		DHCPOPT_DHCP_REBINDING_TIME = 59,
		/// Class Identifier
		DHCPOPT_VENDOR_CLASS_IDENTIFIER = 60,
		/// Class Identifier
		DHCPOPT_DHCP_CLIENT_IDENTIFIER = 61,
		/// NetWare/IP Domain Name
		DHCPOPT_NWIP_DOMAIN_NAME = 62,
		/// NetWare/IP sub Options
		DHCPOPT_NWIP_SUBOPTIONS = 63,
		/// NIS+ v3 Client Domain Name
		DHCPOPT_NIS_DOMAIN_NAME = 64,
		/// NIS+ v3 Server Addresses
		DHCPOPT_NIS_SERVER_ADDRESS = 65,
		/// TFTP Server Name
		DHCPOPT_TFTP_SERVER_NAME = 66,
		/// Boot File Name
		DHCPOPT_BOOTFILE_NAME = 67,
		/// Home Agent Addresses
		DHCPOPT_HOME_AGENT_ADDRESS = 68,
		/// Simple Mail Server (SMTP) Addresses
		DHCPOPT_SMTP_SERVER = 69,
		/// Post Office (POP3) Server Addresses
		DHCPOPT_POP3_SERVER = 70,
		/// Network News (NNTP) Server Addresses
		DHCPOPT_NNTP_SERVER = 71,
		/// WWW Server Addresses
		DHCPOPT_WWW_SERVER = 72,
		/// Finger Server Addresses
		DHCPOPT_FINGER_SERVER = 73,
		/// Chat (IRC) Server Addresses
		DHCPOPT_IRC_SERVER = 74,
		/// StreetTalk Server Addresses
		DHCPOPT_STREETTALK_SERVER = 75,
		/// ST Directory Assist. Addresses
		DHCPOPT_STDA_SERVER = 76,
		/// User Class Information
		DHCPOPT_USER_CLASS = 77,
		/// Directory Agent Information
		DHCPOPT_DIRECTORY_AGENT = 78,
		/// Service Location Agent Scope
		DHCPOPT_SERVICE_SCOPE = 79,
		/// Rapid Commit
		DHCPOPT_RAPID_COMMIT = 80,
		/// Fully Qualified Domain Name
		DHCPOPT_FQDN = 81,
		/// Relay Agent Information
		DHCPOPT_DHCP_AGENT_OPTIONS = 82,
		/// Internet Storage Name Service
		DHCPOPT_ISNS = 83,
		/// Novell Directory Services
		DHCPOPT_NDS_SERVERS = 85,
		/// Novell Directory Services
		DHCPOPT_NDS_TREE_NAME = 86,
		/// Novell Directory Services
		DHCPOPT_NDS_CONTEXT = 87,
		/// BCMCS Controller Domain Name list
		DHCPOPT_BCMCS_CONTROLLER_DOMAIN_NAME_LIST = 88,
		/// BCMCS Controller IPv4 address option
		DHCPOPT_BCMCS_CONTROLLER_IPV4_ADDRESS = 89,
		/// Authentication
		DHCPOPT_AUTHENTICATION = 90,
		/// Client Last Transaction Time
		DHCPOPT_CLIENT_LAST_TXN_TIME = 91,
		/// Associated IP
		DHCPOPT_ASSOCIATED_IP = 92,
		/// Client System Architecture
		DHCPOPT_CLIENT_SYSTEM = 93,
		/// Client Network Device Interface
		DHCPOPT_CLIENT_NDI = 94,
		/// Lightweight Directory Access Protocol [
		DHCPOPT_LDAP = 95,
		/// UUID/GUID-based Client Identifier
		DHCPOPT_UUID_GUID = 97,
		/// Open Group's User Authentication
		DHCPOPT_USER_AUTH = 98,
		/// GEOCONF_CIVIC
		DHCPOPT_GEOCONF_CIVIC = 99,
		/// IEEE 1003.1 TZ String
		DHCPOPT_PCODE = 100,
		/// Reference to the TZ Database
		DHCPOPT_TCODE = 101,
		/// NetInfo Parent Server Address
		DHCPOPT_NETINFO_ADDRESS = 112,
		/// NetInfo Parent Server Tag
		DHCPOPT_NETINFO_TAG = 113,
		/// URL
		DHCPOPT_URL = 114,
		/// DHCP Auto-Configuration
		DHCPOPT_AUTO_CONFIG = 116,
		/// Name Service Search
		DHCPOPT_NAME_SERVICE_SEARCH = 117,
		/// Subnet Selection Option
		DHCPOPT_SUBNET_SELECTION = 118,
		/// DNS Domain Search List
		DHCPOPT_DOMAIN_SEARCH = 119,
		/// SIP Servers DHCP Option
		DHCPOPT_SIP_SERVERS = 120,
		/// Classless Static Route Option
		DHCPOPT_CLASSLESS_STATIC_ROUTE = 121,
		/// CableLabs Client Configuration
		DHCPOPT_CCC = 122,
		/// GeoConf Option
		DHCPOPT_GEOCONF = 123,
		/// Vendor-Identifying Vendor Class
		DHCPOPT_V_I_VENDOR_CLASS = 124,
		/// Vendor-Identifying Vendor-Specific Information
		DHCPOPT_V_I_VENDOR_OPTS = 125,
		/// OPTION_PANA_AGENT
		DHCPOPT_OPTION_PANA_AGENT = 136,
		/// OPTION_V4_LOST
		DHCPOPT_OPTION_V4_LOST = 137,
		/// CAPWAP Access Controller addresses
		DHCPOPT_OPTION_CAPWAP_AC_V4 = 138,
		/// A Series Of Suboptions
		DHCPOPT_OPTION_IPV4_ADDRESS_MOS = 139,
		/// A Series Of Suboptions
		DHCPOPT_OPTION_IPV4_FQDN_MOS = 140,
		/// List of domain names to search for SIP User Agent Configuration
		DHCPOPT_SIP_UA_CONFIG = 141,
		/// ANDSF IPv4 Address Option for DHCPv4
		DHCPOPT_OPTION_IPV4_ADDRESS_ANDSF = 142,
		/// Geospatial Location with Uncertainty [RF
		DHCPOPT_GEOLOC = 144,
		/// Forcerenew Nonce Capable
		DHCPOPT_FORCERENEW_NONCE_CAPABLE = 145,
		/// Information for selecting RDNSS
		DHCPOPT_RDNSS_SELECTION = 146,
		/// Status code and optional N byte text message describing status
		DHCPOPT_STATUS_CODE = 151,
		/// Absolute time (seconds since Jan 1, 1970) message was sent
		DHCPOPT_BASE_TIME = 152,
		/// Number of seconds in the past when client entered current state
		DHCPOPT_START_TIME_OF_STATE = 153,
		/// Absolute time (seconds since Jan 1, 1970) for beginning of query
		DHCPOPT_QUERY_START_TIME = 154,
		/// Absolute time (seconds since Jan 1, 1970) for end of query
		DHCPOPT_QUERY_END_TIME = 155,
		/// State of IP address
		DHCPOPT_DHCP_STATE = 156,
		/// Indicates information came from local or remote server
		DHCPOPT_DATA_SOURCE = 157,
		/// Includes one or multiple lists of PCP server IP addresses; each list is treated as a separate PCP server
		DHCPOPT_OPTION_V4_PCP_SERVER = 158,
		/// This option is used to configure a set of ports bound to a shared IPv4 address
		DHCPOPT_OPTION_V4_PORTPARAMS = 159,
		/// DHCP Captive-Portal
		DHCPOPT_CAPTIVE_PORTAL = 160,
		/// Manufacturer Usage Descriptions
		DHCPOPT_OPTION_MUD_URL_V4 = 161,
		/// Etherboot
		DHCPOPT_ETHERBOOT = 175,
		/// IP Telephone
		DHCPOPT_IP_TELEPHONE = 176,
		/// Magic string = F1:00:74:7E
		DHCPOPT_PXELINUX_MAGIC = 208,
		/// Configuration file
		DHCPOPT_CONFIGURATION_FILE = 209,
		/// Path Prefix Option
		DHCPOPT_PATH_PREFIX = 210,
		/// Reboot Time
		DHCPOPT_REBOOT_TIME = 211,
		/// OPTION_6RD with N/4 6rd BR addresses
		DHCPOPT_OPTION_6RD = 212,
		/// Access Network Domain Name
		DHCPOPT_OPTION_V4_ACCESS_DOMAIN = 213,
		/// Subnet Allocation Option
		DHCPOPT_SUBNET_ALLOCATION = 220,
		/// Virtual Subnet Selection (VSS) Option
		DHCPOPT_VIRTUAL_SUBNET_SELECTION = 221,
		/// End (last option)
		DHCPOPT_END = 255
	};

	/// @class DhcpOption
	/// A wrapper class for DHCP options. This class does not create or modify DHCP option records, but rather
	/// serves as a wrapper and provides useful methods for setting and retrieving data to/from them
	class DhcpOption : public TLVRecord<uint8_t, uint8_t>
	{
	public:
		/// A c'tor for this class that gets a pointer to the option raw data (byte array)
		/// @param[in] optionRawData A pointer to the option raw data
		explicit DhcpOption(uint8_t* optionRawData) : TLVRecord(optionRawData)
		{}

		/// A d'tor for this class, currently does nothing
		~DhcpOption() override = default;

		/// Retrieve DHCP option data as IPv4 address. Relevant only if option value is indeed an IPv4 address
		/// @return DHCP option data as IPv4 address
		IPv4Address getValueAsIpAddr() const
		{
			return getValueAs<uint32_t>();
		}

		/// Set DHCP option data as IPv4 address. This method copies the 4 bytes of the IP address to the option value
		/// @param[in] addr The IPv4 address to set
		/// @param[in] valueOffset An optional parameter that specifies where to start set the option data (default set
		/// to 0). For example: if option data is 20 bytes long and you want to set the IP address in the 4 last bytes
		/// then use this method like this: setValueIpAddr(your_addr, 16)
		void setValueIpAddr(const IPv4Address& addr, int valueOffset = 0)
		{
			setValue<uint32_t>(addr.toInt(), valueOffset);
		}

		/// Retrieve DHCP option data as string. Relevant only if option value is indeed a string
		/// @param[in] valueOffset An optional parameter that specifies where to start copy the DHCP option data. For
		/// example: when retrieving Client FQDN option, you may ignore the flags and RCODE fields using this method
		/// like this: getValueAsString(3). The default is 0 - start copying from the beginning of option data
		/// @return DHCP option data as string
		std::string getValueAsString(int valueOffset = 0) const
		{
			if (m_Data == nullptr || m_Data->recordLen - valueOffset < 1)
				return "";

			return std::string(reinterpret_cast<const char*>(m_Data->recordValue) + valueOffset,
			                   static_cast<int>(m_Data->recordLen) - valueOffset);
		}

		/// Set DHCP option data as string. This method copies the string to the option value. If the string is longer
		/// than option length the string is trimmed so it will fit the option length
		/// @param[in] stringValue The string to set
		/// @param[in] valueOffset An optional parameter that specifies where to start set the option data (default set
		/// to 0). For example: if option data is 20 bytes long and you want to set a 6 char-long string in the 6 last
		/// bytes then use this method like this: setValueString("string", 14)
		void setValueString(const std::string& stringValue, int valueOffset = 0)
		{
			// calculate the maximum length of the destination buffer
			size_t len = static_cast<size_t>(m_Data->recordLen) - static_cast<size_t>(valueOffset);

			// use the length of input string if a buffer is large enough for whole string
			if (stringValue.length() < len)
				len = stringValue.length();

			memcpy(m_Data->recordValue + valueOffset, stringValue.data(), len);
		}

		/// Check if a pointer can be assigned to the TLV record data
		/// @param[in] recordRawData A pointer to the TLV record raw data
		/// @param[in] tlvDataLen The size of the TLV record raw data
		/// @return True if data is valid and can be assigned
		static bool canAssign(const uint8_t* recordRawData, size_t tlvDataLen)
		{
			auto data = reinterpret_cast<TLVRawData const*>(recordRawData);
			if (data == nullptr)
				return false;

			if (tlvDataLen < sizeof(TLVRawData::recordType))
				return false;

			if (data->recordType == static_cast<uint8_t>(DHCPOPT_END) ||
			    data->recordType == static_cast<uint8_t>(DHCPOPT_PAD))
				return true;

			return TLVRecord<uint8_t, uint8_t>::canAssign(recordRawData, tlvDataLen);
		}

		// implement abstract methods

		size_t getTotalSize() const override
		{
			if (m_Data == nullptr)
				return 0;

			if (m_Data->recordType == static_cast<uint8_t>(DHCPOPT_END) ||
			    m_Data->recordType == static_cast<uint8_t>(DHCPOPT_PAD))
				return sizeof(uint8_t);

			return sizeof(uint8_t) * 2 + static_cast<size_t>(m_Data->recordLen);
		}

		size_t getDataSize() const override
		{
			if (m_Data == nullptr)
				return 0;

			if (m_Data->recordType == static_cast<uint8_t>(DHCPOPT_END) ||
			    m_Data->recordType == static_cast<uint8_t>(DHCPOPT_PAD))
				return 0;

			return m_Data->recordLen;
		}
	};

	/// @class DhcpOptionBuilder
	/// A class for building DHCP options. This builder receives the option parameters in its c'tor,
	/// builds the DHCP option raw buffer and provides a build() method to get a DhcpOption object out of it
	class DhcpOptionBuilder : public TLVRecordBuilder
	{
	public:
		/// A c'tor for building DHCP options which their value is a byte array. The DhcpOption object can later
		/// be retrieved by calling build()
		/// @param[in] optionType DHCP option type
		/// @param[in] optionValue A buffer containing the option value. This buffer is read-only and isn't modified in
		/// any way
		/// @param[in] optionValueLen DHCP option value length in bytes
		DhcpOptionBuilder(DhcpOptionTypes optionType, const uint8_t* optionValue, uint8_t optionValueLen)
		    : TLVRecordBuilder(static_cast<uint8_t>(optionType), optionValue, optionValueLen)
		{}

		/// A c'tor for building DHCP options which have a 1-byte value. The DhcpOption object can later be retrieved
		/// by calling build()
		/// @param[in] optionType DHCP option type
		/// @param[in] optionValue A 1-byte option value
		DhcpOptionBuilder(DhcpOptionTypes optionType, uint8_t optionValue)
		    : TLVRecordBuilder(static_cast<uint8_t>(optionType), optionValue)
		{}

		/// A c'tor for building DHCP options which have a 2-byte value. The DhcpOption object can later be retrieved
		/// by calling build()
		/// @param[in] optionType DHCP option type
		/// @param[in] optionValue A 2-byte option value
		DhcpOptionBuilder(DhcpOptionTypes optionType, uint16_t optionValue)
		    : TLVRecordBuilder(static_cast<uint8_t>(optionType), optionValue)
		{}

		/// A c'tor for building DHCP options which have a 4-byte value. The DhcpOption object can later be retrieved
		/// by calling build()
		/// @param[in] optionType DHCP option type
		/// @param[in] optionValue A 4-byte option value
		DhcpOptionBuilder(DhcpOptionTypes optionType, uint32_t optionValue)
		    : TLVRecordBuilder(static_cast<uint8_t>(optionType), optionValue)
		{}

		/// A c'tor for building DHCP options which have an IPv4Address value. The DhcpOption object can later be
		/// retrieved by calling build()
		/// @param[in] optionType DHCP option type
		/// @param[in] optionValue The IPv4 address option value
		DhcpOptionBuilder(DhcpOptionTypes optionType, const IPv4Address& optionValue)
		    : TLVRecordBuilder(static_cast<uint8_t>(optionType), optionValue)
		{}

		/// A c'tor for building DHCP options which have a string value. The DhcpOption object can later be retrieved
		/// by calling build()
		/// @param[in] optionType DHCP option type
		/// @param[in] optionValue The string option value
		DhcpOptionBuilder(DhcpOptionTypes optionType, const std::string& optionValue)
		    : TLVRecordBuilder(static_cast<uint8_t>(optionType), optionValue)
		{}

		/// A copy c'tor which copies all the data from another instance of DhcpOptionBuilder
		/// @param[in] other The instance to copy from
		DhcpOptionBuilder(const DhcpOptionBuilder& other) : TLVRecordBuilder(other)
		{}

		/// Assignment operator that copies all data from another instance of DhcpOptionBuilder
		/// @param[in] other The instance to assign from
		/// @return A reference to the assignee
		DhcpOptionBuilder& operator=(const DhcpOptionBuilder& other)
		{
			TLVRecordBuilder::operator=(other);
			return *this;
		}

		/// Build the DhcpOption object out of the parameters defined in the c'tor
		/// @return The DhcpOption object
		DhcpOption build() const;
	};

	/// @class DhcpLayer
	/// Represents a DHCP (Dynamic Host Configuration Protocol) protocol layer
	class DhcpLayer : public Layer
	{
	public:
		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		DhcpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/// A constructor that creates the layer from scratch. Adds a ::DHCPOPT_DHCP_MESSAGE_TYPE and a ::DHCPOPT_END
		/// options
		/// @param[in] msgType A DHCP message type to be set
		/// @param[in] clientMacAddr A client MAC address to set in dhcp_header#clientHardwareAddress field
		DhcpLayer(DhcpMessageType msgType, const MacAddress& clientMacAddr);

		/// A constructor that creates the layer from scratch with clean data
		DhcpLayer();

		/// A destructor for this layer
		~DhcpLayer() override = default;

		/// Get a pointer to the DHCP header. Notice this points directly to the data, so every change will change the
		/// actual packet data
		/// @return A pointer to the @ref dhcp_header
		dhcp_header* getDhcpHeader() const
		{
			return reinterpret_cast<dhcp_header*>(m_Data);
		}

		/// @return The BootP opcode of this message
		BootpOpCodes getOpCode() const
		{
			return static_cast<BootpOpCodes>(getDhcpHeader()->opCode);
		}

		/// @return The client IPv4 address (as extracted from dhcp_header#clientIpAddress converted to IPv4Address
		/// object)
		IPv4Address getClientIpAddress() const
		{
			return getDhcpHeader()->clientIpAddress;
		}

		/// Set the client IPv4 address in dhcp_header#clientIpAddress
		/// @param[in] addr The IPv4 address to set
		void setClientIpAddress(const IPv4Address& addr)
		{
			getDhcpHeader()->clientIpAddress = addr.toInt();
		}

		/// @return The server IPv4 address (as extracted from dhcp_header#serverIpAddress converted to IPv4Address
		/// object)
		IPv4Address getServerIpAddress() const
		{
			return getDhcpHeader()->serverIpAddress;
		}

		/// Set the server IPv4 address in dhcp_header#serverIpAddress
		/// @param[in] addr The IPv4 address to set
		void setServerIpAddress(const IPv4Address& addr)
		{
			getDhcpHeader()->serverIpAddress = addr.toInt();
		}

		/// @return Your IPv4 address (as extracted from dhcp_header#yourIpAddress converted to IPv4Address object)
		IPv4Address getYourIpAddress() const
		{
			return getDhcpHeader()->yourIpAddress;
		}

		/// Set your IPv4 address in dhcp_header#yourIpAddress
		/// @param[in] addr The IPv4 address to set
		void setYourIpAddress(const IPv4Address& addr)
		{
			getDhcpHeader()->yourIpAddress = addr.toInt();
		}

		/// @return Gateway IPv4 address (as extracted from dhcp_header#gatewayIpAddress converted to IPv4Address
		/// object)
		IPv4Address getGatewayIpAddress() const
		{
			return getDhcpHeader()->gatewayIpAddress;
		}

		/// Set the gateway IPv4 address in dhcp_header#gatewayIpAddress
		/// @param[in] addr The IPv4 address to set
		void setGatewayIpAddress(const IPv4Address& addr)
		{
			getDhcpHeader()->gatewayIpAddress = addr.toInt();
		}

		/// @return The client MAC address as extracted from dhcp_header#clientHardwareAddress, assuming
		/// dhcp_header#hardwareType is 1 (Ethernet) and dhcp_header#hardwareAddressLength is 6 (MAC address length).
		/// Otherwise returns MacAddress#Zero
		MacAddress getClientHardwareAddress() const;

		/// Set a MAC address into the first 6 bytes of dhcp_header#clientHardwareAddress. This method also sets
		/// dhcp_header#hardwareType to 1 (Ethernet) and dhcp_header#hardwareAddressLength to 6 (MAC address length)
		/// @param[in] addr The MAC address to set
		void setClientHardwareAddress(const MacAddress& addr);

		/// @return DHCP message type as extracted from ::DHCPOPT_DHCP_MESSAGE_TYPE option. If this option doesn't exist
		/// the value of
		/// ::DHCP_UNKNOWN_MSG_TYPE is returned
		DhcpMessageType getMessageType() const;

		/// Set DHCP message type. This method searches for existing ::DHCPOPT_DHCP_MESSAGE_TYPE option. If found, it
		/// sets the requested message type as its value. If not, it creates a ::DHCPOPT_DHCP_MESSAGE_TYPE option and
		/// sets the requested message type as its value
		/// @param[in] msgType Message type to set
		/// @return True if message type was set successfully or false if msgType is ::DHCP_UNKNOWN_MSG_TYPE or if
		/// failed to add
		/// ::DHCPOPT_DHCP_MESSAGE_TYPE option
		bool setMessageType(DhcpMessageType msgType);

		/// @return The first DHCP option in the packet. If there are no DHCP options the returned value will contain
		/// a logical null (DhcpOption#isNull() == true)
		DhcpOption getFirstOptionData() const;

		/// Get the DHCP option that comes after a given option. If the given option was the last one, the
		/// returned value will contain a logical null (DhcpOption#isNull() == true)
		/// @param[in] dhcpOption A given DHCP option
		/// @return A DhcpOption object containing the option data that comes next, or logical null if the given DHCP
		/// option: (1) was the last one; (2) contains a logical null or (3) doesn't belong to this packet
		DhcpOption getNextOptionData(DhcpOption dhcpOption) const;

		/// Get a DHCP option by type
		/// @param[in] option DHCP option type
		/// @return A DhcpOption object containing the first DHCP option data that matches this type, or logical null
		/// (DhcpOption#isNull() == true) if no such option found
		DhcpOption getOptionData(DhcpOptionTypes option) const;

		/// @return The number of DHCP options in this layer
		size_t getOptionsCount() const;

		/// Add a new DHCP option at the end of the layer
		/// @param[in] optionBuilder A DhcpOptionBuilder object that contains the requested DHCP option data to add
		/// @return A DhcpOption object containing the newly added DHCP option data or logical null
		/// (DhcpOption#isNull() == true) if addition failed
		DhcpOption addOption(const DhcpOptionBuilder& optionBuilder);

		/// Add a new DHCP option after an existing one
		/// @param[in] optionBuilder A DhcpOptionBuilder object that contains the requested DHCP option data to add
		/// @param[in] prevOption The DHCP option type which the newly added option will come after
		/// @return A DhcpOption object containing the newly added DHCP option data or logical null
		/// (DhcpOption#isNull() == true) if addition failed
		DhcpOption addOptionAfter(const DhcpOptionBuilder& optionBuilder, DhcpOptionTypes prevOption);

		/// Remove an existing DHCP option from the layer
		/// @param[in] optionType The DHCP option type to remove
		/// @return True if DHCP option was successfully removed or false if type wasn't found or if removal failed
		bool removeOption(DhcpOptionTypes optionType);

		/// Remove all DHCP options in this layer
		/// @return True if all DHCP options were successfully removed or false if removal failed for some reason
		bool removeAllOptions();

		/// A static method that checks whether a pair of ports are considered DHCP ports
		/// @param[in] portSrc The source port number to check
		/// @param[in] portDst The destination port number to check
		/// @return True if these are DHCP port numbers, false otherwise
		static inline bool isDhcpPorts(uint16_t portSrc, uint16_t portDst);

		// implement abstract methods

		/// Does nothing for this layer (DhcpLayer is always last)
		void parseNextLayer() override
		{}

		/// @return The size of @ref dhcp_header + size of options
		size_t getHeaderLen() const override
		{
			return m_DataLen;
		}

		/// Calculate the following fields:
		/// - @ref dhcp_header#magicNumber = DHCP magic number (0x63538263)
		/// - @ref dhcp_header#opCode = ::DHCP_BOOTREQUEST for message types: ::DHCP_DISCOVER, ::DHCP_REQUEST,
		/// ::DHCP_DECLINE, ::DHCP_RELEASE,
		///                            ::DHCP_INFORM, ::DHCP_UNKNOWN_MSG_TYPE
		///                            ::DHCP_BOOTREPLY for message types: ::DHCP_OFFER, ::DHCP_ACK, ::DHCP_NAK
		/// - @ref dhcp_header#hardwareType = 1 (Ethernet)
		/// - @ref dhcp_header#hardwareAddressLength = 6 (MAC address length)
		void computeCalculateFields() override;

		std::string toString() const override;

		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelApplicationLayer;
		}

	private:
		uint8_t* getOptionsBasePtr() const
		{
			return m_Data + sizeof(dhcp_header);
		}

		TLVRecordReader<DhcpOption> m_OptionReader;

		void initDhcpLayer(size_t numOfBytesToAllocate);

		DhcpOption addOptionAt(const DhcpOptionBuilder& optionBuilder, int offset);
	};

	// implementation of inline methods

	bool DhcpLayer::isDhcpPorts(uint16_t portSrc, uint16_t portDst)
	{
		return ((portSrc == 68 && portDst == 67) || (portSrc == 67 && portDst == 68) ||
		        (portSrc == 67 && portDst == 67));
	}

}  // namespace pcpp
