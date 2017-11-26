#ifndef PACKETPP_DHCP_LAYER
#define PACKETPP_DHCP_LAYER

#include "Layer.h"
#include "IpAddress.h"
#include "MacAddress.h"
#include <string.h>

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * @struct dhcp_header
	 * Represents a DHCP protocol header
	 */
	#pragma pack(push, 1)
	struct dhcp_header {
		/** BootP opcode */
        uint8_t opCode;
        /** Hardware type, set to 1 (Ethernet) by default */
        uint8_t hardwareType;
        /** Hardware address length, set to 6 (MAC address length) by default */
        uint8_t hardwareAddressLength;
        /** Hop count */
        uint8_t hops;
        /** DHCP/BootP transaction ID */
        uint32_t transactionID;
        /** The elapsed time, in seconds since the client sent its first BOOTREQUEST message */
        uint16_t secondsElapsed;
        /** BootP flags */
        uint16_t flags;
        /** Client IPv4 address */
        uint32_t clientIpAddress;
        /** Your IPv4 address */
        uint32_t yourIpAddress;
        /** Server IPv4 address */
        uint32_t serverIpAddress;
        /** Gateway IPv4 address */
        uint32_t gatewayIpAddress;
        /** Client hardware address, by default contains the MAC address (only 6 first bytes are used) */
        uint8_t clientHardwareAddress[16];
        /** BootP server name */
        uint8_t serverName[64];
        /** BootP boot file name */
        uint8_t bootFilename[128];
        /** DHCP magic number (set to the default value of 0x63538263) */
        uint32_t magicNumber;
	};
	#pragma pack(pop)


	/**
	 * BootP opcodes
	 */
	enum BootpOpCodes
	{
		/** BootP request */
		DHCP_BOOTREQUEST = 1,
		/** BootP reply */
		DHCP_BOOTREPLY = 2
	};

    /**
     * DHCP message types
     */
    enum DhcpMessageType {
    	/** Unknown message type */
    	DHCP_UNKNOWN_MSG_TYPE = 0,
    	/** Discover message type */
    	DHCP_DISCOVER         = 1,
    	/** Offer message type */
    	DHCP_OFFER            = 2,
    	/** Request message type */
    	DHCP_REQUEST          = 3,
    	/** Decline message type */
    	DHCP_DECLINE          = 4,
    	/** Acknowledge message type */
    	DHCP_ACK              = 5,
    	/** Non-acknowledge message type */
    	DHCP_NAK              = 6,
    	/** Release message type */
    	DHCP_RELEASE          = 7,
    	/** Inform message type */
    	DHCP_INFORM           = 8
    };

    /**
     * DHCP option types.
     */
    enum DhcpOptionTypes {
    	/** Unknown option type */
    	DHCPOPT_UNKNOWN = -1,
    	/** Pad */
    	DHCPOPT_PAD = 0,
    	/** Subnet Mask Value */
    	DHCPOPT_SUBNET_MASK = 1,
    	/** Time Offset in Seconds from UTC */
    	DHCPOPT_TIME_OFFSET = 2,
    	/** N/4 Router addresses */
    	DHCPOPT_ROUTERS = 3,
    	/** N/4 Timeserver addresses */
    	DHCPOPT_TIME_SERVERS = 4,
    	/** N/4 IEN-116 Server addresses */
    	DHCPOPT_NAME_SERVERS = 5,
    	/** N/4 DNS Server addresses */
    	DHCPOPT_DOMAIN_NAME_SERVERS = 6,
    	/** N/4 Logging Server addresses */
    	DHCPOPT_LOG_SERVERS = 7,
    	/** N/4 Quotes Server addresses */
    	DHCPOPT_QUOTES_SERVERS = 8,
    	/** N/4 Quotes Server addresses */
    	DHCPOPT_LPR_SERVERS = 9,
    	/** N/4 Quotes Server addresses */
    	DHCPOPT_IMPRESS_SERVERS = 10,
    	/** N/4 RLP Server addresses */
    	DHCPOPT_RESOURCE_LOCATION_SERVERS = 11,
    	/** Hostname string */
    	DHCPOPT_HOST_NAME = 12,
    	/** Size of boot file in 512 byte chunks */
    	DHCPOPT_BOOT_SIZE = 13,
    	/** Client to dump and name the file to dump it to */
    	DHCPOPT_MERIT_DUMP = 14,
    	/** The DNS domain name of the client */
    	DHCPOPT_DOMAIN_NAME = 15,
    	/** Swap Server address */
    	DHCPOPT_SWAP_SERVER = 16,
    	/** Path name for root disk */
    	DHCPOPT_ROOT_PATH = 17,
    	/** Path name for more BOOTP info */
    	DHCPOPT_EXTENSIONS_PATH = 18,
    	/** Enable/Disable IP Forwarding */
    	DHCPOPT_IP_FORWARDING = 19,
    	/** Enable/Disable Source Routing */
    	DHCPOPT_NON_LOCAL_SOURCE_ROUTING = 20,
    	/** Routing Policy Filters */
    	DHCPOPT_POLICY_FILTER = 21,
    	/** Max Datagram Reassembly Size */
    	DHCPOPT_MAX_DGRAM_REASSEMBLY = 22,
    	/** Default IP Time to Live */
    	DEFAULT_IP_TTL = 23,
    	/** Path MTU Aging Timeout */
    	DHCPOPT_PATH_MTU_AGING_TIMEOUT = 24,
    	/** Path MTU Plateau Table */
    	PATH_MTU_PLATEAU_TABLE = 25,
    	/** Interface MTU Size */
    	DHCPOPT_INTERFACE_MTU = 26,
    	/** All Subnets are Local */
    	DHCPOPT_ALL_SUBNETS_LOCAL = 27,
    	/** Broadcast Address */
    	DHCPOPT_BROADCAST_ADDRESS = 28,
    	/** Perform Mask Discovery */
    	DHCPOPT_PERFORM_MASK_DISCOVERY = 29,
    	/** Provide Mask to Others */
    	DHCPOPT_MASK_SUPPLIER = 30,
    	/** Perform Router Discovery */
    	DHCPOPT_ROUTER_DISCOVERY = 31,
    	/** Router Solicitation Address */
    	DHCPOPT_ROUTER_SOLICITATION_ADDRESS = 32,
    	/** Static Routing Table */
    	DHCPOPT_STATIC_ROUTES = 33,
    	/** Trailer Encapsulation */
    	DHCPOPT_TRAILER_ENCAPSULATION  =34,
    	/** ARP Cache Timeout */
    	DHCPOPT_ARP_CACHE_TIMEOUT = 35,
    	/** IEEE802.3 Encapsulation */
    	DHCPOPT_IEEE802_3_ENCAPSULATION = 36,
    	/** Default TCP Time to Live */
    	DHCPOPT_DEFAULT_TCP_TTL = 37,
    	/** TCP Keepalive Interval */
    	DHCPOPT_TCP_KEEPALIVE_INTERVAL = 38,
    	/** TCP Keepalive Garbage */
    	DHCPOPT_TCP_KEEPALIVE_GARBAGE = 39,
    	/** NIS Domain Name */
    	DHCPOPT_NIS_DOMAIN = 40,
    	/** NIS Server Addresses */
    	DHCPOPT_NIS_SERVERS = 41,
    	/** NTP Server Addresses */
    	DHCPOPT_NTP_SERVERS = 42,
    	/** Vendor Specific Information */
    	DHCPOPT_VENDOR_ENCAPSULATED_OPTIONS = 43,
    	/** NETBIOS Name Servers */
    	DHCPOPT_NETBIOS_NAME_SERVERS = 44,
    	/** NETBIOS Datagram Distribution */
    	DHCPOPT_NETBIOS_DD_SERVER = 45,
    	/** NETBIOS Node Type */
    	DHCPOPT_NETBIOS_NODE_TYPE = 46,
    	/** NETBIOS Scope */
    	DHCPOPT_NETBIOS_SCOPE = 47,
    	/** X Window Font Server */
    	DHCPOPT_FONT_SERVERS = 48,
    	/** X Window Display Manager */
    	DHCPOPT_X_DISPLAY_MANAGER = 49,
    	/** Requested IP Address */
    	DHCPOPT_DHCP_REQUESTED_ADDRESS = 50,
    	/** IP Address Lease Time */
    	DHCPOPT_DHCP_LEASE_TIME = 51,
    	/** Overload "sname" or "file" */
    	DHCPOPT_DHCP_OPTION_OVERLOAD = 52,
    	/** DHCP Message Type */
    	DHCPOPT_DHCP_MESSAGE_TYPE = 53,
    	/** DHCP Server Identification */
    	DHCPOPT_DHCP_SERVER_IDENTIFIER = 54,
    	/** Parameter Request List */
    	DHCPOPT_DHCP_PARAMETER_REQUEST_LIST = 55,
    	/** DHCP Error Message */
    	DHCPOPT_DHCP_MESSAGE = 56,
    	/** DHCP Maximum Message Size */
    	DHCPOPT_DHCP_MAX_MESSAGE_SIZE = 57,
    	/** DHCP Renewal (T1) Time */
    	DHCPOPT_DHCP_RENEWAL_TIME = 58,
    	/** DHCP Rebinding (T2) Time */
    	DHCPOPT_DHCP_REBINDING_TIME = 59,
    	/** Class Identifier */
    	DHCPOPT_VENDOR_CLASS_IDENTIFIER = 60,
    	/** Class Identifier */
    	DHCPOPT_DHCP_CLIENT_IDENTIFIER = 61,
    	/** NetWare/IP Domain Name */
    	DHCPOPT_NWIP_DOMAIN_NAME = 62,
    	/** NetWare/IP sub Options */
    	DHCPOPT_NWIP_SUBOPTIONS = 63,
    	/** NIS+ v3 Client Domain Name */
    	DHCPOPT_NIS_DOMAIN_NAME = 64,
    	/** NIS+ v3 Server Addresses */
    	DHCPOPT_NIS_SERVER_ADDRESS = 65,
    	/** TFTP Server Name */
    	DHCPOPT_TFTP_SERVER_NAME = 66,
    	/** Boot File Name */
    	DHCPOPT_BOOTFILE_NAME = 67,
    	/** Home Agent Addresses */
    	DHCPOPT_HOME_AGENT_ADDRESS = 68,
    	/** Simple Mail Server (SMTP) Addresses */
    	DHCPOPT_SMTP_SERVER = 69,
    	/** Post Office (POP3) Server Addresses */
    	DHCPOPT_POP3_SERVER = 70,
    	/** Network News (NNTP) Server Addresses */
    	DHCPOPT_NNTP_SERVER = 71,
    	/** WWW Server Addresses */
    	DHCPOPT_WWW_SERVER = 72,
    	/** Finger Server Addresses */
    	DHCPOPT_FINGER_SERVER = 73,
    	/** Chat (IRC) Server Addresses */
    	DHCPOPT_IRC_SERVER = 74,
    	/** StreetTalk Server Addresses */
    	DHCPOPT_STREETTALK_SERVER = 75,
    	/** ST Directory Assist. Addresses */
    	DHCPOPT_STDA_SERVER = 76,
    	/** User Class Information */
    	DHCPOPT_USER_CLASS = 77,
    	/** Directory Agent Information */
    	DHCPOPT_DIRECTORY_AGENT = 78,
    	/** Service Location Agent Scope */
    	DHCPOPT_SERVICE_SCOPE = 79,
    	/** Rapid Commit */
    	DHCPOPT_RAPID_COMMIT = 80,
    	/** Fully Qualified Domain Name */
    	DHCPOPT_FQDN = 81,
    	/** Relay Agent Information */
    	DHCPOPT_DHCP_AGENT_OPTIONS = 82,
    	/** Internet Storage Name Service */
    	DHCPOPT_ISNS = 83,
    	/** Novell Directory Services */
    	DHCPOPT_NDS_SERVERS = 85,
    	/** Novell Directory Services */
    	DHCPOPT_NDS_TREE_NAME = 86,
    	/** Novell Directory Services */
    	DHCPOPT_NDS_CONTEXT = 87,
    	/** BCMCS Controller Domain Name list */
    	DHCPOPT_BCMCS_CONTROLLER_DOMAIN_NAME_LIST = 88,
    	/** BCMCS Controller IPv4 address option */
    	DHCPOPT_BCMCS_CONTROLLER_IPV4_ADDRESS = 89,
    	/** Authentication */
    	DHCPOPT_AUTHENTICATION = 90,
    	/** Client Last Transaction Time */
    	DHCPOPT_CLIENT_LAST_TXN_TIME = 91,
    	/** Associated IP */
    	DHCPOPT_ASSOCIATED_IP = 92,
    	/** Client System Architecture */
    	DHCPOPT_CLIENT_SYSTEM = 93,
    	/** Client Network Device Interface */
    	DHCPOPT_CLIENT_NDI = 94,
    	/** Lightweight Directory Access Protocol 	[ */
    	DHCPOPT_LDAP = 95,
    	/** UUID/GUID-based Client Identifier */
    	DHCPOPT_UUID_GUID = 97,
    	/** Open Group's User Authentication */
    	DHCPOPT_USER_AUTH = 98,
    	/** GEOCONF_CIVIC */
    	DHCPOPT_GEOCONF_CIVIC = 99,
    	/** IEEE 1003.1 TZ String */
    	DHCPOPT_PCODE = 100,
    	/** Reference to the TZ Database */
    	DHCPOPT_TCODE = 101,
    	/** NetInfo Parent Server Address */
    	DHCPOPT_NETINFO_ADDRESS = 112,
    	/** NetInfo Parent Server Tag */
    	DHCPOPT_NETINFO_TAG = 113,
    	/** URL */
    	DHCPOPT_URL = 114,
    	/** DHCP Auto-Configuration */
    	DHCPOPT_AUTO_CONFIG = 116,
    	/** Name Service Search */
    	DHCPOPT_NAME_SERVICE_SEARCH = 117,
    	/** Subnet Selection Option */
    	DHCPOPT_SUBNET_SELECTION = 118,
    	/** DNS Domain Search List */
    	DHCPOPT_DOMAIN_SEARCH = 119,
    	/** SIP Servers DHCP Option */
    	DHCPOPT_SIP_SERVERS = 120,
    	/** Classless Static Route Option */
    	DHCPOPT_CLASSLESS_STATIC_ROUTE = 121,
    	/** CableLabs Client Configuration */
    	DHCPOPT_CCC = 122,
    	/** GeoConf Option */
    	DHCPOPT_GEOCONF = 123,
    	/** Vendor-Identifying Vendor Class */
    	DHCPOPT_V_I_VENDOR_CLASS = 124,
    	/** Vendor-Identifying Vendor-Specific Information */
    	DHCPOPT_V_I_VENDOR_OPTS = 125,
    	/** OPTION_PANA_AGENT */
    	DHCPOPT_OPTION_PANA_AGENT = 136,
    	/** OPTION_V4_LOST */
    	DHCPOPT_OPTION_V4_LOST  =137,
    	/** CAPWAP Access Controller addresses */
    	DHCPOPT_OPTION_CAPWAP_AC_V4 = 138,
    	/** A Series Of Suboptions */
    	DHCPOPT_OPTION_IPV4_ADDRESS_MOS = 139,
    	/** A Series Of Suboptions */
    	DHCPOPT_OPTION_IPV4_FQDN_MOS = 140,
    	/** List of domain names to search for SIP User Agent Configuration */
    	DHCPOPT_SIP_UA_CONFIG = 141,
    	/** ANDSF IPv4 Address Option for DHCPv4 */
    	DHCPOPT_OPTION_IPV4_ADDRESS_ANDSF = 142,
    	/** Geospatial Location with Uncertainty 	[RF */
    	DHCPOPT_GEOLOC = 144,
    	/** Forcerenew Nonce Capable */
    	DHCPOPT_FORCERENEW_NONCE_CAPABLE = 145,
    	/** Information for selecting RDNSS */
    	DHCPOPT_RDNSS_SELECTION = 146,
    	/** Status code and optional N byte text message describing status */
    	DHCPOPT_STATUS_CODE = 151,
    	/** Absolute time (seconds since Jan 1, 1970) message was sent */
    	DHCPOPT_BASE_TIME = 152,
    	/** Number of seconds in the past when client entered current state */
    	DHCPOPT_START_TIME_OF_STATE = 153,
    	/** Absolute time (seconds since Jan 1, 1970) for beginning of query */
    	DHCPOPT_QUERY_START_TIME = 154,
    	/** Absolute time (seconds since Jan 1, 1970) for end of query */
    	DHCPOPT_QUERY_END_TIME = 155,
    	/** State of IP address */
    	DHCPOPT_DHCP_STATE = 156,
    	/** Indicates information came from local or remote server */
    	DHCPOPT_DATA_SOURCE = 157,
    	/** Includes one or multiple lists of PCP server IP addresses; each list is treated as a separate PCP server */
    	DHCPOPT_OPTION_V4_PCP_SERVER = 158,
    	/** This option is used to configure a set of ports bound to a shared IPv4 address */
    	DHCPOPT_OPTION_V4_PORTPARAMS = 159,
    	/** DHCP Captive-Portal */
    	DHCPOPT_CAPTIVE_PORTAL = 160,
    	/** Manufacturer Usage Descriptions */
    	DHCPOPT_OPTION_MUD_URL_V4 = 161,
    	/** Etherboot  */
    	DHCPOPT_ETHERBOOT = 175,
    	/** IP Telephone */
    	DHCPOPT_IP_TELEPHONE = 176,
    	/** Magic string = F1:00:74:7E */
    	DHCPOPT_PXELINUX_MAGIC = 208,
    	/** Configuration file */
    	DHCPOPT_CONFIGURATION_FILE = 209,
    	/** Path Prefix Option */
    	DHCPOPT_PATH_PREFIX = 210,
    	/** Reboot Time */
    	DHCPOPT_REBOOT_TIME = 211,
    	/** OPTION_6RD with N/4 6rd BR addresses */
    	DHCPOPT_OPTION_6RD = 212,
    	/** Access Network Domain Name */
    	DHCPOPT_OPTION_V4_ACCESS_DOMAIN = 213,
    	/** Subnet Allocation Option */
    	DHCPOPT_SUBNET_ALLOCATION = 220,
    	/** Virtual Subnet Selection (VSS) Option */
    	DHCPOPT_VIRTUAL_SUBNET_SELECTION = 221,
    	/** End (last option) */
    	DHCPOPT_END	= 255
    };


	/**
	 * @struct DhcpOptionData
	 * Representing a DHCP option in a TLV (type-length-value) structure
	 */
	struct DhcpOptionData
	{
	public:
		/** DHCP option code, should be on of DhcpOptionTypes */
		uint8_t opCode;
		/** DHCP option length */
		uint8_t len;
		/** DHCP option value */
		uint8_t value[];

		/**
		 * A templated method to retrieve the DHCP option data as a certain type T. For example, if DHCP option data is 4B
		 * (integer) then this method should be used as getValueAs<int>() and it will return the DHCP option data as an integer.<BR>
		 * Notice this return value is a copy of the data, not a pointer to the actual data
		 * @param[in] valueOffset An optional parameter that specifies where to start copy the DHCP option data. For example:
		 * if option data is 20 bytes and you need only the 4 last bytes as integer then use this method like this:
		 * getValueAs<int>(16). The default is 0 - start copying from the beginning of option data
		 * @return The DHCP option data as type T
		 */
		template<typename T>
		T getValueAs(int valueOffset = 0)
		{
			if (getTotalSize() <= 2*sizeof(uint8_t) + valueOffset)
				return 0;
			if (getTotalSize() - 2*sizeof(uint8_t) - valueOffset < sizeof(T))
				return 0;

			T result;
			memcpy(&result, value+valueOffset, sizeof(T));
			return result;
		}

		/**
		 * Retrieve DHCP option data as IPv4 address. Relevant only if option value is indeed an IPv4 address
		 * @return DHCP option data as IPv4 address
		 */
		IPv4Address getValueAsIpAddr()
		{
			uint32_t addrAsInt = getValueAs<uint32_t>();
			return IPv4Address(addrAsInt);
		}

		/**
		 * Retrieve DHCP option data as string. Relevant only if option value is indeed a string
		 * @return DHCP option data as string
		 */
		std::string getValueAsString()
		{
			if (len < 1)
				return "";

			return std::string((char*)value, len);
		}

		/**
		 * A templated method to copy data of type T into the DHCP option data. For example: if option data is 4[Bytes] long use
		 * this method with \<int\> to set an integer value into the DHCP option data: setValue<int>(num)
		 * @param[in] newValue The value of type T to copy to DHCP option data
		 * @param[in] valueOffset An optional parameter that specifies where to start setting the option data (default set to 0). For example:
		 * if option data is 20 bytes long and you only need to set the 4 last bytes as integer then use this method like this:
		 * setValue<int>(num, 16)
		 */
		template<typename T>
		void setValue(T newValue, int valueOffset = 0)
		{
			memcpy(value+valueOffset, &newValue, sizeof(T));
		}

		/**
		 * Set DHCP option data as IPv4 address. This method copies the 4 bytes of the IP address to the option value
		 * @param[in] addr The IPv4 address to set
		 * @param[in] valueOffset An optional parameter that specifies where to start set the option data (default set to 0). For example:
		 * if option data is 20 bytes long and you want to set the IP address in the 4 last bytes then use this method like this:
		 * setValueIpAddr(your_addr, 16)
		 */
		void setValueIpAddr(const IPv4Address& addr, int valueOffset = 0)
		{
			setValue<uint32_t>(addr.toInt(), valueOffset);
		}

		/**
		 * Set DHCP option data as string. This method copies the string to the option value. If the string is longer than option length
		 * the string is trimmed so it will fit the option length
		 * @param[in] stringValue The string to set
		 * @param[in] valueOffset An optional parameter that specifies where to start set the option data (default set to 0). For example:
		 * if option data is 20 bytes long and you want to set a 6 char-long string in the 6 last bytes then use this method like this:
		 * setValueString("string", 14)
		 */
		void setValueString(const std::string& stringValue, int valueOffset = 0)
		{
			std::string val = stringValue;
			if (stringValue.length() > (size_t)len-(size_t)valueOffset)
				val = stringValue.substr(0, len-valueOffset);

			memcpy(value+valueOffset, val.c_str(), val.length());
		}

		/**
		 * @return The total size in bytes of this DHCP option which includes: 1[Byte] (option type) + 1[Byte]
		 * (option length) + X[Bytes] (option data length). For ::DHCPOPT_END and ::DHCPOPT_PAD the value 1 is returned
		 */
		inline size_t getTotalSize() const
		{
			if (opCode == (uint8_t)DHCPOPT_END || opCode == (uint8_t)DHCPOPT_PAD)
				return sizeof(uint8_t);

			return sizeof(uint8_t)*2 + (size_t)len;
		}

		/**
		 * @return The length of the option value
		 */
		inline uint8_t getLength()
		{
			if (opCode == (uint8_t)DHCPOPT_END || opCode == (uint8_t)DHCPOPT_PAD)
				return 0;

			return len;
		}

		/**
		 * @return DHCP option type casted as pcpp::DhcpOptionTypes enum
		 */
		inline DhcpOptionTypes getType() { return (DhcpOptionTypes)opCode; }

	private:

		// private c'tor which isn't implemented to make this struct impossible to construct
		DhcpOptionData();
	};


	/**
	 * @class DhcpLayer
	 * Represents A DHCP (Dynamic Host Configuration Protocol) protocol layer
	 */
	class DhcpLayer : public Layer
	{
	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		DhcpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/**
		 * A constructor that creates the layer from scratch. Adds a ::DHCPOPT_DHCP_MESSAGE_TYPE and a ::DHCPOPT_END
		 * options
		 * @param[in] msgType A DHCP message type to be set
		 * @param[in] clientMacAddr A client MAC address to set in dhcp_header#clientHardwareAddress field
		 */
		DhcpLayer(DhcpMessageType msgType, const MacAddress& clientMacAddr);

		/**
		 * A constructor that creates the layer from scratch with clean data
		 */
		DhcpLayer();

		/**
		 * A destructor for this layer
		 */
		virtual ~DhcpLayer() {}

		/**
		 * Get a pointer to the DHCP header. Notice this points directly to the data, so every change will change the actual packet data
		 * @return A pointer to the @ref dhcp_header
		 */
		inline dhcp_header* getDhcpHeader() { return (dhcp_header*)m_Data; };

		/**
		 * @return The BootP opcode of this message
		 */
		inline BootpOpCodes getOpCode() { return (BootpOpCodes)getDhcpHeader()->opCode; }

		/**
		 * @return The client IPv4 address (as extracted from dhcp_header#clientIpAddress converted to IPv4Address object)
		 */
		IPv4Address getClientIpAddress();

		/**
		 * Set the client IPv4 address in dhcp_header#clientIpAddress
		 * @param[in] addr The IPv4 address to set
		 */
		void setClientIpAddress(const IPv4Address& addr);

		/**
		 * @return The server IPv4 address (as extracted from dhcp_header#serverIpAddress converted to IPv4Address object)
		 */
		IPv4Address getServerIpAddress();

		/**
		 * Set the server IPv4 address in dhcp_header#serverIpAddress
		 * @param[in] addr The IPv4 address to set
		 */
		void setServerIpAddress(const IPv4Address& addr);

		/**
		 * @return Your IPv4 address (as extracted from dhcp_header#yourIpAddress converted to IPv4Address object)
		 */
		IPv4Address getYourIpAddress();

		/**
		 * Set your IPv4 address in dhcp_header#yourIpAddress
		 * @param[in] addr The IPv4 address to set
		 */
		void setYourIpAddress(const IPv4Address& addr);

		/**
		 * @return Gateway IPv4 address (as extracted from dhcp_header#gatewayIpAddress converted to IPv4Address object)
		 */
		IPv4Address getGatewayIpAddress();

		/**
		 * Set the gateway IPv4 address in dhcp_header#gatewayIpAddress
		 * @param[in] addr The IPv4 address to set
		 */
		void setGatewayIpAddress(const IPv4Address& addr);

		/**
		 * @return The client MAC address as extracted from dhcp_header#clientHardwareAddress, assuming dhcp_header#hardwareType is 1 (Ethernet)
		 * and dhcp_header#hardwareAddressLength is 6 (MAC address length). Otherwise returns MacAddress#Zero
		 */
		MacAddress getClientHardwareAddress();

		/**
		 * Set a MAC address into the first 6 bytes of dhcp_header#clientHardwareAddress. This method also sets dhcp_header#hardwareType
		 * to 1 (Ethernet) and dhcp_header#hardwareAddressLength to 6 (MAC address length)
		 * @param[in] addr The MAC address to set
		 */
		void setClientHardwareAddress(const MacAddress& addr);

		/**
		 * @return DHCP message type as extracted from ::DHCPOPT_DHCP_MESSAGE_TYPE option. If this option doesn't exist the value of
		 * ::DHCP_UNKNOWN_MSG_TYPE is returned
		 */
		DhcpMessageType getMesageType();

		/**
		 * Set DHCP message type. This method searches for existing ::DHCPOPT_DHCP_MESSAGE_TYPE option. If found, it sets the requested
		 * message type as its value. If not, it creates a ::DHCPOPT_DHCP_MESSAGE_TYPE option and sets the requested message type as its
		 * value
		 * @param[in] msgType Message type to set
		 * @return True if message type was set successfully or false if msgType is ::DHCP_UNKNOWN_MSG_TYPE or if failed to add
		 * ::DHCPOPT_DHCP_MESSAGE_TYPE option
		 */
		bool setMesageType(DhcpMessageType msgType);

		/**
		 * @return The first DHCP option, or NULL if no options exist. Notice the return value is a pointer to the real data casted to
		 * DhcpOptionData type (as opposed to a copy of the option data). So changes in the return value will affect the packet data
		 */
		DhcpOptionData* getFirstOptionData();

		/**
		 * Get the DHCP option that comes next to "dhcpOption" option. If "dhcpOption" is NULL then NULL will be returned.
		 * If "dhcpOption" is the last DHCP option NULL will be returned. Notice the return value is a pointer to the real data casted to
		 * DhcpOptionData type (as opposed to a copy of the option data). So changes in the return value will affect the packet data
		 * @param[in] dhcpOption The DHCP option to start searching from
		 * @return The next DHCP option or NULL if "dhcpOption" is NULL or "dhcpOption" is the last DHCP option
		 */
		DhcpOptionData* getNextOptionData(DhcpOptionData* dhcpOption);

		/**
		 * Search for a DHCP option by type. Notice the return value points directly to the data, so every change will change the actual packet data
		 * @param[in] option The DHCP option type to search
		 * @return A pointer to the DHCP option in this layer
		 */
		DhcpOptionData* getOptionData(DhcpOptionTypes option);

		/**
		 * @return The number of DHCP options in this layer
		 */
		size_t getOptionsCount();

		/**
		 * Add a new DHCP option at the end of the layer (but before the ::DHCPOPT_END option if exists)
		 * @param[in] optionType The type of the newly added option
		 * @param[in] optionLen The length of the option data
		 * @param[in] optionData A pointer to the option data. This data will be copied to newly added option data. Notice the length of
		 * optionData must be optionLen
		 * @return A pointer to the newly added DHCP option data or NULL if addition failed. Notice this is a pointer to the
		 * real data casted to DhcpOptionData type (as opposed to a copy of the option data). So changes in this return
		 * value will affect the packet data
		 */
		DhcpOptionData* addOption(DhcpOptionTypes optionType, uint16_t optionLen, const uint8_t* optionData);

		/**
		 * Add a new DHCP option after an existing option
		 * @param[in] optionType The type of the newly added option
		 * @param[in] optionLen The length of the option data
		 * @param[in] optionData A pointer to the option data. This data will be copied to added option data. Notice the length of
		 * optionData must be optionLength
		 * @param[in] prevOption The DHCP option which the newly added tag will come after. If set to ::DHCPOPT_UNKNOWN DHCP option will be
		 * added as the first DHCP option
		 * @return A pointer to the newly added option or NULL if addition failed. Notice this is a pointer to the real data
		 * casted to DhcpOptionData type (as opposed to a copy of the option data). So changes in this return value will affect
		 * the packet data
		 */
		DhcpOptionData* addOptionAfter(DhcpOptionTypes optionType, uint16_t optionLen, const uint8_t* optionData, DhcpOptionTypes prevOption);

		/**
		 * Remove an existing DHCP option from the layer
		 * @param[in] optionType The DHCP option type to remove
		 * @return True if DHCP option was successfully removed or false if type wasn't found or if removal failed
		 */
		bool removeOption(DhcpOptionTypes optionType);

		/**
		 * Remove all DHCP options in this layer
		 * @return True if all DHCP options were successfully removed or false if removal failed for some reason
		 */
		bool removeAllOptions();

		// implement abstract methods

		/**
		 * Does nothing for this layer (DhcpLayer is always last)
		 */
		void parseNextLayer() {}

		/**
		 * @return The size of @ref dhcp_header + size of options
		 */
		size_t getHeaderLen();

		/**
		 * Calculate the following fields:
		 * - @ref dhcp_header#magicNumber = DHCP magic number (0x63538263)
		 * - @ref dhcp_header#opCode = ::DHCP_BOOTREQUEST for message types: ::DHCP_DISCOVER, ::DHCP_REQUEST, ::DHCP_DECLINE, ::DHCP_RELEASE,
		 *                            ::DHCP_INFORM, ::DHCP_UNKNOWN_MSG_TYPE
		 *                            ::DHCP_BOOTREPLY for message types: ::DHCP_OFFER, ::DHCP_ACK, ::DHCP_NAK
		 * - @ref dhcp_header#hardwareType = 1 (Ethernet)
		 * - @ref dhcp_header#hardwareAddressLength = 6 (MAC address length)
		 */
		void computeCalculateFields();

		std::string toString();

		OsiModelLayer getOsiModelLayer() { return OsiModelApplicationLayer; }

	private:

		size_t m_DhcpOptionsCount;

		void initDhcpLayer(size_t numOfBytesToAllocate);

		DhcpOptionData* castPtrToOptionData(uint8_t* ptr);

		DhcpOptionData* addOptionAt(DhcpOptionTypes optionType, uint16_t optionLen, const uint8_t* optionData, int offset);
	};
}

#endif /* PACKETPP_DHCP_LAYER */
