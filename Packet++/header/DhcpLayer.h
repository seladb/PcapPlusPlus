#ifndef PACKETPP_DHCP_LAYER
#define PACKETPP_DHCP_LAYER

#include <Layer.h>
#include <IpAddress.h>
#include <MacAddress.h>
#include <string.h>

namespace pcpp
{

	/**
	 * @struct dhcp_header
	 * Represents an DHCP protocol header
	 */
	#pragma pack(push, 1)
	struct dhcp_header {
        uint8_t opCode;
        uint8_t hardwareType;
        uint8_t hardwareAddressLength;
        uint8_t hops;
        uint32_t transactionID;
        uint16_t secondsElapsed;
        uint16_t flags;
        uint32_t clientIpAddress;
        uint32_t yourIpAddress;
        uint32_t serverIpAddress;
        uint32_t gatewayIpAddress;
        uint8_t clientHardwareAddress[16];
        uint8_t serverName[64];
        uint8_t bootFilename[128];
        uint32_t magicNumber;
	};
	#pragma pack(pop)


	enum DhcpOpCodes
	{
		DHCP_BOOTREQUEST = 1,
		DHCP_BOOTREPLY = 2
	};

    /**
     * DHCP message types
     */
    enum DhcpMessageType {
    	DHCP_UNKNOWN_MSG_TYPE = 0,
    	DHCP_DISCOVER         = 1,
    	DHCP_OFFER            = 2,
    	DHCP_REQUEST          = 3,
    	DHCP_DECLINE          = 4,
    	DHCP_ACK              = 5,
    	DHCP_NAK              = 6,
    	DHCP_RELEASE          = 7,
    	DHCP_INFORM           = 8
    };

    /**
     * DHCP option types.
     */
    enum DhcpOptionTypes {
    	DHCPOPT_UNKNOWN = -1,
    	DHCPOPT_PAD = 0,
        DHCPOPT_SUBNET_MASK = 1,
        DHCPOPT_TIME_OFFSET = 2,
        DHCPOPT_ROUTERS = 3,
        DHCPOPT_TIME_SERVERS = 4,
        DHCPOPT_NAME_SERVERS = 5,
        DHCPOPT_DOMAIN_NAME_SERVERS = 6,
        DHCPOPT_LOG_SERVERS = 7,
        DHCPOPT_COOKIE_SERVERS = 8,
        DHCPOPT_LPR_SERVERS = 9,
        DHCPOPT_IMPRESS_SERVERS = 10,
        DHCPOPT_RESOURCE_LOCATION_SERVERS = 11,
        DHCPOPT_HOST_NAME = 12,
        DHCPOPT_BOOT_SIZE = 13,
        DHCPOPT_MERIT_DUMP = 14,
        DHCPOPT_DOMAIN_NAME = 15,
        DHCPOPT_SWAP_SERVER = 16,
        DHCPOPT_ROOT_PATH = 17,
        DHCPOPT_EXTENSIONS_PATH = 18,
        DHCPOPT_IP_FORWARDING = 19,
        DHCPOPT_NON_LOCAL_SOURCE_ROUTING = 20,
        DHCPOPT_POLICY_FILTER = 21,
        DHCPOPT_MAX_DGRAM_REASSEMBLY = 22,
        DEFAULT_IP_TTL = 23,
        DHCPOPT_PATH_MTU_AGING_TIMEOUT = 24,
        PATH_MTU_PLATEAU_TABLE = 25,
        DHCPOPT_INTERFACE_MTU = 26,
        DHCPOPT_ALL_SUBNETS_LOCAL = 27,
        DHCPOPT_BROADCAST_ADDRESS = 28,
        DHCPOPT_PERFORM_MASK_DISCOVERY = 29,
        DHCPOPT_MASK_SUPPLIER = 30,
        DHCPOPT_ROUTER_DISCOVERY = 31,
        DHCPOPT_ROUTER_SOLICITATION_ADDRESS = 32,
        DHCPOPT_STATIC_ROUTES = 33,
        DHCPOPT_TRAILER_ENCAPSULATION  =34,
        DHCPOPT_ARP_CACHE_TIMEOUT = 35,
        DHCPOPT_IEEE802_3_ENCAPSULATION = 36,
        DHCPOPT_DEFAULT_TCP_TTL = 37,
        DHCPOPT_TCP_KEEPALIVE_INTERVAL = 38,
        DHCPOPT_TCP_KEEPALIVE_GARBAGE = 39,
        DHCPOPT_NIS_DOMAIN = 40,
        DHCPOPT_NIS_SERVERS = 41,
        DHCPOPT_NTP_SERVERS = 42,
        DHCPOPT_VENDOR_ENCAPSULATED_OPTIONS = 43,
        DHCPOPT_NETBIOS_NAME_SERVERS = 44,
        DHCPOPT_NETBIOS_DD_SERVER = 45,
        DHCPOPT_NETBIOS_NODE_TYPE = 46,
        DHCPOPT_NETBIOS_SCOPE = 47,
        DHCPOPT_FONT_SERVERS = 48,
        DHCPOPT_X_DISPLAY_MANAGER = 49,
        DHCPOPT_DHCP_REQUESTED_ADDRESS = 50,
        DHCPOPT_DHCP_LEASE_TIME = 51,
        DHCPOPT_DHCP_OPTION_OVERLOAD = 52,
        DHCPOPT_DHCP_MESSAGE_TYPE = 53,
        DHCPOPT_DHCP_SERVER_IDENTIFIER = 54,
        DHCPOPT_DHCP_PARAMETER_REQUEST_LIST = 55,
        DHCPOPT_DHCP_MESSAGE = 56,
        DHCPOPT_DHCP_MAX_MESSAGE_SIZE = 57,
        DHCPOPT_DHCP_RENEWAL_TIME = 58,
        DHCPOPT_DHCP_REBINDING_TIME = 59,
        DHCPOPT_VENDOR_CLASS_IDENTIFIER = 60,
        DHCPOPT_DHCP_CLIENT_IDENTIFIER = 61,
        DHCPOPT_NWIP_DOMAIN_NAME = 62,
        DHCPOPT_NWIP_SUBOPTIONS = 63,
        DHCPOPT_NIS_DOMAIN_NAME = 64,
        DHCPOPT_NIS_SERVER_ADDRESS = 65,
        DHCPOPT_TFTP_SERVER_NAME = 66,
        DHCPOPT_BOOTFILE_NAME = 67,
        DHCPOPT_HOME_AGENT_ADDRESS = 68,
        DHCPOPT_SMTP_SERVER = 69,
        DHCPOPT_POP3_SERVER = 70,
        DHCPOPT_NNTP_SERVER = 71,
        DHCPOPT_WWW_SERVER = 72,
        DHCPOPT_FINGER_SERVER = 73,
        DHCPOPT_IRC_SERVER = 74,
        DHCPOPT_STREETTALK_SERVER = 75,
        DHCPOPT_STDA_SERVER = 76,
        DHCPOPT_USER_CLASS = 77,
        DHCPOPT_DIRECTORY_AGENT = 78,
        DHCPOPT_SERVICE_SCOPE = 79,
        DHCPOPT_RAPID_COMMIT = 80,
        DHCPOPT_FQDN = 81,
        DHCPOPT_DHCP_AGENT_OPTIONS = 82,
        DHCPOPT_ISNS = 83,
        DHCPOPT_NDS_SERVERS = 85,
        DHCPOPT_NDS_TREE_NAME = 86,
        DHCPOPT_NDS_CONTEXT = 87,
        DHCPOPT_BCMCS_CONTROLLER_DOMAIN_NAME_LIST = 88,
        DHCPOPT_BCMCS_CONTROLLER__IPV4_ADDRESS = 89,
        DHCPOPT_AUTHENTICATION = 90,
        DHCPOPT_CLIENT_LAST_TXN_TIME = 91,
        DHCPOPT_ASSOCIATED_IP = 92,
        DHCPOPT_CLIENT_SYSTEM = 93,
        DHCPOPT_CLIENT_NDI = 94,
        DHCPOPT_LDAP = 95,
        DHCPOPT_UUID_GUID = 97,
        DHCPOPT_USER_AUTH = 98,
        DHCPOPT_GEOCONF_CIVIC = 99,
        DHCPOPT_PCODE = 100,
        DHCPOPT_TCODE = 101,
        DHCPOPT_NETINFO_ADDRESS = 112,
        DHCPOPT_NETINFO_TAG = 113,
        DHCPOPT_URL = 114,
        DHCPOPT_AUTO_CONFIG = 116,
        DHCPOPT_NAME_SERVICE_SEARCH = 117,
        DHCPOPT_SUBNET_SELECTION = 118,
        DHCPOPT_DOMAIN_SEARCH = 119,
        DHCPOPT_SIP_SERVERS = 120,
        DHCPOPT_CLASSLESS_STATIC_ROUTE = 121,
        DHCPOPT_CCC = 122,
        DHCPOPT_GEOCONF = 123,
        DHCPOPT_V_I_VENDOR_CLASS = 124,
        DHCPOPT_V_I_VENDOR_OPTS = 125,
        DHCPOPT_OPTION_PANA_AGENT = 136,
        DHCPOPT_OPTION_V4_LOST  =137,
        DHCPOPT_OPTION_CAPWAP_AC_V4 = 138,
        DHCPOPT_OPTION_IPV4_ADDRESS_MOS = 139,
        DHCPOPT_OPTION_IPV4_FQDN_MOS = 140,
        DHCPOPT_SIP_UA_CONFIG = 141,
        DHCPOPT_OPTION_IPV4_ADDRESS_ANDSF = 142,
        DHCPOPT_GEOLOC = 144,
        DHCPOPT_FORCERENEW_NONCE_CAPABLE = 145,
        DHCPOPT_RDNSS_SELECTION = 146,
        DHCPOPT_STATUS_CODE = 151,
        DHCPOPT_BASE_TIME = 152,
        DHCPOPT_START_TIME_OF_STATE = 153,
        DHCPOPT_QUERY_START_TIME = 154,
        DHCPOPT_QUERY_END_TIME = 155,
        DHCPOPT_DHCP_STATE = 156,
        DHCPOPT_DATA_SOURCE = 157,
        DHCPOPT_OPTION_V4_PCP_SERVER = 158,
        DHCPOPT_OPTION_V4_PORTPARAMS = 159,
        DHCPOPT_CAPTIVE_PORTAL = 160,
        DHCPOPT_OPTION_MUD_URL_V4 = 161,
        DHCPOPT_ETHERBOOT = 175,
        DHCPOPT_IP_TELEPHONE = 176,
        DHCPOPT_PXELINUX_MAGIC = 208,
        DHCPOPT_CONFIGURATION_FILE = 209,
        DHCPOPT_PATH_PREFIX = 210,
        DHCPOPT_REBOOT_TIME = 211,
        DHCPOPT_OPTION_6RD = 212,
        DHCPOPT_OPTION_V4_ACCESS_DOMAIN = 213,
        DHCPOPT_SUBNET_ALLOCATION = 220,
        DHCPOPT_VIRTUAL_SUBNET_SELECTION = 221,
        DHCPOPT_END	= 255
    };

	/**
	 * @struct DhcpOptionData
	 * Representing a DHCP option in a TLV (type-length-value) type
	 */
	struct DhcpOptionData
	{
	public:
		/** DHCP option code, should be on of ::DhcpOptionTypes */
		uint8_t opCode;
		/** DHCP option length */
		uint8_t len;
		/** DHCP option value */
		uint8_t value[];

		/**
		 * A templated method to retrieve the DHCP option data as a certain type T. For example, DHCP option data is 4B
		 * (integer) then this method should be used as getValueAs<int>() and it will return the TCP option data as an integer.<BR>
		 * Notice this return value is a copy of the data, not a pointer to the actual data
		 * @param[in] valueOffset An optional parameter that specifies where to start copy the DHCP option data. For example:
		 * if option data is 20 bytes and you need only the 4 last bytes as integer then use this method like this:
		 * getValueAs<int>(16). The default is 0 - start copy from the beginning of option data
		 * @return The TCP option data as type T
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

		IPv4Address getValueAsIpAddr()
		{
			uint32_t addrAsInt = getValueAs<uint32_t>();
			return IPv4Address(addrAsInt);
		}

		std::string getValueAsString()
		{
			if (len < 1)
				return "";

			return std::string((char*)value, len);
		}

		/**
		 * A templated method to copy data of type T into the DHCP option data. For example: if option data is 4[Bytes] long use
		 * this method with <int> to set an integer value into the TCP option data: setValue<int>(num)
		 * @param[in] newValue The value of type T to copy to DHCP option data
		 * @param[in] valueOffset An optional parameter that specifies where to start set the option data. For example:
		 * if option data is 20 bytes long and you only need to set the 4 last bytes as integer then use this method like this:
		 * setValue<int>(num, 16). The default is 0 - start copy from the beginning of option data
		 */
		template<typename T>
		void setValue(T newValue, int valueOffset = 0)
		{
			memcpy(value+valueOffset, &newValue, sizeof(T));
		}

		void setValueIpAddr(const IPv4Address& addr, int valueOffset = 0)
		{
			setValue<uint32_t>(addr.toInt(), valueOffset);
		}

		void setValueString(const std::string& stringValue, int valueOffset = 0)
		{
			std::string val = stringValue;
			if (stringValue.length() > len-valueOffset)
				val = stringValue.substr(0, len-valueOffset);

			memcpy(value+valueOffset, val.c_str(), val.length());
		}

		/**
		 * @return The total size in bytes of this DHCP option which includes: 1[Byte] (option type) + 1[Byte]
		 * (option length) + X[Bytes] (option data length)
		 */
		inline size_t getTotalSize() const
		{
			if (opCode == (uint8_t)DHCPOPT_END || opCode == (uint8_t)DHCPOPT_PAD)
				return sizeof(uint8_t);

			return sizeof(uint8_t)*2 + (size_t)len;
		}

		inline uint8_t getLength()
		{
			if (opCode == (uint8_t)DHCPOPT_END || opCode == (uint8_t)DHCPOPT_PAD)
				return 0;

			return len;
		}

		/**
		 * @return DHCP option type casted as DhcpOptionTypes enum
		 */
		inline DhcpOptionTypes getType() {return (DhcpOptionTypes)opCode;}
	private:
		// private c'tor which isn't implemented to make this struct impossible to construct
		DhcpOptionData();
	};

	class DhcpLayer : public Layer
	{
	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to @ref arphdr)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		DhcpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

//		/**
//		 * A constructor that allocates a new ARP header
//		 * @param[in] opCode ARP message type (ARP request or ARP reply)
//		 * @param[in] senderMacAddr The sender MAC address (will be put in arphdr#senderMacAddr)
//		 * @param[in] targetMacAddr The target MAC address (will be put in arphdr#targetMacAddr)
//		 * @param[in] senderIpAddr The sender IP address (will be put in arphdr#senderIpAddr)
//		 * @param[in] targetIpAddr The target IP address (will be put in arphdr#targetIpAddr)
//		 */
//		ArpLayer(ArpOpcode opCode, const MacAddress& senderMacAddr, const MacAddress& targetMacAddr, const IPv4Address senderIpAddr, const IPv4Address& targetIpAddr);

		DhcpLayer(DhcpMessageType msgType, const MacAddress& clientMacAddr);

		DhcpLayer();

		virtual ~DhcpLayer() {}

		/**
		 * Get a pointer to the DHCP header. Notice this points directly to the data, so every change will change the actual packet data
		 * @return A pointer to the @ref dhcp_header
		 */
		inline dhcp_header* getDhcpHeader() { return (dhcp_header*)m_Data; };

		inline DhcpOpCodes getOpCode() { return (DhcpOpCodes)getDhcpHeader()->opCode; }

		IPv4Address getClientIpAddress();

		void setClientIpAddress(const IPv4Address& addr);

		IPv4Address getServerIpAddress();

		void setServerIpAddress(const IPv4Address& addr);

		IPv4Address getYourIpAddress();

		void setYourIpAddress(const IPv4Address& addr);

		IPv4Address getGatewayIpAddress();

		void setGatewayIpAddress(const IPv4Address& addr);

		MacAddress getClientHardwareAddress();

		void setClientHardwareAddress(const MacAddress& addr);

		DhcpMessageType getMesageType();

		bool setMesageType(DhcpMessageType msgType);

		DhcpOptionData* getFirstOptionData();

		DhcpOptionData* getNextOptionData(DhcpOptionData* dhcpOption);

		DhcpOptionData* getOptionData(DhcpOptionTypes option);

		size_t getOptionsCount();

		DhcpOptionData* addOption(DhcpOptionTypes optionType, uint16_t optionLen, const uint8_t* optionData);

		DhcpOptionData* addOptionAfter(DhcpOptionTypes optionType, uint16_t optionLen, const uint8_t* optionData, DhcpOptionTypes prevOption);

		bool removeOption(DhcpOptionTypes optionType);

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
		 * .................................................
		 * Calculate the following fields:
		 * - @ref arphdr#hardwareType = Ethernet (1)
		 * - @ref arphdr#hardwareSize = 6
		 * - @ref arphdr#protocolType = ETHERTYPE_IP (assume IPv4 over ARP)
		 * - @ref arphdr#protocolSize = 4 (assume IPv4 over ARP)
		 * - if it's an ARP requst: @ref arphdr#targetMacAddr = MacAddress("00:00:00:00:00:00")
		 */
		void computeCalculateFields();

		std::string toString();

	private:

		size_t m_DhcpOptionsCount;

		void initDhcpLayer(size_t numOfBytesToAllocate);

		DhcpOptionData* castPtrToOptionData(uint8_t* ptr);

		DhcpOptionData* addOptionAt(DhcpOptionTypes optionType, uint16_t optionLen, const uint8_t* optionData, int offset);
	};
}

#endif /* PACKETPP_DHCP_LAYER */
