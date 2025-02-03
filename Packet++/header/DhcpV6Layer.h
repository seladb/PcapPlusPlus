#pragma once

#include "Layer.h"
#include "TLVData.h"

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	/// DHCPv6 message types
	enum DhcpV6MessageType
	{
		/// Unknown message type
		DHCPV6_UNKNOWN_MSG_TYPE = 0,
		/// Solicit message type (Client to Server)
		DHCPV6_SOLICIT = 1,
		/// Advertise message type (Server to Client)
		DHCPV6_ADVERTISE = 2,
		/// Request message type (Client to Server)
		DHCPV6_REQUEST = 3,
		/// Confirm message type (Client to Server)
		DHCPV6_CONFIRM = 4,
		/// Renew message type (Client to Server)
		DHCPV6_RENEW = 5,
		/// Rebind message type (Client to Server)
		DHCPV6_REBIND = 6,
		/// Reply message type (Server to Client)
		DHCPV6_REPLY = 7,
		/// Release message type (Client to Server)
		DHCPV6_RELEASE = 8,
		/// Decline message type (Client to Server)
		DHCPV6_DECLINE = 9,
		/// Reconfigure message type (Server to Client)
		DHCPV6_RECONFIGURE = 10,
		/// Information-Request message type (Client to Server)
		DHCPV6_INFORMATION_REQUEST = 11,
		/// Relay-Forward message type (Relay agent to Server)
		DHCPV6_RELAY_FORWARD = 12,
		/// Relay-Reply message type (Server to Relay agent)
		DHCPV6_RELAY_REPLY = 13
	};

	/// DHCPv6 option types.
	/// Resources for more information:
	/// - https://onlinelibrary.wiley.com/doi/pdf/10.1002/9781118073810.app2
	/// - https://datatracker.ietf.org/doc/html/rfc5970
	/// - https://datatracker.ietf.org/doc/html/rfc6607
	/// - https://datatracker.ietf.org/doc/html/rfc8520
	enum DhcpV6OptionType
	{
		/// Unknown option type
		DHCPV6_OPT_UNKNOWN = 0,
		/// Client Identifier (DUID of client)
		DHCPV6_OPT_CLIENTID = 1,
		/// Server Identifier (DUID of server)
		DHCPV6_OPT_SERVERID = 2,
		/// Identity Association for Non-temporary addresses
		DHCPV6_OPT_IA_NA = 3,
		/// Identity Association for Temporary addresses
		DHCPV6_OPT_IA_TA = 4,
		/// IA Address option
		DHCPV6_OPT_IAADDR = 5,
		/// Option Request Option
		DHCPV6_OPT_ORO = 6,
		/// Preference setting
		DHCPV6_OPT_PREFERENCE = 7,
		/// The amount of time since the client began the current DHCP transaction
		DHCPV6_OPT_ELAPSED_TIME = 8,
		/// The DHCP message being relayed by a relay agent
		DHCPV6_OPT_RELAY_MSG = 9,
		/// Authentication  information
		DHCPV6_OPT_AUTH = 11,
		/// Server unicast
		DHCPV6_OPT_UNICAST = 12,
		/// Status code
		DHCPV6_OPT_STATUS_CODE = 13,
		/// Rapid commit
		DHCPV6_OPT_RAPID_COMMIT = 14,
		/// User class
		DHCPV6_OPT_USER_CLASS = 15,
		/// Vendor class
		DHCPV6_OPT_VENDOR_CLASS = 16,
		/// Vendor specific information
		DHCPV6_OPT_VENDOR_OPTS = 17,
		/// Interface ID
		DHCPV6_OPT_INTERFACE_ID = 18,
		/// Reconfigure Message
		DHCPV6_OPT_RECONF_MSG = 19,
		/// Reconfigure Accept
		DHCPV6_OPT_RECONF_ACCEPT = 20,
		/// SIP Servers Domain Name
		DHCPV6_OPT_SIP_SERVERS_D = 21,
		/// SIP Servers IPv6 Address List
		DHCPV6_OPT_SIP_SERVERS_A = 22,
		/// DNS Recursive Name Server
		DHCPV6_OPT_DNS_SERVERS = 23,
		/// Domain Search List
		DHCPV6_OPT_DOMAIN_LIST = 24,
		/// Identity Association for Prefix Delegation
		DHCPV6_OPT_IA_PD = 25,
		/// IA_PD Prefix
		DHCPV6_OPT_IAPREFIX = 26,
		/// Network Information Service (NIS) Servers
		DHCPV6_OPT_NIS_SERVERS = 27,
		/// Network Information Service v2 (NIS+) Servers
		DHCPV6_OPT_NISP_SERVERS = 28,
		/// Network Information Service (NIS) domain name
		DHCPV6_OPT_NIS_DOMAIN_NAME = 29,
		/// Network Information Service v2 (NIS+) domain name
		DHCPV6_OPT_NISP_DOMAIN_NAME = 30,
		/// Simple Network Time Protocol (SNTP) servers
		DHCPV6_OPT_SNTP_SERVERS = 31,
		/// Information Refresh
		DHCPV6_OPT_INFORMATION_REFRESH_TIME = 32,
		/// Broadcast and Multicast Service (BCMCS) Domain Name List
		DHCPV6_OPT_BCMCS_SERVER_D = 33,
		/// Broadcast and Multicast Service (BCMCS) IPv6 Address List
		DHCPV6_OPT_BCMCS_SERVER_A = 34,
		/// Geographical location in civic (e.g., postal) format
		DHCPV6_OPT_GEOCONF_CIVIC = 36,
		/// Relay Agent Remote ID
		DHCPV6_OPT_REMOTE_ID = 37,
		/// Relay Agent Subscriber ID
		DHCPV6_OPT_SUBSCRIBER_ID = 38,
		/// FQDN
		DHCPV6_OPT_CLIENT_FQDN = 39,
		/// One or more IPv6 addresses associated with PANA (Protocol for carrying Authentication for Network Access)
		/// Authentication Agents
		DHCPV6_OPT_PANA_AGENT = 40,
		/// Time zone to be used by the client in IEEE 1003.1 format
		DHCPV6_OPT_NEW_POSIX_TIMEZONE = 41,
		/// Time zone (TZ) database entry referred to by entry name
		DHCPV6_OPT_NEW_TZDB_TIMEZONE = 42,
		/// Relay Agent Echo Request
		DHCPV6_OPT_ERO = 43,
		/// Query option
		DHCPV6_OPT_LQ_QUERY = 44,
		/// Client Data
		DHCPV6_OPT_CLIENT_DATA = 45,
		/// Client Last Transaction Time
		DHCPV6_OPT_CLT_TIME = 46,
		/// Relay data
		DHCPV6_OPT_LQ_RELAY_DATA = 47,
		/// Client link
		DHCPV6_OPT_LQ_CLIENT_LINK = 48,
		/// Mobile IPv6 Home Network Information
		DHCPV6_OPT_MIP6_HNINF = 49,
		/// Mobile IPv6 Relay Agent
		DHCPV6_OPT_MIP6_RELAY = 50,
		/// Location to Service Translation (LoST) server domain name
		DHCPV6_OPT_V6_LOST = 51,
		/// Access Points (CAPWAP) Access Controller IPv6 addresses
		DHCPV6_OPT_CAPWAP_AC_V6 = 52,
		/// DHCPv6 Bulk LeaseQuery
		DHCPV6_OPT_RELAY_ID = 53,
		/// List of IPv6 addresses for servers providing particular types of IEEE 802.21 Mobility Service (MoS)
		DHCPV6_OPT_IPH6_ADDRESS_MOS = 54,
		/// List of FQDNs for servers providing particular types of IEEE 802.21 Mobility Service (MoS)
		DHCPV6_OPT_IPV6_FQDN_MOS = 55,
		/// Network Time Protocol (NTP) or Simple NTP (SNTP) Server Location
		DHCPV6_OPT_NTP_SERVER = 56,
		/// Boot File Uniform Resource Locator (URL)
		DHCPV6_OPT_BOOTFILE_URL = 59,
		/// Boot File Parameters
		DHCPV6_OPT_BOOTFILE_PARAM = 60,
		/// Client System Architecture Type
		DHCPV6_OPT_CLIENT_ARCH_TYPE = 61,
		/// Client Network Interface Identifier
		DHCPV6_OPT_NII = 62,
		/// ERP Local Domain Name
		DHCPV6_OPT_ERP_LOCAL_DOMAIN_NAME = 65,
		/// Relay supplied options
		DHCPV6_OPT_RELAY_SUPPLIED_OPTIONS = 66,
		/// Virtual Subnet Selection
		DHCPV6_OPT_VSS = 68,
		/// Client link layer
		DHCPV6_OPT_CLIENT_LINKLAYER_ADDR = 79,
		/// Manufacturer Usage Description
		DHCPV6_OPT_MUD_URL = 112
	};

	/// @class DhcpV6Option
	/// A wrapper class for DHCPv6 options. This class does not create or modify DHCP option records, but rather
	/// serves as a wrapper and provides useful methods for setting and retrieving data to/from them
	class DhcpV6Option : public TLVRecord<uint16_t, uint16_t>
	{
	public:
		/// A c'tor for this class that gets a pointer to the option raw data (byte array)
		/// @param[in] optionRawData A pointer to the option raw data
		explicit DhcpV6Option(uint8_t* optionRawData) : TLVRecord(optionRawData)
		{}

		/// A d'tor for this class, currently does nothing
		~DhcpV6Option() override = default;

		/// @return The option type converted to ::DhcpV6OptionType enum
		DhcpV6OptionType getType() const;

		/// @return The raw option value (byte array) as a hex string
		std::string getValueAsHexString() const;

		// implement abstract methods

		size_t getTotalSize() const override;
		size_t getDataSize() const override;
	};

	/// @class DhcpV6OptionBuilder
	/// A class for building DHCPv6 options. This builder receives the option parameters in its c'tor,
	/// builds the DHCPv6 option raw buffer and provides a build() method to get a DhcpV6Option object out of it
	class DhcpV6OptionBuilder : public TLVRecordBuilder
	{
	public:
		/// A c'tor for building DHCPv6 options from a string representing the hex stream of the raw byte value.
		/// The DhcpV6Option object can later be retrieved by calling build()
		/// @param[in] optionType DHCPv6 option type
		/// @param[in] optionValueAsHexStream The value as a hex stream string
		DhcpV6OptionBuilder(DhcpV6OptionType optionType, const std::string& optionValueAsHexStream)
		    : TLVRecordBuilder(static_cast<uint16_t>(optionType), optionValueAsHexStream, true)
		{}

		/// A c'tor for building DHCPv6 options from a byte array representing their value. The DhcpV6Option object can
		/// be later retrieved by calling build()
		/// @param[in] optionType DHCPv6 option type
		/// @param[in] optionValue A buffer containing the option value. This buffer is read-only and isn't modified in
		/// any way.
		/// @param[in] optionValueLen Option value length in bytes
		DhcpV6OptionBuilder(DhcpV6OptionType optionType, const uint8_t* optionValue, uint8_t optionValueLen)
		    : TLVRecordBuilder(static_cast<uint16_t>(optionType), optionValue, optionValueLen)
		{}

		/// Build the DhcpV6Option object out of the parameters defined in the c'tor
		/// @return The DhcpV6Option object
		DhcpV6Option build() const;
	};

	/// @struct dhcpv6_header
	/// Represents the basic DHCPv6 protocol header
	struct dhcpv6_header
	{
		/// DHCPv6 message type
		uint8_t messageType;
		/// DHCPv6 transaction ID (first byte)
		uint8_t transactionId1;
		/// DHCPv6 transaction ID (second byte)
		uint8_t transactionId2;
		/// DHCPv6 transaction ID (last byte)
		uint8_t transactionId3;
	};
	static_assert(sizeof(dhcpv6_header) == 4, "dhcpv6_header size is not 4 bytes");

	/// @class DhcpV6Layer
	/// Represents a DHCPv6 (Dynamic Host Configuration Protocol version 6) protocol layer
	class DhcpV6Layer : public Layer
	{
	public:
		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		DhcpV6Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/// A constructor that creates the layer from scratch
		/// @param[in] messageType A DHCPv6 message type to be set
		/// @param[in] transactionId The transaction ID to be set. Notice the transaction ID is 3-byte long so the value
		/// shouldn't exceed 0xFFFFFF
		DhcpV6Layer(DhcpV6MessageType messageType, uint32_t transactionId);

		/// @return The message type of this DHCPv6 message
		DhcpV6MessageType getMessageType() const;

		/// @return The string value of the message type of this DHCPv6 message
		std::string getMessageTypeAsString() const;

		/// Set the message type for this layer
		/// @param[in] messageType The message type to set
		void setMessageType(DhcpV6MessageType messageType);

		/// @return The transaction ID of this DHCPv6 message
		uint32_t getTransactionID() const;

		/// Set the transaction ID for this DHCPv6 message
		/// @param[in] transactionId The transaction ID value to set
		void setTransactionID(uint32_t transactionId) const;

		/// @return The first DHCPv6 option in the packet. If there are no DHCPv6 options the returned value will
		/// contain a logical null (DhcpV6Option#isNull() == true)
		DhcpV6Option getFirstOptionData() const;

		/// Get the DHCPv6 option that comes after a given option. If the given option was the last one, the
		/// returned value will contain a logical null (DhcpV6Option#isNull() == true)
		/// @param[in] dhcpv6Option A given DHCPv6 option
		/// @return A DhcpV6Option object containing the option data that comes next, or logical null if the given
		/// DHCPv6 option: (1) was the last one; (2) contains a logical null or (3) doesn't belong to this packet
		DhcpV6Option getNextOptionData(DhcpV6Option dhcpv6Option) const;

		/// Get a DHCPv6 option by type
		/// @param[in] option DHCPv6 option type
		/// @return A DhcpV6OptionType object containing the first DHCP option data that matches this type, or logical
		/// null (DhcpV6Option#isNull() == true) if no such option found
		DhcpV6Option getOptionData(DhcpV6OptionType option) const;

		/// @return The number of DHCPv6 options in this layer
		size_t getOptionCount() const;

		/// Add a new DHCPv6 option at the end of the layer
		/// @param[in] optionBuilder A DhcpV6OptionBuilder object that contains the requested DHCPv6 option data to add
		/// @return A DhcpV6Option object containing the newly added DHCP option data or logical null
		/// (DhcpV6Option#isNull() == true) if addition failed
		DhcpV6Option addOption(const DhcpV6OptionBuilder& optionBuilder);

		/// Add a new DHCPv6 option after an existing one
		/// @param[in] optionBuilder A DhcpV6OptionBuilder object that contains the requested DHCPv6 option data to add
		/// @param[in] optionType The DHCPv6 option type which the newly added option will come after
		/// @return A DhcpV6Option object containing the newly added DHCPv6 option data or logical null
		/// (DhcpV6Option#isNull() == true) if addition failed
		DhcpV6Option addOptionAfter(const DhcpV6OptionBuilder& optionBuilder, DhcpV6OptionType optionType);

		/// Add a new DHCPv6 option before an existing one
		/// @param[in] optionBuilder A DhcpV6OptionBuilder object that contains the requested DHCPv6 option data to add
		/// @param[in] optionType The DHCPv6 option type which the newly added option will come before
		/// @return A DhcpV6Option object containing the newly added DHCPv6 option data or logical null
		/// (DhcpV6Option#isNull() == true) if addition failed
		DhcpV6Option addOptionBefore(const DhcpV6OptionBuilder& optionBuilder, DhcpV6OptionType optionType);

		/// Remove an existing DHCPv6 option from the layer
		/// @param[in] optionType The DHCPv6 option type to remove
		/// @return True if DHCPv6 option was successfully removed or false if type wasn't found or if removal failed
		bool removeOption(DhcpV6OptionType optionType);

		/// Remove all DHCPv6 options in this layer
		/// @return True if all DHCPv6 options were successfully removed or false if removal failed for some reason
		bool removeAllOptions();

		/// A static method that checks whether a port is considered as a DHCPv6 port
		/// @param[in] port The port number to check
		/// @return True if this is a DHCPv6 port number, false otherwise
		static inline bool isDhcpV6Port(uint16_t port);

		/// A static method that validates the input data
		/// @param[in] data The pointer to the beginning of a byte stream of an DHCPv6 layer
		/// @param[in] dataLen The length of the byte stream
		/// @return True if the data is valid and can represent an DHCPv6 layer
		static inline bool isDataValid(const uint8_t* data, size_t dataLen);

		// implement abstract methods

		/// Does nothing for this layer (DhcpV6Layer is always last)
		void parseNextLayer() override
		{}

		/// @return The size of @ref dhcpv6_header + size of options
		size_t getHeaderLen() const override
		{
			return m_DataLen;
		}

		/// Does nothing for this layer
		void computeCalculateFields() override
		{}

		std::string toString() const override;

		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelApplicationLayer;
		}

	private:
		uint8_t* getOptionsBasePtr() const
		{
			return m_Data + sizeof(dhcpv6_header);
		}
		dhcpv6_header* getDhcpHeader() const
		{
			return reinterpret_cast<dhcpv6_header*>(m_Data);
		}
		DhcpV6Option addOptionAt(const DhcpV6OptionBuilder& optionBuilder, int offset);

		TLVRecordReader<DhcpV6Option> m_OptionReader;
	};

	// implementation of inline methods

	bool DhcpV6Layer::isDhcpV6Port(uint16_t port)
	{
		return (port == 546) || (port == 547);
	}

	bool DhcpV6Layer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		return data && dataLen >= sizeof(dhcpv6_header);
	}

}  // namespace pcpp
