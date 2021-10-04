#ifndef PACKETPP_DHCPV6_LAYER
#define PACKETPP_DHCPV6_LAYER

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
	/**
	 * DHCPv6 message types
	 */
	enum DhcpV6MessageType
	{
		/** Unknown message type */
		DHCPV6_UNKNOWN_MSG_TYPE    = 0,
		/** Solicit message type (Client to Server) */
		DHCPV6_SOLICIT             = 1,
		/** Advertise message type (Server to Client) */
		DHCPV6_ADVERTISE           = 2,
		/** Request message type (Client to Server) */
		DHCPV6_REQUEST             = 3,
		/** Confirm message type (Client to Server) */
		DHCPV6_CONFIRM             = 4,
		/** Renew message type (Client to Server) */
		DHCPV6_RENEW               = 5,
		/** Rebind message type (Client to Server) */
		DHCPV6_REBIND              = 6,
		/** Reply message type (Server to Client) */
		DHCPV6_REPLY               = 7,
		/** Release message type (Client to Server) */
		DHCPV6_RELEASE             = 8,
		/** Decline message type (Client to Server) */
		DHCPV6_DECLINE             = 9,
		/** Reconfigure message type (Server to Client) */
		DHCPV6_RECONFIGURE         = 10,
		/** Information-Request message type (Client to Server) */
		DHCPV6_INFORMATION_REQUEST = 11,
		/** Relay-Forward message type (Relay agent to Server) */
		DHCPV6_RELAY_FORWARD       = 12,
		/** Relay-Reply message type (Server to Relay agent) */
		DHCPV6_RELAY_REPLY         = 13
	};

	/**
	 * DHCPv6 option types.
	 * Resources for more information:
	 * - https://onlinelibrary.wiley.com/doi/pdf/10.1002/9781118073810.app2
	 * - https://datatracker.ietf.org/doc/html/rfc5970
	 * - https://datatracker.ietf.org/doc/html/rfc6607
	 * - https://datatracker.ietf.org/doc/html/rfc8520
	 */
	enum DhcpV6OptionType
	{
		/** Unknown option type */
		DVCPV6_OPT_UNKNOWN                  = 0,
		/** Client Identifier (DUID of client) */
		DVCPV6_OPT_CLIENTID                 = 1,
		/** Server Identifier (DUID of server) */
		DVCPV6_OPT_SERVERID                 = 2,
		/** Identity Association for Non-temporary addresses */
		DVCPV6_OPT_IA_NA                    = 3,
		/** Identity Association for Temporary addresses */
		DVCPV6_OPT_IA_TA                    = 4,
		/** IA Address option */
		DVCPV6_OPT_IAADDR                   = 5,
		/** Option Request Option */
		DVCPV6_OPT_ORO                      = 6,
		/** Preference setting */
		DVCPV6_OPT_PREFERENCE               = 7,
		/** The amount of time since the client began the current DHCP transaction */
		DVCPV6_OPT_ELAPSED_TIME             = 8,
		/** The DHCP message being relayed by a relay agent */
		DVCPV6_OPT_RELAY_MSG                = 9,
		/** Authentication  information */
		DVCPV6_OPT_AUTH                     = 11,
		/** Server unicast */
		DVCPV6_OPT_UNICAST                  = 12,
		/** Status code */
		DVCPV6_OPT_STATUS_CODE              = 13,
		/** Rapid commit */
		DVCPV6_OPT_RAPID_COMMIT             = 14,
		/** User class */
		DVCPV6_OPT_USER_CLASS               = 15,
		/** Vendor class */
		DVCPV6_OPT_VENDOR_CLASS             = 16,
		/** Vendor specific information */
		DVCPV6_OPT_VENDOR_OPTS              = 17,
		/** Interface ID */
		DVCPV6_OPT_INTERFACE_ID             = 18,
		/** Reconfigure Message */
		DVCPV6_OPT_RECONF_MSG               = 19,
		/** Reconfigure Accept */
		DVCPV6_OPT_RECONF_ACCEPT            = 20,
		/** SIP Servers Domain Name */
		DVCPV6_OPT_SIP_SERVERS_D            = 21,
		/** SIP Servers IPv6 Address List */
		DVCPV6_OPT_SIP_SERVERS_A            = 22,
		/** DNS Recursive Name Server */
		DVCPV6_OPT_DNS_SERVERS              = 23,
		/** Domain Search List */
		DVCPV6_OPT_DOMAIN_LIST              = 24,
		/** Identity Association for Prefix Delegation */
		DVCPV6_OPT_IA_PD                    = 25,
		/** IA_PD Prefix */
		DVCPV6_OPT_IAPREFIX                 = 26,
		/** Network Information Service (NIS) Servers */
		DVCPV6_OPT_NIS_SERVERS              = 27,
		/** Network Information Service v2 (NIS+) Servers */
		DVCPV6_OPT_NISP_SERVERS             = 28,
		/** Network Information Service (NIS) domain name */
		DVCPV6_OPT_NIS_DOMAIN_NAME          = 29,
		/** Network Information Service v2 (NIS+) domain name */
		DVCPV6_OPT_NISP_DOMAIN_NAME         = 30,
		/** Simple Network Time Protocol (SNTP) servers */
		DVCPV6_OPT_SNTP_SERVERS             = 31,
		/** Information Refresh */
		DVCPV6_OPT_INFORMATION_REFRESH_TIME = 32,
		/** Broadcast and Multicast Service (BCMCS) Domain Name List */
		DVCPV6_OPT_BCMCS_SERVER_D           = 33,
		/** Broadcast and Multicast Service (BCMCS) IPv6 Address List */
		DVCPV6_OPT_BCMCS_SERVER_A           = 34,
		/** Geographical location in civic (e.g., postal) format */
		DVCPV6_OPT_GEOCONF_CIVIC            = 36,
		/** Relay Agent Remote ID */
		DVCPV6_OPT_REMOTE_ID                = 37,
		/** Relay Agent Subscriber ID */
		DVCPV6_OPT_SUBSCRIBER_ID            = 38,
		/** FQDN */
		DVCPV6_OPT_CLIENT_FQDN              = 39,
		/** One or more IPv6 addresses associated with PANA (Protocol for carrying Authentication for Network Access) Authentication Agents */
		DVCPV6_OPT_PANA_AGENT               = 40,
		/** Time zone to be used by the client in IEEE 1003.1 format */
		DVCPV6_OPT_NEW_POSIX_TIMEZONE       = 41,
		/** Time zone (TZ) database entry referred to by entry name */
		DVCPV6_OPT_NEW_TZDB_TIMEZONE        = 42,
		/** Relay Agent Echo Request */
		DVCPV6_OPT_ERO                      = 43,
		/** Query option */
		DVCPV6_OPT_LQ_QUERY                 = 44,
		/** Client Data */
		DVCPV6_OPT_CLIENT_DATA              = 45,
		/** Client Last Transaction Time */
		DVCPV6_OPT_CLT_TIME                 = 46,
		/** Relay data */
		DVCPV6_OPT_LQ_RELAY_DATA            = 47,
		/** Client link */
		DVCPV6_OPT_LQ_CLIENT_LINK           = 48,
		/** Mobile IPv6 Home Network Information */
		DVCPV6_OPT_MIP6_HNINF               = 49,
		/** Mobile IPv6 Relay Agent */
		DVCPV6_OPT_MIP6_RELAY               = 50,
		/** Location to Service Translation (LoST) server domain name */
		DVCPV6_OPT_V6_LOST                  = 51,
		/** Access Points (CAPWAP) Access Controller IPv6 addresses */
		DVCPV6_OPT_CAPWAP_AC_V6             = 52,
		/** DHCPv6 Bulk LeaseQuery */
		DVCPV6_OPT_RELAY_ID                 = 53,
		/** List of IPv6 addresses for servers providing particular types of IEEE 802.21 Mobility Service (MoS) */
		DVCPV6_OPT_IPH6_ADDRESS_MOS         = 54,
		/** List of FQDNs for servers providing particular types of IEEE 802.21 Mobility Service (MoS) */
		DVCPV6_OPT_IPV6_FQDN_MOS            = 55,
		/** Network Time Protocol (NTP) or Simple NTP (SNTP) Server Location */
		DVCPV6_OPT_NTP_SERVER               = 56,
		/** Boot File Uniform Resource Locator (URL) */
		DVCPV6_OPT_BOOTFILE_URL             = 59,
		/** Boot File Parameters */
		DVCPV6_OPT_BOOTFILE_PARAM           = 60,
		/** Client System Architecture Type */
		DVCPV6_OPT_CLIENT_ARCH_TYPE         = 61,
		/** Client Network Interface Identifier */
		DVCPV6_OPT_NII                      = 62,
		/** ERP Local Domain Name */
		DVCPV6_OPT_ERP_LOCAL_DOMAIN_NAME    = 65,
		/** Relay supplied options */
		DVCPV6_OPT_RELAY_SUPPLIED_OPTIONS   = 66,
		/** Virtual Subnet Selection */
		DVCPV6_OPT_VSS                      = 68,
		/** Client link layer */
		DVCPV6_OPT_CLIENT_LINKLAYER_ADDR    = 79,
		/** Manufacturer Usage Description */
		DVCPV6_OPT_MUD_URL                  = 112
	};
}
# endif // PACKETPP_DHCPV6_LAYER