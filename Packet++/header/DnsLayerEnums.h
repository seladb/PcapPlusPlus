#ifndef PACKETPP_DNS_LAYER_ENUMS
#define PACKETPP_DNS_LAYER_ENUMS

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
	/**
	 * An enum for all possible DNS record types
	 */
	enum DnsType
	{
		/** IPv4 address record */
		DNS_TYPE_A = 1,
		/** Name Server record */
		DNS_TYPE_NS,
		/** Obsolete, replaced by MX */
		DNS_TYPE_MD,
		/** Obsolete, replaced by MX */
		DNS_TYPE_MF,
		/** Canonical name record */
		DNS_TYPE_CNAME,
		/** Start of Authority record */
		DNS_TYPE_SOA,
		/** mailbox domain name record */
		DNS_TYPE_MB,
		/** mail group member record */
		DNS_TYPE_MG,
		/** mail rename domain name record */
		DNS_TYPE_MR,
		/** NULL record */
		DNS_TYPE_NULL_R,
		/** well known service description record */
		DNS_TYPE_WKS,
		/** Pointer record */
		DNS_TYPE_PTR,
		/** Host information record */
		DNS_TYPE_HINFO,
		/** mailbox or mail list information record */
		DNS_TYPE_MINFO,
		/** Mail exchanger record */
		DNS_TYPE_MX,
		/** Text record */
		DNS_TYPE_TXT,
		/** Responsible person record */
		DNS_TYPE_RP,
		/** AFS database record */
		DNS_TYPE_AFSDB,
		/** DNS X25 resource record */
		DNS_TYPE_X25,
		/** Integrated Services Digital Network record */
		DNS_TYPE_ISDN,
		/** Route Through record */
		DNS_TYPE_RT,
		/** network service access point address record */
		DNS_TYPE_NSAP,
		/** network service access point address pointer record */
		DNS_TYPE_NSAP_PTR,
		/** Signature record */
		DNS_TYPE_SIG,
		/** Key record */
		DNS_TYPE_KEY,
		/** Mail Mapping Information record */
		DNS_TYPE_PX,
		/** DNS Geographical Position record */
		DNS_TYPE_GPOS,
		/** IPv6 address record */
		DNS_TYPE_AAAA,
		/**	Location record */
		DNS_TYPE_LOC,
		/** Obsolete record */
		DNS_TYPE_NXT,
		/** DNS Endpoint Identifier record */
		DNS_TYPE_EID,
		/** DNS Nimrod Locator record */
		DNS_TYPE_NIMLOC,
		/** Service locator record */
		DNS_TYPE_SRV,
		/** Asynchronous Transfer Mode address record */
		DNS_TYPE_ATMA,
		/** Naming Authority Pointer record */
		DNS_TYPE_NAPTR,
		/** Key eXchanger record */
		DNS_TYPE_KX,
		/** Certificate record */
		DNS_TYPE_CERT,
		/** Obsolete, replaced by AAAA type */
		DNS_TYPE_A6,
		/** Delegation Name record */
		DNS_TYPE_DNAM,
		/** Kitchen sink record */
		DNS_TYPE_SINK,
		/** Option record */
		DNS_TYPE_OPT,
		/** Address Prefix List record */
		DNS_TYPE_APL,
		/** Delegation signer record */
		DNS_TYPE_DS,
		/** SSH Public Key Fingerprint record */
		DNS_TYPE_SSHFP,
		/** IPsec Key record */
		DNS_TYPE_IPSECKEY,
		/** DNSSEC signature record */
		DNS_TYPE_RRSIG,
		/** Next-Secure record */
		DNS_TYPE_NSEC,
		/** DNS Key record */
		DNS_TYPE_DNSKEY,
		/** DHCP identifier record */
		DNS_TYPE_DHCID,
		/** NSEC record version 3 */
		DNS_TYPE_NSEC3,
		/** NSEC3 parameters */
		DNS_TYPE_NSEC3PARAM,
		/** All cached records */
		DNS_TYPE_ALL = 255
	};


	/**
	 * An enum for all possible DNS classes
	 */
	enum DnsClass
	{
		/** Internet class */
		DNS_CLASS_IN = 1,
		/** Internet class with QU flag set to True */
		DNS_CLASS_IN_QU = 32769,
		/** Chaos class */
		DNS_CLASS_CH = 3,
		/** Hesiod class */
		DNS_CLASS_HS = 4,
		/** ANY class */
		DNS_CLASS_ANY = 255
	};


	/**
	 * An enum for representing the 4 types of possible DNS records
	 */
	enum DnsResourceType
	{
		/** DNS query record */
		DnsQueryType = 0,
		/** DNS answer record */
		DnsAnswerType = 1,
		/** DNS authority record */
		DnsAuthorityType = 2,
		/** DNS additional record */
		DnsAdditionalType = 3
	};

}

#endif // PACKETPP_DNS_LAYER_ENUMS
