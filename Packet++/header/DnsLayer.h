#ifndef PACKETPP_DNS_LAYER
#define PACKETPP_DNS_LAYER

#include "Layer.h"
#include <vector>
#ifdef WIN32
#include <winsock2.h>
#elif LINUX
#include <in.h>
#endif

/// @file

using namespace std;

/**
 * @struct dnshdr
 * Represents the fixed part of the DNS header, meaning the part that doesn't include the DNS data (queries, answers, authorities
 * and additional records)
 */
#pragma pack(push, 1)
struct dnshdr
{
	/** DNS query identification */
	uint16_t transactionID;
#if (BYTE_ORDER == LITTLE_ENDIAN)
	uint16_t
	/** Recursion desired flag */
		recursionDesired:1,
	/**	Truncated flag */
		truncation:1,
	/**	Authoritative answer flag */
		authoritativeAnswer:1,
	/** Operation Code */
		opcode:4,
	/**	Query/Response flag */
		queryOrResponse:1,
	/** Return Code */
		responseCode:4,
	/** Checking disabled flag */
		checkingDisabled:1,
	/**	Authenticated data flag */
		authenticData:1,
	/**	Zero flag (Reserved) */
		zero:1,
	/**	Recursion available flag */
		recursionAvailable:1;
#elif (BYTE_ORDER == BIG_ENDIAN)
	uint16_t
	/**	Query/Response flag */
		queryOrResponse:1,
	/** Operation Code */
		opcode:4,
	/**	Authoritative answer flag */
		authoritativeAnswer:1,
	/**	Truncated flag */
		truncation:1,
	/** Recursion desired flag */
		recursionDesired:1,
	/**	Recursion available flag */
		recursionAvailable:1,
	/**	Zero flag (Reserved) */
		zero:1,
	/**	Authenticated data flag */
		authenticData:1,
	/** Checking disabled flag */
		checkingDisabled:1,
	/** Return Code */
		responseCode:4;
#endif
	/** Number of DNS query records in packet */
	uint16_t numberOfQuestions;
	/** Number of DNS answer records in packet */
	uint16_t numberOfAnswers;
	/** Number of authority records in packet */
	uint16_t numberOfAuthority;
	/** Number of additional records in packet */
	uint16_t numberOfAdditional;
};
#pragma pack(pop)


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


class DnsLayer;


/**
 * @class IDnsResource
 * An abstract class for representing all types of DNS records. This class gives access to all available record data such as DNS type, class,
 * name, type of record, etc. The DnsLayer holds an instance of (inherited type of) this class for each DNS record in the DNS packet
 */
class IDnsResource
{
protected:
	friend class DnsLayer;

protected:
	DnsLayer* m_DnsLayer;
	size_t m_OffsetInLayer;
	IDnsResource* m_NextResource;
	string m_DecodedName;
	size_t m_NameLength;

	IDnsResource(DnsLayer* dnsLayer, size_t offsetInLayer);

	size_t decodeName(const char* encodedName, string& result);
	void encodeName(const string& decodedName, char* result, size_t& resultLen);

	inline IDnsResource* getNextResource() { return m_NextResource; }
	inline void setNexResource(IDnsResource* next) { m_NextResource = next; }

	uint8_t* getRawData();

public:
	/**
	 * An enum for representing the 4 types of possible DNS records
	 */
	enum ResourceType
	{
		/** DNS query record */
		DnsQuery,
		/** DNS answer record */
		DnsAnswer,
		/** DNS authority record */
		DnsAuthority,
		/** DNS additional record */
		DnsAdditional
	};

	virtual ~IDnsResource() {}

	/**
	 * @return The DNS type of this record
	 */
	DnsType getDnsType();

	/**
	 * Set DNS type for this record
	 * @param[in] newType The type to set
	 */
	void setDnsType(DnsType newType);

	/**
	 * @return The DNS class of this record
	 */
	DnsClass getDnsClass();

	/**
	 * Set DNS class for this record
	 * @param[in] newClass The class to set
	 */
	void setDnsClass(DnsClass newClass);

	/**
	 * @return The name of this record
	 */
	string getName() { return m_DecodedName; }

	/**
	 * Set the name of this record. Note the new name can be shorter or longer of the old name, so this method can cause the packet to be
	 * shorten or extended
	 * @param[in] newName The name to set
	 */
	bool setName(const string& newName);


	// abstract methods

	/**
	 * @return The total size in bytes of this record
	 */
	virtual size_t getSize() = 0;

	/**
	 * @return The type of this record (query, answer, authority, additional)
	 */
	virtual ResourceType getType() = 0;
};


/**
 * @class DnsQuery
 * Representing a DNS query record
 */
class DnsQuery : public IDnsResource
{
	friend class DnsLayer;

private:
	DnsQuery(DnsLayer* dnsLayer, size_t offsetInLayer) : IDnsResource(dnsLayer, offsetInLayer) {}

public:
	virtual ~DnsQuery() {}

	// abstract methods
	virtual size_t getSize() { return m_NameLength + 2*sizeof(uint16_t); }
	virtual ResourceType getType() { return IDnsResource::DnsQuery; }
};


/**
 * @class DnsResource
 * Representing DNS record other than DNS query
 */
class DnsResource : public IDnsResource
{
	friend class DnsLayer;

private:
	ResourceType m_ResourceType;

	DnsResource(DnsLayer* dnsLayer, size_t offsetInLayer, ResourceType resourceType) : IDnsResource(dnsLayer, offsetInLayer) { m_ResourceType = resourceType; }

public:
	virtual ~DnsResource() {}

	/**
	 * @return The time-to-leave value for this record
	 */
	uint32_t getTTL();

	/**
	 * Set time-to-leave value for this record
	 * @param[in] newTTL The new TTL value to set
	 */
	void setTTL(uint32_t newTTL);

	/**
	 * @return The data length value for this record (taken from the "data length" field of the record)
	 */
	size_t getDataLength();

	/**
	 * @return The record data as string. The return value depends on the DNS type of this record:<BR>
	 * - For type A (::DNS_TYPE_A): the return value is the IPv4 address as string<BR>
	 * - For type AAAA (::DNS_TYPE_AAAA): the return value is the IPv6 address as string<BR>
	 * - For types NS, CNAME, DNAME, PTR, MX (::DNS_TYPE_NS, ::DNS_TYPE_CNAME, ::DNS_TYPE_DNAM, ::DNS_TYPE_PTR,
	 * ::DNS_TYPE_MX): the return value is the name<BR>
	 * - For all other types: the return value is a hex stream of the data
	 */
	string getDataAsString();

	// abstract methods
	virtual size_t getSize() { return m_NameLength + 3*sizeof(uint16_t) + sizeof(uint32_t) + getDataLength(); }
	virtual ResourceType getType() { return m_ResourceType; }

};


/**
 * @class DnsLayer
 * Represents the DNS protocol layer.<BR>
 * CURRENTLY ONLY DNS PARSING IS AVAILABLE. CREATING AND EDITING DNS ATTRIBUTES WILL BE ADDED LATER
 */
class DnsLayer : public Layer
{
	friend class IDnsResource;
	friend class DnsQuery;

public:

	/**
	 * A constructor that creates the layer from an existing packet raw data
	 * @param[in] data A pointer to the raw data
	 * @param[in] dataLen Size of the data in bytes
	 * @param[in] prevLayer A pointer to the previous layer
	 * @param[in] packet A pointer to the Packet instance where layer will be stored in
	 */
	DnsLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

	virtual ~DnsLayer();

	/**
	 * Get a pointer to the DNS header (as opposed to the DNS data which is the queries, answers, etc. Data can be retrieved through the
	 * other methods of this layer. Notice the return value points directly to the data, so every change will change the actual packet data
	 * @return A pointer to the @ref dnshdr
	 */
	inline dnshdr* getDnsHeader() { return (dnshdr*)m_Data; }

	/**
	 * Searches for a DNS query by its name field. Notice this method returns only a query which its name equals to the requested name. If
	 * several queries match the requested name, the first one will be returned. If no queries match the requested name, NULL will be returned
	 * @param[in] name The name of the query to search
	 * @return The first matching DNS query or NULL if no queries were found
	 */
	DnsQuery* getQuery(const string& name);

	/**
	 * @return The first DNS query in the packet or NULL if packet doesn't contain any queries
	 */
	DnsQuery* getFirstQuery();

	/**
	 * Get the DNS query following a certain query
	 * @param[in] query A pointer to a DNS query that exist in the packet
	 * @return The DNS query following 'query'. If 'query' is NULL or 'query' is the last query in the packet NULL will be returned
	 */
	DnsQuery* getNextQuery(DnsQuery* query);

	/**
	 * @return The number of DNS queries in the packet
	 */
	size_t getQueryCount();

	/**
	 * Searches for a DNS answer by its name field. Notice this method returns only an answer which its name equals to the requested name. If
	 * several answers match the requested name, the first one will be returned. If no answers match the requested name, NULL will be returned
	 * @param[in] name The name of the answer to search
	 * @return The first matching DNS answer or NULL if no answers were found
	 */
	DnsResource* getAnswer(const string& name);

	/**
	 * @return The first DNS answer in the packet or NULL if packet doesn't contain any answers
	 */
	DnsResource* getFirstAnswer();

	/**
	 * Get the DNS answer following a certain answer
	 * @param[in] answer A pointer to a DNS answer that exist in the packet
	 * @return The DNS answer following 'answer'. If 'answer' is NULL or 'answer' is the last answer in the packet NULL will be returned
	 */
	DnsResource* getNextAnswer(DnsResource* answer);

	/**
	 * @return The number of DNS answers in the packet
	 */
	size_t getAnswerCount();

	/**
	 * Searches for a DNS authority by its name field. Notice this method returns only an authority which its name equals to the requested name. If
	 * several authorities match the requested name, the first one will be returned. If no authorities match the requested name, NULL will be returned
	 * @param[in] name The name of the authority to search
	 * @return The first matching DNS authority or NULL if no authorities were found
	 */
	DnsResource* getAuthority(const string& name);

	/**
	 * @return The first DNS authority in the packet or NULL if packet doesn't contain any authorities
	 */
	DnsResource* getFirstAuthority();

	/**
	 * Get the DNS authority following a certain authority
	 * @param[in] authority A pointer to a DNS authority that exist in the packet
	 * @return The DNS authority following 'authority'. If 'authority' is NULL or 'authority' is the last authority in the packet NULL will be returned
	 */
	DnsResource* getNextAuthority(DnsResource* authority);

	/**
	 * @return The number of DNS authorities in the packet
	 */
	size_t getAuthorityCount();

	/**
	 * Searches for a DNS additional record by its name field. Notice this method returns only an additional record which its name equals to
	 * the requested name. If several additional records match the requested name, the first one will be returned. If no additional records
	 * match the requested name, NULL will be returned
	 * @param[in] name The name of the additional record to search
	 * @return The first matching DNS additional record or NULL if no additional records were found
	 */
	DnsResource* getAdditionalRecord(const string& name);

	/**
	 * @return The first DNS additional record in the packet or NULL if packet doesn't contain any additional records
	 */
	DnsResource* getFirstAdditionalRecord();

	/**
	 * Get the DNS additional record following a certain additional record
	 * @param[in] additionalRecord A pointer to a DNS additional record that exist in the packet
	 * @return The DNS additional record following 'additionalRecord'. If 'additionalRecord' is NULL or 'additionalRecord' is the
	 * last additional record in the packet NULL will be returned
	 */
	DnsResource* getNextAdditionalRecord(DnsResource* additionalRecord);

	/**
	 * @return The number of DNS additional records in the packet
	 */
	size_t getAdditionalRecordCount();

	// implement abstract methods

	/**
	 * Does nothing for this layer (DnsLayer is always last)
	 */
	void parseNextLayer() {}

	/**
	 * Return the size of the DNS data in the packet including he DNS header and size of all queries, answers, authorities and additional
	 * records
	 */
	inline size_t getHeaderLen() { return m_DataLen; } //No layer above DNS

	/**
	 * Does nothing for this layer
	 */
	void computeCalculateFields() {}

	string toString();

	//	DnsQuery* addQuery(const string& name, DnsType dnsType, DnsClass dnsClass);
	//	void removeQuery(DnsQuery* queryToRemove);
	//	void removeQuery(const string& name);

private:
	IDnsResource* m_ResourceList;
	DnsQuery* m_FirstQuery;
	DnsResource* m_FirstAnswer;
	DnsResource* m_FirstAuthority;
	DnsResource* m_FirstAdditional;

	bool extendLayer(int offsetInLayer, size_t numOfBytesToExtend, IDnsResource* resource);
	bool shortenLayer(int offsetInLayer, size_t numOfBytesToShorten, IDnsResource* resource);

	IDnsResource* getResourceByName(IDnsResource* startFrom, size_t resourceCount, const string& name);

	void parseResources();

};

#endif /* PACKETPP_DNS_LAYER */
