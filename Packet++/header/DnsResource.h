#ifndef PACKETPP_DNS_RESOURCE
#define PACKETPP_DNS_RESOURCE

#include "DnsLayer.h"
#include "DnsLayerEnums.h"
#include "DnsResourceData.h"
#include <stdio.h>
#include <string>
#include <stdint.h>

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
	// forward declarations
	class DnsLayer;
	class IDnsResourceData;
	class DnsResourceDataPtr;


	/**
	 * @class IDnsResource
	 * An abstract class for representing all types of DNS records. This class gives access to all available record data such as DNS type, class,
	 * name, type of record, etc. The DnsLayer holds an instance of (inherited type of) this class for each DNS record in the DNS packet
	 */
	class IDnsResource
	{
	protected:
		friend class DnsLayer;
		friend class IDnsResourceData;

	protected:
		DnsLayer* m_DnsLayer;
		size_t m_OffsetInLayer;
		IDnsResource* m_NextResource;
		std::string m_DecodedName;
		size_t m_NameLength;
		uint8_t* m_ExternalRawData;

		IDnsResource(DnsLayer* dnsLayer, size_t offsetInLayer);

		IDnsResource(uint8_t* emptyRawData);

		size_t decodeName(const char* encodedName, char* result, int iteration = 1);
		void encodeName(const std::string& decodedName, char* result, size_t& resultLen);

		IDnsResource* getNextResource() const { return m_NextResource; }
		void setNexResource(IDnsResource* next) { m_NextResource = next; }

		uint8_t* getRawData() const;

		void setDnsLayer(DnsLayer* dnsLayer, size_t offsetInLayer);

	public:

		virtual ~IDnsResource() {}

		/**
		 * @return The DNS type of this record
		 */
		DnsType getDnsType() const;

		/**
		 * Set DNS type for this record
		 * @param[in] newType The type to set
		 */
		void setDnsType(DnsType newType);

		/**
		 * @return The DNS class of this record
		 */
		DnsClass getDnsClass() const;

		/**
		 * Set DNS class for this record
		 * @param[in] newClass The class to set
		 */
		void setDnsClass(DnsClass newClass);

		/**
		 * @return The name of this record
		 */
		const std::string& getName() const { return m_DecodedName; }

		/**
		 * @return The record name's offset in the packet
		 */
		size_t getNameOffset() const { return m_OffsetInLayer; }

		/**
		 * Set the name of this record. The input name can be a standard hostname (e.g 'google.com'), or it may contain
		 * a pointer to another string in the packet (as explained here: http://www.zytrax.com/books/dns/ch15/#name).
		 * The pointer is used to reduce the DNS packet size and avoid unnecessary duplications. In case you
		 * want to use a pointer in your string you should use the following format: 'some.domain.#{offset}' where '#{offset}'
		 * is a the offset from the start of the layer. For example: if the string 'yahoo.com' already appears in offset
		 * 12 in the packet and you want to set the name of the current record to 'my.subdomain.yahoo.com' you may use
		 * the following string: 'my.subdomain.#12'. This will result in writing 'my.subdomain' and a pointer to offset 12.<BR>
		 * Please notice the new name can be shorter or longer of the old name, so this method can cause the packet to be
		 * shorten or extended
		 * @param[in] newName The name to set
		 * @return True if name was set successfully or false if input string is malformed or if an error occurred
		 */
		bool setName(const std::string& newName);


		// abstract methods

		/**
		 * @return The total size in bytes of this record
		 */
		virtual size_t getSize() const = 0;

		/**
		 * @return The type of this record (query, answer, authority, additional)
		 */
		virtual DnsResourceType getType() const = 0;
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

		DnsQuery(uint8_t* emptyRawData) : IDnsResource(emptyRawData) {}

	public:
		virtual ~DnsQuery() {}

		// implementation of abstract methods
		virtual size_t getSize() const { return m_NameLength + 2 * sizeof(uint16_t); }
		virtual DnsResourceType getType() const { return DnsQueryType; }
	};


	/**
	 * @class DnsResource
	 * Representing DNS record other than DNS query
	 */
	class DnsResource : public IDnsResource
	{
		friend class DnsLayer;

	private:
		DnsResourceType m_ResourceType;

		DnsResource(DnsLayer* dnsLayer, size_t offsetInLayer, DnsResourceType resourceType) : IDnsResource(dnsLayer, offsetInLayer) { m_ResourceType = resourceType; }

		DnsResource(uint8_t* emptyRawData, DnsResourceType resType) : IDnsResource(emptyRawData), m_ResourceType(resType) {}

	public:
		virtual ~DnsResource() {}

		/**
		 * @return The time-to-leave value for this record
		 */
		uint32_t getTTL() const;

		/**
		 * Set time-to-leave value for this record
		 * @param[in] newTTL The new TTL value to set
		 */
		void setTTL(uint32_t newTTL);

		/**
		 * @return The data length value for this record (taken from the "data length" field of the record)
		 */
		size_t getDataLength() const;

		/**
		 * @return A smart pointer to an IDnsResourceData object that contains the DNS resource data. It is guaranteed that the
		 * smart pointer will always point to an object and never to NULL. The specific object type depends on the DNS type of this record:<BR>
		 * - For type A (::DNS_TYPE_A): the return value is a smart pointer to IPv4DnsResourceData object that contains the IPv4 address<BR>
		 * - For type AAAA (::DNS_TYPE_AAAA): the return value is a smart pointer to IPv6DnsResourceData object that contains the IPv6 address<BR>
		 * - For types NS, CNAME, DNAME, PTR (::DNS_TYPE_NS, ::DNS_TYPE_CNAME, ::DNS_TYPE_DNAM, ::DNS_TYPE_PTR): the return value is
		 *   a smart pointer to StringDnsResourceData object that contains the name<BR>
		 * - For type MX (::DNS_TYPE_MX): the return value is a smart pointer to MxDnsResourceData object that contains the MX data (preference and
		 *   mail exchange name)<BR>
		 * - For all other types: the return value is a smart pointer to GenericDnsResourceData which contains a byte array of the data
		 */
		DnsResourceDataPtr getData() const;

		/**
		 * @return The offset of data in the DNS layer
		 */
		size_t getDataOffset() const;

		/**
		 * Set resource data. The given IDnsResourceData input object is validated against the DNS type of the resource. For example: if DNS type is A
		 * and data isn't of type IPv4DnsResourceData (which contains the IPv4 address) a log error will be printed and the method will return false.
		 * This method currently supports the following DNS types:<BR>
		 * - ::DNS_TYPE_A (IPv4 address) - data is expected to be a pointer to IPv4DnsResourceData with a valid IPv4 address
		 * - ::DNS_TYPE_AAAA (IPv6 address) - data is expected to be a pointer to IPv6DnsResourceData with a valid IPv6 address
		 * - ::DNS_TYPE_NS, ::DNS_TYPE_CNAME, ::DNS_TYPE_DNAM, ::DNS_TYPE_PTR (name data) - data is expected to be a pointer to StringDnsResourceData
		 *   object that contains a host name, e.g: 'www.google.com'
		 * - ::DNS_TYPE_MX (MX data) - data is expected to be a pointer to MxDnsResourceData object that contains the MX data
		 * - else: data is expected to be a pointer to GenericDnsResourceData object that contains a valid hex string (valid hex string means a string
		 *   which has an even number of characters representing a valid hex data. e.g: '0d0a45569a9b')
		 * @param[in] data The pointer to the data object, as described above
		 * @return True if data was properly set or false if data is illegal or method couldn't extend or shorted the packet (appropriate error log is
		 * printed in all cases)
		 */
		bool setData(IDnsResourceData* data);

		/**
		 * Some records don't have a DNS class and the bytes used for storing the DNS class are used for other purpose. This method enables the
		 * user to receive these bytes
		 * @return The value stored in this place
		 */
		uint16_t getCustomDnsClass() const;

		/**
		 * Some records don't have a DNS class and the bytes used for storing the DNS class are used for other purpose. This method enables the
		 * user to set these bytes
		 * @param[in] customValue The value to set
		 */
		void setCustomDnsClass(uint16_t customValue);

		// implementation of abstract methods
		virtual size_t getSize() const { return m_NameLength + 3 * sizeof(uint16_t) + sizeof(uint32_t) + getDataLength(); }
		virtual DnsResourceType getType() const { return m_ResourceType; }

	};

}

#endif // PACKETPP_DNS_RESOURCE
