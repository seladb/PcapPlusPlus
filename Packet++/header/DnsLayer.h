#ifndef PACKETPP_DNS_LAYER
#define PACKETPP_DNS_LAYER

#include "DnsLayerEnums.h"
#include "DnsResource.h"
#include "DnsResourceData.h"
#include "Layer.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

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


	// forward declarations
	class DnsQuery;
	class IDnsResource;
	class DnsResource;
	class IDnsResourceData;


	/**
	 * @class DnsLayer
	 * Represents the DNS protocol layer
	 */
	class DnsLayer : public Layer
	{
		friend class IDnsResource;
		friend class DnsQuery;
		friend class DnsResource;

	public:

		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		DnsLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/**
		 * A constructor that creates an empty DNS layer: all members of dnshdr are set to 0 and layer will contain no records
		 */
		DnsLayer();

		/**
		 * A copy constructor for this layer
		 * @param[in] other The DNS layer to copy from
		 */
		DnsLayer(const DnsLayer& other);

		/**
		 * An assignment operator for this layer
		 * @param[in] other The DNS layer to assign
		 * @return A reference to the assignee
		 */
		DnsLayer& operator=(const DnsLayer& other);

		virtual ~DnsLayer();

		/**
		 * Get a pointer to the DNS header (as opposed to the DNS data which is the queries, answers, etc. Data can be retrieved through the
		 * other methods of this layer. Notice the return value points directly to the data, so every change will change the actual packet data
		 * @return A pointer to the @ref dnshdr
		 */
		dnshdr* getDnsHeader() const;

		/**
		 * Searches for a DNS query by its name field. Notice this method returns only a query which its name equals to the requested name. If
		 * several queries match the requested name, the first one will be returned. If no queries match the requested name, NULL will be returned
		 * @param[in] name The name of the query to search
		 * @param[in] exactMatch Indicate whether to match the whole name or just a part of it
		 * @return The first matching DNS query or NULL if no queries were found
		 */
		DnsQuery* getQuery(const std::string& name, bool exactMatch) const;

		/**
		 * @return The first DNS query in the packet or NULL if packet doesn't contain any queries
		 */
		DnsQuery* getFirstQuery() const;

		/**
		 * Get the DNS query following a certain query
		 * @param[in] query A pointer to a DNS query that exist in the packet
		 * @return The DNS query following 'query'. If 'query' is NULL or 'query' is the last query in the packet NULL will be returned
		 */
		DnsQuery* getNextQuery(DnsQuery* query) const;

		/**
		 * @return The number of DNS queries in the packet
		 */
		size_t getQueryCount() const;

		/**
		 * Add a new DNS query to the layer
		 * @param[in] name The value that shall be set in the name field of the query
		 * @param[in] dnsType The value that shall be set in the DNS type field of the query
		 * @param[in] dnsClass The value that shall be set in the DNS class field of the query
		 * @return A pointer to the newly created DNS query or NULL if query could not be created (an appropriate error log message will be
		 * printed in this case)
		 */
		DnsQuery* addQuery(const std::string& name, DnsType dnsType, DnsClass dnsClass);

		/**
		 * Add a new DNS query similar to an already existing DNS query. All query fields will be copied from the existing query
		 * @param[in] copyQuery The record to create the new record from. copyQuery won't be changed in any way
		 * @return A pointer to the newly created DNS query or NULL if query could not be created (an appropriate error log message will be
		 * printed in this case)
		 */
		DnsQuery* addQuery(DnsQuery* const copyQuery);

		/**
		 * Remove an existing query by name. If several queries matches the name, the first match will be removed
		 * @param[in] queryNameToRemove The name of the query to remove
		 * @param[in] exactMatch Indicate whether to match the whole name or just a part of it
		 * @return True if query was found and successfully removed or false if query was not found or couldn't be removed
		 */
		bool removeQuery(const std::string& queryNameToRemove, bool exactMatch);

		/**
		 * Remove an existing query
		 * @param[in] queryToRemove A pointer to the query to remove
		 * @return True if query was found and successfully removed or false if query was not found or couldn't be removed
		 */
		bool removeQuery(DnsQuery* queryToRemove);

		/**
		 * Searches for a DNS answer by its name field. Notice this method returns only an answer which its name equals to the requested name. If
		 * several answers match the requested name, the first one will be returned. If no answers match the requested name, NULL will be returned
		 * @param[in] name The name of the answer to search
		 * @param[in] exactMatch Indicate whether to match the whole name or just a part of it
		 * @return The first matching DNS answer or NULL if no answers were found
		 */
		DnsResource* getAnswer(const std::string& name, bool exactMatch) const;

		/**
		 * @return The first DNS answer in the packet or NULL if packet doesn't contain any answers
		 */
		DnsResource* getFirstAnswer() const;

		/**
		 * Get the DNS answer following a certain answer
		 * @param[in] answer A pointer to a DNS answer that exist in the packet
		 * @return The DNS answer following 'answer'. If 'answer' is NULL or 'answer' is the last answer in the packet NULL will be returned
		 */
		DnsResource* getNextAnswer(DnsResource* answer) const;

		/**
		 * @return The number of DNS answers in the packet
		 */
		size_t getAnswerCount() const;

		/**
		 * Add a new DNS answer to the layer
		 * @param[in] name The value that shall be set in the name field of the answer
		 * @param[in] dnsType The value that shall be set in the DNS type field of the answer
		 * @param[in] dnsClass The value that shall be set in the DNS class field of the answer
		 * @param[in] ttl The value that shall be set in the 'time-to-leave' field of the answer
		 * @param[in] data The answer data to be set. The type of the data should match the type of the DNS record
		 * (for example: DNS record of type A should have data of type IPv4DnsResourceData. Please see DnsResource#setData()
		 * for more info on this
		 * @return A pointer to the newly created DNS answer or NULL if answer could not be created (an appropriate error log message will be
		 * printed in this case)
		 */
		DnsResource* addAnswer(const std::string& name, DnsType dnsType, DnsClass dnsClass, uint32_t ttl, IDnsResourceData* data);

		/**
		 * Add a new DNS answer similar to an already existing DNS answer. All answer fields will be copied from the existing answer
		 * @param[in] copyAnswer The record to create the new record from. copyAnswer won't be changed in any way
		 * @return A pointer to the newly created DNS answer or NULL if query could not be created (an appropriate error log message will be
		 * printed in this case)
		 */
		DnsResource* addAnswer(DnsResource* const copyAnswer);

		/**
		 * Remove an existing answer by name. If several answers matches the name, the first match will be removed
		 * @param[in] answerNameToRemove The name of the answer to remove
		 * @param[in] exactMatch Indicate whether to match the whole name or just a part of it
		 * @return True if answer was found and successfully removed or false if answer was not found or couldn't be removed
		 */
		bool removeAnswer(const std::string& answerNameToRemove, bool exactMatch);

		/**
		 * Remove an existing answer
		 * @param[in] answerToRemove A pointer to the answer to remove
		 * @return True if answer was found and successfully removed or false if answer was not found or couldn't be removed
		 */
		bool removeAnswer(DnsResource* answerToRemove);


		/**
		 * Searches for a DNS authority by its name field. Notice this method returns only an authority which its name equals to the requested name. If
		 * several authorities match the requested name, the first one will be returned. If no authorities match the requested name, NULL will be returned
		 * @param[in] name The name of the authority to search
		 * @param[in] exactMatch Indicate whether to match the whole name or just a part of it
		 * @return The first matching DNS authority or NULL if no authorities were found
		 */
		DnsResource* getAuthority(const std::string& name, bool exactMatch) const;

		/**
		 * @return The first DNS authority in the packet or NULL if packet doesn't contain any authorities
		 */
		DnsResource* getFirstAuthority() const;

		/**
		 * Get the DNS authority following a certain authority
		 * @param[in] authority A pointer to a DNS authority that exist in the packet
		 * @return The DNS authority following 'authority'. If 'authority' is NULL or 'authority' is the last authority in the packet NULL will be returned
		 */
		DnsResource* getNextAuthority(DnsResource* authority) const;

		/**
		 * @return The number of DNS authorities in the packet
		 */
		size_t getAuthorityCount() const;

		/**
		 * Add a new DNS authority to the layer
		 * @param[in] name The value that shall be set in the name field of the authority
		 * @param[in] dnsType The value that shall be set in the DNS type field of the authority
		 * @param[in] dnsClass The value that shall be set in the DNS class field of the authority
		 * @param[in] ttl The value that shall be set in the 'time-to-leave' field of the authority
		 * @param[in] data The authority data to be set. The type of the data should match the type of the DNS record
		 * (for example: DNS record of type A should have data of type IPv4DnsResourceData. Please see DnsResource#setData()
		 * for more info on this
		 * @return A pointer to the newly created DNS authority or NULL if authority could not be created (an appropriate error log message will be
		 * printed in this case)
		 */
		DnsResource* addAuthority(const std::string& name, DnsType dnsType, DnsClass dnsClass, uint32_t ttl, IDnsResourceData* data);

		/**
		 * Add a new DNS authority similar to an already existing DNS authority. All authority fields will be copied from the existing authority
		 * @param[in] copyAuthority The record to create the new record from. copyAuthority won't be changed in any way
		 * @return A pointer to the newly created DNS authority or NULL if query could not be created (an appropriate error log message will be
		 * printed in this case)
		 */
		DnsResource* addAuthority(DnsResource* const copyAuthority);

		/**
		 * Remove an existing authority by name. If several authorities matches the name, the first match will be removed
		 * @param[in] authorityNameToRemove The name of the authority to remove
		 * @param[in] exactMatch Indicate whether to match the whole name or just a part of it
		 * @return True if authority was found and successfully removed or false if authority was not found or couldn't be removed
		 */
		bool removeAuthority(const std::string& authorityNameToRemove, bool exactMatch);

		/**
		 * Remove an existing authority
		 * @param[in] authorityToRemove A pointer to the authority to remove
		 * @return True if authority was found and successfully removed or false if authority was not found or couldn't be removed
		 */
		bool removeAuthority(DnsResource* authorityToRemove);


		/**
		 * Searches for a DNS additional record by its name field. Notice this method returns only an additional record which its name equals to
		 * the requested name. If several additional records match the requested name, the first one will be returned. If no additional records
		 * match the requested name, NULL will be returned
		 * @param[in] name The name of the additional record to search
		 * @param[in] exactMatch Indicate whether to match the whole name or just a part of it
		 * @return The first matching DNS additional record or NULL if no additional records were found
		 */
		DnsResource* getAdditionalRecord(const std::string& name, bool exactMatch) const;

		/**
		 * @return The first DNS additional record in the packet or NULL if packet doesn't contain any additional records
		 */
		DnsResource* getFirstAdditionalRecord() const;

		/**
		 * Get the DNS additional record following a certain additional record
		 * @param[in] additionalRecord A pointer to a DNS additional record that exist in the packet
		 * @return The DNS additional record following 'additionalRecord'. If 'additionalRecord' is NULL or 'additionalRecord' is the
		 * last additional record in the packet NULL will be returned
		 */
		DnsResource* getNextAdditionalRecord(DnsResource* additionalRecord) const;

		/**
		 * @return The number of DNS additional records in the packet
		 */
		size_t getAdditionalRecordCount() const;

		/**
		 * Add a new DNS additional record to the layer
		 * @param[in] name The value that shall be set in the name field of the additional record
		 * @param[in] dnsType The value that shall be set in the DNS type field of the additional record
		 * @param[in] dnsClass The value that shall be set in the DNS class field of the additional record
		 * @param[in] ttl The value that shall be set in the 'time-to-leave' field of the additional record
		 * @param[in] data The additional record data to be set. The type of the data should match the type of the DNS record
		 * (for example: DNS record of type A should have data of type IPv4DnsResourceData. Please see DnsResource#setData()
		 * for more info on this
		 * @return A pointer to the newly created DNS additional record or NULL if additional record could not be created (an appropriate error
		 * log message will be printed in this case)
		 */
		DnsResource* addAdditionalRecord(const std::string& name, DnsType dnsType, DnsClass dnsClass, uint32_t ttl, IDnsResourceData* data);

		/**
		 * Add a new DNS additional record to the layer that doesn't have DNS class and TTL. Instead these bytes may contains some arbitrary
		 * data. In the future I may add support for these kinds of additional data records. For now, these bytes are set as raw
		 * @param[in] name The value that shall be set in the name field of the additional record
		 * @param[in] dnsType The value that shall be set in the DNS type field of the additional record
		 * @param[in] customData1 Two bytes of the arbitrary data that will be set in the offset usually used for the DNS class
		 * @param[in] customData2 Four bytes of the arbitrary data that will be set in the offset usually used for the TTL
		 * @param[in] data The additional record data to be set. The type of the data should match the type of the DNS record.
		 * (for example: DNS record of type A should have data of type IPv4DnsResourceData. Please see DnsResource#setData()
		 * for more info on this
		 * @return A pointer to the newly created DNS additional record or NULL if additional record could not be created (an appropriate error
		 * log message will be printed in this case)
		 */
		DnsResource* addAdditionalRecord(const std::string& name, DnsType dnsType, uint16_t customData1, uint32_t customData2, IDnsResourceData* data);

		/**
		 * Add a new DNS additional record similar to an already existing DNS additional record. All additional record fields will be copied from the
		 * existing additional record
		 * @param[in] copyAdditionalRecord The record to create the new record from. copyAdditionalRecord won't be changed in any way
		 * @return A pointer to the newly created DNS additional record or NULL if query could not be created (an appropriate error log message will
		 * be printed in this case)
		 */
		DnsResource* addAdditionalRecord(DnsResource* const copyAdditionalRecord);

		/**
		 * Remove an existing additional record by name. If several additional records matches the name, the first match will be removed
		 * @param[in] additionalRecordNameToRemove The name of the additional record to remove
		 * @param[in] exactMatch Indicate whether to match the whole name or just a part of it
		 * @return True if additional record was found and successfully removed or false if additional record was not found or couldn't be removed
		 */
		bool removeAdditionalRecord(const std::string& additionalRecordNameToRemove, bool exactMatch);

		/**
		 * Remove an existing additional record
		 * @param[in] additionalRecordToRemove A pointer to the additional record to remove
		 * @return True if additional record was found and successfully removed or false if additional record was not found or couldn't be removed
		 */
		bool removeAdditionalRecord(DnsResource* additionalRecordToRemove);

		// implement abstract methods

		/**
		 * Does nothing for this layer (DnsLayer is always last)
		 */
		void parseNextLayer() {}

		/**
		 * @return The size of the DNS data in the packet including he DNS header and size of all queries, answers, authorities and additional
		 * records
		 */
		size_t getHeaderLen() const { return m_DataLen; } //No layer above DNS

		/**
		 * Does nothing for this layer
		 * @return No return value
		 */
		virtual void computeCalculateFields() {}

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const { return OsiModelApplicationLayer; }

		/**
		 * A static method that checks whether the port is considered as DNS
		 * @param[in] port The port number to be checked
		 * @return True if the port is associated with the DNS protocol
		 */
		static inline bool isDnsPort(uint16_t port);

		/**
		 * A static method that validates the input data
		 * @param[in] data The pointer to the beginning of a byte stream of a DNS packet
		 * @param[in] dataLen The length of the byte stream
		 * @param[in] dnsOverTcp Should be set to "true" if this is DNS is over TCP, otherwise set to "false"
		 * (which is also the default value)
		 * @return True if the data is valid and can represent a DNS packet
		 */
		static inline bool isDataValid(const uint8_t* data, size_t dataLen, bool dnsOverTcp = false);

	protected:
		DnsLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet, size_t offsetAdjustment);
		DnsLayer(size_t offsetAdjustment);

	private:
		IDnsResource* m_ResourceList;
		DnsQuery*     m_FirstQuery;
		DnsResource*  m_FirstAnswer;
		DnsResource*  m_FirstAuthority;
		DnsResource*  m_FirstAdditional;
		uint16_t      m_OffsetAdjustment;

		size_t getBasicHeaderSize();
		void init(size_t offsetAdjustment, bool callParseResource);
		void initNewLayer(size_t offsetAdjustment);

		IDnsResource* getFirstResource(DnsResourceType resType) const;
		void setFirstResource(DnsResourceType resType, IDnsResource* resource);

		using Layer::extendLayer;
		bool extendLayer(int offsetInLayer, size_t numOfBytesToExtend, IDnsResource* resource);

		using Layer::shortenLayer;
		bool shortenLayer(int offsetInLayer, size_t numOfBytesToShorten, IDnsResource* resource);

		IDnsResource* getResourceByName(IDnsResource* startFrom, size_t resourceCount, const std::string& name, bool exactMatch) const;

		void parseResources();

		DnsResource* addResource(DnsResourceType resType, const std::string& name, DnsType dnsType, DnsClass dnsClass,
				uint32_t ttl, IDnsResourceData* data);

		bool removeResource(IDnsResource* resourceToRemove);

	};



	/**
	 * @class DnsOverTcpLayer
	 * Represents the DNS over TCP layer.
	 * DNS over TCP is described here: https://tools.ietf.org/html/rfc7766 .
	 * It is very similar to DNS over UDP, except for one field: TCP message length which is added in the beginning of the message
	 * before the other DNS data properties. The rest of the data is similar.
	 *
	 * Note: DNS over TCP can spread over more than one packet, but this implementation doesn't support this use-case and assumes
	 * the whole message fits in a single packet.
	 */
	class DnsOverTcpLayer : public DnsLayer
	{
	public:

		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		DnsOverTcpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
			: DnsLayer(data, dataLen, prevLayer, packet, sizeof(uint16_t)) {}

		/**
		 * A constructor that creates an empty DNS layer: all members of dnshdr are set to 0 and layer will contain no records
		 */
		DnsOverTcpLayer() : DnsLayer(sizeof(uint16_t)) {}

		/**
		 * A copy constructor for this layer
		 * @param[in] other The DNS over TCP layer to copy from
		 */
		DnsOverTcpLayer(const DnsOverTcpLayer& other) : DnsLayer(other) {}

		/**
		 * @return The value of the TCP message length as described in https://tools.ietf.org/html/rfc7766#section-8
		 */
		uint16_t getTcpMessageLength();

		/**
		 * Set the TCP message length value as described in https://tools.ietf.org/html/rfc7766#section-8
		 * @param[in] value The value to set
		 */
		void setTcpMessageLength(uint16_t value);


		// overridden methods

		/**
		 * Calculate the TCP message length field
		 */
		void computeCalculateFields();
	};


	// implementation of inline methods

	bool DnsLayer::isDnsPort(uint16_t port)
	{
		switch (port)
		{
		case 53:
		case 5353:
		case 5355:
			return true;
		default:
			return false;
		}
	}

	bool DnsLayer::isDataValid(const uint8_t* data, size_t dataLen, bool dnsOverTcp)
	{
		size_t minSize = sizeof(dnshdr) + (dnsOverTcp ? sizeof(uint16_t) : 0);
		return dataLen >= minSize;
	}

} // namespace pcpp

#endif /* PACKETPP_DNS_LAYER */
