#define LOG_MODULE PacketLogModuleDnsLayer

#include "DnsLayer.h"
#include "Logger.h"
#include <sstream>
#include <vector>
#include "EndianPortable.h"

namespace pcpp
{

	// ~~~~~~~~
	// DnsLayer
	// ~~~~~~~~

	DnsLayer::DnsLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	    : Layer(data, dataLen, prevLayer, packet)
	{
		init(0, true);
	}

	DnsLayer::DnsLayer()
	{
		initNewLayer(0);
	}

	DnsLayer::DnsLayer(const DnsLayer& other) : Layer(other)
	{
		init(other.m_OffsetAdjustment, true);
	}

	DnsLayer::DnsLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet, size_t offsetAdjustment)
	    : Layer(data, dataLen, prevLayer, packet)
	{
		init(offsetAdjustment, true);
	}

	DnsLayer::DnsLayer(size_t offsetAdjustment)
	{
		initNewLayer(offsetAdjustment);
	}

	DnsLayer& DnsLayer::operator=(const DnsLayer& other)
	{
		Layer::operator=(other);

		IDnsResource* curResource = m_ResourceList;
		while (curResource != nullptr)
		{
			IDnsResource* temp = curResource->getNextResource();
			delete curResource;
			curResource = temp;
		}

		init(other.m_OffsetAdjustment, true);

		return (*this);
	}

	DnsLayer::~DnsLayer()
	{
		IDnsResource* curResource = m_ResourceList;
		while (curResource != nullptr)
		{
			IDnsResource* nextResource = curResource->getNextResource();
			delete curResource;
			curResource = nextResource;
		}
	}

	void DnsLayer::init(size_t offsetAdjustment, bool callParseResource)
	{
		m_OffsetAdjustment = offsetAdjustment;
		m_Protocol = DNS;
		m_ResourceList = nullptr;

		m_FirstQuery = nullptr;
		m_FirstAnswer = nullptr;
		m_FirstAuthority = nullptr;
		m_FirstAdditional = nullptr;

		if (callParseResource)
			parseResources();
	}

	void DnsLayer::initNewLayer(size_t offsetAdjustment)
	{
		m_OffsetAdjustment = offsetAdjustment;
		const size_t headerLen = getBasicHeaderSize();
		allocData(headerLen);

		init(m_OffsetAdjustment, false);
	}

	size_t DnsLayer::getBasicHeaderSize()
	{
		return sizeof(dnshdr) + m_OffsetAdjustment;
	}

	dnshdr* DnsLayer::getDnsHeader() const
	{
		uint8_t* ptr = m_Data + m_OffsetAdjustment;
		return reinterpret_cast<dnshdr*>(ptr);
	}

	bool DnsLayer::extendLayer(int offsetInLayer, size_t numOfBytesToExtend, IDnsResource* resource)
	{
		if (!Layer::extendLayer(offsetInLayer, numOfBytesToExtend))
			return false;

		IDnsResource* curResource = resource->getNextResource();
		while (curResource != nullptr)
		{
			curResource->m_OffsetInLayer += numOfBytesToExtend;
			curResource = curResource->getNextResource();
		}
		return true;
	}

	bool DnsLayer::shortenLayer(int offsetInLayer, size_t numOfBytesToShorten, IDnsResource* resource)
	{
		if (!Layer::shortenLayer(offsetInLayer, numOfBytesToShorten))
			return false;

		IDnsResource* curResource = resource->getNextResource();
		while (curResource != nullptr)
		{
			curResource->m_OffsetInLayer -= numOfBytesToShorten;
			curResource = curResource->getNextResource();
		}
		return true;
	}

	void DnsLayer::parseResources()
	{
		size_t offsetInPacket = getBasicHeaderSize();
		IDnsResource* curResource = m_ResourceList;

		uint16_t numOfQuestions = be16toh(getDnsHeader()->numberOfQuestions);
		uint16_t numOfAnswers = be16toh(getDnsHeader()->numberOfAnswers);
		uint16_t numOfAuthority = be16toh(getDnsHeader()->numberOfAuthority);
		uint16_t numOfAdditional = be16toh(getDnsHeader()->numberOfAdditional);

		uint32_t numOfOtherResources = numOfQuestions + numOfAnswers + numOfAuthority + numOfAdditional;

		if (numOfOtherResources > 300)
		{
			PCPP_LOG_ERROR(
			    "DNS layer contains more than 300 resources, probably a bad packet. Skipping parsing DNS resources");
			return;
		}

		for (uint32_t i = 0; i < numOfOtherResources; i++)
		{
			DnsResourceType resType;
			if (numOfQuestions > 0)
			{
				resType = DnsQueryType;
				numOfQuestions--;
			}
			else if (numOfAnswers > 0)
			{
				resType = DnsAnswerType;
				numOfAnswers--;
			}
			else if (numOfAuthority > 0)
			{
				resType = DnsAuthorityType;
				numOfAuthority--;
			}
			else
			{
				resType = DnsAdditionalType;
				numOfAdditional--;
			}

			DnsResource* newResource = nullptr;
			DnsQuery* newQuery = nullptr;
			IDnsResource* newGenResource = nullptr;
			if (resType == DnsQueryType)
			{
				newQuery = new DnsQuery(this, offsetInPacket);
				newGenResource = newQuery;
				offsetInPacket += newQuery->getSize();
			}
			else
			{
				newResource = new DnsResource(this, offsetInPacket, resType);
				newGenResource = newResource;
				offsetInPacket += newResource->getSize();
			}

			if (offsetInPacket > m_DataLen)
			{
				// Parse packet failed, DNS resource is out of bounds. Probably a bad packet
				delete newGenResource;
				return;
			}

			// this resource is the first resource
			if (m_ResourceList == nullptr)
			{
				m_ResourceList = newGenResource;
				curResource = m_ResourceList;
			}
			else
			{
				curResource->setNextResource(newGenResource);
				curResource = curResource->getNextResource();
			}

			if (resType == DnsQueryType && m_FirstQuery == nullptr)
				m_FirstQuery = newQuery;
			else if (resType == DnsAnswerType && m_FirstAnswer == nullptr)
				m_FirstAnswer = newResource;
			else if (resType == DnsAuthorityType && m_FirstAuthority == nullptr)
				m_FirstAuthority = newResource;
			else if (resType == DnsAdditionalType && m_FirstAdditional == nullptr)
				m_FirstAdditional = newResource;
		}
	}

	IDnsResource* DnsLayer::getResourceByName(IDnsResource* startFrom, size_t resourceCount, const std::string& name,
	                                          bool exactMatch) const
	{
		size_t index = 0;
		while (index < resourceCount)
		{
			if (startFrom == nullptr)
				return nullptr;

			std::string resourceName = startFrom->getName();
			if (exactMatch && resourceName == name)
				return startFrom;
			else if (!exactMatch && resourceName.find(name) != std::string::npos)
				return startFrom;

			startFrom = startFrom->getNextResource();

			index++;
		}

		return nullptr;
	}

	DnsQuery* DnsLayer::getQuery(const std::string& name, bool exactMatch) const
	{
		uint16_t numOfQueries = be16toh(getDnsHeader()->numberOfQuestions);
		IDnsResource* res = getResourceByName(m_FirstQuery, numOfQueries, name, exactMatch);
		if (res != nullptr)
			return dynamic_cast<DnsQuery*>(res);
		return nullptr;
	}

	DnsQuery* DnsLayer::getFirstQuery() const
	{
		return m_FirstQuery;
	}

	DnsQuery* DnsLayer::getNextQuery(DnsQuery* query) const
	{
		if (query == nullptr || query->getNextResource() == nullptr || query->getType() != DnsQueryType ||
		    query->getNextResource()->getType() != DnsQueryType)
			return nullptr;

		return (DnsQuery*)(query->getNextResource());
	}

	size_t DnsLayer::getQueryCount() const
	{
		return be16toh(getDnsHeader()->numberOfQuestions);
	}

	DnsResource* DnsLayer::getAnswer(const std::string& name, bool exactMatch) const
	{
		uint16_t numOfAnswers = be16toh(getDnsHeader()->numberOfAnswers);
		IDnsResource* res = getResourceByName(m_FirstAnswer, numOfAnswers, name, exactMatch);
		if (res != nullptr)
			return dynamic_cast<DnsResource*>(res);
		return nullptr;
	}

	DnsResource* DnsLayer::getFirstAnswer() const
	{
		return m_FirstAnswer;
	}

	DnsResource* DnsLayer::getNextAnswer(DnsResource* answer) const
	{
		if (answer == nullptr || answer->getNextResource() == nullptr || answer->getType() != DnsAnswerType ||
		    answer->getNextResource()->getType() != DnsAnswerType)
			return nullptr;

		return (DnsResource*)(answer->getNextResource());
	}

	size_t DnsLayer::getAnswerCount() const
	{
		return be16toh(getDnsHeader()->numberOfAnswers);
	}

	DnsResource* DnsLayer::getAuthority(const std::string& name, bool exactMatch) const
	{
		uint16_t numOfAuthorities = be16toh(getDnsHeader()->numberOfAuthority);
		IDnsResource* res = getResourceByName(m_FirstAuthority, numOfAuthorities, name, exactMatch);
		if (res != nullptr)
			return dynamic_cast<DnsResource*>(res);
		return nullptr;
	}

	DnsResource* DnsLayer::getFirstAuthority() const
	{
		return m_FirstAuthority;
	}

	DnsResource* DnsLayer::getNextAuthority(DnsResource* authority) const
	{
		if (authority == nullptr || authority->getNextResource() == nullptr ||
		    authority->getType() != DnsAuthorityType || authority->getNextResource()->getType() != DnsAuthorityType)
			return nullptr;

		return (DnsResource*)(authority->getNextResource());
	}

	size_t DnsLayer::getAuthorityCount() const
	{
		return be16toh(getDnsHeader()->numberOfAuthority);
	}

	DnsResource* DnsLayer::getAdditionalRecord(const std::string& name, bool exactMatch) const
	{
		uint16_t numOfAdditionalRecords = be16toh(getDnsHeader()->numberOfAdditional);
		IDnsResource* res = getResourceByName(m_FirstAdditional, numOfAdditionalRecords, name, exactMatch);
		if (res != nullptr)
			return dynamic_cast<DnsResource*>(res);
		return nullptr;
	}

	DnsResource* DnsLayer::getFirstAdditionalRecord() const
	{
		return m_FirstAdditional;
	}

	DnsResource* DnsLayer::getNextAdditionalRecord(DnsResource* additionalRecord) const
	{
		if (additionalRecord == nullptr || additionalRecord->getNextResource() == nullptr ||
		    additionalRecord->getType() != DnsAdditionalType ||
		    additionalRecord->getNextResource()->getType() != DnsAdditionalType)
			return nullptr;

		return (DnsResource*)(additionalRecord->getNextResource());
	}

	size_t DnsLayer::getAdditionalRecordCount() const
	{
		return be16toh(getDnsHeader()->numberOfAdditional);
	}

	std::string DnsLayer::toString() const
	{
		std::ostringstream tidAsString;
		tidAsString << be16toh(getDnsHeader()->transactionID);

		std::ostringstream queryCount;
		queryCount << getQueryCount();

		std::ostringstream answerCount;
		answerCount << getAnswerCount();

		std::ostringstream authorityCount;
		authorityCount << getAuthorityCount();

		std::ostringstream additionalCount;
		additionalCount << getAdditionalRecordCount();

		if (getDnsHeader()->queryOrResponse == 1)
		{
			return "DNS query response, ID: " + tidAsString.str() + ";" + " queries: " + queryCount.str() +
			       ", answers: " + answerCount.str() + ", authorities: " + authorityCount.str() +
			       ", additional record: " + additionalCount.str();
		}
		else if (getDnsHeader()->queryOrResponse == 0)
		{
			return "DNS query, ID: " + tidAsString.str() + ";" + " queries: " + queryCount.str() +
			       ", answers: " + answerCount.str() + ", authorities: " + authorityCount.str() +
			       ", additional record: " + additionalCount.str();
		}
		else  // not likely - a DNS with no answers and no queries
		{
			return "DNS record without queries and answers, ID: " + tidAsString.str() + ";" +
			       " queries: " + queryCount.str() + ", answers: " + answerCount.str() +
			       ", authorities: " + authorityCount.str() + ", additional record: " + additionalCount.str();
		}
	}

	static constexpr const char* dnsTypeToString(DnsType dnsType)
	{
		switch (dnsType)
		{
		case DNS_TYPE_A:
			return "A";
		case DNS_TYPE_NS:
			return "NS";
		case DNS_TYPE_MD:
			return "MD";
		case DNS_TYPE_MF:
			return "MF";
		case DNS_TYPE_CNAME:
			return "CNAME";
		case DNS_TYPE_SOA:
			return "SOA";
		case DNS_TYPE_MB:
			return "MB";
		case DNS_TYPE_MG:
			return "MG";
		case DNS_TYPE_MR:
			return "MR";
		case DNS_TYPE_NULL_R:
			return "NULL";
		case DNS_TYPE_WKS:
			return "WKS";
		case DNS_TYPE_PTR:
			return "PTR";
		case DNS_TYPE_HINFO:
			return "HINFO";
		case DNS_TYPE_MINFO:
			return "MINFO";
		case DNS_TYPE_MX:
			return "MX";
		case DNS_TYPE_TXT:
			return "TXT";
		case DNS_TYPE_RP:
			return "RP";
		case DNS_TYPE_AFSDB:
			return "AFSDB";
		case DNS_TYPE_X25:
			return "X25";
		case DNS_TYPE_ISDN:
			return "ISDN";
		case DNS_TYPE_RT:
			return "RT";
		case DNS_TYPE_NSAP:
			return "NSAP";
		case DNS_TYPE_NSAP_PTR:
			return "NSAP-PTR";
		case DNS_TYPE_SIG:
			return "SIG";
		case DNS_TYPE_KEY:
			return "KEY";
		case DNS_TYPE_PX:
			return "PX";
		case DNS_TYPE_GPOS:
			return "GPOS";
		case DNS_TYPE_AAAA:
			return "AAAA";
		case DNS_TYPE_LOC:
			return "LOC";
		case DNS_TYPE_NXT:
			return "NXT";
		case DNS_TYPE_EID:
			return "EID";
		case DNS_TYPE_NIMLOC:
			return "NIMLOC";
		case DNS_TYPE_SRV:
			return "SRV";
		case DNS_TYPE_ATMA:
			return "ATMA";
		case DNS_TYPE_NAPTR:
			return "NAPTR";
		case DNS_TYPE_KX:
			return "KX";
		case DNS_TYPE_CERT:
			return "CERT";
		case DNS_TYPE_A6:
			return "A6";
		case DNS_TYPE_DNAM:
			return "DNAME";
		case DNS_TYPE_SINK:
			return "SINK";
		case DNS_TYPE_OPT:
			return "OPT";
		case DNS_TYPE_APL:
			return "APL";
		case DNS_TYPE_DS:
			return "DS";
		case DNS_TYPE_SSHFP:
			return "SSHFP";
		case DNS_TYPE_IPSECKEY:
			return "IPSECKEY";
		case DNS_TYPE_RRSIG:
			return "RRSIG";
		case DNS_TYPE_NSEC:
			return "NSEC";
		case DNS_TYPE_DNSKEY:
			return "DNSKEY";
		case DNS_TYPE_DHCID:
			return "DHCID";
		case DNS_TYPE_NSEC3:
			return "NSEC3";
		case DNS_TYPE_NSEC3PARAM:
			return "NSEC3PARAM";
		case DNS_TYPE_ALL:
			return "ANY";
		default:
			return "Unknown";
		}
	}

	const FieldDescriptor DnsLayer::SerializedFields::TransactionID{ Layer::SerializedFields::MaxID + 1,
		                                                             "transactionID" };
	const FieldDescriptor DnsLayer::SerializedFields::IsResponse{ Layer::SerializedFields::MaxID + 2, "isResponse" };
	const FieldDescriptor DnsLayer::SerializedFields::Opcode{ Layer::SerializedFields::MaxID + 3, "opcode" };
	const FieldDescriptor DnsLayer::SerializedFields::AuthoritativeAnswer{ Layer::SerializedFields::MaxID + 4,
		                                                                   "authoritativeAnswer" };
	const FieldDescriptor DnsLayer::SerializedFields::Truncation{ Layer::SerializedFields::MaxID + 5, "truncation" };
	const FieldDescriptor DnsLayer::SerializedFields::RecursionDesired{ Layer::SerializedFields::MaxID + 6,
		                                                                "recursionDesired" };
	const FieldDescriptor DnsLayer::SerializedFields::RecursionAvailable{ Layer::SerializedFields::MaxID + 7,
		                                                                  "recursionAvailable" };
	const FieldDescriptor DnsLayer::SerializedFields::AuthenticData{ Layer::SerializedFields::MaxID + 8,
		                                                             "authenticData" };
	const FieldDescriptor DnsLayer::SerializedFields::CheckingDisabled{ Layer::SerializedFields::MaxID + 9,
		                                                                "checkingDisabled" };
	const FieldDescriptor DnsLayer::SerializedFields::ResponseCode{ Layer::SerializedFields::MaxID + 10,
		                                                            "responseCode" };
	const FieldDescriptor DnsLayer::SerializedFields::Queries{ Layer::SerializedFields::MaxID + 11, "queries" };
	const FieldDescriptor DnsLayer::SerializedFields::Answers{ Layer::SerializedFields::MaxID + 12, "answers" };
	const FieldDescriptor DnsLayer::SerializedFields::Authorities{ Layer::SerializedFields::MaxID + 13, "authorities" };
	const FieldDescriptor DnsLayer::SerializedFields::AdditionalRecords{ Layer::SerializedFields::MaxID + 14,
		                                                                 "additionalRecords" };

	const DnsLayer::SerializedFields::QueryObject DnsQueryObject{ 0, "query" };
	const FieldDescriptor DnsLayer::SerializedFields::QueryObject::Name{ 0, "name" };
	const FieldDescriptor DnsLayer::SerializedFields::QueryObject::Type{ 1, "type" };
	const FieldDescriptor DnsLayer::SerializedFields::QueryObject::TypeName{ 2, "typeName" };
	const FieldDescriptor DnsLayer::SerializedFields::QueryObject::Class{ 3, "class" };

	const DnsLayer::SerializedFields::ResourceObject DnsResourceObject{ 0, "resource" };
	const FieldDescriptor DnsLayer::SerializedFields::ResourceObject::Name{ 0, "name" };
	const FieldDescriptor DnsLayer::SerializedFields::ResourceObject::Type{ 1, "type" };
	const FieldDescriptor DnsLayer::SerializedFields::ResourceObject::TypeName{ 2, "typeName" };
	const FieldDescriptor DnsLayer::SerializedFields::ResourceObject::Class{ 3, "class" };
	const FieldDescriptor DnsLayer::SerializedFields::ResourceObject::Ttl{ 4, "ttl" };
	const FieldDescriptor DnsLayer::SerializedFields::ResourceObject::DataLength{ 5, "dataLength" };
	const FieldDescriptor DnsLayer::SerializedFields::ResourceObject::Data{ 6, "data" };

	void DnsLayer::serializeLayer(ObjectScope& serializer) const
	{
		using QueryFields = SerializedFields::QueryObject;
		using ResourceFields = SerializedFields::ResourceObject;

		const dnshdr* hdr = getDnsHeader();
		serializer.writeHexField(SerializedFields::TransactionID, be16toh(hdr->transactionID));
		serializer.writeField(SerializedFields::IsResponse, hdr->queryOrResponse == 1);
		serializer.writeField(SerializedFields::Opcode, static_cast<uint8_t>(hdr->opcode));
		serializer.writeField(SerializedFields::AuthoritativeAnswer, hdr->authoritativeAnswer == 1);
		serializer.writeField(SerializedFields::Truncation, hdr->truncation == 1);
		serializer.writeField(SerializedFields::RecursionDesired, hdr->recursionDesired == 1);
		serializer.writeField(SerializedFields::RecursionAvailable, hdr->recursionAvailable == 1);
		serializer.writeField(SerializedFields::AuthenticData, hdr->authenticData == 1);
		serializer.writeField(SerializedFields::CheckingDisabled, hdr->checkingDisabled == 1);
		serializer.writeField(SerializedFields::ResponseCode, static_cast<uint8_t>(hdr->responseCode));

		{
			auto queries = serializer.writeArray(SerializedFields::Queries);
			for (DnsQuery* query = getFirstQuery(); query != nullptr; query = getNextQuery(query))
			{
				auto queryObject = queries.writeObject(DnsQueryObject);
				queryObject.writeField(QueryFields::Name, query->getName());
				queryObject.writeField(QueryFields::Type, static_cast<uint16_t>(query->getDnsType()));
				queryObject.writeField(QueryFields::TypeName, dnsTypeToString(query->getDnsType()));
				queryObject.writeField(QueryFields::Class, static_cast<uint16_t>(query->getDnsClass()));
			}
		}

		auto writeResource = [](ArrayScope& resources, const DnsResource* resource) {
			auto resourceObject = resources.writeObject(DnsResourceObject);
			resourceObject.writeField(ResourceFields::Name, resource->getName());
			resourceObject.writeField(ResourceFields::Type, static_cast<uint16_t>(resource->getDnsType()));
			resourceObject.writeField(ResourceFields::TypeName, dnsTypeToString(resource->getDnsType()));
			resourceObject.writeField(ResourceFields::Class, static_cast<uint16_t>(resource->getDnsClass()));
			resourceObject.writeField(ResourceFields::Ttl, resource->getTTL());
			resourceObject.writeField(ResourceFields::DataLength, resource->getDataLength());
			// raw byte arrays of records without a dedicated data type aren't meaningful to serialize
			auto data = resource->getData();
			if (!data.isTypeOf<GenericDnsResourceData>())
			{
				resourceObject.writeField(ResourceFields::Data, data->toString());
			}
		};

		{
			auto answers = serializer.writeArray(SerializedFields::Answers);
			for (DnsResource* answer = getFirstAnswer(); answer != nullptr; answer = getNextAnswer(answer))
			{
				writeResource(answers, answer);
			}
		}

		{
			auto authorities = serializer.writeArray(SerializedFields::Authorities);
			for (DnsResource* authority = getFirstAuthority(); authority != nullptr;
			     authority = getNextAuthority(authority))
			{
				writeResource(authorities, authority);
			}
		}

		auto additionalRecords = serializer.writeArray(SerializedFields::AdditionalRecords);
		for (DnsResource* additionalRecord = getFirstAdditionalRecord(); additionalRecord != nullptr;
		     additionalRecord = getNextAdditionalRecord(additionalRecord))
		{
			writeResource(additionalRecords, additionalRecord);
		}
	}

	IDnsResource* DnsLayer::getFirstResource(DnsResourceType resType) const
	{
		switch (resType)
		{
		case DnsQueryType:
		{
			return m_FirstQuery;
		}
		case DnsAnswerType:
		{
			return m_FirstAnswer;
		}
		case DnsAuthorityType:
		{
			return m_FirstAuthority;
		}
		case DnsAdditionalType:
		{
			return m_FirstAdditional;
		}
		default:
			return nullptr;
		}
	}

	void DnsLayer::setFirstResource(DnsResourceType resType, IDnsResource* resource)
	{
		switch (resType)
		{
		case DnsQueryType:
		{
			m_FirstQuery = dynamic_cast<DnsQuery*>(resource);
			break;
		}
		case DnsAnswerType:
		{
			m_FirstAnswer = dynamic_cast<DnsResource*>(resource);
			break;
		}
		case DnsAuthorityType:
		{
			m_FirstAuthority = dynamic_cast<DnsResource*>(resource);
			break;
		}
		case DnsAdditionalType:
		{
			m_FirstAdditional = dynamic_cast<DnsResource*>(resource);
			break;
		}
		default:
			return;
		}
	}

	DnsResource* DnsLayer::addResource(DnsResourceType resType, const std::string& name, DnsType dnsType,
	                                   DnsClass dnsClass, uint32_t ttl, IDnsResourceData* data)
	{
		if (data == nullptr)
		{
			PCPP_LOG_ERROR("Given data is nullptr");
			return nullptr;
		}

		// The temporary buffer holds the encoded name and the fixed RR header. The encoded name is at most the decoded
		// name plus 2 bytes and the fixed RR header is 10 bytes long. The RDATA is added by setData() after the new
		// resource is attached to the layer, so the buffer doesn't need to leave room for it
		std::vector<uint8_t> newResourceRawData(name.size() + 2 + 10, 0);

		DnsResource* newResource = new DnsResource(newResourceRawData.data(), resType);

		newResource->setDnsClass(dnsClass);

		newResource->setDnsType(dnsType);

		// cannot return false since layer shouldn't be extended or shortened in this stage
		newResource->setName(name);

		newResource->setTTL(ttl);

		size_t newResourceOffsetInLayer = getBasicHeaderSize();
		IDnsResource* curResource = m_ResourceList;
		while (curResource != nullptr && curResource->getType() <= resType)
		{
			newResourceOffsetInLayer += curResource->getSize();

			if (newResourceOffsetInLayer > m_DataLen)
			{
				// This possibly means that the DNS layer has been created from a malformed packet.
				PCPP_LOG_ERROR("Couldn't add resource! DNS Layer is malformed and contains out of bounds resources.");
				delete newResource;
				return nullptr;
			}

			IDnsResource* nextResource = curResource->getNextResource();
			if (nextResource == nullptr || nextResource->getType() > resType)
				break;
			curResource = nextResource;
		}

		// set next resource for new resource. This must happen here for extendLayer to succeed
		if (curResource != nullptr)
		{
			if (curResource->getType() > newResource->getType())
				newResource->setNextResource(m_ResourceList);
			else
				newResource->setNextResource(curResource->getNextResource());
		}
		else
		{
			// curResource != nullptr
			newResource->setNextResource(m_ResourceList);
		}

		// extend layer to make room for the new resource
		if (!extendLayer(newResourceOffsetInLayer, newResource->getSize(), newResource))
		{
			PCPP_LOG_ERROR("Couldn't extend DNS layer, addResource failed");
			delete newResource;
			return nullptr;
		}

		// connect the new resource to layer
		newResource->setDnsLayer(this, newResourceOffsetInLayer);

		// connect the new resource to the layer's resource list
		if (curResource != nullptr)
		{
			// if the new resource should be the first resource in the packet, its next resource is already the current
			// first resource, which must not point back to it
			if (curResource->getType() <= newResource->getType())
			{
				curResource->setNextResource(newResource);
			}
			// this means the new resource is the first of it's type
			if (curResource->getType() < newResource->getType())
			{
				setFirstResource(resType, newResource);
			}
			// this means the new resource should be the first resource in the packet
			else if (curResource->getType() > newResource->getType())
			{
				m_ResourceList = newResource;

				setFirstResource(resType, newResource);
			}
		}
		else  // curResource != nullptr, meaning this is the first resource in layer
		{
			m_ResourceList = newResource;

			setFirstResource(resType, newResource);
		}

		// set the resource data after the resource is attached to the layer, so setData() can extend the layer
		// by the size of the serialized RDATA
		if (!newResource->setData(data))
		{
			PCPP_LOG_ERROR("Couldn't set new resource data");
			if (!removeResource(newResource))
				PCPP_LOG_ERROR("Couldn't remove the new resource from the DNS layer");
			return nullptr;
		}

		return newResource;
	}

	DnsQuery* DnsLayer::addQuery(const std::string& name, DnsType dnsType, DnsClass dnsClass)
	{
		// create new query on temporary buffer
		uint8_t newQueryRawData[256];
		DnsQuery* newQuery = new DnsQuery(newQueryRawData);

		newQuery->setDnsClass(dnsClass);
		newQuery->setDnsType(dnsType);

		// cannot return false since layer shouldn't be extended or shortened in this stage
		newQuery->setName(name);

		// find the offset in the layer to insert the new query
		size_t newQueryOffsetInLayer = getBasicHeaderSize();
		DnsQuery* curQuery = getFirstQuery();
		while (curQuery != nullptr)
		{
			newQueryOffsetInLayer += curQuery->getSize();
			DnsQuery* nextQuery = getNextQuery(curQuery);
			if (nextQuery == nullptr)
				break;
			curQuery = nextQuery;
		}

		// set next resource for new query. This must happen here for extendLayer to succeed
		if (curQuery != nullptr)
			newQuery->setNextResource(curQuery->getNextResource());
		else
			newQuery->setNextResource(m_ResourceList);

		// extend layer to make room for the new query
		if (!extendLayer(newQueryOffsetInLayer, newQuery->getSize(), newQuery))
		{
			PCPP_LOG_ERROR("Couldn't extend DNS layer, addQuery failed");
			delete newQuery;
			return nullptr;
		}

		// connect the new query to layer
		newQuery->setDnsLayer(this, newQueryOffsetInLayer);

		// connect the new query to the layer's resource list
		if (curQuery != nullptr)
			curQuery->setNextResource(newQuery);
		else  // curQuery == nullptr, meaning this is the first query
		{
			m_ResourceList = newQuery;
			m_FirstQuery = newQuery;
		}

		// increase number of queries
		getDnsHeader()->numberOfQuestions = htobe16(getQueryCount() + 1);

		return newQuery;
	}

	DnsQuery* DnsLayer::addQuery(DnsQuery* const copyQuery)
	{
		if (copyQuery == nullptr)
			return nullptr;

		return addQuery(copyQuery->getName(), copyQuery->getDnsType(), copyQuery->getDnsClass());
	}

	bool DnsLayer::removeQuery(const std::string& queryNameToRemove, bool exactMatch)
	{
		DnsQuery* queryToRemove = getQuery(queryNameToRemove, exactMatch);
		if (queryToRemove == nullptr)
		{
			PCPP_LOG_DEBUG("Query not found");
			return false;
		}

		return removeQuery(queryToRemove);
	}

	bool DnsLayer::removeQuery(DnsQuery* queryToRemove)
	{
		bool res = removeResource(queryToRemove);
		if (res)
		{
			// decrease number of query records
			getDnsHeader()->numberOfQuestions = htobe16(getQueryCount() - 1);
		}

		return res;
	}

	DnsResource* DnsLayer::addAnswer(const std::string& name, DnsType dnsType, DnsClass dnsClass, uint32_t ttl,
	                                 IDnsResourceData* data)
	{
		DnsResource* res = addResource(DnsAnswerType, name, dnsType, dnsClass, ttl, data);
		if (res != nullptr)
		{
			// increase number of answer records
			getDnsHeader()->numberOfAnswers = htobe16(getAnswerCount() + 1);
		}

		return res;
	}

	DnsResource* DnsLayer::addAnswer(DnsResource* const copyAnswer)
	{
		if (copyAnswer == nullptr)
			return nullptr;

		return addAnswer(copyAnswer->getName(), copyAnswer->getDnsType(), copyAnswer->getDnsClass(),
		                 copyAnswer->getTTL(), copyAnswer->getData().get());
	}

	bool DnsLayer::removeAnswer(const std::string& answerNameToRemove, bool exactMatch)
	{
		DnsResource* answerToRemove = getAnswer(answerNameToRemove, exactMatch);
		if (answerToRemove == nullptr)
		{
			PCPP_LOG_DEBUG("Answer record not found");
			return false;
		}

		return removeAnswer(answerToRemove);
	}

	bool DnsLayer::removeAnswer(DnsResource* answerToRemove)
	{
		bool res = removeResource(answerToRemove);
		if (res)
		{
			// decrease number of answer records
			getDnsHeader()->numberOfAnswers = htobe16(getAnswerCount() - 1);
		}

		return res;
	}

	DnsResource* DnsLayer::addAuthority(const std::string& name, DnsType dnsType, DnsClass dnsClass, uint32_t ttl,
	                                    IDnsResourceData* data)
	{
		DnsResource* res = addResource(DnsAuthorityType, name, dnsType, dnsClass, ttl, data);
		if (res != nullptr)
		{
			// increase number of authority records
			getDnsHeader()->numberOfAuthority = htobe16(getAuthorityCount() + 1);
		}

		return res;
	}

	DnsResource* DnsLayer::addAuthority(DnsResource* const copyAuthority)
	{
		if (copyAuthority == nullptr)
			return nullptr;

		return addAuthority(copyAuthority->getName(), copyAuthority->getDnsType(), copyAuthority->getDnsClass(),
		                    copyAuthority->getTTL(), copyAuthority->getData().get());
	}

	bool DnsLayer::removeAuthority(const std::string& authorityNameToRemove, bool exactMatch)
	{
		DnsResource* authorityToRemove = getAuthority(authorityNameToRemove, exactMatch);
		if (authorityToRemove == nullptr)
		{
			PCPP_LOG_DEBUG("Authority not found");
			return false;
		}

		return removeAuthority(authorityToRemove);
	}

	bool DnsLayer::removeAuthority(DnsResource* authorityToRemove)
	{
		bool res = removeResource(authorityToRemove);
		if (res)
		{
			// decrease number of authority records
			getDnsHeader()->numberOfAuthority = htobe16(getAuthorityCount() - 1);
		}

		return res;
	}

	DnsResource* DnsLayer::addAdditionalRecord(const std::string& name, DnsType dnsType, DnsClass dnsClass,
	                                           uint32_t ttl, IDnsResourceData* data)
	{
		DnsResource* res = addResource(DnsAdditionalType, name, dnsType, dnsClass, ttl, data);
		if (res != nullptr)
		{
			// increase number of authority records
			getDnsHeader()->numberOfAdditional = htobe16(getAdditionalRecordCount() + 1);
		}

		return res;
	}

	DnsResource* DnsLayer::addAdditionalRecord(const std::string& name, DnsType dnsType, uint16_t customData1,
	                                           uint32_t customData2, IDnsResourceData* data)
	{
		DnsResource* res = addAdditionalRecord(name, dnsType, DNS_CLASS_ANY, customData2, data);
		if (res != nullptr)
		{
			res->setCustomDnsClass(customData1);
		}

		return res;
	}

	DnsResource* DnsLayer::addAdditionalRecord(DnsResource* const copyAdditionalRecord)
	{
		if (copyAdditionalRecord == nullptr)
			return nullptr;

		return addAdditionalRecord(copyAdditionalRecord->getName(), copyAdditionalRecord->getDnsType(),
		                           copyAdditionalRecord->getCustomDnsClass(), copyAdditionalRecord->getTTL(),
		                           copyAdditionalRecord->getData().get());
	}

	bool DnsLayer::removeAdditionalRecord(const std::string& additionalRecordNameToRemove, bool exactMatch)
	{
		DnsResource* additionalRecordToRemove = getAdditionalRecord(additionalRecordNameToRemove, exactMatch);
		if (additionalRecordToRemove == nullptr)
		{
			PCPP_LOG_DEBUG("Additional record not found");
			return false;
		}

		return removeAdditionalRecord(additionalRecordToRemove);
	}

	bool DnsLayer::removeAdditionalRecord(DnsResource* additionalRecordToRemove)
	{
		bool res = removeResource(additionalRecordToRemove);
		if (res)
		{
			// decrease number of additional records
			getDnsHeader()->numberOfAdditional = htobe16(getAdditionalRecordCount() - 1);
		}

		return res;
	}

	bool DnsLayer::removeResource(IDnsResource* resourceToRemove)
	{
		if (resourceToRemove == nullptr)
		{
			PCPP_LOG_DEBUG("resourceToRemove cannot be nullptr");
			return false;
		}

		// find the resource preceding resourceToRemove
		IDnsResource* prevResource = m_ResourceList;

		if (m_ResourceList != resourceToRemove)
		{
			while (prevResource != nullptr)
			{
				IDnsResource* temp = prevResource->getNextResource();
				if (temp == resourceToRemove)
					break;

				prevResource = temp;
			}
		}

		if (prevResource == nullptr)
		{
			PCPP_LOG_DEBUG("Resource not found");
			return false;
		}

		// shorten the layer and fix offset in layer for all next DNS resources in the packet
		if (!shortenLayer(resourceToRemove->m_OffsetInLayer, resourceToRemove->getSize(), resourceToRemove))
		{
			PCPP_LOG_ERROR("Couldn't shorten the DNS layer, resource cannot be removed");
			return false;
		}

		// remove resourceToRemove from the resources linked list
		if (m_ResourceList != resourceToRemove)
		{
			prevResource->setNextResource(resourceToRemove->getNextResource());
		}
		else
		{
			m_ResourceList = resourceToRemove->getNextResource();
		}

		// check whether resourceToRemove was the first of its type
		if (getFirstResource(resourceToRemove->getType()) == resourceToRemove)
		{
			IDnsResource* nextResource = resourceToRemove->getNextResource();
			if (nextResource != nullptr && nextResource->getType() == resourceToRemove->getType())
				setFirstResource(resourceToRemove->getType(), nextResource);
			else
				setFirstResource(resourceToRemove->getType(), nullptr);
		}

		// free resourceToRemove memory
		delete resourceToRemove;

		return true;
	}

	// ~~~~~~~~~~~~~~~
	// DnsOverTcpLayer
	// ~~~~~~~~~~~~~~~

	uint16_t DnsOverTcpLayer::getTcpMessageLength()
	{
		return be16toh(*(uint16_t*)m_Data);
	}

	void DnsOverTcpLayer::setTcpMessageLength(uint16_t value)
	{
		((uint16_t*)m_Data)[0] = htobe16(value);
	}

	void DnsOverTcpLayer::computeCalculateFields()
	{
		setTcpMessageLength(m_DataLen - sizeof(uint16_t));
	}

	const FieldDescriptor DnsOverTcpLayer::SerializedFields::TcpMessageLength{ DnsLayer::SerializedFields::MaxID + 1,
		                                                                       "tcpMessageLength" };

	void DnsOverTcpLayer::serializeLayer(ObjectScope& serializer) const
	{
		DnsLayer::serializeLayer(serializer);
		serializer.writeField(SerializedFields::TcpMessageLength, be16toh(*reinterpret_cast<uint16_t*>(m_Data)));
	}

}  // namespace pcpp
