#define LOG_MODULE PacketLogModuleDnsLayer

#include "DnsLayer.h"
#include "Logger.h"
#include "IpAddress.h"
#include <sstream>
#include <string.h>
#include <iomanip>
#include <stdlib.h>

namespace pcpp
{

static std::map<uint16_t, bool> createDNSPortMap()
{
	std::map<uint16_t, bool> result;
	result[53] = true;
	result[5353] = true;
	result[5355] = true;
	return result;
}

static const std::map<uint16_t, bool> DNSPortMap = createDNSPortMap();


DnsLayer::DnsLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	: Layer(data, dataLen, prevLayer, packet)
{
	m_Protocol = DNS;
	m_ResourceList = NULL;

	m_FirstQuery = NULL;
	m_FirstAnswer = NULL;
	m_FirstAuthority = NULL;
	m_FirstAdditional = NULL;

	parseResources();
}

DnsLayer::DnsLayer()
{
	m_DataLen = sizeof(dnshdr);
	m_Data = new uint8_t[m_DataLen];
	memset(m_Data, 0, m_DataLen);
	m_Protocol = DNS;

	m_ResourceList = NULL;

	m_FirstQuery = NULL;
	m_FirstAnswer = NULL;
	m_FirstAuthority = NULL;
	m_FirstAdditional = NULL;
}

DnsLayer::DnsLayer(const DnsLayer& other) : Layer(other)
{
	m_Protocol = DNS;

	m_ResourceList = NULL;

	m_FirstQuery = NULL;
	m_FirstAnswer = NULL;
	m_FirstAuthority = NULL;
	m_FirstAdditional = NULL;

	parseResources();
}

DnsLayer& DnsLayer::operator=(const DnsLayer& other)
{
	Layer::operator=(other);

	IDnsResource* curResource = m_ResourceList;
	while (curResource != NULL)
	{
		IDnsResource* temp = curResource->getNextResource();
		delete curResource;
		curResource = temp;
	}

	m_ResourceList = NULL;

	m_FirstQuery = NULL;
	m_FirstAnswer = NULL;
	m_FirstAuthority = NULL;
	m_FirstAdditional = NULL;

	parseResources();

	return (*this);
}

DnsLayer::~DnsLayer()
{
	IDnsResource* curResource = m_ResourceList;
	while (curResource != NULL)
	{
		IDnsResource* nextResource = curResource->getNextResource();
		delete curResource;
		curResource = nextResource;
	}
}

bool DnsLayer::extendLayer(int offsetInLayer, size_t numOfBytesToExtend, IDnsResource* resource)
{
	if (!Layer::extendLayer(offsetInLayer, numOfBytesToExtend))
		return false;

	IDnsResource* curResource = resource->getNextResource();
	while (curResource != NULL)
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
	while (curResource != NULL)
	{
		curResource->m_OffsetInLayer -= numOfBytesToShorten;
		curResource = curResource->getNextResource();
	}
	return true;
}


void DnsLayer::parseResources()
{
	size_t offsetInPacket = sizeof(dnshdr);
	IDnsResource* curResource = m_ResourceList;

	uint16_t numOfQuestions = ntohs(getDnsHeader()->numberOfQuestions);
	uint16_t numOfAnswers = ntohs(getDnsHeader()->numberOfAnswers);
	uint16_t numOfAuthority = ntohs(getDnsHeader()->numberOfAuthority);
	uint16_t numOfAdditional = ntohs(getDnsHeader()->numberOfAdditional);

	uint16_t numOfOtherResources = numOfQuestions + numOfAnswers + numOfAuthority + numOfAdditional;

	if (numOfOtherResources > 300)
	{
		LOG_ERROR("DNS layer contains more than 300 resources, probably a bad packet. "
				"Skipping parsing DNS resources");
		return;
	}

	for (uint16_t i = 0; i < numOfOtherResources; i++)
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

		DnsResource* newResource = NULL;
		DnsQuery* newQuery = NULL;
		IDnsResource* newGenResource = NULL;
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
			//Parse packet failed, DNS resource is out of bounds. Probably a bad packet
			delete newGenResource;
			return;
		}

		// this resource is the first resource
		if (m_ResourceList == NULL)
		{
			m_ResourceList = newGenResource;
			curResource = m_ResourceList;
		}
		else
		{
			curResource->setNexResource(newGenResource);
			curResource = curResource->getNextResource();
		}

		if (resType == DnsQueryType && m_FirstQuery == NULL)
			m_FirstQuery = newQuery;
		else if (resType == DnsAnswerType && m_FirstAnswer == NULL)
			m_FirstAnswer = newResource;
		else if (resType == DnsAuthorityType && m_FirstAuthority == NULL)
			m_FirstAuthority = newResource;
		else if (resType == DnsAdditionalType && m_FirstAdditional == NULL)
			m_FirstAdditional = newResource;
	}

}

IDnsResource* DnsLayer::getResourceByName(IDnsResource* startFrom, size_t resourceCount, const std::string& name, bool exactMatch)
{
	uint16_t i = 0;
	while (i < resourceCount)
	{
		if (startFrom == NULL)
			return NULL;

		std::string resourceName = startFrom->getName();
		if (exactMatch && resourceName == name)
			return startFrom;
		else if (!exactMatch && resourceName.find(name) != std::string::npos)
			return startFrom;

		startFrom = startFrom->getNextResource();

		i++;
	}

	return NULL;
}

DnsQuery* DnsLayer::getQuery(const std::string& name, bool exactMatch)
{
	uint16_t numOfQueries = ntohs(getDnsHeader()->numberOfQuestions);
	IDnsResource* res = getResourceByName(m_FirstQuery, numOfQueries, name, exactMatch);
	if (res != NULL)
		return dynamic_cast<DnsQuery*>(res);
	return NULL;
}


DnsQuery* DnsLayer::getFirstQuery()
{
	return m_FirstQuery;
}


DnsQuery* DnsLayer::getNextQuery(DnsQuery* query)
{
	if (query == NULL 
		|| query->getNextResource() == NULL 
		|| query->getType() != DnsQueryType
		|| query->getNextResource()->getType() != DnsQueryType)
		return NULL;

	return (DnsQuery*)(query->getNextResource());
}

size_t DnsLayer::getQueryCount()
{
	return ntohs(getDnsHeader()->numberOfQuestions);
}

DnsResource* DnsLayer::getAnswer(const std::string& name, bool exactMatch)
{
	uint16_t numOfAnswers = ntohs(getDnsHeader()->numberOfAnswers);
	IDnsResource* res = getResourceByName(m_FirstAnswer, numOfAnswers, name, exactMatch);
	if (res != NULL)
		return dynamic_cast<DnsResource*>(res);
	return NULL;
}

DnsResource* DnsLayer::getFirstAnswer()
{
	return m_FirstAnswer;
}

DnsResource* DnsLayer::getNextAnswer(DnsResource* answer)
{
	if (answer == NULL
		|| answer->getNextResource() == NULL
		|| answer->getType() != DnsAnswerType
		|| answer->getNextResource()->getType() != DnsAnswerType)
		return NULL;

	return (DnsResource*)(answer->getNextResource());
}

size_t DnsLayer::getAnswerCount()
{
	return ntohs(getDnsHeader()->numberOfAnswers);
}

DnsResource* DnsLayer::getAuthority(const std::string& name, bool exactMatch)
{
	uint16_t numOfAuthorities = ntohs(getDnsHeader()->numberOfAuthority);
	IDnsResource* res = getResourceByName(m_FirstAuthority, numOfAuthorities, name, exactMatch);
	if (res != NULL)
		return dynamic_cast<DnsResource*>(res);
	return NULL;
}

DnsResource* DnsLayer::getFirstAuthority()
{
	return m_FirstAuthority;
}

DnsResource* DnsLayer::getNextAuthority(DnsResource* authority)
{
	if (authority == NULL
		|| authority->getNextResource() == NULL
		|| authority->getType() != DnsAuthorityType
		|| authority->getNextResource()->getType() != DnsAuthorityType)
		return NULL;

	return (DnsResource*)(authority->getNextResource());
}

size_t DnsLayer::getAuthorityCount()
{
	return ntohs(getDnsHeader()->numberOfAuthority);
}

DnsResource* DnsLayer::getAdditionalRecord(const std::string& name, bool exactMatch)
{
	uint16_t numOfAdditionalRecords = ntohs(getDnsHeader()->numberOfAdditional);
	IDnsResource* res = getResourceByName(m_FirstAdditional, numOfAdditionalRecords, name, exactMatch);
	if (res != NULL)
		return dynamic_cast<DnsResource*>(res);
	return NULL;
}

DnsResource* DnsLayer::getFirstAdditionalRecord()
{
	return m_FirstAdditional;
}

DnsResource* DnsLayer::getNextAdditionalRecord(DnsResource* additionalRecord)
{
	if (additionalRecord == NULL
		|| additionalRecord->getNextResource() == NULL
		|| additionalRecord->getType() != DnsAdditionalType
		|| additionalRecord->getNextResource()->getType() != DnsAdditionalType)
		return NULL;

	return (DnsResource*)(additionalRecord->getNextResource());
}

size_t DnsLayer::getAdditionalRecordCount()
{
	return ntohs(getDnsHeader()->numberOfAdditional);
}

std::string DnsLayer::toString()
{
	std::ostringstream tidAsString;
	tidAsString << ntohs(getDnsHeader()->transactionID);

	std::ostringstream queryCount;
	queryCount << getQueryCount();

	std::ostringstream answerCount;
	answerCount << getAnswerCount();

	std::ostringstream authorityCount;
	authorityCount << getAuthorityCount();

	std::ostringstream additionalCount;
	additionalCount << getAdditionalRecordCount();

	if (getAnswerCount() > 0)
	{
		return "DNS query response, ID: " + tidAsString.str() + ";" +
				" queries: " + queryCount.str() +
				", answers: " + answerCount.str() +
				", authorities: " + authorityCount.str() +
				", additional record: " + additionalCount.str();
	}
	else if (getQueryCount() > 0)
	{
		return "DNS query, ID: " + tidAsString.str() + ";" +
				" queries: " + queryCount.str() +
				", answers: " + answerCount.str() +
				", authorities: " + authorityCount.str() +
				", additional record: " + additionalCount.str();

	}
	else // not likely - a DNS with no answers and no queries
	{
		return "DNS record without queries and answers, ID: " + tidAsString.str() + ";" +
				" queries: " + queryCount.str() +
				", answers: " + answerCount.str() +
				", authorities: " + authorityCount.str() +
				", additional record: " + additionalCount.str();
	}
}

IDnsResource* DnsLayer::getFirstResource(DnsResourceType resType)
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
		return NULL;
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

DnsResource* DnsLayer::addResource(DnsResourceType resType, const std::string& name, DnsType dnsType, DnsClass dnsClass,
		uint32_t ttl, IDnsResourceData* data)
{
	// create new query on temporary buffer
	uint8_t newResourceRawData[256];
	memset(newResourceRawData, 0, 256);

	DnsResource* newResource = new DnsResource(newResourceRawData, resType);

	newResource->setDnsClass(dnsClass);

	newResource->setDnsType(dnsType);

	// cannot return false since layer shouldn't be extended or shortened in this stage
	newResource->setName(name);

	newResource->setTTL(ttl);

	if (!newResource->setData(data))
	{
		delete newResource;
		LOG_ERROR("Couldn't set new resource data");
		return NULL;
	}

	size_t newResourceOffsetInLayer = sizeof(dnshdr);
	IDnsResource* curResource = m_ResourceList;
	while (curResource != NULL && curResource->getType() <= resType)
	{
		newResourceOffsetInLayer += curResource->getSize();
		IDnsResource* nextResource = curResource->getNextResource();
		if (nextResource == NULL || nextResource->getType() > resType)
			break;
		curResource = nextResource;
	}


	// set next resource for new resource. This must happen here for extendLayer to succeed
	if (curResource != NULL)
	{
		if (curResource->getType() > newResource->getType())
			newResource->setNexResource(m_ResourceList);
		else
			newResource->setNexResource(curResource->getNextResource());
	}
	else //curResource != NULL
		newResource->setNexResource(m_ResourceList);

	// extend layer to make room for the new resource
	if (!extendLayer(newResourceOffsetInLayer, newResource->getSize(), newResource))
	{
		LOG_ERROR("Couldn't extend DNS layer, addResource failed");
		delete newResource;
		return NULL;
	}

	// connect the new resource to layer
	newResource->setDnsLayer(this, newResourceOffsetInLayer);

	// connect the new resource to the layer's resource list
	if (curResource != NULL)
	{
		curResource->setNexResource(newResource);
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
	else // curResource != NULL, meaning this is the first resource in layer
	{
		m_ResourceList = newResource;

		setFirstResource(resType, newResource);
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
	size_t newQueryOffsetInLayer = sizeof(dnshdr);
	DnsQuery* curQuery = getFirstQuery();
	while (curQuery != NULL)
	{
		newQueryOffsetInLayer += curQuery->getSize();
		DnsQuery* nextQuery = getNextQuery(curQuery);
		if (nextQuery == NULL)
			break;
		curQuery = nextQuery;

	}

	// set next resource for new query. This must happen here for extendLayer to succeed
	if (curQuery != NULL)
		newQuery->setNexResource(curQuery->getNextResource());
	else
		newQuery->setNexResource(m_ResourceList);

	// extend layer to make room for the new query
	if (!extendLayer(newQueryOffsetInLayer, newQuery->getSize(), newQuery))
	{
		LOG_ERROR("Couldn't extend DNS layer, addQuery failed");
		delete newQuery;
		return NULL;
	}

	// connect the new query to layer
	newQuery->setDnsLayer(this, newQueryOffsetInLayer);

	// connect the new query to the layer's resource list
	if (curQuery != NULL)
		curQuery->setNexResource(newQuery);
	else // curQuery == NULL, meaning this is the first query
	{
		m_ResourceList = newQuery;
		m_FirstQuery = newQuery;
	}

	// increase number of queries
	getDnsHeader()->numberOfQuestions = htons(getQueryCount() + 1);

	return newQuery;
}

DnsQuery* DnsLayer::addQuery(DnsQuery* const copyQuery)
{
	if (copyQuery == NULL)
		return NULL;

	return addQuery(copyQuery->getName(), copyQuery->getDnsType(), copyQuery->getDnsClass());
}

bool DnsLayer::removeQuery(const std::string& queryNameToRemove, bool exactMatch)
{
	DnsQuery* queryToRemove = getQuery(queryNameToRemove, exactMatch);
	if (queryToRemove == NULL)
	{
		LOG_DEBUG("Query not found");
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
		getDnsHeader()->numberOfQuestions = htons(getQueryCount() - 1);
	}

	return res;
}

DnsResource* DnsLayer::addAnswer(const std::string& name, DnsType dnsType, DnsClass dnsClass, uint32_t ttl, IDnsResourceData* data)
{
	DnsResource* res = addResource(DnsAnswerType, name, dnsType, dnsClass, ttl, data);
	if (res != NULL)
	{
		// increase number of answer records
		getDnsHeader()->numberOfAnswers = htons(getAnswerCount() + 1);
	}

	return res;
}

DnsResource* DnsLayer::addAnswer(DnsResource* const copyAnswer)
{
	if (copyAnswer == NULL)
		return NULL;

	return addAnswer(copyAnswer->getName(), copyAnswer->getDnsType(), copyAnswer->getDnsClass(), copyAnswer->getTTL(), copyAnswer->getData().get());
}

bool DnsLayer::removeAnswer(const std::string& answerNameToRemove, bool exactMatch)
{
	DnsResource* answerToRemove = getAnswer(answerNameToRemove, exactMatch);
	if (answerToRemove == NULL)
	{
		LOG_DEBUG("Answer record not found");
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
		getDnsHeader()->numberOfAnswers = htons(getAnswerCount() - 1);
	}

	return res;
}

const std::map<uint16_t, bool>* DnsLayer::getDNSPortMap()
{
	return &DNSPortMap;
}


DnsResource* DnsLayer::addAuthority(const std::string& name, DnsType dnsType, DnsClass dnsClass, uint32_t ttl, IDnsResourceData* data)
{
	DnsResource* res = addResource(DnsAuthorityType, name, dnsType, dnsClass, ttl, data);
	if (res != NULL)
	{
		// increase number of authority records
		getDnsHeader()->numberOfAuthority = htons(getAuthorityCount() + 1);
	}

	return res;
}

DnsResource* DnsLayer::addAuthority(DnsResource* const copyAuthority)
{
	if (copyAuthority == NULL)
		return NULL;

	return addAuthority(copyAuthority->getName(), copyAuthority->getDnsType(), copyAuthority->getDnsClass(), copyAuthority->getTTL(), copyAuthority->getData().get());
}

bool DnsLayer::removeAuthority(const std::string& authorityNameToRemove, bool exactMatch)
{
	DnsResource* authorityToRemove = getAuthority(authorityNameToRemove, exactMatch);
	if (authorityToRemove == NULL)
	{
		LOG_DEBUG("Authority not found");
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
		getDnsHeader()->numberOfAuthority = htons(getAuthorityCount() - 1);
	}

	return res;
}


DnsResource* DnsLayer::addAdditionalRecord(const std::string& name, DnsType dnsType, DnsClass dnsClass, uint32_t ttl, IDnsResourceData* data)
{
	DnsResource* res = addResource(DnsAdditionalType, name, dnsType, dnsClass, ttl, data);
	if (res != NULL)
	{
		// increase number of authority records
		getDnsHeader()->numberOfAdditional = htons(getAdditionalRecordCount() + 1);
	}

	return res;
}

DnsResource* DnsLayer::addAdditionalRecord(const std::string& name, DnsType dnsType, uint16_t customData1, uint32_t customData2, IDnsResourceData* data)
{
	DnsResource* res = addAdditionalRecord(name, dnsType, DNS_CLASS_ANY, customData2, data);
	if (res != NULL)
	{
		res->setCustomDnsClass(customData1);
	}

	return res;
}

DnsResource* DnsLayer::addAdditionalRecord(DnsResource* const copyAdditionalRecord)
{
	if (copyAdditionalRecord == NULL)
		return NULL;

	return addAdditionalRecord(copyAdditionalRecord->getName(), copyAdditionalRecord->getDnsType(), copyAdditionalRecord->getCustomDnsClass(), copyAdditionalRecord->getTTL(), copyAdditionalRecord->getData().get());
}

bool DnsLayer::removeAdditionalRecord(const std::string& additionalRecordNameToRemove, bool exactMatch)
{
	DnsResource* additionalRecordToRemove = getAdditionalRecord(additionalRecordNameToRemove, exactMatch);
	if (additionalRecordToRemove == NULL)
	{
		LOG_DEBUG("Additional record not found");
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
		getDnsHeader()->numberOfAdditional = htons(getAdditionalRecordCount() - 1);
	}

	return res;
}

bool DnsLayer::removeResource(IDnsResource* resourceToRemove)
{
	if (resourceToRemove == NULL)
	{
		LOG_DEBUG("resourceToRemove cannot be NULL");
		return false;
	}

	// find the resource preceding resourceToRemove
	IDnsResource* prevResource = m_ResourceList;

	if (m_ResourceList != resourceToRemove)
	{
		while (prevResource != NULL)
		{
			IDnsResource* temp = prevResource->getNextResource();
			if (temp == resourceToRemove)
				break;

			prevResource = temp;
		}
	}

	if (prevResource == NULL)
	{
		LOG_DEBUG("Resource not found");
		return false;
	}

	// shorten the layer and fix offset in layer for all next DNS resources in the packet
	if (!shortenLayer(resourceToRemove->m_OffsetInLayer, resourceToRemove->getSize(), resourceToRemove))
	{
		LOG_ERROR("Couldn't shorten the DNS layer, resource cannot be removed");
		return false;
	}

	// remove resourceToRemove from the resources linked list
	if (m_ResourceList != resourceToRemove)
	{
		prevResource->setNexResource(resourceToRemove->getNextResource());
	}
	else
	{
		m_ResourceList = resourceToRemove->getNextResource();
	}

	// check whether resourceToRemove was the first of its type
	if (getFirstResource(resourceToRemove->getType()) == resourceToRemove)
	{
		IDnsResource* nextResource = resourceToRemove->getNextResource();
		if (nextResource != NULL && nextResource->getType() == resourceToRemove->getType())
			setFirstResource(resourceToRemove->getType(), nextResource);
		else
			setFirstResource(resourceToRemove->getType(), NULL);
	}

	// free resourceToRemove memory
	delete resourceToRemove;

	return true;
}

} // namespace pcpp
