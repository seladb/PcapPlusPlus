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



IDnsResource::IDnsResource(DnsLayer* dnsLayer, size_t offsetInLayer)
	: m_DnsLayer(dnsLayer), m_OffsetInLayer(offsetInLayer), m_NextResource(NULL)
{
	char decodedName[256];
	m_NameLength = decodeName((const char*)getRawData(), decodedName);
	m_DecodedName = decodedName;
}

IDnsResource::IDnsResource(uint8_t* emptyRawData)
	: m_DnsLayer(NULL), m_OffsetInLayer(0), m_NextResource(NULL), m_DecodedName(""), m_NameLength(0), m_ExternalRawData(emptyRawData)
{
}

uint8_t* IDnsResource::getRawData()
{
	if (m_DnsLayer == NULL)
		return m_ExternalRawData;

	return m_DnsLayer->m_Data + m_OffsetInLayer;
}

size_t IDnsResource::decodeName(const char* encodedName, char* result, int iteration)
{
	size_t encodedNameLength = 0;
	char* resultPtr = result;	
	resultPtr[0] = 0;

	size_t curOffsetInLayer = (uint8_t*)encodedName - m_DnsLayer->m_Data;
	if (curOffsetInLayer + 1 > m_DnsLayer->m_DataLen)
		return encodedNameLength;

	if (iteration > 20)
		return encodedNameLength;

	uint8_t wordLength = encodedName[0];

	// A string to parse
	while (wordLength != 0)
	{
		// A pointer to another place in the packet
		if ((wordLength & 0xc0) == 0xc0)
		{
			if (curOffsetInLayer + 2 > m_DnsLayer->m_DataLen)
				return encodedNameLength;

			uint16_t offsetInLayer = (wordLength & 0x3f)*256 + (0xFF & encodedName[1]);
			if (offsetInLayer < sizeof(dnshdr) || offsetInLayer >= m_DnsLayer->m_DataLen)
			{
				LOG_ERROR("DNS parsing error: name pointer is illegal");
				return 0;
			}

			char tempResult[256];
			int i = 0;
			decodeName((const char*)(m_DnsLayer->m_Data + offsetInLayer), tempResult, iteration+1);
			while (tempResult[i] != 0)
			{
				resultPtr[0] = tempResult[i++];
				resultPtr++;
			}

			resultPtr[0] = 0;

			// in this case the length of the pointer is: 1B for 0xc0 + 1B for the offset itself
			return encodedNameLength + sizeof(uint16_t);
		}
		else
		{
			if (curOffsetInLayer + wordLength + 1 > m_DnsLayer->m_DataLen)
				return encodedNameLength;

			memcpy(resultPtr, encodedName+1, wordLength);
			resultPtr += wordLength;
			resultPtr[0] = '.';
			resultPtr++;
			encodedName += wordLength + 1;
			encodedNameLength += wordLength + 1;

			curOffsetInLayer = (uint8_t*)encodedName - m_DnsLayer->m_Data;
			if (curOffsetInLayer + 1 > m_DnsLayer->m_DataLen)
				return encodedNameLength;

			wordLength = encodedName[0];
		}
	}

	// remove the last "."
	if (resultPtr > result)
	{
		result[resultPtr - result - 1] = 0;
	}

	// add the last '\0' to encodedNameLength
	resultPtr[0] = 0;
	encodedNameLength++;

	return encodedNameLength;
}


void IDnsResource::encodeName(const std::string& decodedName, char* result, size_t& resultLen)
{
	resultLen = 0;
	std::stringstream strstream(decodedName);
    std::string word;
    while (getline(strstream, word, '.'))
    {
    	result[0] = word.length();
    	result++;
    	memcpy(result, word.c_str(), word.length());
    	result += word.length();
    	resultLen += word.length() + 1;
    }

    // add '\0' at the end
    result[0] = 0;
    resultLen++;
}


DnsType IDnsResource::getDnsType()
{
	uint16_t dnsType = *(uint16_t*)(getRawData() + m_NameLength);
	return (DnsType)ntohs(dnsType);
}

void IDnsResource::setDnsType(DnsType newType)
{
	uint16_t newTypeAsInt = htons((uint16_t)newType);
	memcpy(getRawData() + m_NameLength, &newTypeAsInt, sizeof(uint16_t));
}

DnsClass IDnsResource::getDnsClass()
{
	uint16_t dnsClass = *(uint16_t*)(getRawData() + m_NameLength + sizeof(uint16_t));
	return (DnsClass)ntohs(dnsClass);
}

void IDnsResource::setDnsClass(DnsClass newClass)
{
	uint16_t newClassAsInt = htons((uint16_t)newClass);
	memcpy(getRawData() + m_NameLength + sizeof(uint16_t), &newClassAsInt, sizeof(uint16_t));
}

bool IDnsResource::setName(const std::string& newName)
{
	char encodedName[256];
	size_t encodedNameLen = 0;
	encodeName(newName, encodedName, encodedNameLen);
	if (m_DnsLayer != NULL)
	{
		if (encodedNameLen > m_NameLength)
		{
			if (!m_DnsLayer->extendLayer(m_OffsetInLayer, encodedNameLen-m_NameLength, this))
			{
				LOG_ERROR("Couldn't set name for DNS query, unable to extend layer");
				return false;
			}
		}
		else if (encodedNameLen < m_NameLength)
		{
			if (!m_DnsLayer->shortenLayer(m_OffsetInLayer, m_NameLength-encodedNameLen, this))
			{
				LOG_ERROR("Couldn't set name for DNS query, unable to shorten layer");
				return false;
			}
		}
	}
	else
	{
		size_t size = getSize();
		char* tempData = new char[size];
		memcpy(tempData, m_ExternalRawData, getSize());
		memcpy(m_ExternalRawData + encodedNameLen, tempData, getSize());
		delete[] tempData;
	}

	memcpy(getRawData(), encodedName, encodedNameLen);
	m_NameLength = encodedNameLen;
	m_DecodedName = newName;

	return true;
}

void IDnsResource::setDnsLayer(DnsLayer* dnsLayer, size_t offsetInLayer)
{
	memcpy(dnsLayer->m_Data + offsetInLayer, m_ExternalRawData, getSize());
	m_DnsLayer = dnsLayer;
	m_OffsetInLayer = offsetInLayer;
	m_ExternalRawData = NULL;
}

uint32_t DnsResource::getTTL()
{
	uint32_t ttl = *(uint32_t*)(getRawData() + m_NameLength + 2*sizeof(uint16_t));
	return ntohl(ttl);
}

void DnsResource::setTTL(uint32_t newTTL)
{
	newTTL = htonl(newTTL);
	memcpy(getRawData() + m_NameLength + 2*sizeof(uint16_t), &newTTL, sizeof(uint32_t));
}

size_t DnsResource::getDataLength()
{
	uint16_t dataLength = *(uint16_t*)(getRawData() + m_NameLength + 2*sizeof(uint16_t) + sizeof(uint32_t));
	return ntohs(dataLength);
}

std::string DnsResource::getDataAsString()
{
	uint8_t* resourceRawData = getRawData() + m_NameLength + 3*sizeof(uint16_t) + sizeof(uint32_t);
	size_t dataLength = getDataLength();

	DnsType dnsType = getDnsType();

	std::string result = "";

	switch (dnsType)
	{
	case DNS_TYPE_A:
	{
		if (dataLength != 4)
		{
			LOG_ERROR("DNS type is A but resource length is not 4 - packet is malformed");
			break;
		}

		uint32_t addrAsInt = *(uint32_t*)resourceRawData;
		IPv4Address ip4AddrElad(addrAsInt);
		if (!ip4AddrElad.isValid())
		{
			LOG_ERROR("Invalid IPv4 address for DNS resource of type A");
			break;
		}

		result = ip4AddrElad.toString();
		break;
	}

	case DNS_TYPE_AAAA:
	{
		if (dataLength != 16)
		{
			LOG_ERROR("DNS type is AAAA but resource length is not 16 - packet is malformed");
			break;
		}

		IPv6Address ip6Addr(resourceRawData);
		if (!ip6Addr.isValid())
		{
			LOG_ERROR("Invalid IPv6 address for DNS resource of type AAAA");
			break;
		}
		result = ip6Addr.toString();
		break;
	}

	case DNS_TYPE_NS:
	case DNS_TYPE_CNAME:
	case DNS_TYPE_DNAM:
	case DNS_TYPE_PTR:
	case DNS_TYPE_MX:
	{
		char tempResult[256];
		decodeName((const char*)resourceRawData, tempResult);
		result = tempResult;
		break;
	}

	default:
	{
		std::stringstream sstream;
	    sstream << "0x" << std::hex;
	    for(size_t i = 0; i < dataLength; i++)
	        sstream << std::setw(2) << std::setfill('0') << (int)resourceRawData[i];
	    result = sstream.str();

		break;
	}

	}

	return result;

}

bool DnsResource::setData(const std::string& dataAsString)
{
	// convert data to byte array according to the DNS type
	size_t dataLength = 0;
	uint8_t dataAsByteArr[256];

	switch (getDnsType())
	{
	case DNS_TYPE_A:
	{
		IPv4Address ip4Addr((std::string)dataAsString);
		if (!ip4Addr.isValid())
		{
			LOG_ERROR("Requested DNS type is A but data '%s' is an illegal IPv4 address. Couldn't set data for resource", dataAsString.c_str());
			return false;
		}
		dataLength = 4;
		uint32_t addrAsInt = ip4Addr.toInt();
		memcpy(dataAsByteArr, &addrAsInt, dataLength);
		break;
	}

	case DNS_TYPE_AAAA:
	{
		IPv6Address ip6Addr((std::string)dataAsString);
		if (!ip6Addr.isValid())
		{
			LOG_ERROR("Requested DNS type is AAAA but data '%s' is an illegal IPv6 address. Couldn't set data for resource", dataAsString.c_str());
			return false;
		}
		dataLength = 16;
		ip6Addr.copyTo(dataAsByteArr);
		break;
	}

	case DNS_TYPE_NS:
	case DNS_TYPE_CNAME:
	case DNS_TYPE_DNAM:
	case DNS_TYPE_PTR:
	case DNS_TYPE_MX:
	{
		encodeName(dataAsString, (char*)dataAsByteArr, dataLength);
		break;
	}

	default:
	{
		if (dataAsString.substr(0, 2) != "0x")
		{
			LOG_ERROR("DNS data for DNS type %d should be an hex stream and begin with '0x'", getDnsType());
			return false;
		}
		if (dataAsString.length() % 2 != 0)
		{
			LOG_ERROR("DNS data for DNS type %d should be an hex stream with an even number of character. "
					"Current character count is an odd number: %d", getDnsType(), (int)dataAsString.length());
			return false;
		}
		char* dataAsCharPtr = (char*)dataAsString.c_str();
		dataAsCharPtr += 2; //skip the '0x' prefix
		char strtolBuf[5] = { '0', 'x', 0, 0, 0 };
		char* strtolEndPtr;
		while (*dataAsCharPtr != 0)
		{
			strtolBuf[2] = dataAsCharPtr[0];
			strtolBuf[3] = dataAsCharPtr[1];
			dataAsByteArr[dataLength] = strtol(strtolBuf, &strtolEndPtr, 0);

	        if (strtolEndPtr[0] != '\0') {
	        	//non-hexadecimal character encountered
	        	LOG_ERROR("DNS data for DNS type %d should be a valid hex stream", getDnsType());
	            return false;
	        }

	        dataAsCharPtr += 2 * sizeof(char);
	        dataLength++;
		}
		break;
	}
	}

	size_t dataLengthOffset = m_NameLength + (2*sizeof(uint16_t)) + sizeof(uint32_t);
	size_t dataOffset = dataLengthOffset + sizeof(uint16_t);

	if (m_DnsLayer != NULL)
	{
		size_t curLength = getDataLength();
		if (dataLength > curLength)
		{
			if (!m_DnsLayer->extendLayer(m_OffsetInLayer + dataOffset, dataLength-curLength, this))
			{
				LOG_ERROR("Couldn't set data for DNS query, unable to extend layer");
				return false;
			}
		}
		else if (dataLength < curLength)
		{
			if (!m_DnsLayer->shortenLayer(m_OffsetInLayer + dataOffset, curLength-dataLength, this))
			{
				LOG_ERROR("Couldn't set data for DNS query, unable to shorten layer");
				return false;
			}
		}
	}

	// write data to resource
	memcpy(getRawData() + dataOffset, dataAsByteArr, dataLength);
	//update data length in resource
	dataLength = htons(dataLength);
	memcpy(getRawData() + dataLengthOffset, &dataLength, sizeof(uint16_t));

	return true;
}

uint16_t DnsResource::getCustomDnsClass()
{
	uint16_t value = *(uint16_t*)(getRawData() + m_NameLength + sizeof(uint16_t));
	return ntohs(value);
}

void DnsResource::setCustomDnsClass(uint16_t customValue)
{
	memcpy(getRawData() + m_NameLength + sizeof(uint16_t), &customValue, sizeof(uint16_t));
}

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
		IDnsResource::ResourceType resType;
		if (numOfQuestions > 0)
		{
			resType = IDnsResource::DnsQuery;
			numOfQuestions--;
		}
		else if (numOfAnswers > 0)
		{
			resType = IDnsResource::DnsAnswer;
			numOfAnswers--;
		}
		else if (numOfAuthority > 0)
		{
			resType = IDnsResource::DnsAuthority;
			numOfAuthority--;
		}
		else
		{
			resType = IDnsResource::DnsAdditional;
			numOfAdditional--;
		}

		DnsResource* newResource = NULL;
		DnsQuery* newQuery = NULL;
		IDnsResource* newGenResource = NULL;
		if (resType == IDnsResource::DnsQuery)
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

		if (resType == IDnsResource::DnsQuery && m_FirstQuery == NULL)
			m_FirstQuery = newQuery;
		else if (resType == IDnsResource::DnsAnswer && m_FirstAnswer == NULL)
			m_FirstAnswer = newResource;
		else if (resType == IDnsResource::DnsAuthority && m_FirstAuthority == NULL)
			m_FirstAuthority = newResource;
		else if (resType == IDnsResource::DnsAdditional && m_FirstAdditional == NULL)
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
		|| query->getType() != IDnsResource::DnsQuery 
		|| query->getNextResource()->getType() != IDnsResource::DnsQuery)
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
		|| answer->getType() != IDnsResource::DnsAnswer
		|| answer->getNextResource()->getType() != IDnsResource::DnsAnswer)
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
		|| authority->getType() != IDnsResource::DnsAuthority
		|| authority->getNextResource()->getType() != IDnsResource::DnsAuthority)
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
		|| additionalRecord->getType() != IDnsResource::DnsAdditional
		|| additionalRecord->getNextResource()->getType() != IDnsResource::DnsAdditional)
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

IDnsResource* DnsLayer::getFirstResource(IDnsResource::ResourceType resType)
{
	switch (resType)
	{
	case IDnsResource::DnsQuery:
	{
		return m_FirstQuery;
	}
	case IDnsResource::DnsAnswer:
	{
		return m_FirstAnswer;
	}
	case IDnsResource::DnsAuthority:
	{
		return m_FirstAuthority;
	}
	case IDnsResource::DnsAdditional:
	{
		return m_FirstAdditional;
	}
	default:
		return NULL;
	}
}

void DnsLayer::setFirstResource(IDnsResource::ResourceType resType, IDnsResource* resource)
{
	switch (resType)
	{
	case IDnsResource::DnsQuery:
	{
		m_FirstQuery = dynamic_cast<DnsQuery*>(resource);
		break;
	}
	case IDnsResource::DnsAnswer:
	{
		m_FirstAnswer = dynamic_cast<DnsResource*>(resource);
		break;
	}
	case IDnsResource::DnsAuthority:
	{
		m_FirstAuthority = dynamic_cast<DnsResource*>(resource);
		break;
	}
	case IDnsResource::DnsAdditional:
	{
		m_FirstAdditional = dynamic_cast<DnsResource*>(resource);
		break;
	}
	default:
		return;
	}
}

DnsResource* DnsLayer::addResource(IDnsResource::ResourceType resType, const std::string& name, DnsType dnsType, DnsClass dnsClass,
		uint32_t ttl, const std::string& data)
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

DnsResource* DnsLayer::addAnswer(const std::string& name, DnsType dnsType, DnsClass dnsClass, uint32_t ttl, const std::string& data)
{
	DnsResource* res = addResource(IDnsResource::DnsAnswer, name, dnsType, dnsClass, ttl, data);
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

	return addAnswer(copyAnswer->getName(), copyAnswer->getDnsType(), copyAnswer->getDnsClass(), copyAnswer->getTTL(), copyAnswer->getDataAsString());
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


DnsResource* DnsLayer::addAuthority(const std::string& name, DnsType dnsType, DnsClass dnsClass, uint32_t ttl, const std::string& data)
{
	DnsResource* res = addResource(IDnsResource::DnsAuthority, name, dnsType, dnsClass, ttl, data);
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

	return addAuthority(copyAuthority->getName(), copyAuthority->getDnsType(), copyAuthority->getDnsClass(), copyAuthority->getTTL(), copyAuthority->getDataAsString());
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


DnsResource* DnsLayer::addAdditionalRecord(const std::string& name, DnsType dnsType, DnsClass dnsClass, uint32_t ttl, const std::string& data)
{
	DnsResource* res = addResource(IDnsResource::DnsAdditional, name, dnsType, dnsClass, ttl, data);
	if (res != NULL)
	{
		// increase number of authority records
		getDnsHeader()->numberOfAdditional = htons(getAdditionalRecordCount() + 1);
	}

	return res;
}

DnsResource* DnsLayer::addAdditionalRecord(const std::string& name, DnsType dnsType, uint16_t customData1, uint32_t customData2, const std::string& data)
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

	return addAdditionalRecord(copyAdditionalRecord->getName(), copyAdditionalRecord->getDnsType(), copyAdditionalRecord->getCustomDnsClass(), copyAdditionalRecord->getTTL(), copyAdditionalRecord->getDataAsString());
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
