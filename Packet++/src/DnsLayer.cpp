#define LOG_MODULE PacketLogModuleDnsLayer

#include "DnsLayer.h"
#include "Logger.h"
#include "IpAddress.h"
#include <sstream>
#include <string.h>
#include <iomanip>


IDnsResource::IDnsResource(DnsLayer* dnsLayer, size_t offsetInLayer)
	: m_DnsLayer(dnsLayer), m_OffsetInLayer(offsetInLayer), m_NextResource(NULL)
{
	m_NameLength = decodeName((const char*)getRawData(), m_DecodedName);
}

uint8_t* IDnsResource::getRawData()
{
	return m_DnsLayer->m_Data + m_OffsetInLayer;
}

size_t IDnsResource::decodeName(const char* encodedName, string& result)
{
	size_t encodedNameLength = 0;
	result = "";

	uint8_t wordLength = encodedName[0];

	// A string to parse
	while (wordLength != 0)
	{
		// A pointer to another place in the packet
		if (wordLength == 0xc0)
		{
			uint8_t offsetInLayer = encodedName[1];
			if (offsetInLayer < sizeof(dnshdr))
			{
				LOG_ERROR("DNS parsing error: name pointer is illegal");
				return 0;
			}

			string tempResult;
			decodeName((const char*)(m_DnsLayer->m_Data + offsetInLayer), tempResult);
			result += tempResult;

			// in this case the length of the pointer is: 1B for 0xc0 + 1B for the offset itself
			return encodedNameLength + sizeof(uint16_t);
		}
		else
		{
			result.append(encodedName+1, wordLength);
			result.append(".");
			encodedName += wordLength + 1;
			encodedNameLength += wordLength + 1;
			wordLength = encodedName[0];
		}
	}

	// remove the last "."
	if (result != "")
		result = result.substr(0, result.size()-1);

	// add the last '\0' to encodedNameLength
	encodedNameLength++;
	return encodedNameLength;
}


void IDnsResource::encodeName(const std::string& decodedName, char* result, size_t& resultLen)
{
	resultLen = 0;
    stringstream strstream(decodedName);
    string word;
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


//DnsQuery::DnsQuery(std::string name, DnsType dnsType, DnsClass dnsClass) : IDnsResource()
//{
//	m_ParsedName = name;
//	// DNS name has the following structure for name field: [LengthUntilTheNextDot][string][LengthUntilTheNextDot][string]...[\0]
//	// For example: www.google.com will look like: [3][www][6][google][3][com][\0]
//	// So need to allocate data as follows:
//	// - Trailing length - 1 byte
//	// - Name length
//	// - \0 in the end- 1 byte
//	// - Type field - 2 bytes
//	// - Class field - 2 bytes
//	m_NameLength = m_ParsedName.length() + 2;
//	m_TempData = new uint8_t[m_NameLength + 4];
//	unparseName(m_ParsedName, (char*)m_TempData);
//	memcpy(m_TempData + m_NameLength, )
//
//}

bool IDnsResource::setName(const std::string& newName)
{
	char encodedName[256];
	size_t encodedNameLen = 0;
	encodeName(newName, encodedName, encodedNameLen);
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

	memcpy(getRawData() + m_OffsetInLayer, encodedName, encodedNameLen);
	m_NameLength = encodedNameLen;
	m_DecodedName = newName;
	return true;
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

string DnsResource::getDataAsString()
{
	uint8_t* resourceRawData = getRawData() + m_NameLength + 3*sizeof(uint16_t) + sizeof(uint32_t);
	size_t dataLength = getDataLength();

	DnsType dnsType = getDnsType();

	string result = "";

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
		decodeName((const char*)resourceRawData, result);
		break;
	}

	default:
	{
	    stringstream sstream;
	    sstream << "0x" << std::hex;
	    for(size_t i = 0; i < dataLength; i++)
	        sstream << std::setw(2) << std::setfill('0') << (int)resourceRawData[i];
	    result = sstream.str();

		break;
	}

	}

	return result;

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

		IDnsResource* newResource = NULL;
		if (resType == IDnsResource::DnsQuery)
			newResource = new DnsQuery(this, offsetInPacket);
		else
			newResource = new DnsResource(this, offsetInPacket, resType);

		offsetInPacket += newResource->getSize();

		if (offsetInPacket > m_DataLen)
		{
			LOG_ERROR("Parse packet failed, DNS resource is out of bounds. Probably a bad packet");
			delete newResource;
			return;
		}

		// this resource is the first resource
		if (m_ResourceList == NULL)
		{
			m_ResourceList = newResource;
			curResource = m_ResourceList;
		}
		else
		{
			curResource->setNexResource(newResource);
			curResource = curResource->getNextResource();
		}

		if (resType == IDnsResource::DnsQuery && m_FirstQuery == NULL)
			m_FirstQuery = dynamic_cast<DnsQuery*>(newResource);
		else if (resType == IDnsResource::DnsAnswer && m_FirstAnswer == NULL)
			m_FirstAnswer = dynamic_cast<DnsResource*>(newResource);
		else if (resType == IDnsResource::DnsAuthority && m_FirstAuthority == NULL)
			m_FirstAuthority = dynamic_cast<DnsResource*>(newResource);
		else if (resType == IDnsResource::DnsAdditional && m_FirstAdditional == NULL)
			m_FirstAdditional = dynamic_cast<DnsResource*>(newResource);
	}

}

IDnsResource* DnsLayer::getResourceByName(IDnsResource* startFrom, size_t resourceCount, const string& name)
{
	uint16_t i = 0;
	while (i < resourceCount)
	{
		if (startFrom == NULL)
			return NULL;

		if (startFrom->getName() == name)
			return startFrom;

		startFrom = startFrom->getNextResource();

		i++;
	}

	return NULL;
}

DnsQuery* DnsLayer::getQuery(const string& name)
{
	uint16_t numOfQueries = ntohs(getDnsHeader()->numberOfQuestions);
	IDnsResource* res = getResourceByName(m_FirstQuery, numOfQueries, name);
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
	if (query == NULL || query->getNextResource() == NULL || query->getType() != IDnsResource::DnsQuery)
		return NULL;

	return dynamic_cast<DnsQuery*>(query->getNextResource());
}

size_t DnsLayer::getQueryCount()
{
	return ntohs(getDnsHeader()->numberOfQuestions);
}

DnsResource* DnsLayer::getAnswer(const string& name)
{
	uint16_t numOfAnswers = ntohs(getDnsHeader()->numberOfAnswers);
	IDnsResource* res = getResourceByName(m_FirstAnswer, numOfAnswers, name);
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

	return dynamic_cast<DnsResource*>(answer->getNextResource());
}

size_t DnsLayer::getAnswerCount()
{
	return ntohs(getDnsHeader()->numberOfAnswers);
}

DnsResource* DnsLayer::getAuthority(const string& name)
{
	uint16_t numOfAuthorities = ntohs(getDnsHeader()->numberOfAuthority);
	IDnsResource* res = getResourceByName(m_FirstAuthority, numOfAuthorities, name);
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

	return dynamic_cast<DnsResource*>(authority->getNextResource());
}

size_t DnsLayer::getAuthorityCount()
{
	return ntohs(getDnsHeader()->numberOfAuthority);
}

DnsResource* DnsLayer::getAdditionalRecord(const string& name)
{
	uint16_t numOfAdditionalRecords = ntohs(getDnsHeader()->numberOfAdditional);
	IDnsResource* res = getResourceByName(m_FirstAdditional, numOfAdditionalRecords, name);
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

	return dynamic_cast<DnsResource*>(additionalRecord->getNextResource());
}

size_t DnsLayer::getAdditionalRecordCount()
{
	return ntohs(getDnsHeader()->numberOfAdditional);
}

string DnsLayer::toString()
{
	ostringstream tidAsString;
	tidAsString << ntohs(getDnsHeader()->transactionID);

	ostringstream queryCount;
	queryCount << getQueryCount();

	ostringstream answerCount;
	answerCount << getAnswerCount();

	ostringstream authorityCount;
	authorityCount << getAuthorityCount();

	ostringstream additionalCount;
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
