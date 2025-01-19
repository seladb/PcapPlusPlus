#define LOG_MODULE PacketLogModuleDnsLayer

#include "DnsResourceData.h"
#include "Logger.h"
#include "GeneralUtils.h"
#include <sstream>
#include <utility>
#include "EndianPortable.h"

namespace pcpp
{

	size_t IDnsResourceData::decodeName(const char* encodedName, char* result, IDnsResource* dnsResource) const
	{
		if (dnsResource == nullptr)
		{
			PCPP_LOG_ERROR("Cannot decode name, DNS resource object is nullptr");
			return 0;
		}

		return dnsResource->decodeName(encodedName, result);
	}

	void IDnsResourceData::encodeName(const std::string& decodedName, char* result, size_t& resultLen,
	                                  IDnsResource* dnsResource) const
	{
		if (dnsResource == nullptr)
		{
			PCPP_LOG_ERROR("Cannot encode name, DNS resource object is nullptr");
			return;
		}

		dnsResource->encodeName(decodedName, result, resultLen);
	}

	StringDnsResourceData::StringDnsResourceData(const uint8_t* dataPtr, size_t dataLen, IDnsResource* dnsResource)
	{
		if (dataPtr && dataLen > 0)
		{
			char tempResult[4096];
			decodeName((const char*)dataPtr, tempResult, dnsResource);
			m_Data = tempResult;
		}
		else
			PCPP_LOG_ERROR("Cannot decode name, dataPtr is nullptr or length is 0");
	}

	bool StringDnsResourceData::toByteArr(uint8_t* arr, size_t& arrLength, IDnsResource* dnsResource) const
	{
		encodeName(m_Data, (char*)arr, arrLength, dnsResource);
		return true;
	}

	IPv4DnsResourceData::IPv4DnsResourceData(const uint8_t* dataPtr, size_t dataLen)
	{
		if (dataLen != 4)
		{
			PCPP_LOG_ERROR("DNS type is A but resource length is not 4 - malformed data");
			return;
		}

		uint32_t addrAsInt = *(uint32_t*)dataPtr;
		m_Data = IPv4Address(addrAsInt);
	}

	bool IPv4DnsResourceData::toByteArr(uint8_t* arr, size_t& arrLength, IDnsResource*) const
	{
		arrLength = sizeof(uint32_t);
		memcpy(arr, m_Data.toBytes(), sizeof(uint32_t));
		return true;
	}

	IPv6DnsResourceData::IPv6DnsResourceData(const uint8_t* dataPtr, size_t dataLen)
	{
		if (dataLen != 16)
		{
			PCPP_LOG_ERROR("DNS type is AAAA but resource length is not 16 - malformed data");
			return;
		}

		m_Data = IPv6Address(dataPtr);
	}

	bool IPv6DnsResourceData::toByteArr(uint8_t* arr, size_t& arrLength, IDnsResource*) const
	{
		arrLength = 16;
		m_Data.copyTo(arr);
		return true;
	}

	MxDnsResourceData::MxDnsResourceData(uint8_t* dataPtr, size_t dataLen, IDnsResource* dnsResource)
	{
		if (dataPtr && dataLen > 0)
		{
			uint16_t preference = be16toh(*(uint16_t*)dataPtr);
			char tempMX[4096];
			decodeName((const char*)(dataPtr + sizeof(preference)), tempMX, dnsResource);
			m_Data.preference = preference;
			m_Data.mailExchange = tempMX;
		}
		else
			PCPP_LOG_ERROR("Cannot decode name, dataPtr is nullptr or length is 0");
	}

	MxDnsResourceData::MxDnsResourceData(const uint16_t& preference, const std::string& mailExchange)
	{
		m_Data.preference = preference;
		m_Data.mailExchange = mailExchange;
	}

	bool MxDnsResourceData::operator==(const MxDnsResourceData& other) const
	{
		return (m_Data.preference == other.m_Data.preference) && (m_Data.mailExchange == other.m_Data.mailExchange);
	}

	void MxDnsResourceData::setMxData(uint16_t preference, std::string mailExchange)
	{
		m_Data.preference = preference;
		m_Data.mailExchange = std::move(mailExchange);
	}

	std::string MxDnsResourceData::toString() const
	{
		std::stringstream result;
		result << "pref: " << m_Data.preference << "; mx: " << m_Data.mailExchange;
		return result.str();
	}

	bool MxDnsResourceData::toByteArr(uint8_t* arr, size_t& arrLength, IDnsResource* dnsResource) const
	{
		uint16_t netOrderPreference = htobe16(m_Data.preference);
		memcpy(arr, &netOrderPreference, sizeof(uint16_t));
		encodeName(m_Data.mailExchange, (char*)(arr + sizeof(uint16_t)), arrLength, dnsResource);
		arrLength += sizeof(uint16_t);

		return true;
	}

	GenericDnsResourceData::GenericDnsResourceData(const uint8_t* dataPtr, size_t dataLen)
	{
		m_Data = nullptr;
		m_DataLen = 0;
		if (dataLen > 0 && dataPtr != nullptr)
		{
			m_DataLen = dataLen;
			m_Data = new uint8_t[dataLen];
			memcpy(m_Data, dataPtr, dataLen);
		}
	}

	GenericDnsResourceData::GenericDnsResourceData(const std::string& dataAsHexString)
	{
		m_Data = nullptr;
		uint8_t tempDataArr[2048];
		m_DataLen = hexStringToByteArray(dataAsHexString, tempDataArr, 2048);
		if (m_DataLen != 0)
		{
			m_Data = new uint8_t[m_DataLen];
			memcpy(m_Data, tempDataArr, m_DataLen);
		}
	}

	GenericDnsResourceData::GenericDnsResourceData(const GenericDnsResourceData& other) : IDnsResourceData()
	{
		m_DataLen = other.m_DataLen;

		if (m_DataLen > 0 && other.m_Data != nullptr)
		{
			m_Data = new uint8_t[m_DataLen];
			memcpy(m_Data, other.m_Data, m_DataLen);
		}
	}

	GenericDnsResourceData& GenericDnsResourceData::operator=(const GenericDnsResourceData& other)
	{
		if (m_Data != nullptr)
			delete[] m_Data;

		m_Data = nullptr;
		m_DataLen = other.m_DataLen;
		if (m_DataLen > 0 && other.m_Data != nullptr)
		{
			m_Data = new uint8_t[m_DataLen];
			memcpy(m_Data, other.m_Data, m_DataLen);
		}

		return (*this);
	}

	bool GenericDnsResourceData::operator==(const GenericDnsResourceData& other) const
	{
		if (m_DataLen != other.m_DataLen)
			return false;

		return (memcmp(m_Data, other.m_Data, m_DataLen) == 0);
	}

	std::string GenericDnsResourceData::toString() const
	{
		return byteArrayToHexString(m_Data, m_DataLen);
	}

	bool GenericDnsResourceData::toByteArr(uint8_t* arr, size_t& arrLength, IDnsResource*) const
	{
		if (m_DataLen == 0 || m_Data == nullptr)
		{
			PCPP_LOG_ERROR("Input data is null or illegal" << "|m_DataLen:" << m_DataLen);
			return false;
		}

		arrLength = m_DataLen;
		memcpy(arr, m_Data, m_DataLen);
		return true;
	}

}  // namespace pcpp
