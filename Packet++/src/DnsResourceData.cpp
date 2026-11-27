#define LOG_MODULE PacketLogModuleDnsLayer

#include "DnsResourceData.h"
#include "Logger.h"
#include "GeneralUtils.h"
#include <sstream>
#include <utility>
#include "EndianPortable.h"

namespace pcpp
{

	bool IDnsResourceData::toByteArr(uint8_t* arr, size_t& arrLength, IDnsResource* dnsResource) const
	{
		if (arr == nullptr)
			return false;

		std::vector<uint8_t> data = toBytes(dnsResource);
		if (data.empty())
			return false;

		arrLength = data.size();
		memcpy(arr, data.data(), arrLength);
		return true;
	}

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

	std::vector<uint8_t> StringDnsResourceData::toBytes(IDnsResource* dnsResource) const
	{
		// the encoded name can't be longer than the decoded one plus a length byte for each label and the
		// terminating zero byte
		std::vector<uint8_t> result(m_Data.size() + 2);
		size_t resultLength = 0;
		encodeName(m_Data, reinterpret_cast<char*>(result.data()), resultLength, dnsResource);
		result.resize(resultLength);
		return result;
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

	std::vector<uint8_t> IPv4DnsResourceData::toBytes(IDnsResource*) const
	{
		std::vector<uint8_t> result(sizeof(uint32_t));
		memcpy(result.data(), m_Data.toBytes(), sizeof(uint32_t));
		return result;
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

	std::vector<uint8_t> IPv6DnsResourceData::toBytes(IDnsResource*) const
	{
		// an IPv6 address is 16 bytes long
		std::vector<uint8_t> result(16);
		m_Data.copyTo(result.data());
		return result;
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

	MxDnsResourceData::MxDnsResourceData(uint16_t preference, const std::string& mailExchange)
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

	std::vector<uint8_t> MxDnsResourceData::toBytes(IDnsResource* dnsResource) const
	{
		// the preference field followed by the encoded mail exchange name, which can't be longer than the
		// decoded name plus a length byte for each label and the terminating zero byte
		std::vector<uint8_t> result(sizeof(uint16_t) + m_Data.mailExchange.size() + 2);
		uint16_t netOrderPreference = htobe16(m_Data.preference);
		memcpy(result.data(), &netOrderPreference, sizeof(uint16_t));
		size_t encodedNameLength = 0;
		encodeName(m_Data.mailExchange, reinterpret_cast<char*>(result.data() + sizeof(uint16_t)), encodedNameLength,
		           dnsResource);
		result.resize(sizeof(uint16_t) + encodedNameLength);
		return result;
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
		if (this == &other)
		{
			return *this;
		}

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

	std::vector<uint8_t> GenericDnsResourceData::toBytes(IDnsResource*) const
	{
		if (m_DataLen == 0 || m_Data == nullptr)
		{
			PCPP_LOG_ERROR("Input data is null or illegal" << "|m_DataLen:" << m_DataLen);
			return {};
		}

		return std::vector<uint8_t>(m_Data, m_Data + m_DataLen);
	}

}  // namespace pcpp
