#ifndef PACKETPP_DNS_RESOURCE_DATA
#define PACKETPP_DNS_RESOURCE_DATA

#include "DnsResource.h"
#include "IpAddress.h"
#include <string>
#include <stdint.h>

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	#if __cplusplus > 199711L
	#define PCPP_SMART_PTR(T) std::unique_ptr<T>
	#else
	#define PCPP_SMART_PTR(T) std::auto_ptr<T>
	#endif

	// forward declarations
	class IDnsResource;

	/**
	 * @class IDnsResourceData
	 * A wrapper class for storing DNS RR (resource record) data. This is the base class which introduces several abstract
	 * methods to set and retrieve the stored data. Derived classes should store different type of DNS RR data
	 * (for example: IPv4/IPv6 addresses, MX data, hostnames etc.) and implement these methods accordingly
	 */
	class IDnsResourceData
	{
	protected:

		// unimplemented private copy c'tor
		IDnsResourceData(const IDnsResourceData &other);
		IDnsResourceData() { }

		size_t decodeName(const char* encodedName, char* result, IDnsResource* dnsResource);
		void encodeName(const std::string& decodedName, char* result, size_t& resultLen, IDnsResource* dnsResource);

	public:
		virtual ~IDnsResourceData() { }

		template <class IDnsResourceDataType>
		bool isTypeOf() const { return dynamic_cast<const IDnsResourceDataType*>(this) != NULL; }

		template <class IDnsResourceDataType>
		IDnsResourceDataType* castAs() { return dynamic_cast<IDnsResourceDataType*>(this);}

		virtual std::string toString() = 0;
		virtual bool toByteArr(uint8_t* arr, size_t &arrLength, IDnsResource* dnsResource) = 0;
	};


	/**
	 * @class DnsResourceDataPtr
	 */
	class DnsResourceDataPtr : public PCPP_SMART_PTR(IDnsResourceData)
	{
	public:
		DnsResourceDataPtr(IDnsResourceData* ptr) : PCPP_SMART_PTR(IDnsResourceData)(ptr) {}
#if __cplusplus <= 199711L
		DnsResourceDataPtr(const DnsResourceDataPtr& other) : PCPP_SMART_PTR(IDnsResourceData)((DnsResourceDataPtr&)other) {}
#endif

		template <class IDnsResourceDataType>
		bool isTypeOf() const { return get()->isTypeOf<IDnsResourceDataType>(); }

		template <class IDnsResourceDataType>
		IDnsResourceDataType* castAs() { return get()->castAs<IDnsResourceDataType>();}

	};


	/**
	 * @class StringDnsResourceData
	 */
	class StringDnsResourceData : public IDnsResourceData
	{
	private:
		std::string m_Data;

	public:

		StringDnsResourceData(const std::string& data) { m_Data = data; }
		StringDnsResourceData(const uint8_t* dataPtr, size_t dataLen, IDnsResource* dnsResource);

		~StringDnsResourceData() {}

		bool operator==(const StringDnsResourceData& other) const { return m_Data == other.m_Data; }

		std::string toString() { return m_Data; }
		bool toByteArr(uint8_t* arr, size_t &arrLength, IDnsResource* dnsResource);
	};


	/**
	 * @class IPv4DnsResourceData
	 */
	class IPv4DnsResourceData : public IDnsResourceData
	{
	private:
		IPv4Address m_Data;

	public:

		IPv4DnsResourceData(const uint8_t* dataPtr, size_t dataLen);
		IPv4DnsResourceData(const IPv4Address& addr) : m_Data(addr) {}
		IPv4DnsResourceData(const std::string& addrAsString) : m_Data(addrAsString) {}

		bool operator==(const IPv4DnsResourceData& other) const { return m_Data == other.m_Data; }

		IPv4Address getIpAddress() { return m_Data; }

		std::string toString() { return m_Data.toString(); }
		bool toByteArr(uint8_t* arr, size_t &arrLength, IDnsResource* dnsResource);
	};


	/**
	 * @class IPv6DnsResourceData
	 */
	class IPv6DnsResourceData : public IDnsResourceData
	{
	private:
		IPv6Address m_Data;

	public:

		IPv6DnsResourceData(const uint8_t* dataPtr, size_t dataLen);
		IPv6DnsResourceData(const IPv6Address& addr) : m_Data(addr) {}
		IPv6DnsResourceData(const std::string& addrAsString) : m_Data(addrAsString) {}

		bool operator==(const IPv6DnsResourceData& other) const { return m_Data == other.m_Data; }

		IPv6Address getIpAddress() { return m_Data; }

		std::string toString() { return m_Data.toString(); }
		bool toByteArr(uint8_t* arr, size_t &arrLength, IDnsResource* dnsResource);
	};


	/**
	 * @class MxDnsResourceData
	 */
	class MxDnsResourceData : public IDnsResourceData
	{
	public:

		struct MxData
		{
			uint16_t preference;
			std::string mailExchange;
		};

		MxDnsResourceData(uint8_t* dataPtr, size_t dataLen, IDnsResource* dnsResource);
		MxDnsResourceData(const uint16_t& preference, const std::string& mailExchange);

		~MxDnsResourceData() {}

		bool operator==(const MxDnsResourceData& other) const;

		MxData getMxData() { return m_Data; }

		void setMxData(uint16_t preference, std::string mailExchange);

		std::string toString();
		bool toByteArr(uint8_t* arr, size_t &arrLength, IDnsResource* dnsResource);

	private:
		MxData m_Data;
	};


	/**
	 * @class GenericDnsResourceData
	 */
	class GenericDnsResourceData : public IDnsResourceData
	{
	private:
		uint8_t* m_Data;
		size_t m_DataLen;

	public:

		GenericDnsResourceData(uint8_t* dataPtr, size_t dataLen);
		GenericDnsResourceData(const std::string& dataAsHexString);

		~GenericDnsResourceData() { if (m_Data != NULL) delete [] m_Data; }

		GenericDnsResourceData& operator=(const GenericDnsResourceData& other);
		bool operator==(const GenericDnsResourceData& other) const;

		std::string toString();
		bool toByteArr(uint8_t* arr, size_t &arrLength, IDnsResource* dnsResource);
	};

}

#endif // PACKETPP_DNS_RESOURCE_DATA
