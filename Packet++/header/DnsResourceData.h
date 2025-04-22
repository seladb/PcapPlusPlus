#pragma once

#include "DnsResource.h"
#include "IpAddress.h"
#include <memory>
#include <string>
#include <stdint.h>

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	// forward declarations
	class IDnsResource;

	/// @class IDnsResourceData
	/// A wrapper class for storing DNS RR (resource record) data. This is the base class which introduces several
	/// abstract methods for derived classes to implement for setting and retrieving the stored data. Each derived class
	/// will store different type of DNS RR data and implement these methods accordingly (for example: IPv4/IPv6
	/// addresses, MX data, hostnames, raw byte data etc.)
	class IDnsResourceData
	{
	protected:
		// unimplemented private copy c'tor
		IDnsResourceData(const IDnsResourceData& other);
		IDnsResourceData()
		{}

		size_t decodeName(const char* encodedName, char* result, IDnsResource* dnsResource) const;
		void encodeName(const std::string& decodedName, char* result, size_t& resultLen,
		                IDnsResource* dnsResource) const;

	public:
		/// A virtual d'tor, does nothing
		virtual ~IDnsResourceData() = default;

		/// A templated method which takes a class that derives from IDnsResourceData as the template argument and
		/// checks whether this instance is of this type
		/// @return True if this instance is of the requested type, false otherwise
		template <class IDnsResourceDataType> bool isTypeOf() const
		{
			return dynamic_cast<const IDnsResourceDataType*>(this) != nullptr;
		}

		/// A templated method which take a class that derives from IDnsResourceData as the template argument and tries
		/// to cast the current instance as that type
		/// @return A pointer to the current instance casted as the requested type or nullptr if this instance isn't of
		/// this type
		template <class IDnsResourceDataType> IDnsResourceDataType* castAs()
		{
			return dynamic_cast<IDnsResourceDataType*>(this);
		}

		/// @return A string that represents the current DNS RR data
		virtual std::string toString() const = 0;

		/// Convert the DNS RR data into a byte array
		/// @param[out] arr A pointer to a pre-allocated byte array where the result will be written to
		/// @param[out] arrLength A reference to a 2-byte number where the result array length will be written to
		/// @param[in] dnsResource A pointer to a DNS resource object where this DNS RR data will be stored
		/// @return True if the DNS RR data was successfully converted into a byte array and written to the given array
		/// or false if stored DNS RR data is invalid or if it could not be written to the given array
		virtual bool toByteArr(uint8_t* arr, size_t& arrLength, IDnsResource* dnsResource) const = 0;
	};

	/// @class DnsResourceDataPtr
	/// A smart pointer class that holds pointers of type IDnsResourceData. This object is used in DnsResource#getData()
	class DnsResourceDataPtr : public std::unique_ptr<IDnsResourceData>
	{
	public:
		/// A c'tor to this class
		/// @param[in] ptr A pointer to IDnsResourceData
		explicit DnsResourceDataPtr(IDnsResourceData* ptr) : std::unique_ptr<IDnsResourceData>(ptr)
		{}

		/// A templated method which takes a class that derives from IDnsResourceData as the template argument and
		/// checks whether the pointer stored in this object is of this type
		/// @return True if the stored pointer is of the requested type, false otherwise
		template <class IDnsResourceDataType> bool isTypeOf() const
		{
			return get()->isTypeOf<IDnsResourceDataType>();
		}

		/// A templated method which take a class that derives from IDnsResourceData as the template argument and tries
		/// to cast the pointer stored in this object as that type
		/// @return A pointer to the stored pointer casted as the requested type or nullptr if it isn't of this type
		template <class IDnsResourceDataType> IDnsResourceDataType* castAs()
		{
			return get()->castAs<IDnsResourceDataType>();
		}
	};

	/// @class StringDnsResourceData
	/// A class that represents DNS RR string data, mainly used in DNS RRs that store hostnames (like CNAME, DNAME, NS,
	/// etc.)
	class StringDnsResourceData : public IDnsResourceData
	{
	private:
		std::string m_Data;

	public:
		/// A c'tor for this class
		/// @param[in] data The string data to store in this object. If this string represents a hostname it's possible
		/// to include a pointer to another string in the DNS layer (as explained here:
		/// http://www.zytrax.com/books/dns/ch15/#name). These pointers are often used to reduce the DNS packet size and
		/// avoid unnecessary duplications. The way to include pointers in a hostname string is to use the following
		/// format: 'some.domain.#{offset}' where '#{offset}' is the offset from the start of the DNS layer. For
		/// example: if the string 'yahoo.com' already appears in offset 12 in the packet and you want to set the DNS RR
		/// data as 'my.subdomain.yahoo.com' you may use the following string: 'my.subdomain.#12'. This will result in
		/// writing 'my.subdomain' and a pointer to offset 12
		explicit StringDnsResourceData(const std::string& data) : m_Data(data)
		{}

		StringDnsResourceData(const uint8_t* dataPtr, size_t dataLen, IDnsResource* dnsResource);

		~StringDnsResourceData() override = default;

		/// Equality operator overload for this class that compares the strings stored in each object
		/// @param[in] other The object to compare with
		/// @return True if the string data is the same in both objects, false otherwise
		bool operator==(const StringDnsResourceData& other) const
		{
			return m_Data == other.m_Data;
		}

		// implement abstract methods

		std::string toString() const override
		{
			return m_Data;
		}
		bool toByteArr(uint8_t* arr, size_t& arrLength, IDnsResource* dnsResource) const override;
	};

	/// @class IPv4DnsResourceData
	/// A class that represents DNS RR IPv4 data, mainly used in DNS RRs of type ::DNS_TYPE_A
	class IPv4DnsResourceData : public IDnsResourceData
	{
	private:
		IPv4Address m_Data;

	public:
		/// A c'tor for this class
		/// @param[in] dataPtr A byte array of size 4 that contains an IPv4 address (each byte represents 1 octet)
		/// @param[in] dataLen The byte array size, expected to be 4
		IPv4DnsResourceData(const uint8_t* dataPtr, size_t dataLen);

		/// A c'tor for this class
		/// @param[in] addr The IPv4 address to store in this object
		explicit IPv4DnsResourceData(const IPv4Address& addr) : m_Data(addr)
		{}

		/// A c'tor for this class
		/// @param[in] addrAsString A string representation of an IPv4 address to store in this object
		explicit IPv4DnsResourceData(const std::string& addrAsString) : m_Data(addrAsString)
		{}

		/// Equality operator overload for this class that compares the IPv4 addresses stored in each object
		/// @param[in] other The object to compare with
		/// @return True if IPv4 addresses are the same in both objects, false otherwise
		bool operator==(const IPv4DnsResourceData& other) const
		{
			return m_Data == other.m_Data;
		}

		/// @return The IPv4 address stored in this object
		IPv4Address getIpAddress() const
		{
			return m_Data;
		}

		// implement abstract methods

		std::string toString() const override
		{
			return m_Data.toString();
		}
		bool toByteArr(uint8_t* arr, size_t& arrLength, IDnsResource* dnsResource) const override;
	};

	/// @class IPv6DnsResourceData
	/// A class that represents DNS RR IPv6 data, mainly used in DNS RRs of type ::DNS_TYPE_AAAA
	class IPv6DnsResourceData : public IDnsResourceData
	{
	private:
		IPv6Address m_Data;

	public:
		/// A c'tor for this class
		/// @param[in] dataPtr A byte array of size 16 that contains an IPv6 address (each byte represents 1 octet)
		/// @param[in] dataLen The byte array size, expected to be 16
		IPv6DnsResourceData(const uint8_t* dataPtr, size_t dataLen);

		/// A c'tor for this class
		/// @param[in] addr The IPv6 address to store in this object
		explicit IPv6DnsResourceData(const IPv6Address& addr) : m_Data(addr)
		{}

		/// A c'tor for this class
		/// @param[in] addrAsString A string representation of an IPv6 address to store in this object
		explicit IPv6DnsResourceData(const std::string& addrAsString) : m_Data(addrAsString)
		{}

		/// Equality operator overload for this class that compares the IPv6 addresses stored in each object
		/// @param[in] other The object to compare with
		/// @return True if IPv6 addresses are the same in both objects, false otherwise
		bool operator==(const IPv6DnsResourceData& other) const
		{
			return m_Data == other.m_Data;
		}

		/// @return The IPv6 address stored in this object
		IPv6Address getIpAddress() const
		{
			return m_Data;
		}

		// implement abstract methods

		std::string toString() const override
		{
			return m_Data.toString();
		}
		bool toByteArr(uint8_t* arr, size_t& arrLength, IDnsResource* dnsResource) const override;
	};

	/// @class MxDnsResourceData
	/// A class that represents DNS RR mail exchange (MX) data, used in DNS RRs of type ::DNS_TYPE_MX
	class MxDnsResourceData : public IDnsResourceData
	{
	public:
		/// A struct that represents mail exchange (MX) data
		struct MxData
		{
			/// Preference value
			uint16_t preference;
			/// Mail exchange hostname
			std::string mailExchange;
		};

		/// A c'tor for this class
		/// @param[in] dataPtr A byte array that contains the raw MX data (as written in the DNS packet)
		/// @param[in] dataLen The byte array size
		/// @param[in] dnsResource A pointer to a DNS resource object where this DNS RR data will be stored
		MxDnsResourceData(uint8_t* dataPtr, size_t dataLen, IDnsResource* dnsResource);

		/// A c'tor for this class
		/// @param[in] preference The MX preference value to store in this object
		/// @param[in] mailExchange The MX hostname value to store in this object. It's possible to include a pointer to
		/// another string in the DNS layer (as explained here: http://www.zytrax.com/books/dns/ch15/#name). These
		/// pointers are often used to reduce the DNS packet size and avoid unnecessary duplications. The way to include
		/// pointers in the hostname string is to use the following format: 'some.domain.#{offset}' where '#{offset}' is
		/// the offset from the start of the DNS layer. For example: if the string 'yahoo.com' already appears in offset
		/// 12 in the packet and you want to set the DNS RR data as 'my.subdomain.yahoo.com' you may use the following
		/// string: 'my.subdomain.#12'. This will result in writing 'my.subdomain' and a pointer to offset 12
		MxDnsResourceData(const uint16_t& preference, const std::string& mailExchange);

		~MxDnsResourceData() override = default;

		/// Equality operator overload for this class that compares the MX data stored in each object
		/// @param[in] other The object to compare with
		/// @return True if MX data is the same in both objects, meaning both preference and MX hostname are the same,
		/// false otherwise
		bool operator==(const MxDnsResourceData& other) const;

		/// @return The MX data stored in this object
		MxData getMxData() const
		{
			return m_Data;
		}

		/// Set the MX data stored in this object
		/// @param[in] preference The MX preference value to store in this object
		/// @param[in] mailExchange The MX hostname value to store in this object
		void setMxData(uint16_t preference, std::string mailExchange);

		// implement abstract methods

		/// A string representation of the MX data stored in this object. The string format is as follows:
		/// 'pref: {preference_value}; mx: {mail_exchange_hostname_value}'
		std::string toString() const override;

		bool toByteArr(uint8_t* arr, size_t& arrLength, IDnsResource* dnsResource) const override;

	private:
		MxData m_Data;
	};

	/// @class GenericDnsResourceData
	/// A class that represents generic DNS RR data which cannot be represented in any of the other classes. It stores
	/// the DNS RR data as byte array
	class GenericDnsResourceData : public IDnsResourceData
	{
	private:
		uint8_t* m_Data;
		size_t m_DataLen;

	public:
		/// A c'tor for this class
		/// @param[in] dataPtr A byte array that contains the raw data (as it written in the DNS packet). The data will
		/// be copied from this byte array to the object
		/// @param[in] dataLen The byte array size
		GenericDnsResourceData(const uint8_t* dataPtr, size_t dataLen);

		/// A c'tor for this class
		/// @param[in] dataAsHexString A hex string that represents the DNS RR data
		explicit GenericDnsResourceData(const std::string& dataAsHexString);

		/// A copy c'tor for this class
		/// @param[in] other The instance to copy from
		GenericDnsResourceData(const GenericDnsResourceData& other);

		~GenericDnsResourceData() override
		{
			if (m_Data != nullptr)
				delete[] m_Data;
		}

		GenericDnsResourceData& operator=(const GenericDnsResourceData& other);

		/// Equality operator overload for this class that compares the raw data stored in each object
		/// @param[in] other The object to compare with
		/// @return True if data is the same in both objects, meaning byte streams are equal, false otherwise
		bool operator==(const GenericDnsResourceData& other) const;

		// implement abstract methods

		std::string toString() const override;
		bool toByteArr(uint8_t* arr, size_t& arrLength, IDnsResource* dnsResource) const override;
	};

}  // namespace pcpp
