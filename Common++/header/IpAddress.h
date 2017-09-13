#ifndef PCAPPP_IPADDRESS
#define PCAPPP_IPADDRESS

#include <memory>
#include <stdint.h>
#include <string>

#define MAX_ADDR_STRING_LEN 40 //xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx

/// @file

struct in_addr;
struct in6_addr;

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * @class IPAddress
	 * Base class for IPv4Address and IPv6Address. It's an abstract class and cannot be used as is.
	 * The only useful method in this class are the 2 static methods that constructs an IP address class from string
	 */
	class IPAddress
	{
	protected:
		bool m_IsValid;
		char m_AddressAsString[MAX_ADDR_STRING_LEN];

		// protected c'tor
		IPAddress() : m_IsValid(false) {}
	public:
#if __cplusplus > 199711L
		typedef std::unique_ptr<IPAddress> Ptr_t; 
#else
		typedef std::auto_ptr<IPAddress> Ptr_t; 
#endif

		/**
		 * An enum representing the address type: IPv4 or IPv6
		 */
		enum AddressType {
			/**
			 * IPv4 address type
			 */
			IPv4AddressType,
			/**
			 * IPv6 address type
			 */
			IPv6AddressType
		};

		virtual ~IPAddress();

		/**
		 * Gets the address type: IPv4 or IPv6
		 * @return The address type
		 */
		virtual AddressType getType() const = 0;

		/**
		 * Returns a std::string representation of the address
		 * @return A string representation of the address
		 */
		std::string toString() const { return std::string(m_AddressAsString); }

		/**
		 * Get an indication if the address is valid. An address can be invalid if it was constructed from illegal input, for example:
		 * An IPv4 address that was constructed form the string "999.999.999.999"
		 * @return True if the address is valid, false otherwise
		 */
		bool isValid() { return m_IsValid; }

		/**
		 * Constructs an IP address of type IPv4 or IPv6 from a string (char*) representation
		 * @param[in] addressAsString The address in string (char*) representation
		 * @return an auto-pointer to IPv4Address or IPv6Address instance that the string address represents, or an auto-pointer to NULL if
		 * the string doesn't represent either of types
		 */
		static Ptr_t fromString(char* addressAsString);

		/**
		 * Constructs an IP address of type IPv4 or IPv6 from a std::string representation
		 * @param[in] addressAsString The address in std::string representation
		 * @return an auto-pointer to IPv4Address or IPv6Address instance that the string address represents, or an auto-pointer to NULL if
		 * the string doesn't represent either of types
		 */
		static Ptr_t fromString(std::string addressAsString);
	};

	/**
	 * @class IPv4Address
	 * Represents an IPv4 address (of type XXX.XXX.XXX.XXX). An instance of this class can be constructed from string,
	 * 4-byte integer or from the in_addr struct. It can be converted to each of these types
	 */
	class IPv4Address : public IPAddress
	{
	private:
		in_addr* m_pInAddr;
		void init(char* addressAsString);
	public:
		/**
		 * A constructor that creates an instance of the class out of 4-byte integer value
		 * @todo consider endianess in this method
		 * @param[in] addressAsInt The address as 4-byte integer
		 */
		IPv4Address(uint32_t addressAsInt);

		/**
		 * A constructor that creates an instance of the class out of string (char*) value
		 * If the string doesn't represent a valid IPv4 address, instance will be invalid, meaning isValid() will return false
		 * @param[in] addressAsString The string (char*) representation of the address
		 */
		IPv4Address(char* addressAsString);

		/**
		 * A constructor that creates an instance of the class out of std::string value
		 * If the string doesn't represent a valid IPv4 address, instance will be invalid, meaning isValid() will return false
		 * @param[in] addressAsString The std::string representation of the address
		 */
		IPv4Address(std::string addressAsString);

		/**
		 * A constructor that creates an instance of the class out of in_addr struct pointer
		 * @param[in] inAddr The in_addr struct representation of the address
		 */
		IPv4Address(in_addr* inAddr);

		~IPv4Address();

		/**
		 * A copy constructor for this class
		 */
		IPv4Address(const IPv4Address& other);

		/**
		 * @return IPv4AddressType
		 */
		AddressType getType() const { return IPv4AddressType; }

		/**
		 * Converts the IPv4 address into a 4B integer
		 * @return a 4B integer representing the IPv4 address
		 */
		uint32_t toInt() const;

		/**
		 * Returns a in_addr struct pointer representing the IPv4 address
		 * @return a in_addr struct pointer representing the IPv4 address
		 */
		in_addr* toInAddr() { return m_pInAddr; }

		/**
		 * Overload of the comparison operator
		 * @return true if 2 addresses are equal. False otherwise
		 */
		bool operator==(const IPv4Address& other) const { return toInt() == other.toInt(); }

		/**
		 * Overload of the non-equal operator
		 * @return true if 2 addresses are not equal. False otherwise
		 */
		bool operator!=(const IPv4Address& other) const { return toInt() != other.toInt(); }

		/**
		 * Overload of the assignment operator
		 */
		IPv4Address& operator=(const IPv4Address& other);

		/**
		 * Checks whether the address matches a subnet.
		 * For example: if subnet is 10.1.1.X, subnet mask is 255.255.255.0 and address is 10.1.1.9 then the method will return true
		 * Another example: if subnet is 10.1.X.X, subnet mask is 255.0.0.0 and address is 11.1.1.9 then the method will return false
		 * @param[in] subnet The subnet to be verified. Notice it's an IPv4Address type, so subnets with don't-cares (like 10.0.0.X) must have some number
		 * (it'll be ignored if subnet mask is correct)
		 * @param[in] subnetMask A string representing the subnet mask to compare the address with the subnet
		 *
		 */
		bool matchSubnet(const IPv4Address& subnet, const std::string& subnetMask);

		/**
		 * A static value representing a zero value of IPv4 address, meaning address of value "0.0.0.0"
		 */
		static IPv4Address Zero;
	};


	/**
	 * @class IPv6Address
	 * Represents an IPv6 address (of type xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx). An instance of this class can be constructed from string,
	 * 16-byte array or from the in6_addr struct. It can be converted or copied to each of these types
	 */
	class IPv6Address : public IPAddress
	{
	private:
		in6_addr* m_pInAddr;
		void init(char* addressAsString);
	public:
		~IPv6Address();

		/**
		 * A constructor that creates an instance of the class out of a 16-Byte long byte array.
		 * Array size must be 16 bytes, otherwise instance will be invalid, meaning isValid() will return false
		 * @param addressAsUintArr A 16-byte array containing address value
		 */
		IPv6Address(uint8_t* addressAsUintArr);

		/**
		 * A constructor that creates an instance of the class out of string (char*) value.
		 * If the string doesn't represent a valid IPv6 address, instance will be invalid, meaning isValid() will return false
		 * @param[in] addressAsString The string (char*) representation of the address
		 */
		IPv6Address(char* addressAsString);

		/**
		 * A constructor that creates an instance of the class out of string std::string value
		 * If the string doesn't represent a valid IPv6 address, instance will be invalid, meaning isValid() will return false
		 * @param[in] addressAsString The string std::string representation of the address
		 */
		IPv6Address(std::string addressAsString);

		/**
		 * A copy constructor for this class
		 */
		IPv6Address(const IPv6Address& other);

		/**
		 * @return IPv6AddressType
		 */
		AddressType getType() const { return IPv6AddressType; }

		/**
		 * Returns a in6_addr struct pointer representing the IPv6 address
		 * @return a in6_addr struct pointer representing the IPv6 address
		 */
		in6_addr* toIn6Addr() { return m_pInAddr; }

		/**
		 * Allocates a byte array and copies address value into it. Array deallocation is user responsibility
		 * @param[in] arr A pointer to where array will be allocated
		 * @param[out] length Returns the length in bytes of the array that was allocated
		 */
		void copyTo(uint8_t** arr, size_t& length);

		/**
		 * Gets a pointer to an already allocated byte array and copies the address value to it.
		 * This method assumes array allocated size is at least 16 (the size of an IPv6 address)
		 * @param[in] arr A pointer to the array which address will be copied to
		 */
		void copyTo(uint8_t* arr) const;

		/**
		 * Overload of the comparison operator
		 * @return true if 2 addresses are equal. False otherwise
		 */
		bool operator==(const IPv6Address& other);

		/**
		 * Overload of the non-equal operator
		 * @return true if 2 addresses are not equal. False otherwise
		 */
		bool operator!=(const IPv6Address& other);

		/**
		 * Overload of the assignment operator
		 */
		IPv6Address& operator=(const IPv6Address& other);

		/**
		 * A static value representing a zero value of IPv6 address, meaning address of value
		 * "0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0"
		 */
		static IPv6Address Zero;
	};

} // namespace pcpp

#endif /* PCAPPP_IPADDRESS */
