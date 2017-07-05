#ifndef PCAPPP_MACADDRESS
#define PCAPPP_MACADDRESS

#include <stdint.h>
#include <string>
#include <memory>

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * @class MacAddress
	 * Represents L2 MAC addresses. Can be constructed from string or a series of 6 byte octets
	 */
	class MacAddress
	{
	public:
		/**
		 * A constructor that creates an instance of the class out of a byte array. The byte array length must be equal or greater to 6
		 * (as MAC address is 6-byte long)
		 * @todo there is no verification array length >= 6. If this is not the case, address will read uninitialized memory
		 * @param[in] addr A pointer to the byte array containing 6 bytes representing the MAC address
		 */
		MacAddress(uint8_t* addr);

		/**
		 *  A constructor that creates an instance of the class out of a (char*) string.
		 *  If the string doesn't represent a valid MAC address, instance will be invalid, meaning isValid() will return false
		 *  @param[in] addr A pointer to the (char*) string
		 */
		MacAddress(const char* addr);

		/**
		 *  A constructor that creates an instance of the class out of a std::string.
		 *  If the string doesn't represent a valid MAC address, instance will be invalid, meaning isValid() will return false
	*  	 *	@param[in] addr A pointer to the string
		 */
		MacAddress(const std::string& addr);

		/**
		 *  A constructor that creates an instance of 6 bytes representing the MAC address
		 *  @param[in] firstOctest Represent the first octet in the address
		 *  @param[in] secondOctet Represent the second octet in the address
		 *  @param[in] thirdOctet Represent the third octet in the address
		 *  @param[in] fourthOctet Represent the fourth octet in the address
		 *  @param[in] fifthOctet Represent the fifth octet in the address
		 *  @param[in] sixthOctet Represent the sixth octet in the address
		 */
		MacAddress(uint8_t firstOctest, uint8_t secondOctet, uint8_t thirdOctet, uint8_t fourthOctet, uint8_t fifthOctet, uint8_t sixthOctet);

		/**
		 * A copy constructor for this class
		 */
		MacAddress(const MacAddress& other);

		/**
		 * Overload of the assignment operator
		 */
		MacAddress& operator=(const MacAddress& other);

		/**
		 * Overload of the comparison operator
		 * @return true if 2 addresses are equal. False otherwise
		 */
		inline bool operator==(const MacAddress& other)
				{
					for (int i = 0; i < 6; i++)
						if (m_Address[i] != other.m_Address[i])
							return false;
					return true;
				}

		/**
		 * Overload of the not-equal operator
		 * @return true if 2 addresses are not equal. False otherwise
		 */
		inline bool operator!=(const MacAddress& other) {return !operator==(other);}

		/**
		 * Get an indication whether the MAC address is valid. An address can be invalid if it was constructed from illegal input, for example:
		 * invalid string
		 * @return True if the address is valid, false otherwise
		 */
		bool isValid() { return m_IsValid; }

		/**
		 * Returns a std::string representation of the address
		 * @return A string representation of the address
		 */
		std::string toString();

		/**
		 * Allocates a byte array of length 6 and copies address value into it. Array deallocation is user responsibility
		 * @param[in] arr A pointer to where array will be allocated
		 */
		void copyTo(uint8_t** arr);

		/**
		 * Gets a pointer to an already allocated byte array and copies the address value to it.
		 * This method assumes array allocated size is at least 6 (the size of a MAC address)
		 * @param[in] arr A pointer to the array which address will be copied to
		 */
		void copyTo(uint8_t* arr) const;

		/**
		 * A static value representing a zero value of MAC address, meaning address of value "00:00:00:00:00:00"
		 */
		static MacAddress Zero;
	private:
		uint8_t m_Address[6];
		bool m_IsValid;
		void init(const char* addr);
	};

} // namespace pcpp

#endif /* PCAPPP_MACADDRESS */
