#include "MacAddress.h"

#include <unordered_map>
#include <vector>

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
	/**
	 * @class OUILookup
	 * Provides vendor name matching functionality from MAC addresses
	 */
	class OUILookup
	{
	private:
		/**
		 * MAC addresses with only first three octets
		 * The first element is "XX:XX:XX" formatted MAC address and the second element is the Vendor
		 */
		std::unordered_map<std::string, std::string> OUIVendorListShort;

		/**
		 * Full MAC addresses (with mask)
		 * Every element of vector holds a different mask. The first element of the pair holds the value of mask and
		 * the second one is the MAC address list for this mask. For example for a MAC address "XX:XX:XX:XX:X0:00/36"
		 * the first element will be 36, and the second element will be "XX:XX:XX:XX:X0:00" and vendor name. So the
		 * library will only search the required masks during runtime.
		 */
		std::vector<std::pair<int, std::unordered_map<std::string, std::string>>> OUIVendorListLong;

	public:
		/**
		 * Initialise internal OUI database
		 * @param[in] path Path to OUI database. The database itself is located at PcapPlusPlus_Source_Dir/3rdParty/OUILookup/PCPP_OUIDatabase.dat
		 * @return int64_t Returns the number of total vendors, negative on errors
		 */
		int64_t initOUIDatabase(const std::string &path = "");

		/**
		 * Returns the vendor of the MAC address. OUI database should be initialized with initOUIDatabase()
		 * @param[in] addr MAC address to search
		 * @return Vendor name
		 */
		std::string getVendorName(const pcpp::MacAddress &addr);
	};
} // namespace pcpp
