#pragma once

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
	 * Provides vendor name matching functionality from MAC addresses. It uses an internal database to define name of
	 * the vendor. The class itself should be initialized by using initOUIDatabaseFromJson() otherwise all requests will
	 * return "Unknown" as vendor. The class itself currently does not support on-fly modifying the database but anyone
	 * who wants to add/modify/remove entries, should modify 3rdParty/OUILookup/PCPP_OUIDatabase.json file and call to
	 * initOUIDatabaseFromJson() function to renew the internal data.
	 */
	class OUILookup
	{
	private:
		/**
		 * MAC addresses with mask values. For example for a MAC address "XX:XX:XX:XX:X0:00/36" the first element will
		 * be 36, and the second element will be unsigned integer equivalent of "XX:XX:XX:XX:X0:00" and vendor name.
		 */
		struct MaskedFilter
		{
			int mask;
			std::unordered_map<uint64_t, std::string> vendorMap;
		};

		/// Vendors for MAC addresses and mask filters if exists
		struct VendorData
		{
			std::string vendorName;
			std::vector<MaskedFilter> maskedFilter;
		};

		/**
		 * MAC addresses with only first three octets. The first element is unsigned integer equivalent of "XX:XX:XX"
		 * formatted MAC address
		 */
		typedef std::unordered_map<uint64_t, VendorData> OUIVendorMap;

		/// Internal vendor list for MAC addresses
		OUIVendorMap vendorMap;

		template <typename T> int64_t internalParser(T& jsonData);

	public:
		/**
		 * Initialise internal OUI database from a JSON file
		 * @param[in] path Path to OUI database. The database itself is located at
		 * 3rdParty/OUILookup/PCPP_OUIDatabase.json
		 * @return Returns the number of total vendors, negative on errors
		 */
		int64_t initOUIDatabaseFromJson(const std::string& path = "");

		/**
		 * Returns the vendor of the MAC address. OUI database should be initialized with initOUIDatabaseFromJson()
		 * @param[in] addr MAC address to search
		 * @return Vendor name
		 */
		std::string getVendorName(const pcpp::MacAddress& addr);
	};
}  // namespace pcpp
