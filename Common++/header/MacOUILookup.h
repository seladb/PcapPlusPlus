#ifndef PCPP_MAC_OUI_LOOKUP_HEADER
#define PCPP_MAC_OUI_LOOKUP_HEADER

#include <string>
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
     * MAC addresses with only first three octets
     * The first element is "XX:XX:XX" formatted MAC address and the second element is the Vendor
     */
    extern std::unordered_map<std::string, std::string> MacVendorListShort;

    /**
     * Full MAC addresses (with mask)
     * Every element of vector holds a different mask. The first element of the pair holds the value of mask and
     * the second one is the MAC address list for this mask. For example for a MAC address "XX:XX:XX:XX:X0:00/36"
     * the first element will be 36, and the second element will be "XX:XX:XX:XX:X0:00" and vendor name. So the
     * library will only search the required masks during runtime.
     */
    extern std::vector<std::pair<int, std::unordered_map<std::string, std::string>>> MacVendorListLong;

} // namespace pcpp

#endif // /* PCPP_MAC_OUI_LOOKUP_HEADER */
