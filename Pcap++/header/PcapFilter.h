#pragma once

#include <string>
#include <vector>
#include <memory>
#include "ProtocolType.h"
#include <stdint.h>
#include "ArpLayer.h"
#include "RawPacket.h"

// Forward Declaration - used in GeneralFilter
struct bpf_program;

/// @file
/// Most packet capture engines contain packet filtering capabilities. In order to set the filters there should be a
/// known syntax user can use. The most popular syntax is Berkeley Packet Filter (BPF) - see more in here:
/// http://en.wikipedia.org/wiki/Berkeley_Packet_Filter. Detailed explanation of the syntax can be found here:
/// http://www.tcpdump.org/manpages/pcap-filter.7.html.
///
/// The problem with BPF is that, for my opinion, the syntax is too complicated and too poorly documented. In addition
/// the BPF filter compilers may output syntax errors that are hard to understand. My experience with BPF was not good,
/// so I decided to make the filters mechanism more structured, easier to understand and less error-prone by creating
/// classes that represent filters. Each possible filter phrase is represented by a class. The filter, at the end, is
/// that class.
/// For example: the filter "src net 1.1.1.1" will be represented by IPFilter instance; "dst port 80"
/// will be represented by PortFilter, and so on.
/// So what about complex filters that involve "and", "or"? There are
/// also 2 classes: AndFilter and OrFilter that can store more filters (in a composite idea) and connect them by "and"
/// or "or". For example: "src host 1.1.1.1 and dst port 80" will be represented by an AndFilter that holds IPFilter and
/// PortFilter inside it

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	// Forward Declaration - used in GeneralFilter
	class RawPacket;

	/// An enum that contains direction (source or destination)
	typedef enum
	{
		/// Source
		SRC,
		/// Destination
		DST,
		/// Source or destination
		SRC_OR_DST
	} Direction;

	/// Supported operators enum
	typedef enum
	{
		/// Equals
		EQUALS,
		/// Not equals
		NOT_EQUALS,
		/// Greater than
		GREATER_THAN,
		/// Greater or equal
		GREATER_OR_EQUAL,
		/// Less than
		LESS_THAN,
		/// Less or equal
		LESS_OR_EQUAL
	} FilterOperator;

	namespace internal
	{
		/// @class BpfProgramDeleter
		/// A deleter that cleans up a bpf_program object.
		struct BpfProgramDeleter
		{
			void operator()(bpf_program* ptr) const noexcept;
		};
	}  // namespace internal

	/// @class BpfFilterWrapper
	/// A wrapper class for BPF filtering. Enables setting a BPF filter and matching it against a packet
	class BpfFilterWrapper
	{
	private:
		std::string m_FilterStr;
		LinkLayerType m_LinkType;
		std::unique_ptr<bpf_program, internal::BpfProgramDeleter> m_Program;

		void freeProgram();

	public:
		/// A c'tor for this class
		BpfFilterWrapper();

		/// A copy constructor for this class.
		/// @param[in] other The instance to copy from
		BpfFilterWrapper(const BpfFilterWrapper& other);

		/// A copy assignment operator for this class.
		/// @param[in] other An instance of IPNetwork to assign
		/// @return A reference to the assignee
		BpfFilterWrapper& operator=(const BpfFilterWrapper& other);

		/// Set a filter. This method receives a filter in BPF syntax (https://biot.com/capstats/bpf.html) and an
		/// optional link type, compiles them, and if compilation is successful it stores the filter.
		/// @param[in] filter A filter in BPF syntax
		/// @param[in] linkType An optional parameter to set the filter's link type. The default is LINKTYPE_ETHERNET
		/// @return True if compilation is successful and filter is stored in side this object, false otherwise
		bool setFilter(const std::string& filter, LinkLayerType linkType = LINKTYPE_ETHERNET);

		/// Match a packet with the filter stored in this object. If the filter is empty the method returns "true".
		/// If the link type of the raw packet is different than the one set in setFilter(), the filter will be
		/// re-compiled and stored in the object.
		/// @param[in] rawPacket A pointer to a raw packet which the filter will be matched against
		/// @return True if the filter matches (or if it's empty). False if the packet doesn't match or if the filter
		/// could not be compiled
		bool matchPacketWithFilter(const RawPacket* rawPacket);

		/// Match a packet data with the filter stored in this object. If the filter is empty the method returns "true".
		/// If the link type provided is different than the one set in setFilter(), the filter will be re-compiled
		/// and stored in the object.
		/// @param[in] packetData A byte stream containing the packet data
		/// @param[in] packetDataLength The length in [bytes] of the byte stream
		/// @param[in] packetTimestamp The packet timestamp
		/// @param[in] linkType The packet link type
		/// @return True if the filter matches (or if it's empty). False if the packet doesn't match or if the filter
		/// could not be compiled
		bool matchPacketWithFilter(const uint8_t* packetData, uint32_t packetDataLength, timespec packetTimestamp,
		                           uint16_t linkType);
	};

	/// @class GeneralFilter
	/// The base class for all filter classes. This class is virtual and abstract, hence cannot be instantiated.
	///
	/// For deeper understanding of the filter concept please refer to PcapFilter.h
	class GeneralFilter
	{
	protected:
		BpfFilterWrapper m_BpfWrapper;

	public:
		/// A method that parses the class instance into BPF string format
		/// @param[out] result An empty string that the parsing will be written into. If the string isn't empty, its
		/// content will be overridden
		virtual void parseToString(std::string& result) = 0;

		/// Match a raw packet with a given BPF filter.
		/// @param[in] rawPacket A pointer to the raw packet to match the BPF filter with
		/// @return True if a raw packet matches the BPF filter or false otherwise
		bool matchPacketWithFilter(RawPacket* rawPacket);

		GeneralFilter()
		{}

		/// Virtual destructor, frees the bpf program
		virtual ~GeneralFilter() = default;
	};

	/// @class BPFStringFilter
	/// This class can be loaded with a BPF filter string and then can be used to verify the string is valid.
	class BPFStringFilter : public GeneralFilter
	{
	private:
		const std::string m_FilterStr;

	public:
		explicit BPFStringFilter(const std::string& filterStr) : m_FilterStr(filterStr)
		{}

		virtual ~BPFStringFilter()
		{}

		/// A method that parses the class instance into BPF string format
		/// @param[out] result An empty string that the parsing will be written into. If the string isn't empty, its
		/// content will be overridden If the filter is not valid the result will be an empty string
		void parseToString(std::string& result) override;

		/// Verify the filter is valid
		/// @return True if the filter is valid or false otherwise
		bool verifyFilter();
	};

	/// @class IFilterWithDirection
	/// An abstract class that is the base class for all filters which contain a direction (source or destination). This
	/// class cannot be instantiated
	///
	/// For deeper understanding of the filter concept please refer to PcapFilter.h
	class IFilterWithDirection : public GeneralFilter
	{
	private:
		Direction m_Dir;

	protected:
		void parseDirection(std::string& directionAsString);
		Direction getDir() const
		{
			return m_Dir;
		}
		explicit IFilterWithDirection(Direction dir)
		{
			m_Dir = dir;
		}

	public:
		/// Set the direction for the filter (source or destination)
		/// @param[in] dir The direction
		void setDirection(Direction dir)
		{
			m_Dir = dir;
		}
	};

	/// @class IFilterWithOperator
	/// An abstract class that is the base class for all filters which contain an operator (e.g X equals Y; A is greater
	/// than B; Z1 not equals Z2, etc.). This class cannot be instantiated
	///
	/// For deeper understanding of the filter concept please refer to PcapFilter.h
	class IFilterWithOperator : public GeneralFilter
	{
	private:
		FilterOperator m_Operator;

	protected:
		std::string parseOperator();
		FilterOperator getOperator() const
		{
			return m_Operator;
		}
		explicit IFilterWithOperator(FilterOperator op)
		{
			m_Operator = op;
		}

	public:
		/// Set the operator for the filter
		/// @param[in] op The operator to set
		void setOperator(FilterOperator op)
		{
			m_Operator = op;
		}
	};

	/// @class IPFilter
	/// A class for representing IPv4 or IPv6 address filter, equivalent to "net src x.x.x.x" or "net dst x.x.x.x"
	///
	/// For deeper understanding of the filter concept please refer to PcapFilter.h
	class IPFilter : public IFilterWithDirection
	{
	private:
		IPAddress m_Address;
		IPNetwork m_Network;

	public:
		/// The basic constructor that creates the filter from an IP address string and direction (source or
		/// destination)
		/// @param[in] ipAddress The IP address to build the filter with.
		/// @param[in] dir The address direction to filter (source or destination)
		/// @throws std::invalid_argument The provided address is not a valid IPv4 or IPv6 address.
		IPFilter(const std::string& ipAddress, Direction dir) : IPFilter(IPAddress(ipAddress), dir)
		{}

		/// The basic constructor that creates the filter from an IP address and direction (source or destination)
		/// @param[in] ipAddress The IP address to build the filter with.
		/// @param[in] dir The address direction to filter (source or destination)
		IPFilter(const IPAddress& ipAddress, Direction dir)
		    : IFilterWithDirection(dir), m_Address(ipAddress), m_Network(ipAddress)
		{}

		/// A constructor that enable to filter only part of the address by using a mask (aka subnet). For example:
		/// "filter only IP addresses that matches the subnet 10.0.0.x"
		/// @param[in] ipAddress The IP address to use. Only the part of the address that is not masked will be matched.
		/// For example: if the address is "1.2.3.4" and the mask is "255.255.255.0" than the part of the address that
		/// will be matched is "1.2.3.X".
		/// @param[in] dir The address direction to filter (source or destination)
		/// @param[in] netmask The mask to use. The mask should be a valid IP address in either IPv4 dotted-decimal
		/// format (e.g., 255.255.255.0) or IPv6 colon-separated hexadecimal format (e.g., FFFF:FFFF:FFFF:FFFF::).
		/// @throws std::invalid_argument The provided address is not a valid IP address or the provided netmask string
		/// is invalid..
		IPFilter(const std::string& ipAddress, Direction dir, const std::string& netmask)
		    : IPFilter(IPv4Address(ipAddress), dir, netmask)
		{}

		/// A constructor that enable to filter only part of the address by using a mask (aka subnet). For example:
		/// "filter only IP addresses that matches the subnet 10.0.0.x"
		/// @param[in] ipAddress The IP address to use. Only the part of the address that is not masked will be
		/// matched. For example: if the address is "1.2.3.4" and the mask is "255.255.255.0" than the part of the
		/// address that will be matched is "1.2.3.X".
		/// @param[in] dir The address direction to filter (source or destination)
		/// @param[in] netmask The mask to use. The mask should be a valid IP address in either IPv4 dotted-decimal
		/// format (e.g., 255.255.255.0) or IPv6 colon-separated hexadecimal format (e.g., FFFF:FFFF:FFFF:FFFF::).
		/// @throws std::invalid_argument The provided netmask string is invalid.
		IPFilter(const IPAddress& ipAddress, Direction dir, const std::string& netmask)
		    : IFilterWithDirection(dir), m_Address(ipAddress), m_Network(ipAddress, netmask)
		{}

		/// A constructor that enables to filter by a subnet. For example: "filter only IP addresses that matches the
		/// subnet 10.0.0.3/24" which means the part of the address that will be matched is "10.0.0.X"
		/// @param[in] ipAddress The IP address to use. Only the part of the address that is not masked will be matched.
		/// For example: if the address is "1.2.3.4" and the subnet is "/24" than the part of the address that will be
		/// matched is "1.2.3.X".
		/// @param[in] dir The address direction to filter (source or destination)
		/// @param[in] len The subnet to use (e.g "/24"). Acceptable subnet values are [0, 32] for IPv4 and [0, 128] for
		/// IPv6.
		/// @throws std::invalid_argument The provided address is not a valid IPv4 or IPv6 address or the provided
		/// length is out of acceptable range.
		IPFilter(const std::string& ipAddress, Direction dir, int len) : IPFilter(IPAddress(ipAddress), dir, len)
		{}

		/// A constructor that enables to filter by a subnet. For example: "filter only IP addresses that matches the
		/// subnet 10.0.0.3/24" which means the part of the address that will be matched is "10.0.0.X"
		/// @param[in] ipAddress The IP address to use. Only the part of the address that is not masked will be matched.
		/// For example: if the address is "1.2.3.4" and the subnet is "/24" than the part of the address that will be
		/// matched is "1.2.3.X".
		/// @param[in] dir The address direction to filter (source or destination)
		/// @param[in] len The subnet to use (e.g "/24"). Acceptable subnet values are [0, 32] for IPv4 and [0, 128] for
		/// IPv6.
		/// @throws std::invalid_argument The provided length is out of acceptable range.
		IPFilter(const IPAddress& ipAddress, Direction dir, int len)
		    : IFilterWithDirection(dir), m_Address(ipAddress), m_Network(ipAddress, len)
		{}

		/// A constructor that enables to filter by a predefined network object.
		/// @param[in] network The network to use when filtering. IP address and subnet mask are taken from the network
		/// object.
		/// @param[in] dir The address direction to filter (source or destination)
		IPFilter(const IPNetwork& network, Direction dir)
		    : IFilterWithDirection(dir), m_Address(network.getNetworkPrefix()), m_Network(network)
		{}

		void parseToString(std::string& result) override;

		/// Set the network to build the filter with.
		/// @param[in] network The IP Network object to be used when building the filter.
		void setNetwork(const IPNetwork& network)
		{
			m_Network = network;
			m_Address = m_Network.getNetworkPrefix();
		}

		/// Set the IP address
		/// @param[in] ipAddress The IP address to build the filter with.
		/// @throws std::invalid_argument The provided string does not represent a valid IP address.
		void setAddr(const std::string& ipAddress)
		{
			this->setAddr(IPAddress(ipAddress));
		}

		/// Set the IP address
		/// @param[in] ipAddress The IP address to build the filter with.
		/// @remarks Alternating between IPv4 and IPv6 can have unintended consequences on the subnet mask.
		///  Setting an IPv4 address when the prefix length is over 32 make the new prefix length 32.
		///  Setting an IPv6 address will keep the current IPv4 prefix mask length.
		void setAddr(const IPAddress& ipAddress)
		{
			m_Address = ipAddress;
			uint8_t newPrefixLen = m_Network.getPrefixLen();
			if (m_Address.isIPv4() && newPrefixLen > 32u)
			{
				newPrefixLen = 32u;
			}

			m_Network = IPNetwork(m_Address, newPrefixLen);
		}

		/// Set the subnet mask
		/// @param[in] netmask The mask to use. The mask should match the IP version and be in a valid format.
		/// Valid formats:
		///   IPv4 - (X.X.X.X) - 'X' - a number in the range of 0 and 255 (inclusive)):
		///   IPv6 - (YYYY:YYYY:YYYY:YYYY:YYYY:YYYY:YYYY:YYYY) - 'Y' - a hexadecimal digit [0 - 9, A - F]. Short form
		///   IPv6 formats are allowed.
		/// @throws std::invalid_argument The provided netmask is invalid or does not correspond to the current IP
		/// address version.
		void setMask(const std::string& netmask)
		{
			m_Network = IPNetwork(m_Address, netmask);
		}

		/// Clears the subnet mask.
		void clearMask()
		{
			this->clearLen();
		}

		/// Set the subnet (IPv4) or prefix length (IPv6).
		/// Acceptable subnet values are [0, 32] for IPv4 and [0, 128] for IPv6.
		/// @param[in] len The subnet to use (e.g "/24")
		/// @throws std::invalid_argument The provided length is out of acceptable range.
		void setLen(const int len)
		{
			m_Network = IPNetwork(m_Address, len);
		}

		/// Clears the subnet mask length.
		void clearLen()
		{
			m_Network = IPNetwork(m_Address);
		}
	};

	/// @class IPv4IDFilter
	/// A class for filtering IPv4 traffic by IP ID field of the IPv4 protocol, for example:
	/// "filter only IPv4 traffic which IP ID is greater than 1234"
	///
	/// For deeper understanding of the filter concept please refer to PcapFilter.h
	class IPv4IDFilter : public IFilterWithOperator
	{
	private:
		uint16_t m_IpID;

	public:
		/// A constructor that gets the IP ID to filter and the operator and creates the filter out of them
		/// @param[in] ipID The IP ID to filter
		/// @param[in] op The operator to use (e.g "equal", "greater than", etc.)
		IPv4IDFilter(uint16_t ipID, FilterOperator op) : IFilterWithOperator(op), m_IpID(ipID)
		{}

		void parseToString(std::string& result) override;

		/// Set the IP ID to filter
		/// @param[in] ipID The IP ID to filter
		void setIpID(uint16_t ipID)
		{
			m_IpID = ipID;
		}
	};

	/// @class IPv4TotalLengthFilter
	/// A class for filtering IPv4 traffic by "total length" field of the IPv4 protocol, for example:
	/// "filter only IPv4 traffic which "total length" value is less than 60B"
	///
	/// For deeper understanding of the filter concept please refer to PcapFilter.h
	class IPv4TotalLengthFilter : public IFilterWithOperator
	{
	private:
		uint16_t m_TotalLength;

	public:
		/// A constructor that gets the total length to filter and the operator and creates the filter out of them
		/// @param[in] totalLength The total length value to filter
		/// @param[in] op The operator to use (e.g "equal", "greater than", etc.)
		IPv4TotalLengthFilter(uint16_t totalLength, FilterOperator op)
		    : IFilterWithOperator(op), m_TotalLength(totalLength)
		{}

		void parseToString(std::string& result) override;

		/// Set the total length value
		/// @param[in] totalLength The total length value to filter
		void setTotalLength(uint16_t totalLength)
		{
			m_TotalLength = totalLength;
		}
	};

	/// @class PortFilter
	/// A class for filtering TCP or UDP traffic by port, for example: "dst port 80" or "src port 12345".
	///
	/// For deeper understanding of the filter concept please refer to PcapFilter.h
	class PortFilter : public IFilterWithDirection
	{
	private:
		std::string m_Port;
		void portToString(uint16_t portAsInt);

	public:
		/// A constructor that gets the port and the direction and creates the filter
		/// @param[in] port The port to create the filter with
		/// @param[in] dir The port direction to filter (source or destination)
		PortFilter(uint16_t port, Direction dir);

		void parseToString(std::string& result) override;

		/// Set the port
		/// @param[in] port The port to create the filter with
		void setPort(uint16_t port)
		{
			portToString(port);
		}
	};

	/// @class PortRangeFilter
	/// A class for filtering TCP or UDP port ranges, meaning match only packets which port is within this range, for
	/// example: "src portrange 1000-2000" will match only TCP or UDP traffic which source port is in the range of 1000
	/// - 2000
	///
	/// For deeper understanding of the filter concept please refer to PcapFilter.h
	class PortRangeFilter : public IFilterWithDirection
	{
	private:
		uint16_t m_FromPort;
		uint16_t m_ToPort;

	public:
		/// A constructor that gets the port range the the direction and creates the filter with them
		/// @param[in] fromPort The lower end of the port range
		/// @param[in] toPort The higher end of the port range
		/// @param[in] dir The port range direction to filter (source or destination)
		PortRangeFilter(uint16_t fromPort, uint16_t toPort, Direction dir)
		    : IFilterWithDirection(dir), m_FromPort(fromPort), m_ToPort(toPort)
		{}

		void parseToString(std::string& result) override;

		/// Set the lower end of the port range
		/// @param[in] fromPort The lower end of the port range
		void setFromPort(uint16_t fromPort)
		{
			m_FromPort = fromPort;
		}

		/// Set the higher end of the port range
		/// @param[in] toPort The higher end of the port range
		void setToPort(uint16_t toPort)
		{
			m_ToPort = toPort;
		}
	};

	/// @class MacAddressFilter
	/// A class for filtering Ethernet traffic by MAC addresses, for example: "ether src 12:34:56:78:90:12" or "ether
	/// dst 10:29:38:47:56:10:29"
	///
	/// For deeper understanding of the filter concept please refer to PcapFilter.h
	class MacAddressFilter : public IFilterWithDirection
	{
	private:
		MacAddress m_MacAddress;

	public:
		/// A constructor that gets the MAC address and the direction and creates the filter with them
		/// @param[in] address The MAC address to use for filtering
		/// @param[in] dir The MAC address direction to filter (source or destination)
		MacAddressFilter(MacAddress address, Direction dir) : IFilterWithDirection(dir), m_MacAddress(address)
		{}

		void parseToString(std::string& result) override;

		/// Set the MAC address
		/// @param[in] address The MAC address to use for filtering
		void setMacAddress(MacAddress address)
		{
			m_MacAddress = address;
		}
	};

	/// @class EtherTypeFilter
	/// A class for filtering by EtherType field of the Ethernet protocol. This enables to filter packets from certain
	/// protocols, such as ARP, IPv4, IPv6, VLAN tags, etc.
	///
	/// For deeper understanding of the filter concept please refer to PcapFilter.h
	class EtherTypeFilter : public GeneralFilter
	{
	private:
		uint16_t m_EtherType;

	public:
		/// A constructor that gets the EtherType and creates the filter with it
		/// @param[in] etherType The EtherType value to create the filter with
		explicit EtherTypeFilter(uint16_t etherType) : m_EtherType(etherType)
		{}

		void parseToString(std::string& result) override;

		/// Set the EtherType value
		/// @param[in] etherType The EtherType value to create the filter with
		void setEtherType(uint16_t etherType)
		{
			m_EtherType = etherType;
		}
	};

	/// @class CompositeFilter
	/// The base class for all filter classes composed of several other filters. This class is virtual and abstract,
	/// hence cannot be instantiated.
	///
	/// For deeper understanding of the filter concept please refer to PcapFilter.h
	class CompositeFilter : public GeneralFilter
	{
	protected:
		std::vector<GeneralFilter*> m_FilterList;

	public:
		/// An empty constructor for this class. Use addFilter() to add filters to the composite filter.
		CompositeFilter() = default;

		/// A constructor that gets a list of pointers to filters and creates one filter from all filters
		/// @param[in] filters The list of pointers to filters
		explicit CompositeFilter(const std::vector<GeneralFilter*>& filters);

		/// Add filter to the composite filter
		/// @param[in] filter The filter to add
		void addFilter(GeneralFilter* filter)
		{
			m_FilterList.push_back(filter);
		}

		/// Removes the first matching filter from the composite filter
		/// @param[in] filter The filter to remove
		void removeFilter(GeneralFilter* filter);

		/// Remove the current filters and set new ones
		/// @param[in] filters The new filters to set. The previous ones will be removed
		void setFilters(const std::vector<GeneralFilter*>& filters);

		/// Remove all filters from the composite filter.
		void clearAllFilters()
		{
			m_FilterList.clear();
		}
	};

	/// Supported composite logic filter operators enum
	enum class CompositeLogicFilterOp
	{
		/// Logical AND operation
		AND,
		/// Logical OR operation
		OR,
	};

	namespace internal
	{
		// Could potentially be moved into CompositeLogicFilter as a private member function, with if constexpr when
		// C++17 is the minimum supported standard.

		/// Returns the delimiter for joining filter strings for the composite logic filter operation.
		/// @return A string literal to place between the different filter strings to produce a composite expression.
		template <CompositeLogicFilterOp op> constexpr const char* getCompositeLogicOpDelimiter() = delete;
		template <> constexpr const char* getCompositeLogicOpDelimiter<CompositeLogicFilterOp::AND>()
		{
			return " and ";
		};
		template <> constexpr const char* getCompositeLogicOpDelimiter<CompositeLogicFilterOp::OR>()
		{
			return " or ";
		};
	}  // namespace internal

	/// @class CompositeLogicFilter
	/// A class for connecting several filters into one filter with logical operation between them.
	///
	/// For deeper understanding of the filter concept please refer to PcapFilter.h
	template <CompositeLogicFilterOp op> class CompositeLogicFilter : public CompositeFilter
	{
	public:
		using CompositeFilter::CompositeFilter;

		void parseToString(std::string& result) override
		{
			result.clear();
			for (auto it = m_FilterList.cbegin(); it != m_FilterList.cend(); ++it)
			{
				std::string innerFilter;
				(*it)->parseToString(innerFilter);
				result += '(' + innerFilter + ')';
				if (m_FilterList.cend() - 1 != it)
				{
					result += internal::getCompositeLogicOpDelimiter<op>();
				}
			}
		}
	};

	/// A class for connecting several filters into one filter with logical "and" between them. For example: if the 2
	/// filters are: "IPv4 address = x.x.x.x" + "TCP port dst = 80", then the new filter will be: "IPv4 address =
	/// x.x.x.x _AND_ TCP port dst = 80"
	///
	/// This class follows the composite design pattern.
	///
	/// For deeper understanding of the filter concept please refer to PcapFilter.h
	using AndFilter = CompositeLogicFilter<CompositeLogicFilterOp::AND>;

	/// A class for connecting several filters into one filter with logical "or" between them. For example: if the 2
	/// filters are: "IPv4 address = x.x.x.x" + "TCP port dst = 80", then the new filter will be: "IPv4 address =
	/// x.x.x.x _OR_ TCP port dst = 80"
	///
	/// This class follows the composite design pattern.
	///
	/// For deeper understanding of the filter concept please refer to PcapFilter.h
	using OrFilter = CompositeLogicFilter<CompositeLogicFilterOp::OR>;

	/// @class NotFilter
	/// A class for creating a filter which is inverse to another filter
	///
	/// For deeper understanding of the filter concept please refer to PcapFilter.h
	class NotFilter : public GeneralFilter
	{
	private:
		GeneralFilter* m_FilterToInverse;

	public:
		/// A constructor that gets a pointer to a filter and create the inverse version of it
		/// @param[in] filterToInverse A pointer to filter which the created filter be the inverse of
		explicit NotFilter(GeneralFilter* filterToInverse)
		{
			m_FilterToInverse = filterToInverse;
		}

		void parseToString(std::string& result) override;

		/// Set a filter to create an inverse filter from
		/// @param[in] filterToInverse A pointer to filter which the created filter be the inverse of
		void setFilter(GeneralFilter* filterToInverse)
		{
			m_FilterToInverse = filterToInverse;
		}
	};

	/// @class ProtoFilter
	/// A class for filtering traffic by protocol. Notice not all protocols are supported, only the following protocol
	/// are supported:
	/// ::TCP, ::UDP, ::ICMP, ::VLAN, ::IPv4, ::IPv6, ::ARP, ::Ethernet.
	/// In addition, the following protocol families are supported: ::GRE (distinguish between ::GREv0 and ::GREv1 is
	/// not supported),
	/// ::IGMP (distinguish between ::IGMPv1, ::IGMPv2 and ::IGMPv3 is not supported).
	///
	/// For deeper understanding of the filter concept please refer to PcapFilter.h
	class ProtoFilter : public GeneralFilter
	{
	private:
		ProtocolTypeFamily m_ProtoFamily;

	public:
		/// A constructor that gets a protocol and creates the filter
		/// @param[in] proto The protocol to filter, only packets matching this protocol will be received. Please note
		/// not all protocols are supported. List of supported protocols is found in the class description
		explicit ProtoFilter(ProtocolType proto) : m_ProtoFamily(proto)
		{}

		/// A constructor that gets a protocol family and creates the filter
		/// @param[in] protoFamily The protocol family to filter, only packets matching this protocol will be received.
		/// Please note not all protocols are supported. List of supported protocols is found in the class description
		explicit ProtoFilter(ProtocolTypeFamily protoFamily) : m_ProtoFamily(protoFamily)
		{}

		void parseToString(std::string& result) override;

		/// Set the protocol to filter with
		/// @param[in] proto The protocol to filter, only packets matching this protocol will be received. Please note
		/// not all protocol families are supported. List of supported protocols is found in the class description
		void setProto(ProtocolType proto)
		{
			m_ProtoFamily = proto;
		}

		/// Set the protocol family to filter with
		/// @param[in] protoFamily The protocol family to filter, only packets matching this protocol will be received.
		/// Please note not all protocol families are supported. List of supported protocols is found in the class
		/// description
		void setProto(ProtocolTypeFamily protoFamily)
		{
			m_ProtoFamily = protoFamily;
		}
	};

	/// @class ArpFilter
	/// A class for filtering ARP packets according the ARP opcode. When using this filter only ARP packets with the
	/// relevant opcode will be received
	///
	/// For deeper understanding of the filter concept please refer to PcapFilter.h
	class ArpFilter : public GeneralFilter
	{
	private:
		ArpOpcode m_OpCode;

	public:
		/// A constructor that get the ARP opcode and creates the filter
		/// @param[in] opCode The ARP opcode: ::ARP_REQUEST or ::ARP_REPLY
		explicit ArpFilter(ArpOpcode opCode) : m_OpCode(opCode)
		{}

		void parseToString(std::string& result) override;

		/// Set the ARP opcode
		/// @param[in] opCode The ARP opcode: ::ARP_REQUEST or ::ARP_REPLY
		void setOpCode(ArpOpcode opCode)
		{
			m_OpCode = opCode;
		}
	};

	/// @class VlanFilter
	/// A class for filtering VLAN tagged packets by VLAN ID. When using this filter only packets tagged with VLAN which
	/// has the specific VLAN ID will be received
	///
	/// For deeper understanding of the filter concept please refer to PcapFilter.h
	class VlanFilter : public GeneralFilter
	{
	private:
		uint16_t m_VlanID;

	public:
		/// A constructor the gets the VLAN ID and creates the filter
		/// @param[in] vlanId The VLAN ID to use for the filter
		explicit VlanFilter(uint16_t vlanId) : m_VlanID(vlanId)
		{}

		void parseToString(std::string& result) override;

		/// Set the VLAN ID of the filter
		/// @param[in] vlanId The VLAN ID to use for the filter
		void setVlanID(uint16_t vlanId)
		{
			m_VlanID = vlanId;
		}
	};

	/// @class TcpFlagsFilter
	/// A class for filtering only TCP packets which certain TCP flags are set in them
	///
	/// For deeper understanding of the filter concept please refer to PcapFilter.h
	class TcpFlagsFilter : public GeneralFilter
	{
	public:
		/// An enum of all TCP flags that can be use in the filter
		enum TcpFlags
		{
			/// TCP FIN flag
			tcpFin = 1,
			/// TCP SYN flag
			tcpSyn = 2,
			/// TCP RST flag
			tcpRst = 4,
			/// TCP PSH flag
			tcpPush = 8,
			/// TCP ACK flag
			tcpAck = 16,
			/// TCP URG flag
			tcpUrg = 32
		};

		/// An enum for representing 2 type of matches: match only packets that contain all flags defined in the filter
		/// or match packets that contain at least one of the flags defined in the filter
		enum MatchOptions
		{
			/// Match only packets that contain all flags defined in the filter
			MatchAll,
			/// Match packets that contain at least one of the flags defined in the filter
			MatchOneAtLeast
		};

	private:
		uint8_t m_TcpFlagsBitMask;
		MatchOptions m_MatchOption;

	public:
		/// A constructor that gets a 1-byte bitmask containing all TCP flags participating in the filter and the match
		/// option, and creates the filter
		/// @param[in] tcpFlagBitMask A 1-byte bitmask containing all TCP flags participating in the filter. This
		/// parameter can contain the following value for example: TcpFlagsFilter::tcpSyn | TcpFlagsFilter::tcpAck |
		/// TcpFlagsFilter::tcpUrg
		/// @param[in] matchOption The match option: TcpFlagsFilter::MatchAll or TcpFlagsFilter::MatchOneAtLeast
		TcpFlagsFilter(uint8_t tcpFlagBitMask, MatchOptions matchOption)
		    : m_TcpFlagsBitMask(tcpFlagBitMask), m_MatchOption(matchOption)
		{}

		/// Set the TCP flags and the match option
		/// @param[in] tcpFlagBitMask A 1-byte bitmask containing all TCP flags participating in the filter. This
		/// parameter can contain the following value for example: TcpFlagsFilter::tcpSyn | TcpFlagsFilter::tcpAck |
		/// TcpFlagsFilter::tcpUrg
		/// @param[in] matchOption The match option: TcpFlagsFilter::MatchAll or TcpFlagsFilter::MatchOneAtLeast
		void setTcpFlagsBitMask(uint8_t tcpFlagBitMask, MatchOptions matchOption)
		{
			m_TcpFlagsBitMask = tcpFlagBitMask;
			m_MatchOption = matchOption;
		}

		void parseToString(std::string& result) override;
	};

	/// @class TcpWindowSizeFilter
	/// A class for filtering TCP packets that matches TCP window-size criteria.
	///
	/// For deeper understanding of the filter concept please refer to PcapFilter.h
	class TcpWindowSizeFilter : public IFilterWithOperator
	{
	private:
		uint16_t m_WindowSize;

	public:
		/// A constructor that get the window-size and operator and creates the filter. For example: "filter all TCP
		/// packets with window-size less than 1000"
		/// @param[in] windowSize The window-size value that will be used in the filter
		/// @param[in] op The operator to use (e.g "equal", "greater than", etc.)
		TcpWindowSizeFilter(uint16_t windowSize, FilterOperator op) : IFilterWithOperator(op), m_WindowSize(windowSize)
		{}

		void parseToString(std::string& result) override;

		/// Set window-size value
		/// @param[in] windowSize The window-size value that will be used in the filter
		void setWindowSize(uint16_t windowSize)
		{
			m_WindowSize = windowSize;
		}
	};

	/// @class UdpLengthFilter
	/// A class for filtering UDP packets that matches UDP length criteria.
	///
	/// For deeper understanding of the filter concept please refer to PcapFilter.h
	class UdpLengthFilter : public IFilterWithOperator
	{
	private:
		uint16_t m_Length;

	public:
		/// A constructor that get the UDP length and operator and creates the filter. For example: "filter all UDP
		/// packets with length greater or equal to 500"
		/// @param[in] length The length value that will be used in the filter
		/// @param[in] op The operator to use (e.g "equal", "greater than", etc.)
		UdpLengthFilter(uint16_t length, FilterOperator op) : IFilterWithOperator(op), m_Length(length)
		{}

		void parseToString(std::string& result) override;

		/// Set length value
		/// @param[in] length The length value that will be used in the filter
		void setLength(uint16_t length)
		{
			m_Length = length;
		}
	};
}  // namespace pcpp
