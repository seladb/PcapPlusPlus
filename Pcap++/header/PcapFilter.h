#ifndef PCAPP_FILTER
#define PCAPP_FILTER

#include <string>
#include <vector>
#include "ProtocolType.h"
#include <stdint.h>
#include "ArpLayer.h"

/**
 * @file
 * Most packet capture engines contain packet filtering capabilities. In order to set the filters there should be a known syntax user can use.
 * The most popular syntax is Berkeley Packet Filter (BPF) - see more in here: http://en.wikipedia.org/wiki/Berkeley_Packet_Filter.
 * Detailed explanation of the syntax can be found here: http://www.tcpdump.org/manpages/pcap-filter.7.html.<BR>
 * The problem with BPF is that, for my opinion, the syntax is too complicated and too poorly documented. In addition the BPF filter compilers
 * may output syntax errors that are hard to understand. My experience with BPF was not good, so I decided to make the filters mechanism more
 * structured, easier to understand and less error-prone by creating classes that represent filters. Each possible filter phrase is represented
 * by a class. The filter, at the end, is that class.<BR>
 * For example: the filter "src host 1.1.1.1" will be represented by IPFilter instance; "dst port 80" will be represented by PortFilter, and
 * so on.<BR>
 * So what about complex filters that involve "and", "or"? There are also 2 classes: AndFilter and OrFilter that can store more filters (in a
 * composite idea) and connect them by "and" or "or". For example: "src host 1.1.1.1 and dst port 80" will be represented by an AndFilter that
 * h olds IPFilter and PortFilter inside it
 */

/**
* \namespace pcpp
* \brief The main namespace for the PcapPlusPlus lib
*/
namespace pcpp
{

	/**
	 * An enum that contains direction (source or destination)
	 */
	typedef enum
	{
		/** Source */
		SRC,
		/** Destination */
		DST,
		/** Source or destination */
		SRC_OR_DST
	} Direction;


	/**
	 * Supported operators enum
	 */
	typedef enum
	{
		/** Equals */
		EQUALS,
		/** Not equals */
		NOT_EQUALS,
		/** Greater than */
		GREATER_THAN,
		/** Greater or equal */
		GREATER_OR_EQUAL,
		/** Less than */
		LESS_THAN,
		/** Less or equal */
		LESS_OR_EQUAL
	} FilterOperator;


	/**
	 * @class GeneralFilter
	 * The base class for all filter classes. This class is virtual and abstract, hence cannot be instantiated.<BR>
	 * For deeper understanding of the filter concept please refer to PcapFilter.h
	 */
	class GeneralFilter
	{
	public:
		/**
		 * A method that parses the class instance into BPF string format
		 * @param[out] result An empty string that the parsing will be written into. If the string isn't empty, its content will be overridden
		 */
		virtual void parseToString(std::string& result) = 0;

		/**
		 * Virtual destructor, does nothing for this class
		 */
		virtual ~GeneralFilter();
	};


	/**
	 * @class IFilterWithDirection
	 * An abstract class that is the base class for all filters which contain a direction (source or destination). This class cannot be instantiated<BR>
	 * For deeper understanding of the filter concept please refer to PcapFilter.h
	 */
	class IFilterWithDirection : public GeneralFilter
	{
	private:
		Direction m_Dir;
	protected:
		void parseDirection(std::string& directionAsString);
		inline Direction getDir() { return m_Dir; }
		IFilterWithDirection(Direction dir) { m_Dir = dir; }
	public:
		/**
		 * Set the direction for the filter (source or destination)
		 * @param[in] dir The direction
		 */
		void setDirection(Direction dir) { m_Dir = dir; }
	};


	/**
	 * @class IFilterWithOperator
	 * An abstract class that is the base class for all filters which contain an operator (e.g X equals Y; A is greater than B; Z1 not equals Z2, etc.).
	 * This class cannot be instantiated<BR>
	 * For deeper understanding of the filter concept please refer to PcapFilter.h
	 */
	class IFilterWithOperator : public GeneralFilter
	{
	private:
		FilterOperator m_Operator;
	protected:
		std::string parseOperator();
		inline FilterOperator getOperator() { return m_Operator; }
		IFilterWithOperator(FilterOperator op) { m_Operator = op; }
	public:
		/**
		 * Set the operator for the filter
		 * @param[in] op The operator to set
		 */
		void setOperator(FilterOperator op) { m_Operator = op; }
	};



	/**
	 * @class IPFilter
	 * A class for representing IPv4 address filter, equivalent to "net src x.x.x.x" or "net dst x.x.x.x"<BR>
	 * For deeper understanding of the filter concept please refer to PcapFilter.h
	 * @todo Add IPv6 filtering support
	 */
	class IPFilter : public IFilterWithDirection
	{
	private:
		std::string m_Address;
		std::string m_IPv4Mask;
		int m_Len;
		void convertToIPAddressWithMask(std::string& ipAddrmodified, std::string& mask);
		void convertToIPAddressWithLen(std::string& ipAddrmodified, int& len);
	public:
		/**
		 * The basic constructor that creates the filter from an IPv4 address and direction (source or destination)
		 * @param[in] ipAddress The IPv4 address to build the filter with. If this address is not a valid IPv4 address an error will be
		 * written to log and parsing this filter will fail
		 * @param[in] dir The address direction to filter (source or destination)
		 */
		IPFilter(const std::string& ipAddress, Direction dir) : IFilterWithDirection(dir), m_Address(ipAddress), m_IPv4Mask(""), m_Len(0) {}

		/**
		 * A constructor that enable to filter only part of the address by using a mask (aka subnet). For example: "filter only IP addresses that matches
		 * the subnet 10.0.0.x"
		 * @param[in] ipAddress The IPv4 address to use. Only the part of the address that is not masked will be matched. For example: if the address
		 * is "1.2.3.4" and the mask is "255.255.255.0" than the part of the address that will be matched is "1.2.3.X". If this address is not a
		 * valid IPv4 address an error will be written to log and parsing this filter will fail
		 * @param[in] dir The address direction to filter (source or destination)
		 * @param[in] ipv4Mask The mask to use. Mask should also be in a valid IPv4 format (i.e x.x.x.x), otherwise parsing this filter will fail
		 */
		IPFilter(const std::string& ipAddress, Direction dir, const std::string& ipv4Mask) : IFilterWithDirection(dir), m_Address(ipAddress), m_IPv4Mask(ipv4Mask), m_Len(0) {}

		/**
		 * A constructor that enables to filter by a subnet. For example: "filter only IP addresses that matches the subnet 10.0.0.3/24" which means
		 * the part of the address that will be matched is "10.0.0.X"
		 * @param[in] ipAddress The IPv4 address to use. Only the part of the address that is not masked will be matched. For example: if the address
		 * is "1.2.3.4" and the subnet is "/24" than the part of the address that will be matched is "1.2.3.X". If this address is not a
		 * valid IPv4 address an error will be written to log and parsing this filter will fail
		 * @param[in] dir The address direction to filter (source or destination)
		 * @param[in] len The subnet to use (e.g "/24")
		 */
		IPFilter(const std::string& ipAddress, Direction dir, int len) : IFilterWithDirection(dir), m_Address(ipAddress), m_IPv4Mask(""), m_Len(len) {}

		void parseToString(std::string& result);

		/**
		 * Set the IPv4 address
		 * @param[in] ipAddress The IPv4 address to build the filter with. If this address is not a valid IPv4 address an error will be
		 * written to log and parsing this filter will fail
		 */
		void setAddr(const std::string& ipAddress) { m_Address = ipAddress; }

		/**
		 * Set the IPv4 mask
		 * @param[in] ipv4Mask The mask to use. Mask should also be in a valid IPv4 format (i.e x.x.x.x), otherwise parsing this filter will fail
		 */
		void setMask(const std::string& ipv4Mask) { m_IPv4Mask = ipv4Mask; m_Len = 0; }

		/**
		 * Set the subnet
		 * @param[in] len The subnet to use (e.g "/24")
		 */
		void setLen(int len) { m_IPv4Mask = ""; m_Len = len; }
	};



	/**
	 * @class IpV4IDFilter
	 * A class for filtering IPv4 traffic by IP ID field of the IPv4 protocol, For example:
	 * "filter only IPv4 traffic which IP ID is greater than 1234"<BR>
	 * For deeper understanding of the filter concept please refer to PcapFilter.h
	 */
	class IpV4IDFilter : public IFilterWithOperator
	{
	private:
		uint16_t m_IpID;
	public:
		/**
		 * A constructor that gets the IP ID to filter and the operator and creates the filter out of them
		 * @param[in] ipID The IP ID to filter
		 * @param[in] op The operator to use (e.g "equal", "greater than", etc.)
		 */
		IpV4IDFilter(uint16_t ipID, FilterOperator op) : IFilterWithOperator(op), m_IpID(ipID) {}

		void parseToString(std::string& result);

		/**
		 * Set the IP ID to filter
		 * @param[in] ipID The IP ID to filter
		 */
		void setIpID(uint16_t ipID) { m_IpID = ipID; }
	};



	/**
	 * @class IpV4TotalLengthFilter
	 * A class for filtering IPv4 traffic by "total length" field of the IPv4 protocol, For example:
	 * "filter only IPv4 traffic which "total length" value is less than 60B"<BR>
	 * For deeper understanding of the filter concept please refer to PcapFilter.h
	 */
	class IpV4TotalLengthFilter : public IFilterWithOperator
	{
	private:
		uint16_t m_TotalLength;
	public:
		/**
		 * A constructor that gets the total length to filter and the operator and creates the filter out of them
		 * @param[in] totalLength The total length value to filter
		 * @param[in] op The operator to use (e.g "equal", "greater than", etc.)
		 */
		IpV4TotalLengthFilter(uint16_t totalLength, FilterOperator op) : IFilterWithOperator(op), m_TotalLength(totalLength) {}

		void parseToString(std::string& result);

		/**
		 * Set the total length value
		 * @param[in] totalLength The total length value to filter
		 */
		void setTotalLength(uint16_t totalLength) { m_TotalLength = totalLength; }
	};



	/**
	 * @class PortFilter
	 * A class for filtering TCP or UDP traffic by port, for example: "dst port 80" or "src port 12345"<BR>
	 * For deeper understanding of the filter concept please refer to PcapFilter.h
	 */
	class PortFilter : public IFilterWithDirection
	{
	private:
		std::string m_Port;
		void portToString(uint16_t portAsInt);
	public:
		/**
		 * A constructor that gets the port and the direction and creates the filter
		 * @param[in] port The port to create the filter with
		 * @param[in] dir The port direction to filter (source or destination)
		 */
		PortFilter(uint16_t port, Direction dir);

		void parseToString(std::string& result);

		/**
		 * Set the port
		 * @param[in] port The port to create the filter with
		 */
		void setPort(uint16_t port) { portToString(port); }
	};



	/**
	 * @class PortRangeFilter
	 * A class for filtering TCP or UDP port ranges, meaning match only packets which port is within this range, for example: "src portrange 1000-2000"
	 * will match only TCP or UDP traffic which source port is in the range of 1000 - 2000<BR>
	 * For deeper understanding of the filter concept please refer to PcapFilter.h
	 */
	class PortRangeFilter : public IFilterWithDirection
	{
	private:
		uint16_t m_FromPort;
		uint16_t m_ToPort;
	public:
		/**
		 * A constructor that gets the port range the the direction and creates the filter with them
		 * @param[in] fromPort The lower end of the port range
		 * @param[in] toPort The higher end of the port range
		 * @param[in] dir The port range direction to filter (source or destination)
		 */
		PortRangeFilter(uint16_t fromPort, uint16_t toPort, Direction dir) : IFilterWithDirection(dir), m_FromPort(fromPort), m_ToPort(toPort) {}

		void parseToString(std::string& result);

		/**
		 * Set the lower end of the port range
		 * @param[in] fromPort The lower end of the port range
		 */
		void setFromPort(uint16_t fromPort) { m_FromPort = fromPort; }

		/**
		 * Set the higher end of the port range
		 * @param[in] toPort The higher end of the port range
		 */
		void setToPort(uint16_t toPort) { m_ToPort = toPort; }
	};



	/**
	 * @class MacAddressFilter
	 * A class for filtering Ethernet traffic by MAC addresses, for example: "ether src 12:34:56:78:90:12" or "ether dst "10:29:38:47:56:10:29"<BR>
	 * For deeper understanding of the filter concept please refer to PcapFilter.h
	 */
	class MacAddressFilter : public IFilterWithDirection
	{
	private:
		MacAddress m_MacAddress;
	public:
		/**
		 * A constructor that gets the MAC address and the direction and creates the filter with them
		 * @param[in] address The MAC address to use for filtering
		 * @param[in] dir The MAC address direction to filter (source or destination)
		 */
		MacAddressFilter(MacAddress address, Direction dir) : IFilterWithDirection(dir), m_MacAddress(address) {}

		void parseToString(std::string& result);

		/**
		 * Set the MAC address
		 * @param[in] address The MAC address to use for filtering
		 */
		void setMacAddress(MacAddress address) { m_MacAddress = address; }
	};



	/**
	 * @class EtherTypeFilter
	 * A class for filtering by EtherType field of the Ethernet protocol. This enables to filter packets from certain protocols, such as ARP, IPv4,
	 * IPv6, VLAN tags, etc.<BR>
	 * For deeper understanding of the filter concept please refer to PcapFilter.h
	 */
	class EtherTypeFilter : public GeneralFilter
	{
	private:
		uint16_t m_EtherType;
	public:
		/**
		 * A constructor that gets the EtherType and creates the filter with it
		 * @param[in] etherType The EtherType value to create the filter with
		 */
		EtherTypeFilter(uint16_t etherType) : m_EtherType(etherType) {}

		void parseToString(std::string& result);

		/**
		 * Set the EtherType value
		 * @param[in] etherType The EtherType value to create the filter with
		 */
		void setEtherType(uint16_t etherType) { m_EtherType = etherType; }
	};



	/**
	 * @class AndFilter
	 * A class for connecting several filters into one filter with logical "and" between them. For example: if the 2 filters are: "IPv4 address =
	 * x.x.x.x" + "TCP port dst = 80", then the new filter will be: "IPv4 address = x.x.x.x _AND_ TCP port dst = 80"<BR>
	 * This class follows the composite design pattern<BR>
	 * For deeper understanding of the filter concept please refer to PcapFilter.h
	 * @todo add some methods: "addFilter", "removeFilter", "clearAllFilter"
	 */
	class AndFilter : public GeneralFilter
	{
	private:
		std::vector<GeneralFilter*> m_FilterList;
	public:

		/**
		 * An empty constructor for this class. Use addFilter() to add filters to the and condition
		 */
		AndFilter() {}

		/**
		 * A constructor that gets a list of pointers to filters and creates one filter from all filters with logical "and" between them
		 * @param[in] filters The list of pointers to filters
		 */
		AndFilter(std::vector<GeneralFilter*>& filters);

		/**
		 * Add filter to the and condition
		 * @param[in] filter The filter to add
		 */
		void addFilter(GeneralFilter* filter) { m_FilterList.push_back(filter); }

		void parseToString(std::string& result);
	};



	/**
	 * @class OrFilter
	 * A class for connecting several filters into one filter with logical "or" between them. For example: if the 2 filters are: "IPv4 address =
	 * x.x.x.x" + "TCP port dst = 80", then the new filter will be: "IPv4 address = x.x.x.x _OR_ TCP port dst = 80"<BR>
	 * This class follows the composite design pattern<BR>
	 * For deeper understanding of the filter concept please refer to PcapFilter.h
	 * @todo add some methods: "addFilter", "removeFilter", "clearAllFilter"
	 */
	class OrFilter : public GeneralFilter
	{
	private:
		std::vector<GeneralFilter*> m_FilterList;
	public:

		/**
		 * An empty constructor for this class. Use addFilter() to add filters to the or condition
		 */
		OrFilter() {}

		/**
		 * A constructor that gets a list of pointers to filters and creates one filter from all filters with logical "or" between them
		 * @param[in] filters The list of pointers to filters
		 */
		OrFilter(std::vector<GeneralFilter*>& filters);

		/**
		 * Add filter to the or condition
		 * @param[in] filter The filter to add
		 */
		void addFilter(GeneralFilter* filter) { m_FilterList.push_back(filter); }

		void parseToString(std::string& result);
	};



	/**
	 * @class NotFilter
	 * A class for creating a filter which is inverse to another filter<BR>
	 * For deeper understanding of the filter concept please refer to PcapFilter.h
	 */
	class NotFilter : public GeneralFilter
	{
	private:
		GeneralFilter* m_FilterToInverse;
	public:
		/**
		 * A constructor that gets a pointer to a filter and create the inverse version of it
		 * @param[in] filterToInverse A pointer to filter which the created filter be the inverse of
		 */
		NotFilter(GeneralFilter* filterToInverse) { m_FilterToInverse = filterToInverse; }

		void parseToString(std::string& result);

		/**
		 * Set a filter to create an inverse filter from
		 * @param[in] filterToInverse A pointer to filter which the created filter be the inverse of
		 */
		void setFilter(GeneralFilter* filterToInverse) { m_FilterToInverse = filterToInverse; }
	};



	/**
	 * @class ProtoFilter
	 * A class for filtering traffic by protocol. Notice not all protocols are supported, only the following are supported:
	 * ::TCP, ::UDP, ::ICMP, ::VLAN, ::IPv4, ::IPv6, ::ARP, ::Ethernet. <BR>
	 * For deeper understanding of the filter concept please refer to PcapFilter.h
	 */
	class ProtoFilter : public GeneralFilter
	{
	private:
		ProtocolType m_Proto;
	public:
		/**
		 * A constructor that gets the protocol and creates the filter
		 * @param[in] proto The protocol to filter, only packets matching this protocol will be received. Please note not all protocols are
		 * supported. List of supported protocols is found in the class description
		 */
		ProtoFilter(ProtocolType proto) { m_Proto = proto; }

		void parseToString(std::string& result);

		/**
		 * Set the protocol to filter with
		 * @param[in] proto The protocol to filter, only packets matching this protocol will be received. Please note not all protocols are
		 * supported. List of supported protocols is found in the class description
		 */
		void setProto(ProtocolType proto) { m_Proto = proto; }
	};



	/**
	 * @class ArpFilter
	 * A class for filtering ARP packets according the ARP opcode. When using this filter only ARP packets with the relevant opcode will be
	 * received <BR>
	 * For deeper understanding of the filter concept please refer to PcapFilter.h
	 */
	class ArpFilter : public GeneralFilter
	{
	private:
		ArpOpcode m_OpCode;
	public:
		/**
		 * A constructor that get the ARP opcode and creates the filter
		 * @param[in] opCode The ARP opcode: ::ARP_REQUEST or ::ARP_REPLY
		 */
		ArpFilter(ArpOpcode opCode) { m_OpCode = opCode; }

		void parseToString(std::string& result);

		/**
		 * Set the ARP opcode
		 * @param[in] opCode The ARP opcode: ::ARP_REQUEST or ::ARP_REPLY
		 */
		void setOpCode(ArpOpcode opCode) { m_OpCode = opCode; }
	};



	/**
	 * @class VlanFilter
	 * A class for filtering VLAN tagged packets by VLAN ID. When using this filter only packets tagged with VLAN which has the specific VLAN ID
	 * will be received <BR>
	 * For deeper understanding of the filter concept please refer to PcapFilter.h
	 */
	class VlanFilter : public GeneralFilter
	{
	private:
		uint16_t m_VlanID;
	public:
		/**
		 * A constructor the gets the VLAN ID and creates the filter
		 * @param[in] vlanId The VLAN ID to use for the filter
		 */
		VlanFilter(uint16_t vlanId) : m_VlanID(vlanId) {}

		void parseToString(std::string& result);

		/**
		 * Set the VLAN ID of the filter
		 * @param[in] vlanId The VLAN ID to use for the filter
		 */
		void setVlanID(uint16_t vlanId) { m_VlanID = vlanId; }
	};



	/**
	 * @class TcpFlagsFilter
	 * A class for filtering only TCP packets which certain TCP flags are set in them <BR>
	 * For deeper understanding of the filter concept please refer to PcapFilter.h
	 */
	class TcpFlagsFilter : public GeneralFilter
	{
	public:
		/**
		 * An enum of all TCP flags that can be use in the filter
		 */
		enum TcpFlags
		{
			/** TCP FIN flag */
			tcpFin = 1,
			/** TCP SYN flag */
			tcpSyn = 2,
			/** TCP RST flag */
			tcpRst = 4,
			/** TCP PSH flag */
			tcpPush = 8,
			/** TCP ACK flag */
			tcpAck = 16,
			/** TCP URG flag */
			tcpUrg = 32
		};

		/**
		 * An enum for representing 2 type of matches: match only packets that contain all flags defined in the filter or match packets that
		 * contain at least one of the flags defined in the filter
		 */
		enum MatchOptions
		{
			/** Match only packets that contain all flags defined in the filter */
			MatchAll,
			/** Match packets that contain at least one of the flags defined in the filter */
			MatchOneAtLeast
		};
	private:
		uint8_t m_TcpFlagsBitMask;
		MatchOptions m_MatchOption;
	public:
		/**
		 * A constructor that gets a 1-byte bitmask containing all TCP flags participating in the filter and the match option, and
		 * creates the filter
		 * @param[in] tcpFlagBitMask A 1-byte bitmask containing all TCP flags participating in the filter. This parameter can contain the
		 * following value for example: TcpFlagsFilter::tcpSyn | TcpFlagsFilter::tcpAck | TcpFlagsFilter::tcpUrg
		 * @param[in] matchOption The match option: TcpFlagsFilter::MatchAll or TcpFlagsFilter::MatchOneAtLeast
		 */
		TcpFlagsFilter(uint8_t tcpFlagBitMask, MatchOptions matchOption) : m_TcpFlagsBitMask(tcpFlagBitMask), m_MatchOption(matchOption) {}

		/**
		 * Set the TCP flags and the match option
		 * @param[in] tcpFlagBitMask A 1-byte bitmask containing all TCP flags participating in the filter. This parameter can contain the
		 * following value for example: TcpFlagsFilter::tcpSyn | TcpFlagsFilter::tcpAck | TcpFlagsFilter::tcpUrg
		 * @param[in] matchOption The match option: TcpFlagsFilter::MatchAll or TcpFlagsFilter::MatchOneAtLeast
		 */
		void setTcpFlagsBitMask(uint8_t tcpFlagBitMask, MatchOptions matchOption) { m_TcpFlagsBitMask = tcpFlagBitMask; m_MatchOption = matchOption; }

		void parseToString(std::string& result);
	};



	/**
	 * @class TcpWindowSizeFilter
	 * A class for filtering TCP packets that matches TCP window-size criteria <BR>
	 * For deeper understanding of the filter concept please refer to PcapFilter.h
	 */
	class TcpWindowSizeFilter : public IFilterWithOperator
	{
	private:
		uint16_t m_WindowSize;
	public:
		/**
		 * A constructor that get the window-size and operator and creates the filter. For example: "filter all TCP packets with window-size
		 * less than 1000"
		 * @param[in] windowSize The window-size value that will be used in the filter
		 * @param[in] op The operator to use (e.g "equal", "greater than", etc.)
		 */
		TcpWindowSizeFilter(uint16_t windowSize, FilterOperator op) : IFilterWithOperator(op), m_WindowSize(windowSize) {}

		void parseToString(std::string& result);

		/**
		 * Set window-size value
		 * @param[in] windowSize The window-size value that will be used in the filter
		 */
		void setWindowSize(uint16_t windowSize) { m_WindowSize = windowSize; }
	};



	/**
	 * @class UdpLengthFilter
	 * A class for filtering UDP packets that matches UDP length criteria <BR>
	 * For deeper understanding of the filter concept please refer to PcapFilter.h
	 */
	class UdpLengthFilter : public IFilterWithOperator
	{
	private:
		uint16_t m_Length;
	public:
		/**
		 * A constructor that get the UDP length and operator and creates the filter. For example: "filter all UDP packets with length
		 * greater or equal to 500"
		 * @param[in] legnth The length value that will be used in the filter
		 * @param[in] op The operator to use (e.g "equal", "greater than", etc.)
		 */
		UdpLengthFilter(uint16_t legnth, FilterOperator op) : IFilterWithOperator(op), m_Length(legnth) {}

		void parseToString(std::string& result);

		/**
		 * Set legnth value
		 * @param[in] legnth The legnth value that will be used in the filter
		 */
		void setLength(uint16_t legnth) { m_Length = legnth; }
	};

} // namespace pcpp

#endif
