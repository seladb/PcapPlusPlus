#pragma once

#include "Splitters.h"
#include "PacketUtils.h"
#include "SystemUtils.h"


/**
 * A virtual abstract class for all splitters that split files by IP address or TCP/UDP port. Inherits from ValueBasedSplitter,
 * so it already contains a mapping of IP/port to file number, a flow table, and supports max number of files or undefined
 * number of files. This class arranges packets by TCP/UDP flows and for each flow lets the inherited classes determine
 * to which file number this flow will be matched
 */
class IPPortSplitter : public ValueBasedSplitter
{
public:

	/**
	 * C'tor for this class, does nothing but calling its ancestor
	 */
	IPPortSplitter(int maxFiles) : ValueBasedSplitter(maxFiles) {}

	/**
	 * Implements Splitter's abstract method. This method takes a packet and decides to which flow it belongs to (can
	 * be an existing flow or a new flow). When opening new flows it uses a virtual abstract method that should be
	 * Implemented by inherited classes to determine to which file number the flow will be written to
	 */
	int getFileNumber(pcpp::Packet& packet, std::vector<int>& filesToClose)
	{
		// if it's not a TCP or UDP packet, put it in file #0
		if (!packet.isPacketOfType(pcpp::TCP) && !packet.isPacketOfType(pcpp::UDP))
		{
			return 0;
		}

		// hash the 5-tuple and look for it in the flow table
		uint32_t hash = pcpp::hash5Tuple(&packet);

		if (m_FlowTable.find(hash) != m_FlowTable.end())
		{
			writingToFile(m_FlowTable[hash], filesToClose);

			// if found it, follow the file number written in the hash record
			return m_FlowTable[hash];
		}

		// if it's the first packet seen on this flow, try to guess the server port

		if (packet.isPacketOfType(pcpp::TCP))
		{
			// extract TCP layer
			pcpp::TcpLayer* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
			if (tcpLayer != NULL)
			{
				uint16_t srcPort = tcpLayer->getSrcPort();
				uint16_t dstPort = tcpLayer->getDstPort();

				if (tcpLayer->getTcpHeader()->synFlag)
				{
					// SYN packet
					if (!tcpLayer->getTcpHeader()->ackFlag)
					{
						m_FlowTable[hash] = getFileNumberForValue(getValue(packet, SYN, srcPort, dstPort), filesToClose);
						return m_FlowTable[hash];
					}
					// SYN/ACK packet
					else
					{
						m_FlowTable[hash] = getFileNumberForValue(getValue(packet, SYN_ACK, srcPort, dstPort), filesToClose);
						return m_FlowTable[hash];
					}
				}
				// Other TCP packet
				else
				{
					m_FlowTable[hash] = getFileNumberForValue(getValue(packet, TCP_OTHER, srcPort, dstPort), filesToClose);
					return m_FlowTable[hash];
				}
			}
		}

		else if (packet.isPacketOfType(pcpp::UDP))
		{
			// for UDP packets, decide the server port by the lower port
			pcpp::UdpLayer* udpLayer = packet.getLayerOfType<pcpp::UdpLayer>();
			if (udpLayer != NULL)
			{
				uint16_t srcPort = udpLayer->getSrcPort();
				uint16_t dstPort = udpLayer->getDstPort();
				m_FlowTable[hash] = getFileNumberForValue(getValue(packet, UDP, srcPort, dstPort), filesToClose);
				return m_FlowTable[hash];
			}
		}

		// if reached here, return 0
		writingToFile(0, filesToClose);
		return 0;
	}


	/**
	 * Re-implement Splitter's getFileName() method, this time with the IP/port value
	 */
	std::string getFileName(pcpp::Packet& packet, const std::string &outputPcapBasePath, int fileNumber)
	{
		// first set the base string as the outputPcapBasePath
		std::string result = outputPcapBasePath;

		// if it's not a TCP or UDP packet, put it in file #0
		if (!packet.isPacketOfType(pcpp::TCP) && !packet.isPacketOfType(pcpp::UDP))
		{
			return result + "miscellaneous";
		}

		if (packet.isPacketOfType(pcpp::TCP))
		{
			// extract TCP layer
			pcpp::TcpLayer* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
			if (tcpLayer != NULL)
			{
				uint16_t srcPort = tcpLayer->getSrcPort();
				uint16_t dstPort = tcpLayer->getDstPort();

				if (tcpLayer->getTcpHeader()->synFlag)
				{
					// SYN packet
					if (!tcpLayer->getTcpHeader()->ackFlag)
					{
						return result + getValueString(packet, SYN, srcPort, dstPort);
					}
					// SYN/ACK packet
					else
					{
						return result + getValueString(packet, SYN_ACK, srcPort, dstPort);
					}
				}
				// Other TCP packet
				else
				{
					return result + getValueString(packet, TCP_OTHER, srcPort, dstPort);
				}
			}
		}

		else if (packet.isPacketOfType(pcpp::UDP))
		{
			// for UDP packets, decide the server port by the lower port
			pcpp::UdpLayer* udpLayer = packet.getLayerOfType<pcpp::UdpLayer>();
			if (udpLayer != NULL)
			{
				uint16_t srcPort = udpLayer->getSrcPort();
				uint16_t dstPort = udpLayer->getDstPort();
				return result + getValueString(packet, UDP, srcPort, dstPort);
			}
		}

		// if reached here, return 'miscellaneous'
		return result + "miscellaneous";
	}

protected:

	/**
	 * An enum for TCP/UDP packet type: can be either TCP-SYN, TCP-SYN/ACK, Other TCP packet of UDP packet
	 */
	enum PacketType
	{
		SYN,
		SYN_ACK,
		TCP_OTHER,
		UDP
	};

	/**
	 * This is the virtual abstract method that needs to be implemented by inherited classes. It gets the packet,
	 * the packet type, and the source and dest ports and should return the value by which file will be split.
	 * For example: if files should be split by client IP, this method should extract the client IP and return it as
	 * uint32_t value, or if files should be split by server port, this method should extract the server port and
	 * return it as uint32_t value
	 */
	virtual uint32_t getValue(pcpp::Packet& packet, PacketType packetType, uint16_t srcPort, uint16_t dstPort) = 0;

	/**
	 * This is a virtual abstract method that needs to be implemented by inherited classes. It gets the packet,
	 * packet type, src and dest ports and return the value by which the file will be split, but in its string format.
	 * For example: if the file is split by client-ip the expected result is the client-ip string ("a.b.c.d")
	 */
	virtual std::string getValueString(pcpp::Packet& packet, PacketType packetType, uint16_t srcPort, uint16_t dstPort) = 0;

	/**
	 * An auxiliary method for extracting packet's IPv4/IPv6 source address hashed as 4 bytes uint32_t value
	 */
	uint32_t getSrcIPValue(pcpp::Packet& packet)
	{
		if (packet.isPacketOfType(pcpp::IPv4))
			return packet.getLayerOfType<pcpp::IPv4Layer>()->getSrcIPv4Address().toInt();
		else if (packet.isPacketOfType(pcpp::IPv6))
			return pcpp::fnvHash((uint8_t*)packet.getLayerOfType<pcpp::IPv6Layer>()->getSrcIPv6Address().toBytes(), 16);
		else
			return 0;
	}

	/**
	 * An auxiliary method for extracting packet's IPv4/IPv6 dest address hashed as 4 bytes uint32_t value
	 */
	uint32_t getDstIPValue(pcpp::Packet& packet)
	{
		if (packet.isPacketOfType(pcpp::IPv4))
			return packet.getLayerOfType<pcpp::IPv4Layer>()->getDstIPv4Address().toInt();
		else if (packet.isPacketOfType(pcpp::IPv6))
			return pcpp::fnvHash((uint8_t*)packet.getLayerOfType<pcpp::IPv6Layer>()->getDstIPv6Address().toBytes(), 16);
		else
			return 0;
	}

	/**
	 * An auxiliary method for extracting packet's IPv4/IPv6 source address as string
	 */
	std::string getSrcIPString(pcpp::Packet& packet)
	{
		if (packet.isPacketOfType(pcpp::IP))
			return packet.getLayerOfType<pcpp::IPLayer>()->getSrcIPAddress().toString();
		return "miscellaneous";
	}

	/**
	 * An auxiliary method for extracting packet's IPv4/IPv6 dest address string
	 */
	std::string getDstIPString(pcpp::Packet& packet)
	{
		if (packet.isPacketOfType(pcpp::IP))
			return packet.getLayerOfType<pcpp::IPLayer>()->getDstIPAddress().toString();
		return "miscellaneous";
	}

	/**
	 * An auxiliary method to indicate whether an IPv4/IPv6 source address is multicast or not
	 */
	bool isSrcIPMulticast(pcpp::Packet& packet)
	{
		if (packet.isPacketOfType(pcpp::IP))
			return packet.getLayerOfType<pcpp::IPLayer>()->getSrcIPAddress().isMulticast();
		return false;
	}

	/**
	 * An auxiliary method to indicate whether an IPv4/IPv6 dest address is multicast or not
	 */
	bool isDstIPMulticast(pcpp::Packet& packet)
	{
		if (packet.isPacketOfType(pcpp::IP))
			return packet.getLayerOfType<pcpp::IPLayer>()->getDstIPAddress().isMulticast();
		return false;
	}

	/**
	 * An auxiliary method for replacing '.' and ':' in IPv4/IPv6 addresses with '-'
	 */
	std::string hyphenIP(std::string ipVal)
	{
		// for IPv4 - replace '.' with '-'
		int loc = ipVal.find(".");
		while (loc >= 0)
		{
			ipVal.replace(loc, 1, "-");
			loc = ipVal.find(".");
		}

		// for IPv6 - replace ':' with '-'
		loc = ipVal.find(":");
		while (loc >= 0)
		{
			ipVal.replace(loc, 1, "-");
			loc = ipVal.find(":");
		}

		return ipVal;
	}
};



/**
 * Splits a pcap file by client IP. This means that all flows with a certain client IP will be written to the same
 * file. The client IP for each flow is determined as follows: 1) if it's a TCP flow and we have the SYN packet - the
 * client IP is the source IP of the SYN packet 2) if it's a TCP flow and we only have the SYN/ACK packet - the
 * client IP is the dest IP of the SYN/ACK packet 3) if it's a partial TCP flow and don't have the SYN or SYN/ACK packets,
 * the client IP will be determined by the port: the higher port is considered the client side 4) if it's a UDP multicast
 * flow - the client IP will be determined by the port: the port corresponding to the multicast address is the client side
 * 5) If it's a non-multicast UDP flow - the client IP will be determined by the port: the higher port is considered the
 * client side
 */
class ClientIPSplitter : public IPPortSplitter
{
public:

	/**
	 * C'tor for this class, does nothing but calling its ancestor
	 */
	explicit ClientIPSplitter(int maxFiles) : IPPortSplitter(maxFiles) {}

protected:

	/**
	 * Implementation of the abstract method of IPPortSplitter. This method returns the client IP for a certain flow
	 * by the logic written at the description of this class
	 */
	uint32_t getValue(pcpp::Packet& packet, PacketType packetType, uint16_t srcPort, uint16_t dstPort)
	{
		switch (packetType)
		{
		case SYN:
			return getSrcIPValue(packet);
		case SYN_ACK:
			return getDstIPValue(packet);
		case UDP:
			if(isSrcIPMulticast(packet)) return getSrcIPValue(packet);
			else if(isDstIPMulticast(packet)) return getDstIPValue(packet);
			else return srcPort >= dstPort ? getSrcIPValue(packet) : getDstIPValue(packet);
		// other TCP packet
		default:
			if (srcPort >= dstPort)
				return getSrcIPValue(packet);
			else
				return getDstIPValue(packet);
		}
	}

	std::string getValueString(pcpp::Packet& packet, PacketType packetType, uint16_t srcPort, uint16_t dstPort)
	{
		std::string prefix = "client-ip-";

		switch (packetType)
		{
		case SYN:
			return prefix + hyphenIP(getSrcIPString(packet));
		case SYN_ACK:
			return prefix + hyphenIP(getDstIPString(packet));
		case UDP:
			if(isSrcIPMulticast(packet)) return prefix + hyphenIP(getSrcIPString(packet));
			else if(isDstIPMulticast(packet)) return prefix + hyphenIP(getDstIPString(packet));
			else return srcPort >= dstPort ? prefix + hyphenIP(getSrcIPString(packet)) : prefix + hyphenIP(getDstIPString(packet));
		// other TCP packet
		default:
			if (srcPort >= dstPort)
				return prefix + hyphenIP(getSrcIPString(packet));
			else
				return prefix + hyphenIP(getDstIPString(packet));
		}
	}
};



/**
 * Splits a pcap file by server IP. This means that all flows with a certain server IP will be written to the same
 * file. The server IP for each flow is determined as follows: 1) if it's a TCP flow and we have the SYN packet - the
 * server IP is the dest IP of the SYN packet 2) if it's a TCP flow and we only have the SYN/ACK packet - the
 * server IP is the source IP of the SYN/ACK packet 3) if it's a partial TCP flow and don't have the SYN or SYN/ACK packets,
 * the server IP will be determined by the port: the lower port is considered the server side 4) if it's a multicast UDP flow -
 * the server IP will be determined by the port: the port corresponding to the non-multicast address is consdered as server side
 * 5) if i's a non-multicast UDP flow - the server IP will be determined by the port: the lower port is considered the
 * server side
 */
class ServerIPSplitter : public IPPortSplitter
{
public:

	/**
	 * C'tor for this class, does nothing but calling its ancestor
	 */
	explicit ServerIPSplitter(int maxFiles) : IPPortSplitter(maxFiles) {}

protected:

	/**
	 * Implementation of the abstract method of IPPortSplitter. This method returns the server IP for a certain flow
	 * by the logic written at the description of this class
	 */
	uint32_t getValue(pcpp::Packet& packet, PacketType packetType, uint16_t srcPort, uint16_t dstPort)
	{
		switch (packetType)
		{
		case SYN:
			return getDstIPValue(packet);
		case SYN_ACK:
			return getSrcIPValue(packet);
		case UDP:
			if(isSrcIPMulticast(packet)) return getDstIPValue(packet);
			else if(isDstIPMulticast(packet)) return getSrcIPValue(packet);
			else return srcPort >= dstPort ? getDstIPValue(packet) : getSrcIPValue(packet);
		// other TCP packet
		default:
			if (srcPort >= dstPort)
				return getDstIPValue(packet);
			else
				return getSrcIPValue(packet);
		}
	}

	std::string getValueString(pcpp::Packet& packet, PacketType packetType, uint16_t srcPort, uint16_t dstPort)
	{
		std::string prefix = "server-ip-";

		switch (packetType)
		{
		case SYN:
			return prefix + hyphenIP(getDstIPString(packet));
		case SYN_ACK:
			return prefix + hyphenIP(getSrcIPString(packet));
		case UDP:
			if(isSrcIPMulticast(packet)) return prefix + hyphenIP(getDstIPString(packet));
			else if(isDstIPMulticast(packet)) return prefix + hyphenIP(getSrcIPString(packet));
			else return srcPort >= dstPort ? prefix + hyphenIP(getDstIPString(packet)) : prefix + hyphenIP(getSrcIPString(packet));
		// other TCP packet
		default:
			if (srcPort >= dstPort)
				return prefix + hyphenIP(getDstIPString(packet));
			else
				return prefix + hyphenIP(getSrcIPString(packet));
		}
	}

};



/**
 * Splits a pcap file by server port (most of the time is similar to protocol). This means that all flows with a certain
 * server port will be written to the same file. The server port for each flow is determined as follows: 1) if it's a TCP
 * flow and we have the SYN packet - the server port is the dest port of the SYN packet 2) if it's a TCP flow and we only
 * have the SYN/ACK packet - the server port is the source port of the SYN/ACK packet 3) if it's a partial TCP flow and
 * we don't have the SYN or SYN/ACK packets, the server port will be determined by the port: the lower port is considered
 * the server side 4) if it's a UDP multicast flow - if the sourceIP is a multicast address, the dest port is considered
 * as a server port, otherwise if the destIP is a multicast address, the source port is considered as a server port 5) if
 * it's a UDP flow - the server port will be determined by the port: the lower port is considered as server port
 */
class ServerPortSplitter : public IPPortSplitter
{
public:

	/**
	 * C'tor for this class, does nothing but calling its ancestor
	 */
	explicit ServerPortSplitter(int maxFiles) : IPPortSplitter(maxFiles) {}

protected:

	/**
	 * Implementation of the abstract method of IPPortSplitter. This method returns the server port for a certain flow
	 * by the logic written at the description of this class
	 */
	uint32_t getValue(pcpp::Packet& packet, PacketType packetType, uint16_t srcPort, uint16_t dstPort)
	{
		switch (packetType)
		{
		case SYN:
			return dstPort;
		case SYN_ACK:
			return srcPort;
		case UDP:
			if(isSrcIPMulticast(packet)) return dstPort;
			else if(isDstIPMulticast(packet)) return srcPort;
			else return std::min<uint16_t>(srcPort, dstPort);
		// other TCP packet
		default:
			return std::min<uint16_t>(srcPort, dstPort);
		}
	}

	std::string getValueString(pcpp::Packet& packet, PacketType packetType, uint16_t srcPort, uint16_t dstPort)
	{
		std::string prefix = "server-port-";

		uint16_t res = 0;
		switch (packetType)
		{
		case SYN:
			res = dstPort;
			break;
		case SYN_ACK:
			res = srcPort;
			break;
		case UDP:
			if(isSrcIPMulticast(packet)) res = dstPort;
			else if(isDstIPMulticast(packet)) res = srcPort;
			else res = std::min<uint16_t>(srcPort, dstPort);
			 break;
		// other TCP packet
		default:
			res = std::min<uint16_t>(srcPort, dstPort);
			break;
		}

		std::ostringstream sstream;
		sstream << res;
		return prefix + sstream.str();
	}
};

/**
 * Splits a pcap file by server client (most of the time is similar to protocol). This means that all flows with a certain
 * client port will be written to the same file. The client port for each flow is determined as follows: 1) if it's a TCP
 * flow and we have the SYN packet - the client port is the source port of the SYN packet 2) if it's a TCP flow and we only
 * have the SYN/ACK packet - the client port is the dest port of the SYN/ACK packet 3) if it's a partial TCP flow and
 * we don't have the SYN or SYN/ACK packets, the server port will be determined by the port: the higher port is considered
 * the client side 4) if it's a UDP multicast flow - if the sourceIP is a multicast address, the source port is considered
 * as a client port, otherwise if the destIP is a multicast address, the dest port is considered as a client port 5) if
 * it's a UDP flow - the client port will be determined by the port: the higher port is considered as client port
 */
class ClientPortSplitter : public IPPortSplitter
{
public:

	/**
	 * C'tor for this class, does nothing but calling its ancestor
	 */
	explicit ClientPortSplitter(int maxFiles) : IPPortSplitter(maxFiles) {}

protected:

	/**
	 * Implementation of the abstract method of IPPortSplitter. This method returns the client port for a certain flow
	 * by the logic written at the description of this class
	 */
	uint32_t getValue(pcpp::Packet& packet, PacketType packetType, uint16_t srcPort, uint16_t dstPort)
	{
		switch (packetType)
		{
		case SYN:
			return srcPort;
		case SYN_ACK:
			return dstPort;
		case UDP:
			if(isSrcIPMulticast(packet)) return srcPort;
			else if(isDstIPMulticast(packet)) return dstPort;
			else return std::max<uint16_t>(srcPort, dstPort);
		// other TCP packet
		default:
			return std::max<uint16_t>(srcPort, dstPort);
		}
	}

	std::string getValueString(pcpp::Packet& packet, PacketType packetType, uint16_t srcPort, uint16_t dstPort)
	{
		std::string prefix = "client-port-";

		uint16_t res = 0;
		switch (packetType)
		{
		case SYN:
			res = srcPort;
			break;
		case SYN_ACK:
			res = dstPort;
			break;
		case UDP:
			if(isSrcIPMulticast(packet)) res = srcPort;
			else if(isDstIPMulticast(packet)) res = dstPort;
			else res = std::max<uint16_t>(srcPort, dstPort);
			break;
		// other TCP packet
		default:
			res = std::max<uint16_t>(srcPort, dstPort);
			break;
		}

		std::ostringstream sstream;
		sstream << res;
		return prefix + sstream.str();
	}
};
