#ifndef PACKETPP_UDP_REASSEMBLY
#define PACKETPP_UDP_REASSEMBLY

#include "IpAddress.h"
#include "Packet.h"
#include <map>


/**
 * @namespace pcpp
 * @brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
class UdpPacketData
{
  public:
	UdpPacketData(const uint8_t *udpData, size_t udpDataLength, std::string tupleName)
		: m_Data(udpData), m_DataLen(udpDataLength), m_TupleName(tupleName)
	{
	}

	const uint8_t *getData() const
	{
		return m_Data;
	}

	size_t getDataLength() const
	{
		return m_DataLen;
	}

	std::string getTupleName()
	{
		return m_TupleName;
	}

  private:
	const uint8_t *m_Data;
	size_t m_DataLen;
	std::string m_TupleName;
};

class UDPReassembly
{
  public:
	/**
	 * @typedef OnUdpMessageReady
	 * A callback invoked when new data arrives
	 */
	typedef void (*OnUdpMessageReady)(pcpp::UdpPacketData *udpData, void *userCookie);

	/**
	 * An enum representing the status returned from processing a fragment
	 */
	enum ReassemblyStatus
	{
		NonIpPacket,
		NonUdpPacket,
		UdpMessageHandled,
	};

	UDPReassembly(OnUdpMessageReady onUdpMessageReadyCallback, void *callbackUserCookie = NULL)
		: m_OnUdpMessageReadyCallback(onUdpMessageReadyCallback), m_CallbackUserCookie(callbackUserCookie)
	{
	}


	ReassemblyStatus reassemblePacket(Packet &udpData);

	ReassemblyStatus reassemblePacket(RawPacket *udpRawData);

	std::string getTupleName(IPAddress src, IPAddress dst, uint16_t srcPort, uint16_t dstPort);

  private:
	struct UDPReassemblyData
	{
		IPAddress srcIP;
		IPAddress dstIP;
		uint16_t srcPort;
		uint16_t dstPort;
		std::string tupleName;
		uint16_t number;

		UDPReassemblyData()
		{
		}
		UDPReassemblyData(IPAddress src, IPAddress dst, uint16_t srcP, uint16_t dstP, std::string tName, uint16_t n)
			: srcIP(src), dstIP(dst), srcPort(srcP), dstPort(dstP), tupleName(tName), number(n)
		{
		}
	};

	typedef std::map<std::string, UDPReassemblyData> FragmentList;

	FragmentList m_FragmentList;
	OnUdpMessageReady m_OnUdpMessageReadyCallback;
	void *m_CallbackUserCookie;
};

} // namespace pcpp

#endif // PACKETPP_UDP_REASSEMBLY
