#ifndef PACKETPP_L2TP_REASSEMBLY
#define PACKETPP_L2TP_REASSEMBLY

#include "IpAddress.h"
#include "Packet.h"
#include "L2tpLayer.h"
#include <map>


/**
 * @namespace pcpp
 * @brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
class L2tpPacketData
{
  public:
	L2tpPacketData(L2tpLayer* layer , std::string tupleName)
		: m_Layer(layer), m_TupleName(tupleName)
	{
	}

	const L2tpLayer *getLayer() const
	{
		return m_Layer;
	}

	std::string getTupleName()
	{
		return m_TupleName;
	}

  private:
	L2tpLayer* m_Layer;
	std::string m_TupleName;
};

class L2TPReassembly
{
  public:
	/**
	 * @typedef OnL2tpMessageReady
	 * A callback invoked when new data arrives
	 */
	typedef void (*OnL2tpMessageReady)(pcpp::L2tpPacketData *l2tpData, void *userCookie);

	/**
	 * An enum representing the status returned from processing a fragment
	 */
	enum ReassemblyStatus
	{
		NonIpPacket,
		NonUdpPacket,
		NonL2tpPacket,
		L2tpMessageHandled,
	};

	L2TPReassembly(OnL2tpMessageReady onL2tpMessageReadyCallback, void *callbackUserCookie = NULL)
		: m_OnL2tpMessageReadyCallback(onL2tpMessageReadyCallback), m_CallbackUserCookie(callbackUserCookie)
	{
	}


	ReassemblyStatus reassemblePacket(Packet &l2tpData);

	ReassemblyStatus reassemblePacket(RawPacket *l2tpRawData);

	std::string getTupleName(IPAddress src, IPAddress dst, uint16_t srcPort, uint16_t dstPort);
  private:
	struct L2TPReassemblyData
	{
		IPAddress srcIP;
		IPAddress dstIP;
		uint16_t srcPort;
		uint16_t dstPort;
		std::string tupleName;
		uint16_t number;

		L2TPReassemblyData()
		{
		}
		L2TPReassemblyData(IPAddress src, IPAddress dst, uint16_t srcP, uint16_t dstP, std::string tName, uint16_t n)
			: srcIP(src), dstIP(dst), srcPort(srcP), dstPort(dstP), tupleName(tName), number(n)
		{
		}
	};

	typedef std::map<std::string, L2TPReassemblyData> FragmentList;

	FragmentList m_FragmentList;
	OnL2tpMessageReady m_OnL2tpMessageReadyCallback;
	void *m_CallbackUserCookie;
};

} // namespace pcpp

#endif // PACKETPP_L2TP_REASSEMBLY
