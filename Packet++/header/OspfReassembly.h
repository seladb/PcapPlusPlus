#ifndef PACKETPP_OSPF_REASSEMBLY
#define PACKETPP_OSPF_REASSEMBLY

#include "IpAddress.h"
#include "Packet.h"
#include "OspfLayer.h"
#include <map>


/**
 * @namespace pcpp
 * @brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
class OspfPacketData
{
  public:
	OspfPacketData(const OspfLayer* layer , std::string tupleName)
		: m_Layer(layer), m_TupleName(tupleName)
	{
	}

	const OspfLayer *getLayer() const
	{
		return m_Layer;
	}

	std::string getTupleName()
	{
		return m_TupleName;
	}

  private:
	const OspfLayer* m_Layer;
	std::string m_TupleName;
};

class OSPFReassembly
{
  public:
	/**
	 * @typedef OnOspfMessageReady
	 * A callback invoked when new data arrives
	 */
	typedef void (*OnOspfMessageReady)(pcpp::OspfPacketData *ospfData, void *userCookie);

	/**
	 * An enum representing the status returned from processing a fragment
	 */
	enum ReassemblyStatus
	{
		NonIpPacket,
		NonOspfPacket,
		OspfMessageHandled,
	};

	OSPFReassembly(OnOspfMessageReady onOspfMessageReadyCallback, void *callbackUserCookie = NULL)
		: m_OnOspfMessageReadyCallback(onOspfMessageReadyCallback), m_CallbackUserCookie(callbackUserCookie)
	{
	}


	ReassemblyStatus reassemblePacket(Packet &ospfData);

	ReassemblyStatus reassemblePacket(RawPacket *ospfRawData);

	std::string getTupleName(IPAddress src, IPAddress dst);

  private:
	struct OSPFReassemblyData
	{
		IPAddress srcIP;
		IPAddress dstIP;
		uint16_t srcPort;
		uint16_t dstPort;
		std::string tupleName;
		uint16_t number;

		OSPFReassemblyData()
		{
		}
		OSPFReassemblyData(IPAddress src, IPAddress dst, uint16_t srcP, uint16_t dstP, std::string tName, uint16_t n)
			: srcIP(src), dstIP(dst), srcPort(srcP), dstPort(dstP), tupleName(tName), number(n)
		{
		}
	};

	typedef std::map<std::string, OSPFReassemblyData> FragmentList;

	FragmentList m_FragmentList;
	OnOspfMessageReady m_OnOspfMessageReadyCallback;
	void *m_CallbackUserCookie;
};

} // namespace pcpp

#endif // PACKETPP_OSPF_REASSEMBLY
