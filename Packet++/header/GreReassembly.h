#ifndef PACKETPP_GRE_REASSEMBLY
#define PACKETPP_GRE_REASSEMBLY

#include "IpAddress.h"
#include "Packet.h"
#include <map>


/**
 * @namespace pcpp
 * @brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
class GrePacketData
{
  public:
	GrePacketData(const uint8_t *greData, size_t greDataLength, std::string tupleName)
		: m_Data(greData), m_DataLen(greDataLength), m_TupleName(tupleName)
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

class GREReassembly
{
  public:
	/**
	 * @typedef OnGreMessageReady
	 * A callback invoked when new data arrives
	 */
	typedef void (*OnGreMessageReady)(pcpp::GrePacketData *greData, void *userCookie);

	/**
	 * An enum representing the status returned from processing a fragment
	 */
	enum ReassemblyStatus
	{
		NonIpPacket,
		NonGrePacket,
		GreMessageHandled,
	};

	GREReassembly(OnGreMessageReady onGreMessageReadyCallback, void *callbackUserCookie = NULL)
		: m_OnGreMessageReadyCallback(onGreMessageReadyCallback), m_CallbackUserCookie(callbackUserCookie)
	{
	}


	ReassemblyStatus reassemblePacket(Packet &greData);

	ReassemblyStatus reassemblePacket(RawPacket *greRawData);

	std::string getTupleName(IPAddress src, IPAddress dst);

  private:
	struct GREReassemblyData
	{
		IPAddress srcIP;
		IPAddress dstIP;
		std::string tupleName;
		uint16_t number;

		GREReassemblyData()
		{
		}
		GREReassemblyData(IPAddress src, IPAddress dst, std::string tName, uint16_t n)
			: srcIP(src), dstIP(dst), tupleName(tName), number(n)
		{
		}
	};

	typedef std::map<std::string, GREReassemblyData> FragmentList;

	FragmentList m_FragmentList;
	OnGreMessageReady m_OnGreMessageReadyCallback;
	void *m_CallbackUserCookie;
};

} // namespace pcpp

#endif // PACKETPP_GRE_REASSEMBLY
