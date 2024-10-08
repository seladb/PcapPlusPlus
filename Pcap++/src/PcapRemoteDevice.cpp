#define LOG_MODULE PcapLogModuleRemoteDevice

#include "PcapRemoteDevice.h"
#include "Logger.h"
#include "pcap.h"

namespace pcpp
{

	pcap_rmtauth PcapRemoteAuthentication::getPcapRmAuth() const
	{
		pcap_rmtauth result;
		result.type = RPCAP_RMTAUTH_PWD;
		result.username = const_cast<char*>(userName.c_str());
		result.password = const_cast<char*>(password.c_str());
		return result;
	}

	PcapRemoteDevice::PcapRemoteDevice(DeviceInterfaceDetails deviceInterface,
	                                   std::shared_ptr<PcapRemoteAuthentication> remoteAuthentication,
	                                   const IPAddress& remoteMachineIP, uint16_t remoteMachinePort)
	    : PcapLiveDevice(std::move(deviceInterface), false, false, false), m_RemoteMachineIpAddress(remoteMachineIP),
	      m_RemoteMachinePort(remoteMachinePort), m_RemoteAuthentication(std::move(remoteAuthentication))
	{
		PCPP_LOG_DEBUG("MTU calculation isn't supported for remote devices. Setting MTU to 1514");
		m_DeviceMtu = 1514;
	}

	bool PcapRemoteDevice::open()
	{
		char errbuf[PCAP_ERRBUF_SIZE];
		// PCAP_OPENFLAG_DATATX_UDP doesn't always work
		int flags = PCAP_OPENFLAG_PROMISCUOUS | PCAP_OPENFLAG_NOCAPTURE_RPCAP;
		PCPP_LOG_DEBUG("Opening device '" << m_InterfaceDetails.name << "'");
		pcap_rmtauth* pRmAuth = nullptr;
		pcap_rmtauth rmAuth;
		if (m_RemoteAuthentication != nullptr)
		{
			rmAuth = m_RemoteAuthentication->getPcapRmAuth();
			pRmAuth = &rmAuth;
		}

		m_PcapDescriptor = internal::PcapHandle(
		    pcap_open(m_InterfaceDetails.name.c_str(), PCPP_MAX_PACKET_SIZE, flags, 250, pRmAuth, errbuf));
		if (m_PcapDescriptor == nullptr)
		{
			PCPP_LOG_ERROR("Error opening device. Error was: " << errbuf);
			m_DeviceOpened = false;
			return false;
		}

		// in Remote devices there shouldn't be 2 separate descriptors
		m_PcapSendDescriptor = m_PcapDescriptor.get();

		// setFilter requires that m_DeviceOpened == true
		m_DeviceOpened = true;

		// for some reason if a filter is not set than WinPcap throws an exception. So Here is a generic filter that
		// catches all traffic
		if (!setFilter(
		        "ether proto (\\ip or \\ip6 or \\arp or \\rarp or \\decnet or \\sca or \\lat or \\mopdl or \\moprc or \\iso or \\stp or \\ipx or \\netbeui or 0x80F3)"))  // 0x80F3 == AARP
		{
			PCPP_LOG_ERROR("Error setting the filter. Error was: " << Logger::getInstance().getLastError());
			m_DeviceOpened = false;
			return false;
		}

		PCPP_LOG_DEBUG("Device '" << m_InterfaceDetails.name << "' opened");

		return true;
	}

	void PcapRemoteDevice::getStatistics(PcapStats& stats) const
	{
		int allocatedMemory;
		pcap_stat* tempStats = pcap_stats_ex(m_PcapDescriptor.get(), &allocatedMemory);
		if (allocatedMemory < static_cast<int>(sizeof(pcap_stat)))
		{
			PCPP_LOG_ERROR("Error getting statistics from live device '"
			               << m_InterfaceDetails.name << "': WinPcap did not allocate the entire struct");
			return;
		}
		stats.packetsRecv = tempStats->ps_capt;
		stats.packetsDrop = static_cast<uint64_t>(tempStats->ps_drop) + tempStats->ps_netdrop;
		stats.packetsDropByInterface = tempStats->ps_ifdrop;
	}

	uint32_t PcapRemoteDevice::getMtu() const
	{
		PCPP_LOG_DEBUG("MTU isn't supported for remote devices");
		return 0;
	}

	MacAddress PcapRemoteDevice::getMacAddress() const
	{
		PCPP_LOG_ERROR("MAC address isn't supported for remote devices");
		return MacAddress::Zero;
	}

	PcapRemoteDevice* PcapRemoteDevice::clone() const
	{
		return new PcapRemoteDevice(m_InterfaceDetails, m_RemoteAuthentication, m_RemoteMachineIpAddress,
		                            m_RemoteMachinePort);
	}

}  // namespace pcpp
