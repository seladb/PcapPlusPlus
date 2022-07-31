#define LOG_MODULE PacketLogModuleStpLayer

#include "StpLayer.h"
#include "Logger.h"

namespace pcpp
{

	// ---------------------- Class STP Layer ----------------------
	pcpp::MacAddress StpLayer::StpMulticastDstMAC("01:80:C2:00:00:00");
	pcpp::MacAddress StpLayer::StpUplinkFastMulticastDstMAC("01:00:0C:CD:CD:CD");

	pcpp::MacAddress StpLayer::IDtoMacAddress(uint64_t id)
	{

		return pcpp::MacAddress((id >> 40) & 0xFF, (id >> 32) & 0xFF, (id >> 24) & 0xFF, (id >> 16) & 0xFF,
								(id >> 8) & 0xFF, id & 0xFF);
	}

	bool StpLayer::isDataValid(const uint8_t *data, size_t dataLen) { return data && dataLen; }

	StpLayer::StpType StpLayer::getStpType(const uint8_t *data, size_t dataLen)
	{
		if (dataLen >= sizeof(stp_tcn_bpdu))
		{
			stp_tcn_bpdu *ptr = (stp_tcn_bpdu *)data;
			switch (ptr->type)
			{
			case 0x00:
				return ConfigurationBPDU;
			case 0x80:
				return TopologyChangeBPDU;
			case 0x02: {
				if (ptr->version == 0x2)
					return Rapid;
				if (ptr->version == 0x3)
					return Multiple;
				PCPP_LOG_ERROR("Unknown Spanning Tree Version");
				return NotSTP;
			}
			default:
				PCPP_LOG_ERROR("Unknown Spanning Tree Protocol type");
				return NotSTP;
			}
		}
		else
			PCPP_LOG_ERROR("Data length is less than any STP header");

		return NotSTP;
	}

	// ---------------------- Class StpConfigurationBPDU Layer ----------------------

	std::string StpConfigurationBPDULayer::toString() const { return "Spanning Tree Configuration"; }

	// ---------------------- Class StpTopologyChangeBPDU Layer ----------------------

	std::string StpTopologyChangeBPDULayer::toString() const { return "Spanning Tree Topology Change Notification"; }

	// ---------------------- Class RapidStp Layer ----------------------

	std::string RapidStpLayer::toString() const { return "Rapid Spanning Tree"; }

	// ---------------------- Class MultipleStp Layer ----------------------

	msti_conf_msg *MultipleStpLayer::getMstiConfMessages() const
	{
		if (getNumberOfMSTIConfMessages())
			return (msti_conf_msg *)(m_Data + sizeof(mstp_conf_bpdu));
		return NULL;
	}

	std::string MultipleStpLayer::getMstConfigurationName() const
	{
		std::string str = std::string((char *)(getMstpHeader()->mstConfigName), 32);
		str.erase(std::find(str.begin(), str.end(), '\0'), str.end());
		return str;
	}

	std::string MultipleStpLayer::toString() const { return "Multiple Spanning Tree"; }

} // namespace pcpp
