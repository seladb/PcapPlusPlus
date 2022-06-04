#define LOG_MODULE PacketLogModuleStpLayer

#include "StpLayer.h"
#include "Logger.h"

namespace pcpp
{

	// ---------------------- Class STP Layer ----------------------
	pcpp::MacAddress StpLayer::StpMulticastDstMAC("01:80:C2:00:00:00");
	pcpp::MacAddress StpLayer::StpUplinkFastMulticastDstMAC("01:00:0C:CD:CD:CD");

	bool StpLayer::isDataValid(const uint8_t *data, size_t dataLen)
	{
		if (dataLen >= sizeof(stp_header))
		{
			stp_header *ptr = (stp_header *)data;
			pcpp::MacAddress dstAddr = pcpp::MacAddress(ptr->dstMac);
			if (dstAddr == StpMulticastDstMAC || dstAddr == StpUplinkFastMulticastDstMAC)
				return true;
		}
		return false;
	}

	StpLayer::StpType StpLayer::getStpType(const uint8_t *data, size_t dataLen)
	{
		if (dataLen >= sizeof(stp_header))
		{
			stp_header *header = (stp_header *)data;
			if (header->frameLength >= sizeof(stp_tcn_bpdu))
			{
				stp_tcn_bpdu *ptr = (stp_tcn_bpdu *)&data[sizeof(stp_header)];
				switch (ptr->type)
				{
				case 0x00:
					return ConfigurationBPDU;
				case 0x80:
					return TopologyChangeBPDU;
				case 0x02:
				{
					if(ptr->version == 0x2)
						return Rapid;
					if(ptr->version == 0x3)
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
				PCPP_LOG_ERROR("STP Frame length is too short");
		}
		else
			PCPP_LOG_ERROR("Data length is less than STP header");

		return NotSTP;
	}

	// ---------------------- Class StpConfigurationBPDU Layer ----------------------

	std::string MultipleStpLayer::toString() const
	{
		return "Spanning Tree Configuration";
	}

	// ---------------------- Class StpTopologyChangeBPDU Layer ----------------------

	std::string MultipleStpLayer::toString() const
	{
		return "Spanning Tree Topology Change Notification";
	}

	// ---------------------- Class RapidStp Layer ----------------------

	std::string MultipleStpLayer::toString() const
	{
		return "Rapid Spanning Tree";
	}

	// ---------------------- Class MultipleStp Layer ----------------------
	
	std::string MultipleStpLayer::toString() const
	{
		return "Multiple Spanning Tree";
	}
	

} // namespace pcpp
