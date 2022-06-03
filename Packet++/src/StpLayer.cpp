#define LOG_MODULE PacketLogModuleStpLayer

#include "Logger.h"
#include "StpLayer.h"

namespace pcpp
{
	pcpp::MacAddress StpLayer::StpMulticastDstMAC("01:80:C2:00:00:00");
	pcpp::MacAddress StpLayer::StpUplinkFastMulticastDstMAC("01:00:0C:CD:CD:CD");


} // namespace pcpp
