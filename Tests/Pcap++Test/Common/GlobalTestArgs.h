#pragma once

#include <string>
#include <vector>
#include <cstdint>

struct PcapTestArgs
{
	std::string ipToSendReceivePackets;
	bool debugMode;
	std::string remoteIp;
	uint16_t remotePort;
	int dpdkPort;
	std::vector<std::string> dpdkArgs;
	std::string kniIp;
	std::string xdpInterface;
};
