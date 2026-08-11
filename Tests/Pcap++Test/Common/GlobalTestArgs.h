#pragma once

#include <string>
#include <vector>
#include <cstdint>

struct PcapTestArgs
{
	std::string ipToSendReceivePackets;
	bool debugMode = false;
	std::string remoteIp;
	uint16_t remotePort = 0;
	int dpdkPort = 0;
	std::vector<std::string> dpdkArgs;
	std::string kniIp;
	std::string xdpInterface;
};
