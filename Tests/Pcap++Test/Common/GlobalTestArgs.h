#include <string>

struct PcapTestArgs
{
	std::string ipToSendReceivePackets;
	bool debugMode;
	std::string remoteIp;
	uint16_t remotePort;
	int dpdkPort;
	std::string kniIp;
};
