#ifndef PACKETPP_REASSEMBLY
#define PACKETPP_REASSEMBLY

#include "Layer.h"
#include "ProtocolType.h"

/**
 * @namespace pcpp
 * @brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
enum ReassemblyStatus
{
	Invalid,
	Handled,
};

typedef void (*OnMessageHandled)(std::string *data, std::string tuplename, void *userCookie);

ReassemblyStatus ReassembleMessage(Layer *layer, std::string tuple, void *cookie,
								   OnMessageHandled OnMessageHandledCallback);

} // namespace pcpp

#endif // PACKETPP_UDP_REASSEMBLY
