#define LOG_MODULE PacketLogModuleNflogLayer

#include "NflogLayer.h"
#include "Logger.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "PayloadLayer.h"
#include "ArpLayer.h"
#include "VlanLayer.h"
#include "PPPoELayer.h"
#include "MplsLayer.h"
#include <string.h>
#include "EndianPortable.h"

namespace pcpp
{

void NflogLayer::parseNextLayer()
{
}

void NflogLayer::computeCalculateFields()
{
	
}

std::string NflogLayer::toString() const
{
	return "Linux Netfilter NFLOG";
}

} // namespace pcpp
