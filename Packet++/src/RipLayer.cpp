#define LOG_MODULE PacketLogModuleRipLayer

#include "RipLayer.h"
#include "EndianPortable.h"
#include "Logger.h"
#include "PacketUtils.h"
#include <sstream>
#include <string.h>

// uint64_t arr2num(uint8_t *ch, uint8_t size)
// {
// 	uint64_t result = 0;
// 	--size;
// 	for (size_t i = 0; i < size; ++i)
// 	{
// 		result = (result + *(ch + i)) * 0x100;
// 	}
// 	return result + *(ch + size);
// }

namespace pcpp
{
// //--------------------------------RipTableEntry---------------------------------
// RipTableEntry::RipTableEntry(std::istream &is)
// {
// 	is.read((char *)&re, sizeof(RipEntry));
// 	prefix = arr2num(re.prefix, 4);
// 	mask = arr2num(re.mask, 4);
// 	nexthop = arr2num(re.nexthop, 4);
// 	metric = ntohl(re.metric);
// }

// uint32_t RipTableEntry::get_prefix()
// {
// 	return prefix;
// }
// uint32_t RipTableEntry::get_mask()
// {
// 	return mask;
// }
// uint32_t RipTableEntry::get_nexthop()
// {
// 	return nexthop;
// }
// uint32_t RipTableEntry::get_metric()
// {
// 	return metric;
// }

//--------------------------------RipLayer---------------------------------
uint8_t RipLayer::getCommand() const
{
	return getRipHeader()->command;
}

uint8_t RipLayer::getVersion() const
{
	return getRipHeader()->version;
}

// uint32_t RipLayer::getRteSize() const
// {
// 	return rtes.size();
// }

// std::shared_ptr<RipTableEntry> RipLayer::getRte(uint32_t index)
// {
// 	return rtes[index];
// }

void RipLayer::computeCalculateFields()
{
// 	size_t len = Layer::getLayerPayloadSize();
// 	uint8_t *dt = Layer::getLayerPayload();
// 	// convert uint8_t to char then to string
// 	std::string s((char *)dt, len);
// 	std::istringstream iss(s);
// 	std::istream &stream = iss;

// 	while (len > 0)
// 	{
// 		auto temp_rte = std::make_shared<RipTableEntry>(stream);
// 		rtes.push_back(temp_rte);
// 		len = len - sizeof(RipEntry);
// 	}
}

std::string RipLayer::toString() const
{
	std::ostringstream commandStream;
	commandStream << getCommand();
	std::ostringstream versionStream;
	versionStream << getVersion();

	return "RIP Layer, command: " + commandStream.str() + ", version: " + versionStream.str();
}

} // namespace pcpp
