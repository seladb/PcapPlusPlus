#define LOG_MODULE PacketLogModuleRipLayer

#include "RipLayer.h"
#include "EndianPortable.h"
#include "Logger.h"
#include "PacketUtils.h"
#include <sstream>
#include <string.h>

uint64_t arr2num(uint8_t *ch, uint8_t size)
{
	uint64_t result = 0;
	--size;
	for (size_t i = 0; i < size; ++i)
	{
		result = (result + *(ch + i)) * 0x100;
	}
	return result + *(ch + size);
}

std::string num2ip(uint32_t i)
{
	std::vector<std::string> nums;
	for (size_t j = 0; j < 3; ++j)
	{
		nums.push_back(std::to_string(i % 0x100));
		i = (i - i % 0x100) / 0x100;
	}
	nums.push_back(std::to_string(i));

	return nums[3] + "." + nums[2] + "." + nums[1] + "." + nums[0];
}

namespace pcpp
{
//--------------------------------RipTableEntry---------------------------------
RipTableEntry::RipTableEntry(std::istream &is)
{
	is.read((char *)&re, sizeof(RipEntry));
	prefix = arr2num(re.prefix, 4);
	mask = arr2num(re.mask, 4);
	nexthop = arr2num(re.nexthop, 4);
	metric = ntohl(re.metric);
}

void RipTableEntry::ToV1StructuredOutput(std::ostream &os)
{
	os << '\t' << "RipTableEntry:" << '\n';
	os << "\t\t"
	   << "address family identifier: " << get_family() << '\n';
	os << "\t\t"
	   << "route tag: " << get_tag() << '\n';
	os << "\t\t"
	   << "ip address: " << num2ip(get_prefix()) << '\n';
	os << "\t\t"
	   << "metric: " << get_metric() << '\n';
}

void RipTableEntry::ToV2StructuredOutput(std::ostream &os)
{
	os << '\t' << "RipTableEntry:" << '\n';
	os << "\t\t"
	   << "address family identifier: " << get_family() << '\n';
	os << "\t\t"
	   << "route tag: " << get_tag() << '\n';
	os << "\t\t"
	   << "ip address: " << num2ip(get_prefix()) << '\n';
	os << "\t\t"
	   << "netmask: " << num2ip(get_mask()) << '\n';
	os << "\t\t"
	   << "nexthop: " << num2ip(get_nexthop()) << '\n';
	os << "\t\t"
	   << "metric: " << get_metric() << '\n';
}

uint16_t RipTableEntry::get_family()
{
	return family;
}
uint16_t RipTableEntry::get_tag()
{
	return tag;
}
uint32_t RipTableEntry::get_prefix()
{
	return prefix;
}
uint32_t RipTableEntry::get_mask()
{
	return mask;
}
uint32_t RipTableEntry::get_nexthop()
{
	return nexthop;
}
uint32_t RipTableEntry::get_metric()
{
	return metric;
}

//--------------------------------RipLayer---------------------------------
uint8_t RipLayer::getCommand() const
{
	return getRipHeader()->command;
}

uint8_t RipLayer::getVersion() const
{
	return getRipHeader()->version;
}

uint32_t RipLayer::getRteSize() const
{
	return rtes.size();
}

std::shared_ptr<RipTableEntry> RipLayer::getRte(uint32_t index)
{
	return rtes[index];
}

void RipLayer::ToStructuredOutput(std::ostream &os) const
{
	os << "Rip Packet:" << '\n';
	os << '\t' << "command: " << (uint32_t)getCommand() << '\n'; // uint8_t有些值是不可见字符
	os << '\t' << "version: " << (uint32_t)getVersion() << '\n';
	os << '\t' << "total length: " << getDataLen() << '\n';
	for (auto &var : rtes)
	{
		if (getVersion() == uint8_t(1))
		{
			var->ToV1StructuredOutput(os);
		}
		else if (getVersion() == uint8_t(2))
		{
			var->ToV2StructuredOutput(os);
		}
	}
	os << std::endl;
}

void RipLayer::computeCalculateFields()
{
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
