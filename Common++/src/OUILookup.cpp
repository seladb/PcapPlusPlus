#include "OUILookup.h"
#include "EndianPortable.h"
#include "Logger.h"
#include "json.hpp"

#include <fstream>

namespace pcpp
{
	int64_t OUILookup::initOUIDatabase(const std::string &path)
	{
		int64_t ctrRead = 0;
		std::ifstream dataFile;

		// Open database
		dataFile.open(path);
		if (!dataFile.is_open())
		{
			PCPP_LOG_ERROR(std::string("Can't open OUI database: ") + strerror(errno));
			return -1;
		}

		// Parse values
		nlohmann::json parsedJson = nlohmann::json::parse(dataFile);
		for (const auto &line : parsedJson.items())
		{
			if (!(line.value().is_object()))
				continue;
			auto val = line.value().get<nlohmann::json>();
			if (!(val.contains("vendor")))
				continue;

			std::vector<MaskedFilter> vLocalMaskedFilter;
			if (val.contains("maskedFilter") && val["maskedFilter"].is_array())
			{
				for (const auto &entry : val["maskedFilter"])
				{
					if (entry.is_object() && entry.contains("mask") && entry.contains("vendors") &&
						entry["mask"].is_number_integer() && entry["vendors"].is_object())
					{
						int maskValue = entry["mask"].get<int>();
						vLocalMaskedFilter.push_back({maskValue, {}});

						for (const auto &subentry : entry["vendors"].items())
						{
							if (subentry.value().is_string())
							{
								vLocalMaskedFilter.back().vendorMap.insert(
									{std::stoull(subentry.key()), subentry.value()});
								++ctrRead;
							}
						}
					}
				}
			}

			vendorMap.insert({std::stoull(line.key()), {val["vendor"], vLocalMaskedFilter}});
			++ctrRead;
		}

		PCPP_LOG_DEBUG(std::to_string(ctrRead) + " vendors read successfully");
		return ctrRead;
	}

	std::string OUILookup::getVendorName(const pcpp::MacAddress &addr)
	{
		if (vendorMap.empty())
			PCPP_LOG_ERROR("Vendor map is empty");

		// Get MAC address
		uint8_t buffArray[6];
		addr.copyTo(buffArray);

		uint64_t macAddr = (((uint64_t)((buffArray)[0]) << 0) + ((uint64_t)((buffArray)[1]) << 8) +
							((uint64_t)((buffArray)[2]) << 16) + ((uint64_t)((buffArray)[3]) << 24) +
							((uint64_t)((buffArray)[4]) << 32) + ((uint64_t)((buffArray)[5]) << 40));

		auto itr = vendorMap.find(macAddr & ~uint64_t(UINT32_MAX));
		if (itr == vendorMap.end())
			return "Unknown";

		for (const auto &entry : itr->second.maskedFilter)
		{
			uint64_t maskValue = be64toh(~((1 << (48 - entry.mask)) - 1)) >> 16;
			uint64_t bufferAddr = macAddr & maskValue;

			auto subItr = entry.vendorMap.find(bufferAddr);
			if (subItr != entry.vendorMap.end())
				return subItr->second;
		}

		return itr->second.vendorName;
	}

} // namespace pcpp
