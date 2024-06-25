#include "OUILookup.h"
#include "Logger.h"

#include "json.hpp"

#include <fstream>

namespace pcpp
{

	template <typename T> int64_t OUILookup::internalParser(T& jsonData)
	{
		// Clear all entries before adding
		vendorMap.clear();

		int64_t ctrRead = 0;
		nlohmann::json parsedJson = nlohmann::json::parse(jsonData);
		for (const auto& line : parsedJson.items())
		{
			if (!(line.value().is_object()))
				continue;
			auto val = line.value().get<nlohmann::json>();
			if (!(val.contains("vendor")))
				continue;

			std::vector<MaskedFilter> vLocalMaskedFilter;
			if (val.contains("maskedFilters") && val["maskedFilters"].is_array())
			{
				// Iterate through masked filters
				for (const auto& entry : val["maskedFilters"])
				{
					if (!entry.is_object())
						continue;
					auto subVal = entry.get<nlohmann::json>();
					if (subVal.contains("mask") && subVal.contains("vendors") && subVal["mask"].is_number_integer() &&
					    subVal["vendors"].is_object())
					{
						int maskValue = subVal["mask"].get<int>();
						vLocalMaskedFilter.push_back({ maskValue, {} });

						// Parse masked filter
						for (const auto& subentry : subVal["vendors"].items())
						{
							if (subentry.value().is_string())
							{
								vLocalMaskedFilter.back().vendorMap.insert(
								    { std::stoull(subentry.key()), subentry.value() });
								++ctrRead;
							}
						}
					}
				}
			}

			vendorMap.insert({
			    std::stoull(line.key()), { val["vendor"], vLocalMaskedFilter }
            });
			++ctrRead;
		}

		PCPP_LOG_DEBUG(std::to_string(ctrRead) + " vendors read successfully");
		return ctrRead;
	}

	int64_t OUILookup::initOUIDatabaseFromJson(const std::string& path)
	{
		std::ifstream dataFile;

		// Open database
		dataFile.open(path);
		if (!dataFile.is_open())
		{
			PCPP_LOG_ERROR(std::string("Can't open OUI database: ") + strerror(errno));
			return -1;
		}

		// Parse values
		return internalParser(dataFile);
	}

	std::string OUILookup::getVendorName(const pcpp::MacAddress& addr)
	{
		if (vendorMap.empty())
			PCPP_LOG_DEBUG("Vendor map is empty");

		// Get MAC address
		uint8_t buffArray[6];
		addr.copyTo(buffArray);

		uint64_t macAddr = (((uint64_t)((buffArray)[5]) << 0) + ((uint64_t)((buffArray)[4]) << 8) +
		                    ((uint64_t)((buffArray)[3]) << 16) + ((uint64_t)((buffArray)[2]) << 24) +
		                    ((uint64_t)((buffArray)[1]) << 32) + ((uint64_t)((buffArray)[0]) << 40));

		auto itr = vendorMap.find(macAddr >> 24);
		if (itr == vendorMap.end())
			return "Unknown";

		for (const auto& entry : itr->second.maskedFilter)
		{
			uint64_t maskValue = ~((1 << (48 - entry.mask)) - 1);
			uint64_t bufferAddr = macAddr & maskValue;

			auto subItr = entry.vendorMap.find(bufferAddr);
			if (subItr != entry.vendorMap.end())
				return subItr->second;
		}

		return itr->second.vendorName;
	}

}  // namespace pcpp
