#include "PcapDevice.h"
#include "PcapFilter.h"
#include "Logger.h"
#include "pcap.h"

namespace pcpp
{
	PcapStats IPcapStatisticsProvider::getStatistics() const
	{
		PcapStats stats;
		getStatistics(stats);
		return stats;
	}
}  // namespace pcpp
