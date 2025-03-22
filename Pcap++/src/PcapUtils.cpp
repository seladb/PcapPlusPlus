#include "PcapUtils.h"

#include "pcap.h"

namespace pcpp
{
	namespace internal
	{
		void PcapCloseDeleter::operator()(pcap_t* ptr) const noexcept
		{
			pcap_close(ptr);
		}

		void PcapFreeAllDevsDeleter::operator()(pcap_if_t* ptr) const noexcept
		{
			pcap_freealldevs(ptr);
		}
	}  // namespace internal
}  // namespace pcpp
