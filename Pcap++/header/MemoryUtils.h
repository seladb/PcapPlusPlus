#pragma once

// Forward declarations
struct pcap;
typedef pcap pcap_t;
struct pcap_if;
typedef pcap_if pcap_if_t;

namespace pcpp
{
	namespace internal
	{
		/**
		 * @class PcapCloseDeleter
		 * A deleter that cleans up a pcap_t structure by calling pcap_close.
		 */
		struct PcapCloseDeleter
		{
			void operator()(pcap_t* ptr) const;
		};

		/**
		 * @class FreeAllDevsDeleter
		 * A deleter that frees an interface list of pcap_if_t ptr by calling 'pcap_freealldevs' function on it.
		 */
		struct PcapFreeAllDevsDeleter
		{
			void operator()(pcap_if_t* ptr) const;
		};
	}
}
