#include "pcapplusplus/PcapDevice.h"
#include "pcapplusplus/PcapFilter.h"
#include "pcapplusplus/Logger.h"
#include "pcap.h"

namespace pcpp
{
	namespace internal
	{

		PcapHandle::PcapHandle(pcap_t* pcapDescriptor) noexcept : m_PcapDescriptor(pcapDescriptor)
		{}

		PcapHandle::PcapHandle(PcapHandle&& other) noexcept : m_PcapDescriptor(other.m_PcapDescriptor)
		{
			other.m_PcapDescriptor = nullptr;
		}

		PcapHandle& PcapHandle::operator=(PcapHandle&& other) noexcept
		{
			if (this != &other)
			{
				reset(other.m_PcapDescriptor);
				other.m_PcapDescriptor = nullptr;
			}
			return *this;
		}

		PcapHandle& PcapHandle::operator=(std::nullptr_t) noexcept
		{
			reset();
			return *this;
		}

		PcapHandle::~PcapHandle()
		{
			reset();
		}

		pcap_t* PcapHandle::release() noexcept
		{
			auto result = m_PcapDescriptor;
			m_PcapDescriptor = nullptr;
			return result;
		}

		void PcapHandle::reset(pcap_t* pcapDescriptor) noexcept
		{
			pcap_t* oldDescriptor = m_PcapDescriptor;
			m_PcapDescriptor = pcapDescriptor;
			if (oldDescriptor != nullptr)
			{
				pcap_close(oldDescriptor);
			}
		}

		char const* PcapHandle::getLastError() const noexcept
		{
			if (!isValid())
			{
				static char const* const noHandleError = "No pcap handle";
				return noHandleError;
			}

			return pcap_geterr(m_PcapDescriptor);
		}
	}  // namespace internal

	IPcapDevice::~IPcapDevice()
	{}

	bool IPcapDevice::setFilter(std::string filterAsString)
	{
		PCPP_LOG_DEBUG("Filter to be set: '" << filterAsString << "'");
		if (!m_DeviceOpened)
		{
			PCPP_LOG_ERROR("Device not Opened!! cannot set filter");
			return false;
		}

		struct bpf_program prog;
		PCPP_LOG_DEBUG("Compiling the filter '" << filterAsString << "'");
		if (pcap_compile(m_PcapDescriptor.get(), &prog, filterAsString.c_str(), 1, 0) < 0)
		{
			/*
			 * Print out appropriate text, followed by the error message
			 * generated by the packet capture library.
			 */
			PCPP_LOG_ERROR("Error compiling filter. Error message is: " << m_PcapDescriptor.getLastError());
			return false;
		}

		PCPP_LOG_DEBUG("Setting the compiled filter");
		if (pcap_setfilter(m_PcapDescriptor.get(), &prog) < 0)
		{
			/*
			 * Print out error. The format will be the prefix string,
			 * created above, followed by the error message that the packet
			 * capture library generates.
			 */
			PCPP_LOG_ERROR("Error setting a compiled filter. Error message is: " << m_PcapDescriptor.getLastError());
			pcap_freecode(&prog);
			return false;
		}

		PCPP_LOG_DEBUG("Filter set successfully");

		pcap_freecode(&prog);

		return true;
	}

	bool IPcapDevice::clearFilter()
	{
		return setFilter("");
	}

	bool IPcapDevice::matchPacketWithFilter(GeneralFilter& filter, RawPacket* rawPacket)
	{
		return filter.matchPacketWithFilter(rawPacket);
	}

	std::string IPcapDevice::getPcapLibVersionInfo()
	{
		return std::string(pcap_lib_version());
	}

}  // namespace pcpp
