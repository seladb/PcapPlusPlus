#include "PcapDevice.h"
#include "PcapFilter.h"
#include "Logger.h"
#include "TimespecTimeval.h"
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
				closeHandle();
				m_PcapDescriptor = other.m_PcapDescriptor;
				other.m_PcapDescriptor = nullptr;
			}
			return *this;
		}

		PcapHandle& PcapHandle::operator=(std::nullptr_t) noexcept
		{
			closeHandle();
			return *this;
		}

		PcapHandle::~PcapHandle()
		{
			closeHandle();
		}

		pcap_t* PcapHandle::release() noexcept
		{
			auto result = m_PcapDescriptor;
			m_PcapDescriptor = nullptr;
			return result;
		}

		char const* PcapHandle::getLastErrorView() const noexcept
		{
			return pcap_geterr(m_PcapDescriptor);
		}

		void PcapHandle::closeHandle() noexcept
		{
			if (m_PcapDescriptor != nullptr)
			{
				pcap_close(m_PcapDescriptor);
				m_PcapDescriptor = nullptr;
			}
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
			PCPP_LOG_ERROR("Error compiling filter. Error message is: " << m_PcapDescriptor.getLastErrorView());
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
			PCPP_LOG_ERROR(
			    "Error setting a compiled filter. Error message is: " << m_PcapDescriptor.getLastErrorView());
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
