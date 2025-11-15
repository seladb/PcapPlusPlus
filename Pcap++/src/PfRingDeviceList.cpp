// GCOVR_EXCL_START

#define LOG_MODULE PcapLogModulePfRingDevice

#include <cstdio>
#include <array>
#include "PfRingDeviceList.h"
#include "SystemUtils.h"
#include "DeviceUtils.h"
#include "Logger.h"
#include "pcap.h"
#include "pfring.h"

namespace pcpp
{
	/// @cond PCPP_INTERNAL

	namespace
	{
		/// @class PfRingCloseDeleter
		/// A deleter that cleans up a pfring structure by calling pfring_close.
		struct PfRingCloseDeleter
		{
			void operator()(pfring* ptr) const noexcept
			{
				pfring_close(ptr);
			}
		};

		/// Reads the ring version of a PF_RING handle.
		/// @param[in] ring A PF_RING handle.
		/// @return A string representation of the ring version or empty string if the read fails.
		std::string readPfRingVersion(pfring* ring)
		{
			uint32_t version;
			if (pfring_version(ring, &version) < 0)
			{
				PCPP_LOG_ERROR("Couldn't retrieve PF_RING version, pfring_version returned an error");
				return {};
			}

			std::array<char, 25> versionAsString;
			std::snprintf(versionAsString.data(), versionAsString.size(), "PF_RING v.%u.%u.%u\n",
			              (version & 0xFFFF0000) >> 16, (version & 0x0000FF00) >> 8, version & 0x000000FF);

			return std::string(versionAsString.data());
		}
	}  // namespace

	/// @endcond

	PfRingDeviceList::PfRingDeviceList()
	{
		m_PfRingVersion = "";

		bool moduleLoaded = false;
		try
		{
			// if there is some result the module must be loaded
			moduleLoaded = !(executeShellCommand("lsmod | grep pf_ring").empty());
		}
		catch (const std::exception& e)
		{
			PCPP_LOG_ERROR("PF_RING load error: " << e.what());
			moduleLoaded = false;
		}

		if (!moduleLoaded)
		{
			PCPP_LOG_ERROR(
			    "PF_RING kernel module isn't loaded. Please run: 'sudo insmod <PF_RING_LOCATION>/kernel/pf_ring.ko'");
			return;
		}

		PCPP_LOG_DEBUG("PF_RING kernel module is loaded");

		PCPP_LOG_DEBUG("PfRingDeviceList init: searching all interfaces on machine");
		try
		{
			auto interfaceList = internal::getAllLocalPcapDevices();

			for (pcap_if_t* currInterface = interfaceList.get(); currInterface != nullptr;
			     currInterface = currInterface->next)
			{
				uint32_t flags = PF_RING_PROMISC | PF_RING_DNA_SYMMETRIC_RSS;
				auto ring = std::unique_ptr<pfring, PfRingCloseDeleter>(pfring_open(currInterface->name, 128, flags));
				if (ring != nullptr)
				{
					if (m_PfRingVersion.empty())
					{
						m_PfRingVersion = readPfRingVersion(ring.get());
						PCPP_LOG_DEBUG("PF_RING version is: " << m_PfRingVersion);
					}

					// Not using std::make_unique because ctor of PfRingDevice is private
					auto newDev = std::unique_ptr<PfRingDevice>(new PfRingDevice(currInterface->name));
					m_DeviceList.pushBack(std::move(newDev));
					PCPP_LOG_DEBUG("Found interface: " << currInterface->name);
				}
			}
		}
		catch (const std::runtime_error& e)
		{
			PCPP_LOG_ERROR("PfRingDeviceList init error: " << e.what());
		}

		PCPP_LOG_DEBUG("PfRingDeviceList init end");

		// Full update of all elements of the view vector to synchronize them with the main vector.
		m_PfRingDeviceListView.resize(m_DeviceList.size());
		std::copy(m_DeviceList.begin(), m_DeviceList.end(), m_PfRingDeviceListView.begin());
	}

	PfRingDevice* PfRingDeviceList::getPfRingDeviceByName(const std::string& devName) const
	{
		return getDeviceByName(devName);
	}

	PfRingDevice* PfRingDeviceList::getDeviceByName(const std::string& devName) const
	{
		PCPP_LOG_DEBUG("Searching all live devices...");
		auto devIter = std::find_if(m_DeviceList.begin(), m_DeviceList.end(),
		                            [&devName](PfRingDevice const* dev) { return dev->getDeviceName() == devName; });

		if (devIter == m_DeviceList.end())
		{
			PCPP_LOG_DEBUG("Found no PF_RING devices with name '" << devName << "'");
			return nullptr;
		}

		return *devIter;
	}
}  // namespace pcpp

// GCOVR_EXCL_STOP
