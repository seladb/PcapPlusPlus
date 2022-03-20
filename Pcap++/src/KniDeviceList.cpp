#if defined(USE_DPDK) && defined(__linux__)

#define LOG_MODULE PcapLogModuleKniDevice

#include <inttypes.h>
#include <algorithm>

#include "KniDeviceList.h"
#include "Logger.h"
#include "SystemUtils.h"

#include <rte_version.h>
#include <rte_kni.h>

#ifndef MAX_KNI_DEVICES
// This value have no meaning in current DPDK implementation (ver >= 18.11)
// In older versions have literal meaning
#	define MAX_KNI_DEVICES 4
#endif

namespace pcpp
{

/**
 * ===================
 * Class KniDeviceList
 * ===================
 */

static inline bool checkKniDriver()
{
	std::string execResult = executeShellCommand("lsmod | grep -s rte_kni");
	if (execResult == "")
	{
		PCPP_LOG_ERROR("rte_kni driver isn't loaded, DPDK KNI module cannot be initialized");
		return false;
	}
	PCPP_LOG_DEBUG("rte_kni driver is loaded");
	return true;
}

KniDeviceList::KniDeviceList() :
	m_Devices(),
	m_Initialized(true), m_KniUniqueId(0)
{
	m_Devices.reserve(MAX_KNI_DEVICES);
	if (!checkKniDriver())
	{
		m_Initialized = false;
		return;
	}
	if (!DpdkDeviceList::getInstance().isInitialized())
	{
		m_Initialized = false;
		return;
	}
	#if RTE_VERSION >= RTE_VERSION_NUM(18, 11, 0, 0)
		if (rte_kni_init(MAX_KNI_DEVICES) < 0)
		{
			PCPP_LOG_ERROR("Failed to initialize DPDK KNI module");
			m_Initialized = false;
		}
	#else
		rte_kni_init(MAX_KNI_DEVICES);
	#endif
}

KniDeviceList::~KniDeviceList()
{
	for (size_t i = 0; i < m_Devices.size(); ++i)
		delete m_Devices[i];
	rte_kni_close();
}

KniDeviceList& KniDeviceList::getInstance()
{
	static KniDeviceList g_KniDeviceList;
	return g_KniDeviceList;
}

KniDevice* KniDeviceList::createDevice(
	const KniDevice::KniDeviceConfiguration& config,
	const size_t mempoolSize
)
{
	if (!isInitialized())
		return NULL;
	KniDevice* kniDevice = getDeviceByName(std::string(config.name));
	if (kniDevice != NULL)
	{
		PCPP_LOG_ERROR("Attempt to create DPDK KNI device with same name: '" << config.name << "'");
		PCPP_LOG_DEBUG("Use KniDeviceList::getDeviceByName or KniDeviceList::getDeviceByPort.");
		return NULL;
	}
	if (config.portId != UINT16_MAX)
	{
		kniDevice = getDeviceByPort(config.portId);
		if (kniDevice != NULL)
		{
			PCPP_LOG_ERROR("Attempt to create DPDK KNI device with same port ID: " << config.portId);
			PCPP_LOG_DEBUG("Use KniDeviceList::getDeviceByName or KniDeviceList::getDeviceByPort.");
			return NULL;
		}
	}
	kniDevice = new KniDevice(config, mempoolSize, m_KniUniqueId++);
	m_Devices.push_back(kniDevice);
	return kniDevice;
}

void KniDeviceList::destroyDevice(KniDevice* kniDevice)
{
	m_Devices.erase(
		std::remove(
			m_Devices.begin(),
			m_Devices.end(),
			kniDevice
		),
		m_Devices.end()
	);
	delete kniDevice;
}

KniDevice* KniDeviceList::getDeviceByPort(const uint16_t portId)
{
	//? Linear search here is optimal for low count of devices.
	//? We assume that no one will create large count of devices or will rapidly search them.
	//? Same for <getDeviceByName> function
	KniDevice* kniDevice = NULL;
	if (!isInitialized())
		return kniDevice;
	for (size_t i = 0; i < m_Devices.size(); ++i)
	{
		kniDevice = m_Devices[i];
		if (kniDevice && kniDevice->m_DeviceInfo.portId == portId)
			return kniDevice;
	}
	return kniDevice = NULL;
}

KniDevice* KniDeviceList::getDeviceByName(const std::string& name)
{
	KniDevice* kniDevice = NULL;
	if (!isInitialized())
		return kniDevice;
	for (size_t i = 0; i < m_Devices.size(); ++i)
	{
		kniDevice = m_Devices[i];
		if (kniDevice && kniDevice->m_DeviceInfo.name == name)
			return kniDevice;
	}
	return kniDevice = NULL;
}

KniDeviceList::KniCallbackVersion KniDeviceList::callbackVersion()
{
	#if RTE_VERSION >= RTE_VERSION_NUM(17, 11, 0, 0)
		return KniDeviceList::CALLBACKS_NEW;
	#else
		return KniDeviceList::CALLBACKS_OLD;
	#endif
}

bool KniDeviceList::isCallbackSupported(const KniCallbackType cbType)
{
	switch (cbType)
	{
		case KniDeviceList::CALLBACK_MTU:
			/* fall through */
		case KniDeviceList::CALLBACK_LINK:
			return true;
		case KniDeviceList::CALLBACK_MAC:
			/* fall through */
		case KniDeviceList::CALLBACK_PROMISC:
	#if RTE_VERSION >= RTE_VERSION_NUM(18, 2, 0, 0)
			return true;
	#else
			return false;
	#endif
	}
	return false;
}
} // namespace pcpp
#endif /* defined(USE_DPDK) && defined(__linux__) */
