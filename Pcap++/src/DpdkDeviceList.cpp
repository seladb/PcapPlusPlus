#ifdef USE_DPDK

// GCOVR_EXCL_START

#define LOG_MODULE PcapLogModuleDpdkDevice

#define __STDC_LIMIT_MACROS
#define __STDC_FORMAT_MACROS

#include "DpdkDeviceList.h"
#include "Logger.h"

#include <rte_config.h>
#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_version.h>

#include <sstream>
#include <iomanip>
#include <string>
#include <algorithm>
#include <unistd.h>

#if (RTE_VER_YEAR < 21) || (RTE_VER_YEAR == 21 && RTE_VER_MONTH < 11)
#define GET_MASTER_CORE rte_get_master_lcore
#define MASTER_LCORE "--master-lcore"
#else
#define GET_MASTER_CORE rte_get_main_lcore
#define MASTER_LCORE "--main-lcore"
#endif

namespace pcpp
{

bool DpdkDeviceList::m_IsDpdkInitialized = false;
CoreMask DpdkDeviceList::m_CoreMask = 0;
uint32_t DpdkDeviceList::m_MBufPoolSizePerDevice = 0;

DpdkDeviceList::DpdkDeviceList()
{
	m_IsInitialized = false;
}

DpdkDeviceList::~DpdkDeviceList()
{
	for (std::vector<DpdkDevice*>::iterator iter = m_DpdkDeviceList.begin(); iter != m_DpdkDeviceList.end(); iter++)
	{
		delete (*iter);
	}

	m_DpdkDeviceList.clear();
}

bool DpdkDeviceList::initDpdk(CoreMask coreMask, uint32_t mBufPoolSizePerDevice, uint8_t masterCore, uint32_t initDpdkArgc, char **initDpdkArgv, const std::string& appName)
{
	char **initDpdkArgvBuffer;

	if (m_IsDpdkInitialized)
	{
		if (coreMask == m_CoreMask)
			return true;
		else
		{
			PCPP_LOG_ERROR("Trying to re-initialize DPDK with a different core mask");
			return false;
		}
	}

	if (!verifyHugePagesAndDpdkDriver())
	{
		return false;
	}

	// verify mBufPoolSizePerDevice is power of 2 minus 1
	bool isPoolSizePowerOfTwoMinusOne = !(mBufPoolSizePerDevice == 0) && !((mBufPoolSizePerDevice+1) & (mBufPoolSizePerDevice));
	if (!isPoolSizePowerOfTwoMinusOne)
	{
		PCPP_LOG_ERROR("mBuf pool size must be a power of two minus one: n = (2^q - 1). It's currently: " << mBufPoolSizePerDevice);
		return false;
	}


	std::stringstream dpdkParamsStream;
	dpdkParamsStream << appName << " ";
	dpdkParamsStream << "-n ";
	dpdkParamsStream << "2 ";
	dpdkParamsStream << "-c ";
	dpdkParamsStream << "0x" << std::hex << std::setw(2) << std::setfill('0') << coreMask << " ";
	dpdkParamsStream << MASTER_LCORE << " ";
	dpdkParamsStream << (int)masterCore << " ";

	uint32_t i = 0;
	while (i < initDpdkArgc && initDpdkArgv[i] != NULL)
	{
		dpdkParamsStream << initDpdkArgv[i] << " ";
		i++;
	}

	// Should be equal to the number of static params
	initDpdkArgc += 7;
	std::string dpdkParamsArray[initDpdkArgc];
	initDpdkArgvBuffer = new char*[initDpdkArgc];
	i = 0;
	while (dpdkParamsStream.good() && i < initDpdkArgc)
	{
		dpdkParamsStream >> dpdkParamsArray[i];
		initDpdkArgvBuffer[i] = new char[dpdkParamsArray[i].length() + 1];
		strcpy(initDpdkArgvBuffer[i], dpdkParamsArray[i].c_str());
		i++;
	}

	char* lastParam = initDpdkArgvBuffer[i-1];

	for (i = 0; i < initDpdkArgc; i++)
	{
		PCPP_LOG_DEBUG("DPDK initialization params: " << initDpdkArgvBuffer[i]);
	}

	optind = 1;
	// init the EAL
	int ret = rte_eal_init(initDpdkArgc, (char**)initDpdkArgvBuffer);
	if (ret < 0)
	{
		PCPP_LOG_ERROR("failed to init the DPDK EAL");
		return false;
	}

	for (i = 0; i < initDpdkArgc-1; i++)
	{
		delete [] initDpdkArgvBuffer[i];
	}
	delete [] lastParam;

	delete [] initDpdkArgvBuffer;

	m_CoreMask = coreMask;
	m_IsDpdkInitialized = true;

	m_MBufPoolSizePerDevice = mBufPoolSizePerDevice;
	DpdkDeviceList::getInstance().setDpdkLogLevel(Logger::Info);
	return DpdkDeviceList::getInstance().initDpdkDevices(m_MBufPoolSizePerDevice);
}

bool DpdkDeviceList::initDpdkDevices(uint32_t mBufPoolSizePerDevice)
{
	if (!m_IsDpdkInitialized)
	{
		PCPP_LOG_ERROR("DPDK is not initialized!! Please call DpdkDeviceList::initDpdk(coreMask, mBufPoolSizePerDevice) before start using DPDK devices");
		return false;
	}

	if (m_IsInitialized)
		return true;

#if (RTE_VER_YEAR < 18) || (RTE_VER_YEAR == 18 && RTE_VER_MONTH < 5)
	int numOfPorts = (int)rte_eth_dev_count();
#else
	int numOfPorts = (int)rte_eth_dev_count_avail();
#endif

	if (numOfPorts <= 0)
	{
		PCPP_LOG_ERROR("Zero DPDK ports are initialized. Something went wrong while initializing DPDK");
		return false;
	}

	PCPP_LOG_DEBUG("Found " << numOfPorts << " DPDK ports. Constructing DpdkDevice for each one");

	// Initialize a DpdkDevice per port
	for (int i = 0; i < numOfPorts; i++)
	{
		DpdkDevice* newDevice = new DpdkDevice(i, mBufPoolSizePerDevice);
		PCPP_LOG_DEBUG("DpdkDevice #" << i << ": Name='" << newDevice->getDeviceName() << "', PCI-slot='" << newDevice->getPciAddress() << "', PMD='" << newDevice->getPMDName() << "', MAC Addr='" << newDevice->getMacAddress() << "'");
		m_DpdkDeviceList.push_back(newDevice);
	}

	m_IsInitialized = true;
	return true;
}

DpdkDevice* DpdkDeviceList::getDeviceByPort(int portId) const
{
	if (!isInitialized())
	{
		PCPP_LOG_ERROR("DpdkDeviceList not initialized");
		return NULL;
	}

	if ((uint32_t)portId >= m_DpdkDeviceList.size())
	{
		return NULL;
	}

	return m_DpdkDeviceList.at(portId);
}

DpdkDevice* DpdkDeviceList::getDeviceByPciAddress(const std::string& pciAddr) const
{
	if (!isInitialized())
	{
		PCPP_LOG_ERROR("DpdkDeviceList not initialized");
		return NULL;
	}

	for (std::vector<DpdkDevice*>::const_iterator iter = m_DpdkDeviceList.begin(); iter != m_DpdkDeviceList.end(); iter++)
	{
		if ((*iter)->getPciAddress() == pciAddr)
			return (*iter);
	}

	return NULL;
}

bool DpdkDeviceList::verifyHugePagesAndDpdkDriver()
{
	std::string execResult = executeShellCommand("cat /proc/meminfo | grep -s HugePages_Total | awk '{print $2}'");
	// trim '\n' at the end
	execResult.erase(std::remove(execResult.begin(), execResult.end(), '\n'), execResult.end());

	// convert the result to long
	char* endPtr;
	long totalHugePages = strtol(execResult.c_str(), &endPtr, 10);

	PCPP_LOG_DEBUG("Total number of huge-pages is " << totalHugePages);

	if (totalHugePages <= 0)
	{
		PCPP_LOG_ERROR("Huge pages aren't set, DPDK cannot be initialized. Please run <PcapPlusPlus_Root>/setup_dpdk.sh");
		return false;
	}

	execResult = executeShellCommand("lsmod | grep -s igb_uio");
	if (execResult == "")
	{
		execResult = executeShellCommand("modinfo -d uio_pci_generic");
		if (execResult.find("ERROR") != std::string::npos)
		{
			execResult = executeShellCommand("modinfo -d vfio-pci");
			if (execResult.find("ERROR") != std::string::npos)
			{
				PCPP_LOG_ERROR("None of igb_uio, uio_pci_generic, vfio-pci kernel modules are loaded so DPDK cannot be initialized. Please run <PcapPlusPlus_Root>/setup_dpdk.sh");
				return false;
			}
			else
			{
				PCPP_LOG_DEBUG("vfio-pci module is loaded");
			}
		}
		else
		{
			PCPP_LOG_DEBUG("uio_pci_generic module is loaded");
		}
	}
	else
		PCPP_LOG_DEBUG("igb_uio driver is loaded");

	return true;
}

SystemCore DpdkDeviceList::getDpdkMasterCore() const
{
	return SystemCores::IdToSystemCore[GET_MASTER_CORE()];
}

void DpdkDeviceList::setDpdkLogLevel(Logger::LogLevel logLevel)
{
#if (RTE_VER_YEAR > 17) || (RTE_VER_YEAR == 17 && RTE_VER_MONTH >= 11)
	if (logLevel == Logger::Info)
		rte_log_set_global_level(RTE_LOG_NOTICE);
	else // logLevel == Logger::Debug
		rte_log_set_global_level(RTE_LOG_DEBUG);
#else
	if (logLevel == Logger::Info)
		rte_set_log_level(RTE_LOG_NOTICE);
	else // logLevel == Logger::Debug
		rte_set_log_level(RTE_LOG_DEBUG);
#endif
}

Logger::LogLevel DpdkDeviceList::getDpdkLogLevel() const
{
#if (RTE_VER_YEAR > 17) || (RTE_VER_YEAR == 17 && RTE_VER_MONTH >= 11)
	if (rte_log_get_global_level() <= RTE_LOG_NOTICE)
#else
	if (rte_get_log_level() <= RTE_LOG_NOTICE)
#endif
		return Logger::Info;
	else
		return Logger::Debug;
}

bool DpdkDeviceList::writeDpdkLogToFile(FILE* logFile)
{
	return (rte_openlog_stream(logFile) == 0);
}

int DpdkDeviceList::dpdkWorkerThreadStart(void *ptr)
{
	DpdkWorkerThread* workerThread = (DpdkWorkerThread*)ptr;
	workerThread->run(rte_lcore_id());
	return 0;
}

bool DpdkDeviceList::startDpdkWorkerThreads(CoreMask coreMask, std::vector<DpdkWorkerThread*>& workerThreadsVec)
{
	if (!isInitialized())
	{
		PCPP_LOG_ERROR("DpdkDeviceList not initialized");
		return false;
	}

	CoreMask tempCoreMask = coreMask;
	size_t numOfCoresInMask = 0;
	int coreNum = 0;
	while (tempCoreMask > 0)
	{
		if (tempCoreMask & 1)
		{
			if (!rte_lcore_is_enabled(coreNum))
			{
				PCPP_LOG_ERROR("Trying to use core #" << coreNum << " which isn't initialized by DPDK");
				return false;
			}

			numOfCoresInMask++;
		}
		tempCoreMask = tempCoreMask >> 1;
		coreNum++;
	}

	if (numOfCoresInMask == 0)
	{
		PCPP_LOG_ERROR("Number of cores in mask is 0");
		return false;
	}

	if (numOfCoresInMask != workerThreadsVec.size())
	{
		PCPP_LOG_ERROR("Number of cores in core mask different from workerThreadsVec size");
		return false;
	}

	if (coreMask & getDpdkMasterCore().Mask)
	{
		PCPP_LOG_ERROR("Cannot run worker thread on DPDK master core");
		return false;
	}

	m_WorkerThreads.clear();
	uint32_t index = 0;
	std::vector<DpdkWorkerThread*>::iterator iter = workerThreadsVec.begin();
	while (iter != workerThreadsVec.end())
	{
		SystemCore core = SystemCores::IdToSystemCore[index];
		if (!(coreMask & core.Mask))
		{
			index++;
			continue;
		}

		int err = rte_eal_remote_launch(dpdkWorkerThreadStart, *iter, core.Id);
		if (err != 0)
		{
			for (std::vector<DpdkWorkerThread*>::iterator iter2 = workerThreadsVec.begin(); iter2 != iter; iter2++)
			{
				(*iter)->stop();
				rte_eal_wait_lcore((*iter)->getCoreId());
				PCPP_LOG_DEBUG("Thread on core [" << (*iter)->getCoreId() << "] stopped");
			}
			PCPP_LOG_ERROR("Cannot create worker thread #" << core.Id << ". Error was: [" << strerror(err) << "]");
			return false;
		}
		m_WorkerThreads.push_back(*iter);

		index++;
		iter++;
	}

	return true;
}

void DpdkDeviceList::stopDpdkWorkerThreads()
{
	if (m_WorkerThreads.empty())
	{
		PCPP_LOG_ERROR("No worker threads were set");
		return;
	}

	for (std::vector<DpdkWorkerThread*>::iterator iter = m_WorkerThreads.begin(); iter != m_WorkerThreads.end(); iter++)
	{
		(*iter)->stop();
		rte_eal_wait_lcore((*iter)->getCoreId());
		PCPP_LOG_DEBUG("Thread on core [" << (*iter)->getCoreId() << "] stopped");
	}

	m_WorkerThreads.clear();
	std::vector<DpdkWorkerThread*>(m_WorkerThreads).swap(m_WorkerThreads);

	PCPP_LOG_DEBUG("All worker threads stopped");
}

} // namespace pcpp

// GCOVR_EXCL_STOP

#endif /* USE_DPDK */
