#ifdef USE_DPDK

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

#include <iomanip>
#include <algorithm>
#include <utility>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

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


struct DpdkOptionDescription
{
	DpdkOption::Type type;
	const char* name;
	size_t nameLen; // the name length including trailing '\0'
	bool hasArgument;
	const char* typeStr;
};

static const DpdkOptionDescription optionDescr[] =
{
	{ DpdkOption::Type::OptionServiceCoreMask,      "-s",                  sizeof("-s"),                  true,  "ServiceCoreMask"      },
	{ DpdkOption::Type::OptionPciBlackList,         "-b",                  sizeof("-b"),                  true,  "PciBlackList"         },
	{ DpdkOption::Type::OptionPciWhiteList,         "-w",                  sizeof("-w"),                  true,  "PciWhiteList"         },
	{ DpdkOption::Type::OptionVirtualDevice,        "--vdev",              sizeof("--vdev"),              true,  "VirtualDevice"        },
	{ DpdkOption::Type::OptionLoadExternalDriver,   "-d",                  sizeof("-d"),                  true,  "LoadExternalDriver"   },
	{ DpdkOption::Type::OptionNoPci,                "--no-pci",            sizeof("--no-pci"),            false, "NoPci"                },
	{ DpdkOption::Type::OptionVmWareTsc,            "--vmware-tsc-map",    sizeof("--vmware-tsc-map"),    false, "VmWareTsc"            },
	{ DpdkOption::Type::OptionNoHPET,               "--no-hpet",           sizeof("--no-hpet"),           false, "NoHPET"               },
	{ DpdkOption::Type::OptionFilePrefix,           "--file-prefix",       sizeof("--file-prefix"),       true,  "FilePrefix"           },
	{ DpdkOption::Type::OptionMemChannels,          "-n",                  sizeof("-n"),                  true,  "MemChannels"          },
	{ DpdkOption::Type::OptionMemPreallocate,       "-m",                  sizeof("-m"),                  true,  "MemPreallocate"       },
	{ DpdkOption::Type::OptionMemIovaMode,          "--iova-mode",         sizeof("--iova-mode"),         true,  "MemIovaMode"          },
	{ DpdkOption::Type::OptionMemSocketPreallocate, "--socket-mem",        sizeof("--socket-mem"),        true,  "MemSocketPreallocate" },
	{ DpdkOption::Type::OptionMemSocketLimit,       "--socket-limit",      sizeof("--socket-limit"),      true,  "MemSocketLimit"       },
	{ DpdkOption::Type::OptionMemFreeHugepages,     "--match-allocations", sizeof("--match-allocations"), false, "MemFreeHugepages"     },
	{ DpdkOption::Type::OptionLogLevel,             "--log-level",         sizeof("--log-level"),         true,  "LogLevel"             }
};
static const size_t optionDescrLen = sizeof(optionDescr) / sizeof(optionDescr[0]);


static const DpdkOptionDescription* findOptionDescription(DpdkOption::Type type)
{
	for(size_t i = 0; i < optionDescrLen; ++i)
		if(optionDescr[i].type == type)
			return &optionDescr[i];

	return NULL;
}


bool DpdkDeviceList::initDpdk(CoreMask coreMask, uint32_t mBufPoolSizePerDevice, uint8_t masterCore, const std::vector<DpdkOption>& options)
{
	if (m_IsDpdkInitialized)
	{
		if (coreMask == m_CoreMask)
			return true;
		else
		{
			LOG_ERROR("Trying to re-initialize DPDK with a different core mask");
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
		LOG_ERROR("mBuf pool size must be a power of two minus one: n = (2^q - 1). It's currently: %d", mBufPoolSizePerDevice);
		return false;
	}

	std::vector<char*> initDpdkArgv;
	initDpdkArgv.reserve(options.size() * 2 + 1 /* app name */ + 2 /* master lcore */ + 2 /* core mask */ + 2 /* mem channels if an option is not defined */);

	// creating mandatory options
	char tempBuf[32];
	typedef std::pair<std::string, std::string> MandatoryOption;
	std::vector<MandatoryOption> mandatoryOptions;

	// application name
	mandatoryOptions.push_back(std::make_pair("pcapplusplusapp", std::string()));
	// core mask
	snprintf(tempBuf, sizeof(tempBuf), "0x%X", coreMask);
	mandatoryOptions.push_back(std::make_pair("-c", tempBuf));
	// master lcore
	snprintf(tempBuf, sizeof(tempBuf), "%d", masterCore);
	mandatoryOptions.push_back(std::make_pair("--master-lcore", tempBuf));
	// mem channels
	mandatoryOptions.push_back(std::make_pair("-n", "2"));

	for (size_t i = 0; i < mandatoryOptions.size(); ++i)
	{
		const MandatoryOption& opt = mandatoryOptions[i];
		// option name
		initDpdkArgv.push_back(new char[opt.first.length() + 1]);
		strcpy(initDpdkArgv.back(), opt.first.c_str());
		// option value
		if (!opt.second.empty())
		{
			initDpdkArgv.push_back(new char[opt.second.length() + 1]);
			strcpy(initDpdkArgv.back(), opt.second.c_str());
		}
	}

	size_t optValueMemChannelsPos = initDpdkArgv.size() - 1;

	// processing the user-defined options
	for (size_t i = 0; i < options.size(); ++i)
	{
		const DpdkOption& userOption = options[i];

		if (userOption.type == DpdkOption::OptionUnknown)
			continue;

		const DpdkOptionDescription* optDescrPtr = findOptionDescription(userOption.type);
		if (optDescrPtr == NULL) // should not happen
			continue;

		if (optDescrPtr->hasArgument && userOption.value.empty())
		{
			LOG_ERROR("An option of type %s must have an argument", optDescrPtr->typeStr);
			return false;
		}

		// mandatory option overriden by the user
		if (optDescrPtr->type == DpdkOption::Type::OptionMemChannels)
		{
			delete[] initDpdkArgv[optValueMemChannelsPos];
			initDpdkArgv[optValueMemChannelsPos] = new char[userOption.value.length() + 1];
			strcpy(initDpdkArgv[optValueMemChannelsPos], userOption.value.c_str());
			continue;
		}

		// option name
		initDpdkArgv.push_back(new char[optDescrPtr->nameLen]);
		strcpy(initDpdkArgv.back(), optDescrPtr->name);

		// option value
		if (!userOption.value.empty())
		{
			initDpdkArgv.push_back(new char[userOption.value.length() + 1]);
			strcpy(initDpdkArgv.back(), userOption.value.c_str());
		}
	} // for, user-defined options

	if (IS_DEBUG)
	{
		for (size_t i = 0; i < initDpdkArgv.size(); ++i)
		{
			LOG_DEBUG("DPDK initialization params: %s", initDpdkArgv[i]);
		}
	}

	optind = 1;
	// init the EAL
	if (rte_eal_init(static_cast<int>(initDpdkArgv.size()), &initDpdkArgv[0]) < 0)
	{
		LOG_ERROR("failed to init the DPDK EAL");
		return false;
	}

	for (size_t i = 0; i < initDpdkArgv.size(); ++i)
		delete[] initDpdkArgv[i];

	m_CoreMask = coreMask;
	m_IsDpdkInitialized = true;

	m_MBufPoolSizePerDevice = mBufPoolSizePerDevice;
	DpdkDeviceList::getInstance().setDpdkLogLevel(LoggerPP::Normal);
	return DpdkDeviceList::getInstance().initDpdkDevices(m_MBufPoolSizePerDevice);
}

bool DpdkDeviceList::initDpdkDevices(uint32_t mBufPoolSizePerDevice)
{
	if (!m_IsDpdkInitialized)
	{
		LOG_ERROR("DPDK is not initialized!! Please call DpdkDeviceList::initDpdk(coreMask, mBufPoolSizePerDevice) before start using DPDK devices");
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
		LOG_ERROR("Zero DPDK ports are initialized. Something went wrong while initializing DPDK");
		return false;
	}

	LOG_DEBUG("Found %d DPDK ports. Constructing DpdkDevice for each one", numOfPorts);

	// Initialize a DpdkDevice per port
	for (int i = 0; i < numOfPorts; i++)
	{
		DpdkDevice* newDevice = new DpdkDevice(i, mBufPoolSizePerDevice);
		LOG_DEBUG("DpdkDevice #%d: Name='%s', PCI-slot='%s', PMD='%s', MAC Addr='%s'",
				i,
				newDevice->getDeviceName().c_str(),
				newDevice->getPciAddress().c_str(),
				newDevice->getPMDName().c_str(),
				newDevice->getMacAddress().toString().c_str());
		m_DpdkDeviceList.push_back(newDevice);
	}

	m_IsInitialized = true;
	return true;
}

DpdkDevice* DpdkDeviceList::getDeviceByPort(int portId) const
{
	if (!isInitialized())
	{
		LOG_ERROR("DpdkDeviceList not initialized");
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
		LOG_ERROR("DpdkDeviceList not initialized");
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

	LOG_DEBUG("Total number of huge-pages is %lu", totalHugePages);

	if (totalHugePages <= 0)
	{
		LOG_ERROR("Huge pages aren't set, DPDK cannot be initialized. Please run <PcapPlusPlus_Root>/setup_dpdk.sh");
		return false;
	}

	execResult = executeShellCommand("lsmod | grep -s igb_uio");
	if (execResult == "")
	{
		LOG_ERROR("igb_uio driver isn't loaded, DPDK cannot be initialized. Please run <PcapPlusPlus_Root>/setup_dpdk.sh");
		return false;

	}
	else
		LOG_DEBUG("igb_uio driver is loaded");

	return true;
}

SystemCore DpdkDeviceList::getDpdkMasterCore() const
{
	return SystemCores::IdToSystemCore[rte_get_master_lcore()];
}

void DpdkDeviceList::setDpdkLogLevel(LoggerPP::LogLevel logLevel)
{
#if (RTE_VER_YEAR > 17) || (RTE_VER_YEAR == 17 && RTE_VER_MONTH >= 11)
	if (logLevel == LoggerPP::Normal)
		rte_log_set_global_level(RTE_LOG_NOTICE);
	else // logLevel == LoggerPP::Debug
		rte_log_set_global_level(RTE_LOG_DEBUG);
#else
	if (logLevel == LoggerPP::Normal)
		rte_set_log_level(RTE_LOG_NOTICE);
	else // logLevel == LoggerPP::Debug
		rte_set_log_level(RTE_LOG_DEBUG);
#endif
}

LoggerPP::LogLevel DpdkDeviceList::getDpdkLogLevel() const
{
#if (RTE_VER_YEAR > 17) || (RTE_VER_YEAR == 17 && RTE_VER_MONTH >= 11)
	if (rte_log_get_global_level() <= RTE_LOG_NOTICE)
#else
	if (rte_get_log_level() <= RTE_LOG_NOTICE)
#endif
		return LoggerPP::Normal;
	else
		return LoggerPP::Debug;
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
		LOG_ERROR("DpdkDeviceList not initialized");
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
				LOG_ERROR("Trying to use core #%d which isn't initialized by DPDK", coreNum);
				return false;
			}

			numOfCoresInMask++;
		}
		tempCoreMask = tempCoreMask >> 1;
		coreNum++;
	}

	if (numOfCoresInMask == 0)
	{
		LOG_ERROR("Number of cores in mask is 0");
		return false;
	}

	if (numOfCoresInMask != workerThreadsVec.size())
	{
		LOG_ERROR("Number of cores in core mask different from workerThreadsVec size");
		return false;
	}

	if (coreMask & getDpdkMasterCore().Mask)
	{
		LOG_ERROR("Cannot run worker thread on DPDK master core");
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
				LOG_DEBUG("Thread on core [%d] stopped", (*iter)->getCoreId());
			}
			LOG_ERROR("Cannot create worker thread #%d. Error was: [%s]", core.Id, strerror(err));
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
		LOG_ERROR("No worker threads were set");
		return;
	}

	for (std::vector<DpdkWorkerThread*>::iterator iter = m_WorkerThreads.begin(); iter != m_WorkerThreads.end(); iter++)
	{
		(*iter)->stop();
		rte_eal_wait_lcore((*iter)->getCoreId());
		LOG_DEBUG("Thread on core [%d] stopped", (*iter)->getCoreId());
	}

	m_WorkerThreads.clear();
	std::vector<DpdkWorkerThread*>(m_WorkerThreads).swap(m_WorkerThreads);

	LOG_DEBUG("All worker threads stopped");
}

} // namespace pcpp

#endif /* USE_DPDK */
