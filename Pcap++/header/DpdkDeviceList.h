#ifndef PCAPPP_DPDK_DEVICE_LIST
#define PCAPPP_DPDK_DEVICE_LIST

#ifdef USE_DPDK

#include <SystemUtils.h>
#include <DpdkDevice.h>
#include <Logger.h>
#include <vector>

/// @file

/**
 * @class DpdkWorkerThread
 * TODO
 */
class DpdkWorkerThread
{
public:
	virtual ~DpdkWorkerThread() {}
	virtual bool run(uint32_t coreId) = 0;
	virtual void stop() = 0;
	virtual uint32_t getCoreId() = 0;
};


/**
 * @class DpdkDeviceList
 * TODO
 */
class DpdkDeviceList
{
private:
	bool m_IsInitialized;
	static bool m_IsDpdkInitialized;
	static uint32_t m_MBufPoolSizePerDevice;
	static CoreMask m_CoreMask;
	vector<DpdkDevice*> m_DpdkDeviceList;
	vector<DpdkWorkerThread*> m_WorkerThreads;

	DpdkDeviceList();

	inline bool isInitialized() { return (m_IsInitialized && m_IsDpdkInitialized); }
	bool initDpdkDevices(uint32_t mBufPoolSizePerDevice);
	static bool verifyHugePagesAndDpdkDriver();

	static int dpdkWorkerThreadStart(void *ptr);
public:

	~DpdkDeviceList();

	static inline DpdkDeviceList& getInstance()
	{
		static DpdkDeviceList instance;
		if (!instance.isInitialized())
			instance.initDpdkDevices(DpdkDeviceList::m_MBufPoolSizePerDevice);

		return instance;
	}

	static bool initDpdk(CoreMask coreMask, uint32_t mBufPoolSizePerDevice);

	/**
	 * Get a DpdkDevice by port ID
	 * @param[in] portId The port ID
	 * @return A pointer to the DpdkDevice or NULL if no such device found
	 */
	DpdkDevice* getDeviceByPort(int portId);

	/**
	 * Get a DpdkDevice by port PCI address
	 * @param[in] pciAddr The port PCI address
	 * @return A pointer to the DpdkDevice or NULL if no such device found
	 */
	DpdkDevice* getDeviceByPciAddress(const PciAddress& pciAddr);

	/**
	 * @return A vector of all DpdkDevice instances
	 */
	inline const vector<DpdkDevice*>& getDpdkDeviceList() { return m_DpdkDeviceList; }

	/**
	 * @return DPDK master core
	 */
	SystemCore getDpdkMasterCore();

	void setDpdkLogLevel(LoggerPP::LogLevel logLevel);

	LoggerPP::LogLevel getDpdkLogLevel();

	bool writeDpdkLogToFile(FILE* logFile);

	bool startDpdkWorkerThreads(CoreMask coreMask, vector<DpdkWorkerThread*>& workerThreadsVec);

	void stopDpdkWorkerThreads();
};

#endif /* USE_DPDK */

#endif /* PCAPPP_DPDK_DEVICE_LIST */
