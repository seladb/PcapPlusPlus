#ifndef PCAPPP_DPDK_DEVICE_LIST
#define PCAPPP_DPDK_DEVICE_LIST

#ifdef USE_DPDK

#include <SystemUtils.h>
#include <DpdkDevice.h>
#include <Logger.h>
#include <vector>

/**
 * @file
 * For PcapPlusPlus DPDK support see DpdkDevice.h
 */

/**
 * @class DpdkWorkerThread
 * There are two ways to capture packets using DpdkDevice: one of them is using worker threads and the other way is using
 * a callback which is invoked on each a burst of packets are captured (@see DpdkDevice#startCaptureSingleThread() ). This class
 * is a base class for implementing workers. A worker is basically a class that is activated by DpdkDeviceList#startDpdkWorkerThreads()
 * and runs on a designated core. When it runs it can do whatever the user wants it to do. The most common use it running in an
 * endless loop and receive and/or send packets with one or more DpdkDevice instance(s). It can do all kinds of processing for
 * these packets. The only restriction for a worker class is that it must implement the 3 abstract methods for start running,
 * stop running and get the core ID it's running on.
 */
class DpdkWorkerThread
{
public:
	/**
	 * A virtual d'tor. Can be overridden by child classes if needed
	 */
	virtual ~DpdkWorkerThread() {}

	/**
	 * An abstract method that must be implemented by child class. It's the indication for the worker to start running
	 * @param[in] coreId The core ID the worker is running on
	 * @return True if all went well or false otherwise
	 */
	virtual bool run(uint32_t coreId) = 0;

	/**
	 * An abstract method that must be implemented by child class. It's the indication for the worker to stop running. After
	 * this method is called the caller expects the worker to stop running as fast as possible
	 */
	virtual void stop() = 0;

	/**
	 * An abstract method that must be implemented by child class. Get the core ID the worker is running on (as sent to the run() method)
	 * @return The core ID the worker is running on
	 */
	virtual uint32_t getCoreId() = 0;
};


/**
 * @class DpdkDeviceList
 * A singleton class that encapsulates DPDK initialization and holds DpdkDevice instances. As this it's a singleton, it has only
 * one active instance doesn't have a public c'tor. This class have several main uses:
 * - it contains the initDpdk() static method that needs to be called once at the startup of every application to initialize DPDK
 * - it contains the list of DpdkDevice instances and enables access to them
 * - it has methods to start and stop worker threads
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

	/**
	 * As DpdkDeviceList is a singleton, this is the static method to retrieve its instance. Notice that if the static method
	 * initDpdk() was not called or returned false this instance won't be initialized and DpdkDevices won't be initialized either
	 * @return The singleton instance of DpdkDeviceList
	 */
	static inline DpdkDeviceList& getInstance()
	{
		static DpdkDeviceList instance;
		if (!instance.isInitialized())
			instance.initDpdkDevices(DpdkDeviceList::m_MBufPoolSizePerDevice);

		return instance;
	}

	/**
	 * A static method that has to be called once at the beginning of every application that uses DPDK. This method
	 * does various things:
	 * - verifies huge-pages are set and DPDK kernel module is loaded (these are set by the setup-dpdk.sh external script that
	 * has to be run before application is started)
	 * - initializes the DPDK infrastructure
	 * - initializes the DpdkDevice instances for all ports available for DPDK
	 * @param[in] coreMask The cores to initialize DPDK with. After initialization, DPDK will only be able to use these cores
	 * for its work
	 * @param[in] mBufPoolSizePerDevice The mbuf pool size each DpdkDevice will have. This has to be a number which is a power of 2
	 * minus 1, for example: 1023 (= 2^10-1), 4,294,967,295 (= 2^32-1), etc. This is a DPDK limitation, regardless of PcapPlusPlus.
	 * The size of the mbuf pool size dictates how many packets can be handled by an application at the same time. For example: if
	 * pool size is 1023 it means that no more than 1023 packets can be handled or stored in application memory at every point in time
	 * @return True if initialization succeeded or false if huge-pages or DPDK kernel driver are not loaded, if mBufPoolSizePerDevice
	 * isn't power of 2 minus 1, if DPDK infra initialization failed or if DpdkDevice initialization failed. Anyway, if this method
	 * returned false it's impossible to use DPDK with PcapPlusPlus
	 */
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

	/**
	 * Change the log level of all modules of DPDK
	 * @param[in] logLevel The log level to set. LoggerPP#Normal is RTE_LOG_NOTICE and LoggerPP#Debug is RTE_LOG_DEBUG
	 */
	void setDpdkLogLevel(LoggerPP::LogLevel logLevel);

	/**
	 * @return Current DPDK log level. RTE_LOG_NOTICE and lower will be considered as LoggerPP#Normal. RTE_LOG_INFO or RTE_LOG_DEBUG
	 * will be considered as LoggerPP#Debug
	 */
	LoggerPP::LogLevel getDpdkLogLevel();

	/**
	 * Order DPDK to write all its logs to a file
	 * @param[in] logFile The file to write to
	 * @return True if action succeeded, false otherwise
	 */
	bool writeDpdkLogToFile(FILE* logFile);

	/**
	 * There are two ways to capture packets using DpdkDevice: one of them is using worker threads and the other way is setting
	 * a callback which is invoked each time a burst of packets is captured (@see DpdkDevice#startCaptureSingleThread() ). This
	 * method implements the first way. See a description of worker thread in DpdkWorkerThread class description. This method
	 * gets a vector of DpdkWorkerThread instances and a core mask and starts a worker thread on each core (meaning - call the
	 * worker thread's DpdkWorkerThread#run() method). Worker threads usually run in an endless loop and will be ordered to stop
	 * by calling stopDpdkWorkerThreads().<BR>
	 * Notice number of cores in the core mask must be equal to number of worker threads. In addition it's impossible to run a
	 * worker thread on DPDK master core, so the core mask shouldn't include the master core (user can find the master core by
	 * calling getDpdkMasterCore() ).
	 * @param[in] coreMask The list of core to run worker threads on. Notice this list shouldn't include DPDK master core
	 * @param[in] workerThreadsVec A vector of worker thread instances to run. Notice that number of worker threads must equal
	 * to number of cores in the core mask. Notice the instances of DpdkWorkerThread shouldn't be freed after calling this method
	 * as these instances are running
	 * @return True if all worker thread started successfully or false if: DPDK isn't initialized (initDpdk() wasn't called or
	 * returned false), if number of cores differs from number of worker threads, if core mask includes DPDK master core or if
	 * couldn't run one of the worker threads
	 */
	bool startDpdkWorkerThreads(CoreMask coreMask, vector<DpdkWorkerThread*>& workerThreadsVec);

	/**
	 * Assuming worker threads are running, this method orders them to stop by calling DpdkWorkerThread#stop(). Then it waits until
	 * they stop running and exits
	 */
	void stopDpdkWorkerThreads();
};

#endif /* USE_DPDK */

#endif /* PCAPPP_DPDK_DEVICE_LIST */
