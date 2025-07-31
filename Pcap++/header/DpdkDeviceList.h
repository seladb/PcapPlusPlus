#pragma once

// GCOVR_EXCL_START

#include "SystemUtils.h"
#include "DpdkDevice.h"
#include "DeviceListBase.h"
#include "Logger.h"
#include <vector>

/// @file
/// For details about PcapPlusPlus support for DPDK see DpdkDevice.h file description

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	/// @class DpdkWorkerThread
	/// There are two ways to capture packets using DpdkDevice: one of them is using worker threads and the other way is
	/// using a callback which is invoked on each a burst of packets are captured (see
	/// DpdkDevice#startCaptureSingleThread() ). This class is a base class for implementing workers. A worker is
	/// basically a class that is activated by DpdkDeviceList#startDpdkWorkerThreads() and runs on a designated core.
	/// When it runs it can do whatever the user wants it to do. The most common use it running in an endless loop and
	/// receive, analyze and send packets using one or more DpdkDevice instances. It can do all kinds of processing for
	/// these packets. The only restriction for a worker class is that it must implement the 3 abstract methods stated
	/// in this class-interface for start running, stop running and get the core ID the worker is running on.
	class DpdkWorkerThread
	{
	public:
		/// A virtual d'tor. Can be overridden by child class if needed
		virtual ~DpdkWorkerThread() = default;

		/// An abstract method that must be implemented by child class. It's the indication for the worker to start
		/// running
		/// @param[in] coreId The core ID the worker is running on (should be returned in getCoreId() )
		/// @return True if all went well or false otherwise
		virtual bool run(uint32_t coreId) = 0;

		/// An abstract method that must be implemented by child class. It's the indication for the worker to stop
		/// running. After this method is called the caller expects the worker to stop running as fast as possible
		virtual void stop() = 0;

		/// An abstract method that must be implemented by child class. Get the core ID the worker is running on (as
		/// sent to the run() method as a parameter)
		/// @return The core ID the worker is running on
		virtual uint32_t getCoreId() const = 0;
	};

	class KniDeviceList;

	/// @class DpdkDeviceList
	/// A singleton class that encapsulates DPDK initialization and holds the list of DpdkDevice instances. As it's a
	/// singleton, it has only one active instance doesn't have a public c'tor. This class has several main uses:
	///    - it contains the initDpdk() static method which initializes the DPDK infrastructure. It should be called
	///      once in every application at its startup process
	///    - it contains the list of DpdkDevice instances and enables access to them
	///    - it has methods to start and stop worker threads. See more details in startDpdkWorkerThreads()
	class DpdkDeviceList : internal::DeviceListBase<DpdkDevice>
	{
		friend class KniDeviceList;

	private:
		using Base = internal::DeviceListBase<DpdkDevice>;

		bool m_IsInitialized;
		static bool m_IsDpdkInitialized;
		static uint32_t m_MBufPoolSizePerDevice;
		static uint16_t m_MBufDataSize;
		static CoreMask m_CoreMask;
		std::vector<DpdkDevice*> m_DpdkDeviceListView;
		std::vector<DpdkWorkerThread*> m_WorkerThreads;

		DpdkDeviceList();

		bool isInitialized() const
		{
			return (m_IsInitialized && m_IsDpdkInitialized);
		}
		bool initDpdkDevices(uint32_t mBufPoolSizePerDevice, uint16_t mMbufDataSize);
		static bool verifyHugePagesAndDpdkDriver();

		static int dpdkWorkerThreadStart(void* ptr);

	public:
		~DpdkDeviceList();

		/// As DpdkDeviceList is a singleton, this is the static getter to retrieve its instance. Note that if the
		/// static method initDpdk() was not called or returned false this instance won't be initialized and DpdkDevices
		/// won't be initialized either
		/// @return The singleton instance of DpdkDeviceList
		static DpdkDeviceList& getInstance()
		{
			static DpdkDeviceList instance;
			if (!instance.isInitialized())
				instance.initDpdkDevices(DpdkDeviceList::m_MBufPoolSizePerDevice, DpdkDeviceList::m_MBufDataSize);

			return instance;
		}

		/// A static method that has to be called once at the startup of every application that uses DPDK. It does
		/// several things:
		/// - verifies huge-pages are set and DPDK kernel module is loaded, unless specifically asked not to (these are
		///   set by the setup_dpdk.py external script that has to be run before application is started)
		/// - initializes the DPDK infrastructure
		/// - creates DpdkDevice instances for all ports available for DPDK
		///
		/// @param[in] coreMask The cores to initialize DPDK with. After initialization, DPDK will only be able to use
		/// these cores for its work. The core mask should have a bit set for every core to use. For example: if the
		/// user want to use cores 1,2 the core mask should be 6 (binary: 110)
		/// @param[in] mBufPoolSizePerDevice The mbuf pool size each DpdkDevice will have. This has to be a number which
		/// is a power of 2 minus 1, for example: 1023 (= 2^10-1) or 4,294,967,295 (= 2^32-1), etc. This is a DPDK
		/// limitation, not PcapPlusPlus. The size of the mbuf pool size dictates how many packets can be handled by the
		/// application at the same time. For example: if pool size is 1023 it means that no more than 1023 packets can
		/// be handled or stored in application memory at every point in time
		/// @param[in] mBufDataSize The size of data buffer in each mbuf. If this value is less than 1, we will use
		/// RTE_MBUF_DEFAULT_BUF_SIZE.
		/// @param[in] masterCore The core DPDK will use as master to control all worker thread. The default, unless set
		/// otherwise, is 0
		/// @param[in] initDpdkArgc Number of optional arguments
		/// @param[in] initDpdkArgv Optional arguments
		/// @param[in] appName Program name to be provided for the DPDK
		/// @param[in] verifyHugePagesAndDriver Verify huge-pages are set and DPDK kernel module is loaded. The default
		/// value it true
		/// @return True if initialization succeeded or false if huge-pages or DPDK kernel driver are not loaded, if
		/// mBufPoolSizePerDevice isn't power of 2 minus 1, if DPDK infra initialization failed or if DpdkDevice
		/// initialization failed. Anyway, if this method returned false it's impossible to use DPDK with PcapPlusPlus.
		/// You can get some more details about mbufs and pools in DpdkDevice.h file description or in DPDK web site
		static bool initDpdk(CoreMask coreMask, uint32_t mBufPoolSizePerDevice, uint16_t mBufDataSize = 0,
		                     uint8_t masterCore = 0, uint32_t initDpdkArgc = 0, char** initDpdkArgv = nullptr,
		                     const std::string& appName = "pcapplusplusapp", bool verifyHugePagesAndDriver = true);

		/// Get a DpdkDevice by port ID
		/// @param[in] portId The port ID
		/// @return A pointer to the DpdkDevice or nullptr if no such device is found
		DpdkDevice* getDeviceByPort(int portId) const;

		/// Get a DpdkDevice by port PCI address
		/// @param[in] pciAddr The port PCI address
		/// @return A pointer to the DpdkDevice or nullptr if no such device is found
		DpdkDevice* getDeviceByPciAddress(const std::string& pciAddr) const;

		/// @return A vector of all DpdkDevice instances
		const std::vector<DpdkDevice*>& getDpdkDeviceList() const
		{
			return m_DpdkDeviceListView;
		}

		/// @return DPDK master core which is the core that initializes the application
		SystemCore getDpdkMasterCore() const;

		/// Change the log level of all modules of DPDK
		/// @param[in] logLevel The log level to set. Logger#Info is RTE_LOG_NOTICE and Logger#Debug is RTE_LOG_DEBUG
		void setDpdkLogLevel(Logger::LogLevel logLevel);

		/// @return The current DPDK log level. RTE_LOG_NOTICE and lower are considered as Logger#Info. RTE_LOG_INFO or
		/// RTE_LOG_DEBUG are considered as Logger#Debug
		Logger::LogLevel getDpdkLogLevel() const;

		/// Order DPDK to write all its logs to a file
		/// @param[in] logFile The file to write to
		/// @return True if action succeeded, false otherwise
		bool writeDpdkLogToFile(FILE* logFile);

		/// There are two ways to capture packets using DpdkDevice: one of them is using worker threads and the other
		/// way is setting a callback which is invoked each time a burst of packets is captured (see
		/// DpdkDevice#startCaptureSingleThread() ). This method implements the first way. See a detailed description of
		/// workers in DpdkWorkerThread class description. This method gets a vector of workers (classes that implement
		/// the DpdkWorkerThread interface) and a core mask and starts a worker thread on each core (meaning - call the
		/// worker's DpdkWorkerThread#run() method). Workers usually run in an endless loop and will be ordered to stop
		/// by calling stopDpdkWorkerThreads().<BR> Note that number of cores in the core mask must be equal to the
		/// number of workers. In addition it's impossible to run a worker thread on DPDK master core, so the core mask
		/// shouldn't include the master core (you can find the master core by calling getDpdkMasterCore() ).
		/// @param[in] coreMask The bitmask of cores to run worker threads on. This list shouldn't include DPDK master
		/// core
		/// @param[in] workerThreadsVec A vector of worker instances to run (classes who implement the DpdkWorkerThread
		/// interface). Number of workers in this vector must be equal to the number of cores in the core mask. Notice
		/// that the instances of DpdkWorkerThread shouldn't be freed until calling stopDpdkWorkerThreads() as these
		/// instances are running
		/// @return True if all worker threads started successfully or false if: DPDK isn't initialized (initDpdk()
		/// wasn't called or returned false), number of cores differs from number of workers, core mask includes DPDK
		/// master core or if one of the worker threads couldn't be run
		bool startDpdkWorkerThreads(CoreMask coreMask, std::vector<DpdkWorkerThread*>& workerThreadsVec);

		/// Assuming worker threads are running, this method orders them to stop by calling DpdkWorkerThread#stop().
		/// Then it waits until they stop running
		void stopDpdkWorkerThreads();
	};

}  // namespace pcpp

// GCOVR_EXCL_STOP
