#ifndef PCAPPP_DPDK_DEVICE_LIST
#define PCAPPP_DPDK_DEVICE_LIST

#include "SystemUtils.h"
#include "DpdkDevice.h"
#include "Logger.h"
#include <vector>
#include <string>

/**
 * @file
 * For details about PcapPlusPlus support for DPDK see DpdkDevice.h file description
 */

/**
* \namespace pcpp
* \brief The main namespace for the PcapPlusPlus lib
*/
namespace pcpp
{

	/**
	 * @class DpdkWorkerThread
	 * There are two ways to capture packets using DpdkDevice: one of them is using worker threads and the other way is using
	 * a callback which is invoked on each a burst of packets are captured (see DpdkDevice#startCaptureSingleThread() ). This class
	 * is a base class for implementing workers. A worker is basically a class that is activated by DpdkDeviceList#startDpdkWorkerThreads()
	 * and runs on a designated core. When it runs it can do whatever the user wants it to do. The most common use it running in an
	 * endless loop and receive, analyze and send packets using one or more DpdkDevice instances. It can do all kinds of processing for
	 * these packets. The only restriction for a worker class is that it must implement the 3 abstract methods stated in this class-interface
	 * for start running, stop running and get the core ID the worker is running on.
	 */
	class DpdkWorkerThread
	{
	public:
		/**
		 * A virtual d'tor. Can be overridden by child class if needed
		 */
		virtual ~DpdkWorkerThread() {}

		/**
		 * An abstract method that must be implemented by child class. It's the indication for the worker to start running
		 * @param[in] coreId The core ID the worker is running on (should be returned in getCoreId() )
		 * @return True if all went well or false otherwise
		 */
		virtual bool run(uint32_t coreId) = 0;

		/**
		 * An abstract method that must be implemented by child class. It's the indication for the worker to stop running. After
		 * this method is called the caller expects the worker to stop running as fast as possible
		 */
		virtual void stop() = 0;

		/**
		 * An abstract method that must be implemented by child class. Get the core ID the worker is running on (as sent to the run() method
		 * as a parameter)
		 * @return The core ID the worker is running on
		 */
		virtual uint32_t getCoreId() const = 0;
	};

	class KniDeviceList;
	struct DpdkOption;

	/**
	 * @class DpdkDeviceList
	 * A singleton class that encapsulates DPDK initialization and holds the list of DpdkDevice instances. As it's a singleton, it has only
	 * one active instance doesn't have a public c'tor. This class has several main uses:
	 *    - it contains the initDpdk() static method which initializes the DPDK infrastructure. It should be called once in every application at
	 *      its startup process
	 *    - it contains the list of DpdkDevice instances and enables access to them
	 *    - it has methods to start and stop worker threads. See more details in startDpdkWorkerThreads()
	 */
	class DpdkDeviceList
	{
		friend class KniDeviceList;
	private:
		bool m_IsInitialized;
		static bool m_IsDpdkInitialized;
		static uint32_t m_MBufPoolSizePerDevice;
		static CoreMask m_CoreMask;
		std::vector<DpdkDevice*> m_DpdkDeviceList;
		std::vector<DpdkWorkerThread*> m_WorkerThreads;

		DpdkDeviceList();

		bool isInitialized() const { return (m_IsInitialized && m_IsDpdkInitialized); }
		bool initDpdkDevices(uint32_t mBufPoolSizePerDevice);
		static bool verifyHugePagesAndDpdkDriver();

		static int dpdkWorkerThreadStart(void* ptr);
	public:

		~DpdkDeviceList();

		/**
		 * As DpdkDeviceList is a singleton, this is the static getter to retrieve its instance. Note that if the static method
		 * initDpdk() was not called or returned false this instance won't be initialized and DpdkDevices won't be initialized either
		 * @return The singleton instance of DpdkDeviceList
		 */
		static DpdkDeviceList& getInstance()
		{
			static DpdkDeviceList instance;
			if (!instance.isInitialized())
				instance.initDpdkDevices(DpdkDeviceList::m_MBufPoolSizePerDevice);

			return instance;
		}

		/**
		 * A static method that has to be called once at the startup of every application that uses DPDK. It does several things:
		 *    - verifies huge-pages are set and DPDK kernel module is loaded (these are set by the setup-dpdk.sh external script that
		 *      has to be run before application is started)
		 *    - initializes the DPDK infrastructure
		 *    - creates DpdkDevice instances for all ports available for DPDK
		 *
		 * @param[in] coreMask The cores to initialize DPDK with. After initialization, DPDK will only be able to use these cores
		 * for its work. The core mask should have a bit set for every core to use. For example: if the user want to use cores 1,2
		 * the core mask should be 6 (binary: 110)
		 * @param[in] mBufPoolSizePerDevice The mbuf pool size each DpdkDevice will have. This has to be a number which is a power of 2
		 * minus 1, for example: 1023 (= 2^10-1) or 4,294,967,295 (= 2^32-1), etc. This is a DPDK limitation, not PcapPlusPlus.
		 * The size of the mbuf pool size dictates how many packets can be handled by the application at the same time. For example: if
		 * pool size is 1023 it means that no more than 1023 packets can be handled or stored in application memory at every point in time
		 * @param[in] masterCore The core DPDK will use as master to control all worker thread. The default, unless set otherwise, is 0
		 * @param[in] options The optional list of parameters for initialization a DPDK
		 * @return True if initialization succeeded or false if huge-pages or DPDK kernel driver are not loaded, if mBufPoolSizePerDevice
		 * isn't power of 2 minus 1, if DPDK infra initialization failed or if DpdkDevice initialization failed. Anyway, if this method
		 * returned false it's impossible to use DPDK with PcapPlusPlus. You can get some more details about mbufs and pools in
		 * DpdkDevice.h file description or in DPDK web site
		 */
		static bool initDpdk(CoreMask coreMask, uint32_t mBufPoolSizePerDevice, uint8_t masterCore = 0, const std::vector<DpdkOption>& options = std::vector<DpdkOption>());

		/**
		 * Get a DpdkDevice by port ID
		 * @param[in] portId The port ID
		 * @return A pointer to the DpdkDevice or NULL if no such device is found
		 */
		DpdkDevice* getDeviceByPort(int portId) const;

		/**
		 * Get a DpdkDevice by port PCI address
		 * @param[in] pciAddr The port PCI address
		 * @return A pointer to the DpdkDevice or NULL if no such device is found
		 */
		DpdkDevice* getDeviceByPciAddress(const std::string& pciAddr) const;

		/**
		 * @return A vector of all DpdkDevice instances
		 */
		const std::vector<DpdkDevice*>& getDpdkDeviceList() const { return m_DpdkDeviceList; }

		/**
		 * @return DPDK master core which is the core that initializes the application
		 */
		SystemCore getDpdkMasterCore() const;

		/**
		 * Change the log level of all modules of DPDK
		 * @param[in] logLevel The log level to set. LoggerPP#Normal is RTE_LOG_NOTICE and LoggerPP#Debug is RTE_LOG_DEBUG
		 */
		void setDpdkLogLevel(LoggerPP::LogLevel logLevel);

		/**
		 * @return The current DPDK log level. RTE_LOG_NOTICE and lower are considered as LoggerPP#Normal. RTE_LOG_INFO or RTE_LOG_DEBUG
		 * are considered as LoggerPP#Debug
		 */
		LoggerPP::LogLevel getDpdkLogLevel() const;

		/**
		 * Order DPDK to write all its logs to a file
		 * @param[in] logFile The file to write to
		 * @return True if action succeeded, false otherwise
		 */
		bool writeDpdkLogToFile(FILE* logFile);

		/**
		 * There are two ways to capture packets using DpdkDevice: one of them is using worker threads and the other way is setting
		 * a callback which is invoked each time a burst of packets is captured (see DpdkDevice#startCaptureSingleThread() ). This
		 * method implements the first way. See a detailed description of workers in DpdkWorkerThread class description. This method
		 * gets a vector of workers (classes that implement the DpdkWorkerThread interface) and a core mask and starts a worker thread
		 * on each core (meaning - call the worker's DpdkWorkerThread#run() method). Workers usually run in an endless loop and will
		 * be ordered to stop by calling stopDpdkWorkerThreads().<BR>
		 * Note that number of cores in the core mask must be equal to the number of workers. In addition it's impossible to run a
		 * worker thread on DPDK master core, so the core mask shouldn't include the master core (you can find the master core by
		 * calling getDpdkMasterCore() ).
		 * @param[in] coreMask The bitmask of cores to run worker threads on. This list shouldn't include DPDK master core
		 * @param[in] workerThreadsVec A vector of worker instances to run (classes who implement the DpdkWorkerThread interface).
		 * Number of workers in this vector must be equal to the number of cores in the core mask. Notice that the instances of
		 * DpdkWorkerThread shouldn't be freed until calling stopDpdkWorkerThreads() as these instances are running
		 * @return True if all worker threads started successfully or false if: DPDK isn't initialized (initDpdk() wasn't called or
		 * returned false), number of cores differs from number of workers, core mask includes DPDK master core or if one of the
		 * worker threads couldn't be run
		 */
		bool startDpdkWorkerThreads(CoreMask coreMask, std::vector<DpdkWorkerThread*>& workerThreadsVec);

		/**
		 * Assuming worker threads are running, this method orders them to stop by calling DpdkWorkerThread#stop(). Then it waits until
		 * they stop running
		 */
		void stopDpdkWorkerThreads();
	};


	/**
	 * @struct DpdkOption
	 * A struct that contains user configurable parameter for initialization a DPDK.
	 * Most of options have an argument while other are the switches.
	 * Refer to http://doc.dpdk.org/guides/linux_gsg/linux_eal_parameters.html for more details about DPDK EAL parameters
	 */
	struct DpdkOption
	{
		/**
		 * A type of option
		 */
		enum Type
		{
			/**
			 * Unknown option type
			 */
			OptionUnknown = 0,

			/** === Lcore-related options === */

			/**
			 * Hexadecimal bitmask of cores to be used as service cores
			 */
			OptionServiceCoreMask,


			/** === Device-related options === */

			/**
			 * Blacklist a PCI device to prevent EAL from using it. Multiple options of this type are allowed.
			 * Possible values have the following format: <[domain:]bus:devid.func>
			 */
			OptionPciBlackList,

			/**
			 * Add a PCI device in white list.
			 * Possible values have the following format: <[domain:]bus:devid.func>
			 */
			OptionPciWhiteList,

			/**
			 * Add a virtual device using the format: <driver><id>[,key=val, ...]
			 */
			OptionVirtualDevice,

			/**
			 * Load external drivers. An argument can be a single shared object file, or a directory containing multiple driver shared objects.
			 * Multiple options of this type are allowed.
			 */
			OptionLoadExternalDriver,

			/**
			 * Disable PCI bus. Option of this type has no an argument
			 */
			OptionNoPci,

			/**
			 * Use VMware TSC map instead of native RDTSC. Option of this type has no an argument. This is a linux-specific parameter.
			 */
			OptionVmWareTsc,

			/**
			 * Do not use the HPET timer. Option of this type has no an argument. This is a linux-specific parameter.
			 */
			OptionNoHPET,


			/** === Multiprocessing-related options === */

			/**
			 * Use a different shared data file prefix for a DPDK process.
			 * This option allows running multiple independent DPDK primary/secondary processes under different prefixes.
			 * This is a linux-specific parameter
			 */
			OptionFilePrefix,


			/** === Memory-related options === */

			/**
			 * Set the number of memory channels to use. The default value is 2 when option of this type is not defined
			 */
			OptionMemChannels,

			/**
			 * Amount of memory expressed in megabytes to preallocate at startup
			 */
			OptionMemPreallocate,

			/**
			 * Force IOVA mode to a specific value. Allowed values are "pa", "va"
			 */
			OptionMemIovaMode,

			/**
			 * Preallocate specified amounts of memory per socket expressed in megabytes. The parameter is a comma-separated list of values.
			 * For example: 1024,2048. This will allocate 1 gigabyte of memory on socket 0, and 2048 megabytes of memory on socket 1.
			 * This is a linux-specific parameter
			 */
			OptionMemSocketPreallocate,

			/**
			 * Place a per-socket upper limit on memory use. The parameter is a comma-separated list of values which are expressed in megabytes.
			 * 0 will disable the limit for a particular socket. This is a linux-specific parameter
			 */
			OptionMemSocketLimit,

			/**
			 * Free hugepages back to system exactly as they were originally allocated. This is a linux-specific parameter
			 */
			OptionMemFreeHugepages,


			/** === Debugging options === */

			/**
			 * Specify log level for a specific component using the format: <type:val> (for example: eal:8). Can be specified multiple times
			 */
			OptionLogLevel
		}; // enum Type


		/**
		 * A default constructor that creates an option with unknown type and an empty value
		 */
		DpdkOption() : type(Type::OptionUnknown)
		{
		}

		/**
		 * A constructor that creates an option with certain type and value
		 * @param[in] type The type of option
		 * @param[in] value The value of option. This parameter can be omitted which means the value is not assigned
		 */
		DpdkOption(Type type, const std::string &value = std::string()) : type(type), value(value)
		{
		}


		/** Type of option */
		Type type;

		/** The value of option. An empty string means the value is not assigned */
		std::string value;
	}; // struct DpdkOption

} // namespace pcpp

#endif /* PCAPPP_DPDK_DEVICE_LIST */
