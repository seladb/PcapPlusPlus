#ifndef PCAPPP_KNI_DEVICE_LIST
#define PCAPPP_KNI_DEVICE_LIST

#include <vector>

#include "KniDevice.h"
#include "DpdkDeviceList.h"

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * @class KniDeviceList
	 * A singleton class that encapsulates DPDK KNI module initialization
	 * and holds the list of KniDevice instances.
	 * As it's a singleton, it has only one active instance doesn't have a public c'tor.
	 */
	class KniDeviceList
	{
		KniDeviceList();

		/**
		 * @brief Explicit destruction of KNI device.
		 * After this call device is no longer available for external (by Linux)
		 * or internal (by application) usage.
		 * All threads running on this device are stopped (request and/or capturing).
		 * The device can no longer be found by it's name or id.
		 * @warning NOT MT SAFE
		 * @warning This method is forbidden as the result of discussion about packet memory pool
		 * lifetime made <a href="https://github.com/seladb/PcapPlusPlus/pull/196#discussion_r286649704">here</a>.
		 * If You feel safe to use it please do, but no guarantee is provided.
		 * @param[in] kniDevice KNI device to be destroyed explicitly
		 */
		void destroyDevice(KniDevice* kniDevice);
	public:
		/**
		 * Callback related constants for KNI device
		 */
		enum KniCallbackVersion
		{
			/** Reports that DPDK supports only KniDevice#KniIoctlCallbacks callback structure */
			CALLBACKS_NEW = 0,
			/** Reports that DPDK supports only KniDevice#KniOldIoctlCallbacks callback structure */
			CALLBACKS_OLD = 1
		};
		/**
		 * Various callback types supported by KNI device
		 */
		enum KniCallbackType
		{
			/** KniDevice#KniIoctlCallbacks#change_mtu and KniDevice#KniOldIoctlCallbacks#change_mtu callback */
			CALLBACK_MTU,
			/** KniDevice#KniIoctlCallbacks#config_network_if and KniDevice#KniOldIoctlCallbacks#config_network_if callback */
			CALLBACK_LINK,
			/** KniDevice#KniIoctlCallbacks#config_mac_address callback */
			CALLBACK_MAC,
			/** KniDevice#KniIoctlCallbacks#config_promiscusity callback */
			CALLBACK_PROMISC
		};

		~KniDeviceList();

		/**
		 * @brief Getter for singleton
		 * @warning Initialization of Kni module depends on initialization of DPDK made by DpdkDeviceList
		 * @return The singleton instance of KniDeviceList
		 */
		static KniDeviceList& getInstance();

		/**
		 * @return true if KNI module was initialized successfully false otherwise
		 */
		inline bool isInitialized() { return m_Initialized; }

		/* Device manipulation */

		/**
		 * @brief Factory method for KNI devices.
		 * Newly created device is remembered under portId and name provided in config and can be found later by them.
		 * If KNI device is not destroyed explicitly thru KniDeviceList#destroyDevice
		 * then it will be destroyed implicitly by the time application exits.
		 * @warning NOT MT SAFE
		 * @param[in] config KNI device configuration structure
		 * @param[in] mempoolSize Size of packet mempool used by this device
		 * @return Pointer to new KNI device or NULL in case of error
		 */
		KniDevice* createDevice(const KniDevice::KniDeviceConfiguration& config, const size_t mempoolSize);
		/**
		 * @brief Returns KNI device with specified portId.
		 * @note MT SAFE if createDevice or destroyDevice is not called concurrently
		 * @param[in] portId ID of KNI device to find
		 * @return Pointer to KNI device or NULL if device not found
		 */
		KniDevice* getDeviceByPort(const uint16_t portId);
		/**
		 * @brief Returns KNI device with specified name.
		 * @note MT SAFE if createDevice or destroyDevice is not called concurrently
		 * @param[in] name Name of KNI device to find
		 * @return Pointer to KNI device or NULL if device not found
		 */
		KniDevice* getDeviceByName(const std::string& name);

		/* Static information */

		/**
		 * Returns KniCallbackVersion#CALLBACKS_NEW or
		 * KniCallbackVersion#CALLBACKS_OLD based on DPDK version used
		 * @note MT SAFE
		 */
		static KniCallbackVersion callbackVersion();
		/**
		 * Returns true if provided callback type is supported by used DPDK version
		 * @note MT SAFE
		 * @param[in] cbType One of KniCallbackType enum values
		 */
		static bool isCallbackSupported(const KniCallbackType cbType);
	private:
		std::vector<KniDevice*> m_Devices;
		bool m_Initialized;
		int m_KniUniqueId;
	};
} // namespace pcpp
#endif /* PCAPPP_KNI_DEVICE_LIST */
