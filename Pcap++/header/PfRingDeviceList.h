#ifndef PCAPPP_PF_RING_DEVICE_LIST
#define PCAPPP_PF_RING_DEVICE_LIST

#ifdef USE_PF_RING

#include <PfRingDevice.h>

/// @file

/**
 * @class PfRingDeviceList
 * A singleton class that holds all available PF_RING devices. Through this class the user can iterate all PF_RING devices or find a specific
 * device by name
 */
class PfRingDeviceList
{
private:
	vector<PfRingDevice*> m_PfRingDeviceList;
	string m_PfRingVersion;

	PfRingDeviceList();
	// private copy c'tor
	PfRingDeviceList(const PfRingDeviceList& other);
	PfRingDeviceList& operator=(const PfRingDeviceList& other);
	// private d'tor
	~PfRingDeviceList();

	void calcPfRingVersion(void* ring);
public:
	/**
	 * A static method that returns the singleton object for PfRingDeviceList
	 * @return PfRingDeviceList singleton
	 */
	static inline PfRingDeviceList& getInstance()
	{
		static PfRingDeviceList instance;
		return instance;
	}

	/**
	 * Return a list of all available PF_RING devices
	 * @return a list of all available PF_RING devices
	 */
	inline const vector<PfRingDevice*>& getPfRingDevicesList() { return m_PfRingDeviceList; }

	/**
	 * Get a PF_RING device by name. The name is the Linux interface name which appears in ifconfig
	 * (e.g eth0, eth1, etc.)
	 * @return A pointer to the PF_RING device
	 */
	PfRingDevice* getPfRingDeviceByName(const string devName);


	/**
	 * Get installed PF_RING version
	 * @return A string representing PF_RING version
	 */
	inline string getPfRingVersion() { return m_PfRingVersion; }
};

#endif /* USE_PF_RING */

#endif /* PCAPPP_PF_RING_DEVICE_LIST */
