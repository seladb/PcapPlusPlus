#ifdef USE_PF_RING

// GCOVR_EXCL_START

#define LOG_MODULE PcapLogModulePfRingDevice

#include "PfRingDeviceList.h"
#include "Logger.h"
#include "pcap.h"
#include "pfring.h"

namespace pcpp
{

PfRingDeviceList::PfRingDeviceList()
{
	m_PfRingVersion = "";

	FILE *fd = popen("lsmod | grep pf_ring", "r");
	char buf[16];
	if (!fread(buf, 1, sizeof (buf), fd)) // if there is some result the module must be loaded
	{
		PCPP_LOG_ERROR("PF_RING kernel module isn't loaded. Please run: 'sudo insmod <PF_RING_LOCATION>/kernel/pf_ring.ko'");
		return;
	}

	PCPP_LOG_DEBUG("PF_RING kernel module is loaded");

	pcap_if_t* interfaceList;
	char errbuf[PCAP_ERRBUF_SIZE];
	PCPP_LOG_DEBUG("PfRingDeviceList init: searching all interfaces on machine");
	int err = pcap_findalldevs(&interfaceList, errbuf);
	if (err < 0)
	{
		PCPP_LOG_ERROR("Error searching for PF_RING devices: " << errbuf);
	}

	pcap_if_t* currInterface = interfaceList;
	while (currInterface != NULL)
	{
		uint32_t flags = PF_RING_PROMISC | PF_RING_DNA_SYMMETRIC_RSS;
		pfring* ring = pfring_open(currInterface->name, 128, flags);
		if (ring != NULL)
		{
			if (m_PfRingVersion == "")
				calcPfRingVersion(ring);
			pfring_close(ring);
			PfRingDevice* newDev = new PfRingDevice(currInterface->name);
			m_PfRingDeviceList.push_back(newDev);
			PCPP_LOG_DEBUG("Found interface: " << currInterface->name);
		}

		currInterface = currInterface->next;
	}

	PCPP_LOG_DEBUG("PfRingDeviceList init end");
	pcap_freealldevs(interfaceList);
}

PfRingDeviceList::~PfRingDeviceList()
{
	for(std::vector<PfRingDevice*>::iterator devIter = m_PfRingDeviceList.begin(); devIter != m_PfRingDeviceList.end(); devIter++)
	{
		delete (*devIter);
	}
}

PfRingDevice* PfRingDeviceList::getPfRingDeviceByName(const std::string &devName) const
{
	PCPP_LOG_DEBUG("Searching all live devices...");
	for(std::vector<PfRingDevice*>::const_iterator devIter = m_PfRingDeviceList.begin(); devIter != m_PfRingDeviceList.end(); devIter++)
	{
		if ((*devIter)->getDeviceName() == devName)
			return (*devIter);
	}

	PCPP_LOG_DEBUG("Found no PF_RING devices with name '" << devName << "'");
	return NULL;
}

void PfRingDeviceList::calcPfRingVersion(void* ring)
{
	pfring* ringPtr = (pfring*)ring;
	uint32_t version;
	if (pfring_version(ringPtr, &version) < 0)
	{
		PCPP_LOG_ERROR("Couldn't retrieve PF_RING version, pfring_version returned an error");
		return;
	}

	char versionAsString[25];
	sprintf(versionAsString, "PF_RING v.%u.%u.%u\n",
	  (version & 0xFFFF0000) >> 16,
	  (version & 0x0000FF00) >> 8,
	  version & 0x000000FF);

	PCPP_LOG_DEBUG("PF_RING version is: " << versionAsString);
	m_PfRingVersion = std::string(versionAsString);
}

} // namespace pcpp

// GCOVR_EXCL_STOP

#endif /* USE_PF_RING */
