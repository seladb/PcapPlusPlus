#ifdef USE_PF_RING

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
	if (fread (buf, 1, sizeof (buf), fd) <= 0) // if there is some result the module must be loaded
	{
		LOG_ERROR("PF_RING kernel module isn't loaded. Please run: 'sudo insmod <PF_RING_LOCATION>/kernel/pf_ring.ko'");
		return;
	}

	LOG_DEBUG("PF_RING kernel module is loaded");

	pcap_if_t* interfaceList;
	char errbuf[PCAP_ERRBUF_SIZE];
	LOG_DEBUG("PfRingDeviceList init: searching all interfaces on machine");
	int err = pcap_findalldevs(&interfaceList, errbuf);
	if (err < 0)
	{
		LOG_ERROR("Error searching for PF_RING devices: %s", errbuf);
	}

	pcap_if_t* currInterface = interfaceList;
	while (currInterface != NULL)
	{
		if ((currInterface->flags & 0x1) != PCAP_IF_LOOPBACK)
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
				LOG_DEBUG("Found interface: %s", currInterface->name);
			}
		}

		currInterface = currInterface->next;
	}

	LOG_DEBUG("PfRingDeviceList init end");
	pcap_freealldevs(interfaceList);
}

PfRingDeviceList::~PfRingDeviceList()
{
	for(std::vector<PfRingDevice*>::iterator devIter = m_PfRingDeviceList.begin(); devIter != m_PfRingDeviceList.end(); devIter++)
	{
		delete (*devIter);
	}
}

PfRingDevice* PfRingDeviceList::getPfRingDeviceByName(const std::string devName)
{
	LOG_DEBUG("Searching all live devices...");
	for(std::vector<PfRingDevice*>::iterator devIter = m_PfRingDeviceList.begin(); devIter != m_PfRingDeviceList.end(); devIter++)
	{
		if ((*devIter)->getDeviceName() == devName)
			return (*devIter);
	}

	LOG_DEBUG("Found no PF_RING devices with name '%s'", devName.c_str());
	return NULL;
}

void PfRingDeviceList::calcPfRingVersion(void* ring)
{
	pfring* ringPtr = (pfring*)ring;
	uint32_t version;
    if (pfring_version(ringPtr, &version) < 0)
    {
    	LOG_ERROR("Couldn't retrieve PF_RING version, pfring_version returned an error");
    	return;
    }

    char versionAsString[25];
    sprintf(versionAsString, "PF_RING v.%d.%d.%d\n",
	   (version & 0xFFFF0000) >> 16,
	   (version & 0x0000FF00) >> 8,
	   version & 0x000000FF);

    LOG_DEBUG("PF_RING version is: %s", versionAsString);
    m_PfRingVersion = std::string(versionAsString);
}

} // namespace pcpp

#endif /* USE_PF_RING */
