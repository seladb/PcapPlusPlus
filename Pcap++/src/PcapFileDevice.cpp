#define LOG_MODULE PcapLogModuleFileDevice

#include <PcapFileDevice.h>
#include <Logger.h>
#include <string.h>

namespace pcpp
{

IPcapFileDevice::IPcapFileDevice(const char* fileName) : IPcapDevice()
{
	m_FileName = new char[strlen(fileName)+1];
	strcpy(m_FileName, fileName);
	m_PcapLinkLayerType = PCAP_LINKTYPE_ETHERNET;
}

IPcapFileDevice::~IPcapFileDevice()
{
	close();
	delete[] m_FileName;
}

void IPcapFileDevice::close()
{
	if (m_PcapDescriptor == NULL)
	{
		LOG_DEBUG("Pcap descriptor already NULL. Nothing to do");
		return;
	}

	pcap_close(m_PcapDescriptor);
	LOG_DEBUG("Successfully closed file reader device for filename '%s'", m_FileName);
	m_PcapDescriptor = NULL;
}

PcapFileReaderDevice::PcapFileReaderDevice(const char* fileName) : IPcapFileDevice(fileName)
{
	m_NumOfPacketsNotParsed = 0;
	m_NumOfPacketsRead = 0;
}

PcapFileReaderDevice::~PcapFileReaderDevice()
{
}

//TODO: look at: http://savagelook.com/blog/code/offline-packet-capture-processing-with-cc-and-libpcap
bool PcapFileReaderDevice::open()
{
	m_NumOfPacketsRead = 0;
	m_NumOfPacketsNotParsed = 0;

	if (m_PcapDescriptor != NULL)
	{
		LOG_DEBUG("Pcap descriptor already opened. Nothing to do");
		return true;
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	m_PcapDescriptor = pcap_open_offline(m_FileName, errbuf);
	if (m_PcapDescriptor == NULL)
	{
		LOG_ERROR("Cannot open file reader device for filename '%s': %s", m_FileName, errbuf);
		m_DeviceOpened = false;
		return false;
	}

	m_PcapLinkLayerType = static_cast<PcapLinkLayerType>(pcap_datalink(m_PcapDescriptor));
	switch(m_PcapLinkLayerType)
	{
		case PCAP_LINKTYPE_ETHERNET:
		case PCAP_LINKTYPE_LINUX_SLL:
			break;
		default:
			LOG_ERROR("The link type %d is not supported", m_PcapLinkLayerType);
			return false;
	}

	LOG_DEBUG("Successfully opened file reader device for filename '%s'", m_FileName);
	m_DeviceOpened = true;
	return true;
}

void PcapFileReaderDevice::getStatistics(pcap_stat& stats)
{
	stats.ps_recv = m_NumOfPacketsRead;
	stats.ps_drop = m_NumOfPacketsNotParsed;
	stats.ps_ifdrop = 0;
	LOG_DEBUG("Statistics received for reader device for filename '%s'", m_FileName);
}

bool PcapFileReaderDevice::getNextPacket(RawPacket& rawPacket)
{
	rawPacket.clear();
	if (m_PcapDescriptor == NULL)
	{
		LOG_ERROR("File device '%s' not opened", m_FileName);
		return false;
	}
	pcap_pkthdr pkthdr;
	const uint8_t* pPacketData = pcap_next(m_PcapDescriptor, &pkthdr);
	if (pPacketData == NULL)
	{
		LOG_DEBUG("Packet could not be read. Probably end-of-file");
		return false;
	}

	uint8_t* pMyPacketData = new uint8_t[pkthdr.caplen];
	memcpy(pMyPacketData, pPacketData, pkthdr.caplen);
	if (!rawPacket.setRawData(pMyPacketData, pkthdr.caplen, pkthdr.ts, static_cast<LinkLayerType>(m_PcapLinkLayerType)))
	{
		LOG_ERROR("Couldn't set data to raw packet");
		return false;
	}
	m_NumOfPacketsRead++;
	return true;
}

PcapFileWriterDevice::PcapFileWriterDevice(const char* fileName, PcapLinkLayerType linkLayerType) : IPcapFileDevice(fileName)
{
	m_PcapDumpHandler = NULL;
	m_NumOfPacketsNotWritten = 0;
	m_NumOfPacketsWritten = 0;
	m_PcapLinkLayerType = linkLayerType;
}

PcapFileWriterDevice::~PcapFileWriterDevice()
{
}

bool PcapFileWriterDevice::writePacket(RawPacket const& packet)
{
	if ((m_PcapDescriptor == NULL) || (m_PcapDumpHandler == NULL))
	{
		LOG_ERROR("Device not opened");
		m_NumOfPacketsNotWritten++;
		return false;
	}

	if (packet.getLinkLayerType() != m_PcapLinkLayerType)
	{
		LOG_ERROR("Cannot write a packet with a different link layer type");
		m_NumOfPacketsNotWritten++;
		return false;
	}

	pcap_pkthdr pktHdr;
	pktHdr.caplen = ((RawPacket&)packet).getRawDataLen();
	pktHdr.len = ((RawPacket&)packet).getRawDataLen();
	pktHdr.ts = ((RawPacket&)packet).getPacketTimeStamp();
	pcap_dump((uint8_t*)m_PcapDumpHandler, &pktHdr, ((RawPacket&)packet).getRawData());
	LOG_DEBUG("Packet written successfully to '%s'", m_FileName);
	m_NumOfPacketsWritten++;
	return true;
}

bool PcapFileWriterDevice::writePackets(const RawPacketVector& packets)
{
	for (RawPacketVector::ConstVectorIterator iter = packets.begin(); iter != packets.end(); iter++)
	{
		if (!writePacket(**iter))
			return false;
	}

	return true;
}

bool PcapFileWriterDevice::open()
{
	if (m_PcapDescriptor != NULL)
	{
		LOG_DEBUG("Pcap descriptor already opened. Nothing to do");
		return true;
	}

	switch(m_PcapLinkLayerType)
	{
		case PCAP_LINKTYPE_ETHERNET:
		case PCAP_LINKTYPE_LINUX_SLL:
			break;
		default:
			LOG_ERROR("The link type %d is not supported", m_PcapLinkLayerType);
			return false;
	}

	m_NumOfPacketsNotWritten = 0;
	m_NumOfPacketsWritten = 0;

	m_PcapDescriptor = pcap_open_dead(m_PcapLinkLayerType, PCPP_MAX_PACKET_SIZE);
	if (m_PcapDescriptor == NULL)
	{
		LOG_ERROR("Error opening file writer device for file '%s': pcap_open_dead returned NULL", m_FileName);
		m_DeviceOpened = false;
		return false;
	}


	m_PcapDumpHandler = pcap_dump_open(m_PcapDescriptor, m_FileName);
	if (m_PcapDumpHandler == NULL)
	{
		LOG_ERROR("Error opening file writer device for file '%s': pcap_dump_open returned NULL", m_FileName);
		m_DeviceOpened = false;
		return false;
	}

	m_DeviceOpened = true;
	LOG_DEBUG("File writer device for file '%s' opened successfully", m_FileName);
	return true;
}

void PcapFileWriterDevice::close()
{
	if (pcap_dump_flush(m_PcapDumpHandler) == -1)
	{
		LOG_ERROR("Error while flushing the packets to file");
	}

	IPcapFileDevice::close();

	pcap_dump_close(m_PcapDumpHandler);
	m_PcapDumpHandler = NULL;
	LOG_DEBUG("File writer closed for file '%s'", m_FileName);
}

void PcapFileWriterDevice::getStatistics(pcap_stat& stats)
{
	stats.ps_recv = m_NumOfPacketsWritten;
	stats.ps_drop = m_NumOfPacketsNotWritten;
	stats.ps_ifdrop = 0;
	LOG_DEBUG("Statistics received for writer device for filename '%s'", m_FileName);
}

} // namespace pcpp
