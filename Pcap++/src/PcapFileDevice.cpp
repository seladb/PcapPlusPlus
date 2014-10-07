#define LOG_MODULE PcapLogModuleFileDevice

#include <PcapFileDevice.h>
#include <Logger.h>
#include <string.h>

IPcapFileDevice::IPcapFileDevice(const char* pFileName) : IPcapDevice()
{
	m_pFileName = new char[strlen(pFileName)+1];
	strcpy(m_pFileName, pFileName);
}

IPcapFileDevice::~IPcapFileDevice()
{
	close();
	delete[] m_pFileName;
}

void IPcapFileDevice::close()
{
	if (m_pPcapDescriptor == NULL)
	{
		LOG_DEBUG("Pcap descriptor already NULL. Nothing to do");
		return;
	}

	pcap_close(m_pPcapDescriptor);
	LOG_DEBUG("Successfully closed file reader device for filename '%s'", m_pFileName);
	m_pPcapDescriptor = NULL;
}

PcapFileReaderDevice::PcapFileReaderDevice(const char* pFileName) : IPcapFileDevice(pFileName)
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

	if (m_pPcapDescriptor != NULL)
	{
		LOG_DEBUG("Pcap descriptor already opened. Nothing to do");
		return true;
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	m_pPcapDescriptor = pcap_open_offline(m_pFileName, errbuf);
	if (m_pPcapDescriptor == NULL)
	{
		LOG_ERROR("Cannot open file reader device for filename '%s': %s", m_pFileName, errbuf);
		m_DeviceOpened = false;
		return false;
	}

	LOG_DEBUG("Successfully opened file reader device for filename '%s'", m_pFileName);
	m_DeviceOpened = true;
	return true;
}

void PcapFileReaderDevice::getStatistics(pcap_stat& stats)
{
	stats.ps_recv = m_NumOfPacketsRead;
	stats.ps_drop = m_NumOfPacketsNotParsed;
	stats.ps_ifdrop = 0;
	LOG_DEBUG("Statistics received for reader device for filename '%s'", m_pFileName);
}

bool PcapFileReaderDevice::getNextPacket(RawPacket& rRawPacket)
{
	rRawPacket.clear();
	if (m_pPcapDescriptor == NULL)
	{
		LOG_ERROR("File device '%s' not opened", m_pFileName);
		return false;
	}
	pcap_pkthdr pkthdr;
	const uint8_t* pPacketData = pcap_next(m_pPcapDescriptor, &pkthdr);
	if (pPacketData == NULL)
	{
		LOG_DEBUG("Packet could not be read. Probably end-of-file");
		return false;
	}

	uint8_t* pMyPacketData = new uint8_t[pkthdr.caplen];
	memcpy(pMyPacketData, pPacketData, pkthdr.caplen);
	rRawPacket.setRawData(pMyPacketData, pkthdr.caplen, pkthdr.ts);
	m_NumOfPacketsRead++;
	return true;
}

PcapFileWriterDevice::PcapFileWriterDevice(const char* pFileName) : IPcapFileDevice(pFileName)
{
	m_pPcapDumpHandler = NULL;
	m_NumOfPacketsNotWritten = 0;
	m_NumOfPacketsWritten = 0;
}

PcapFileWriterDevice::~PcapFileWriterDevice()
{
}

bool PcapFileWriterDevice::writePacket(RawPacket const& packet)
{
	if ((m_pPcapDescriptor == NULL) || (m_pPcapDumpHandler == NULL))
	{
		LOG_ERROR("Device not opened");
		m_NumOfPacketsNotWritten++;
		return false;
	}

	pcap_pkthdr pktHdr;
	pktHdr.caplen = ((RawPacket&)packet).getRawDataLen();
	pktHdr.len = ((RawPacket&)packet).getRawDataLen();
	pktHdr.ts = ((RawPacket&)packet).getPacketTimeStamp();
	pcap_dump((uint8_t*)m_pPcapDumpHandler, &pktHdr, ((RawPacket&)packet).getRawData());
	LOG_DEBUG("Packet written successfully to '%s'", m_pFileName);
	m_NumOfPacketsWritten++;
	return true;
}

bool PcapFileWriterDevice::open()
{
	m_NumOfPacketsNotWritten = 0;
	m_NumOfPacketsWritten = 0;

	m_pPcapDescriptor = pcap_open_dead(1 /*Ethernet*/, MAX_PACKET_SIZE);
	if (m_pPcapDescriptor == NULL)
	{
		LOG_ERROR("Error opening file writer device for file '%s': pcap_open_dead returned NULL", m_pFileName);
		m_DeviceOpened = false;
		return false;
	}


	m_pPcapDumpHandler = pcap_dump_open(m_pPcapDescriptor, m_pFileName);
	if (m_pPcapDumpHandler == NULL)
	{
		LOG_ERROR("Error opening file writer device for file '%s': pcap_dump_open returned NULL", m_pFileName);
		m_DeviceOpened = false;
		return false;
	}

	m_DeviceOpened = true;
	LOG_DEBUG("File writer device for file '%s' opened successfully", m_pFileName);
	return true;
}

void PcapFileWriterDevice::close()
{
	if (pcap_dump_flush(m_pPcapDumpHandler) == -1)
	{
		LOG_ERROR("Error while flushing the packets to file");
	}

	IPcapFileDevice::close();

	pcap_dump_close(m_pPcapDumpHandler);
	m_pPcapDumpHandler = NULL;
	LOG_DEBUG("File writer closed for file '%s'", m_pFileName);
}

void PcapFileWriterDevice::getStatistics(pcap_stat& stats)
{
	stats.ps_recv = m_NumOfPacketsWritten;
	stats.ps_drop = m_NumOfPacketsNotWritten;
	stats.ps_ifdrop = 0;
	LOG_DEBUG("Statistics received for writer device for filename '%s'", m_pFileName);
}
