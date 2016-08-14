#define LOG_MODULE PcapLogModuleFileDevice

#include <stdio.h>
#include <cerrno>
#include <PcapFileDevice.h>
#include <Logger.h>
#include <string.h>

namespace pcpp
{

struct pcap_file_header
{
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t linktype;
};

struct packet_header
{
	uint32_t tv_sec;
	uint32_t tv_usec;
	uint32_t caplen;
	uint32_t len;
};

IPcapFileDevice::IPcapFileDevice(const char* fileName) : IPcapDevice()
{
	m_FileName = new char[strlen(fileName)+1];
	strcpy(m_FileName, fileName);
	m_PcapLinkLayerType = LINKTYPE_ETHERNET;
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

	m_PcapLinkLayerType = static_cast<LinkLayerType>(pcap_datalink(m_PcapDescriptor));
	switch(m_PcapLinkLayerType)
	{
		case LINKTYPE_ETHERNET:
		case LINKTYPE_LINUX_SLL:
			break;
		default:
			LOG_ERROR("Cannot open file reader device for filename '%s': the link type %d is not supported", m_FileName, m_PcapLinkLayerType);
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

PcapFileWriterDevice::PcapFileWriterDevice(const char* fileName, LinkLayerType linkLayerType) : IPcapFileDevice(fileName)
{
	m_PcapDumpHandler = NULL;
	m_NumOfPacketsNotWritten = 0;
	m_NumOfPacketsWritten = 0;
	m_PcapLinkLayerType = linkLayerType;
	m_AppendMode = false;
	m_File = NULL;
}

PcapFileWriterDevice::~PcapFileWriterDevice()
{

}

void PcapFileWriterDevice::closeFile()
{
	if (m_AppendMode && m_File != NULL)
	{
		fclose(m_File);
		m_File = NULL;
	}
}

bool PcapFileWriterDevice::writePacket(RawPacket const& packet)
{
	if ((!m_AppendMode && m_PcapDescriptor == NULL) || (m_PcapDumpHandler == NULL))
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
	if (!m_AppendMode)
		pcap_dump((uint8_t*)m_PcapDumpHandler, &pktHdr, ((RawPacket&)packet).getRawData());
	else
	{
		// Below are actually the lines run by pcap_dump. The reason I had to put them instead pcap_dump is that on Windows using WinPcap
		// you can't pass pointers between libraries compiled with different compilers. In this case - PcapPlusPlus and WinPcap weren't
		// compiled with the same compiler so it's impossible to fopen a file in PcapPlusPlus, pass the pointer to WinPcap and use the
		// FILE* pointer there. Doing this throws an exception. So the only option when implementing append to pcap is to write all relevant
		// WinPcap code that handles opening/closing/writing to pcap files inside PcapPlusPlus code

		// the reason to create this packet_header struct is timeval has different sizes in 32-bit and 64-bit systems,
		// but pcap format uses the 32-bit timeval version, so we need to align timeval to that
		packet_header pktHdrTemp;
		pktHdrTemp.tv_sec = pktHdr.ts.tv_sec;
		pktHdrTemp.tv_usec = pktHdr.ts.tv_usec;
		pktHdrTemp.caplen = pktHdr.caplen;
		pktHdrTemp.len = pktHdr.len;
		fwrite(&pktHdrTemp, sizeof(pktHdrTemp), 1, m_File);
		fwrite(((RawPacket&)packet).getRawData(), pktHdrTemp.caplen, 1, m_File);
	}
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
		case LINKTYPE_ETHERNET:
		case LINKTYPE_LINUX_SLL:
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
		LOG_ERROR("Error opening file writer device for file '%s': pcap_dump_open returned NULL with error: '%s'",
				m_FileName, pcap_geterr(m_PcapDescriptor));
		m_DeviceOpened = false;
		return false;
	}

	m_DeviceOpened = true;
	LOG_DEBUG("File writer device for file '%s' opened successfully", m_FileName);
	return true;
}

void PcapFileWriterDevice::close()
{
	if (!m_AppendMode && pcap_dump_flush(m_PcapDumpHandler) == -1)
	{
		LOG_ERROR("Error while flushing the packets to file");
	}
	// in append mode it's impossible to use pcap_dump_flush, see comment above pcap_dump
	else if (m_AppendMode && fflush(m_File) == EOF)
	{
		LOG_ERROR("Error while flushing the packets to file");
	}

	IPcapFileDevice::close();

	if (!m_AppendMode)
		pcap_dump_close(m_PcapDumpHandler);
	else
		// in append mode it's impossible to use pcap_dump_close, see comment above pcap_dump
		fclose(m_File);

	m_PcapDumpHandler = NULL;
	m_File = NULL;
	LOG_DEBUG("File writer closed for file '%s'", m_FileName);
}

void PcapFileWriterDevice::getStatistics(pcap_stat& stats)
{
	stats.ps_recv = m_NumOfPacketsWritten;
	stats.ps_drop = m_NumOfPacketsNotWritten;
	stats.ps_ifdrop = 0;
	LOG_DEBUG("Statistics received for writer device for filename '%s'", m_FileName);
}

bool PcapFileWriterDevice::open(bool appendMode)
{
	if (!appendMode)
		return open();

	m_AppendMode = appendMode;

#if !defined(WIN32)
	m_File = fopen(m_FileName, "r+");
#else
	m_File = fopen(m_FileName, "rb+");
#endif

	if (m_File == NULL)
	{
		LOG_ERROR("Cannot open '%s' for reading and writing", m_FileName);
		return false;
	}

	pcap_file_header pcapFileHeader;
	int amountRead = fread(&pcapFileHeader, 1, sizeof(pcapFileHeader), m_File);
	if (amountRead != sizeof(pcap_file_header))
	{
		if (ferror(m_File))
			LOG_ERROR("Cannot read pcap header from file '%s', error was: %s", m_FileName, errno);
		else
			LOG_ERROR("Cannot read pcap header from file '%s', unknown error", m_FileName);

		closeFile();
		return false;
	}

	LinkLayerType linkLayerType = static_cast<LinkLayerType>(pcapFileHeader.linktype);
	if (linkLayerType != m_PcapLinkLayerType)
	{
		LOG_ERROR("Pcap file has a different link layer type then the one chosen in PcapFileWriterDevice c'tor");
		closeFile();
		return false;
	}

	if (fseek(m_File, 0, SEEK_END) == -1)
	{
		LOG_ERROR("Cannot read pcap file '%s' to it's end, error was: %d", m_FileName, errno);
		closeFile();
		return false;
	}

	m_PcapDumpHandler = ((pcap_dumper_t *)m_File);

	m_DeviceOpened = true;
	LOG_DEBUG("File writer device for file '%s' opened successfully in append mode", m_FileName);
	return true;
}

} // namespace pcpp
