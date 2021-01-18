#define LOG_MODULE PcapLogModuleFileDevice

#include <stdio.h>
#include <cerrno>
#include "PcapFileDevice.h"
#include "light_pcapng_ext.h"
#include "Logger.h"
#include "TimespecTimeval.h"
#include "pcap.h"
#include <string.h>
#include <fstream>

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

// ~~~~~~~~~~~~~~~~~~~
// IFileDevice members
// ~~~~~~~~~~~~~~~~~~~

IFileDevice::IFileDevice(const std::string& fileName) : IPcapDevice()
{
	m_FileName = fileName;
}

IFileDevice::~IFileDevice()
{
	IFileDevice::close();
}

std::string IFileDevice::getFileName() const
{
	return m_FileName;
}

void IFileDevice::close()
{
	if (m_PcapDescriptor != NULL)
	{
		pcap_close(m_PcapDescriptor);
		LOG_DEBUG("Successfully closed file reader device for filename '%s'", m_FileName.c_str());
		m_PcapDescriptor = NULL;
	}

	m_DeviceOpened = false;
}


// ~~~~~~~~~~~~~~~~~~~~~~~~~
// IFileReaderDevice members
// ~~~~~~~~~~~~~~~~~~~~~~~~~

IFileReaderDevice::IFileReaderDevice(const std::string& fileName) : IFileDevice(fileName)
{
	m_NumOfPacketsNotParsed = 0;
	m_NumOfPacketsRead = 0;
}

IFileReaderDevice* IFileReaderDevice::getReader(const std::string& fileName)
{
	const char* fileExtension = strrchr(fileName.c_str(), '.');

	if (fileExtension != NULL && strcmp(fileExtension, ".pcapng") == 0)
		return new PcapNgFileReaderDevice(fileName);

	return new PcapFileReaderDevice(fileName);
}

uint64_t IFileReaderDevice::getFileSize() const
{
	std::ifstream fileStream(m_FileName.c_str(), std::ifstream::ate | std::ifstream::binary);
	return fileStream.tellg();
}

int IFileReaderDevice::getNextPackets(RawPacketVector& packetVec, int numOfPacketsToRead)
{
	int numOfPacketsRead = 0;

	for (; numOfPacketsToRead < 0 || numOfPacketsRead < numOfPacketsToRead; numOfPacketsRead++)
	{
		RawPacket* newPacket = new RawPacket();
		bool packetRead = getNextPacket(*newPacket);
		if (packetRead)
		{
			packetVec.pushBack(newPacket);
		}
		else
		{
			delete newPacket;
			break;
		}
	}

	return numOfPacketsRead;
}


// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// PcapFileReaderDevice members
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~


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
	m_PcapDescriptor = pcap_open_offline(m_FileName.c_str(), errbuf);
	if (m_PcapDescriptor == NULL)
	{
		LOG_ERROR("Cannot open file reader device for filename '%s': %s", m_FileName.c_str(), errbuf);
		m_DeviceOpened = false;
		return false;
	}

	int linkLayer = pcap_datalink(m_PcapDescriptor);
	if (!RawPacket::isLinkTypeValid(linkLayer))
	{
		LOG_ERROR("Invalid link layer (%d) for reader device filename '%s'", linkLayer, m_FileName.c_str());
		pcap_close(m_PcapDescriptor);
		m_PcapDescriptor = NULL;
		m_DeviceOpened = false;
		return false;
	}

	m_PcapLinkLayerType = static_cast<LinkLayerType>(linkLayer);

	LOG_DEBUG("Successfully opened file reader device for filename '%s'", m_FileName.c_str());
	m_DeviceOpened = true;
	return true;
}

void PcapFileReaderDevice::getStatistics(PcapStats& stats) const
{
	stats.packetsRecv = m_NumOfPacketsRead;
	stats.packetsDrop = m_NumOfPacketsNotParsed;
	stats.packetsDropByInterface = 0;
	LOG_DEBUG("Statistics received for reader device for filename '%s'", m_FileName.c_str());
}

bool PcapFileReaderDevice::getNextPacket(RawPacket& rawPacket)
{
	rawPacket.clear();
	if (m_PcapDescriptor == NULL)
	{
		LOG_ERROR("File device '%s' not opened", m_FileName.c_str());
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
	if (!rawPacket.setRawData(pMyPacketData, pkthdr.caplen, pkthdr.ts, static_cast<LinkLayerType>(m_PcapLinkLayerType), pkthdr.len))
	{
		LOG_ERROR("Couldn't set data to raw packet");
		return false;
	}
	m_NumOfPacketsRead++;
	return true;
}


// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// PcapNgFileReaderDevice members
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

PcapNgFileReaderDevice::PcapNgFileReaderDevice(const std::string& fileName) : IFileReaderDevice(fileName)
{
	m_LightPcapNg = NULL;
}

bool PcapNgFileReaderDevice::open()
{
	m_NumOfPacketsRead = 0;
	m_NumOfPacketsNotParsed = 0;

	if (m_LightPcapNg != NULL)
	{
		LOG_DEBUG("pcapng descriptor already opened. Nothing to do");
		return true;
	}

	m_LightPcapNg = light_pcapng_open_read(m_FileName.c_str(), LIGHT_FALSE);
	if (m_LightPcapNg == NULL)
	{
		LOG_ERROR("Cannot open pcapng reader device for filename '%s'", m_FileName.c_str());
		m_DeviceOpened = false;
		return false;
	}

	LOG_DEBUG("Successfully opened pcapng reader device for filename '%s'", m_FileName.c_str());
	m_DeviceOpened = true;
	return true;
}

bool PcapNgFileReaderDevice::getNextPacket(RawPacket& rawPacket, std::string& packetComment)
{
	rawPacket.clear();
	packetComment = "";

	if (m_LightPcapNg == NULL)
	{
		LOG_ERROR("Pcapng file device '%s' not opened", m_FileName.c_str());
		return false;
	}

	light_packet_header pktHeader;
	const uint8_t* pktData = NULL;

	if (!light_get_next_packet((light_pcapng_t*)m_LightPcapNg, &pktHeader, &pktData))
	{
		LOG_DEBUG("Packet could not be read. Probably end-of-file");
		return false;
	}
	
	while (!m_BpfWrapper.matchPacketWithFilter(pktData, pktHeader.captured_length, pktHeader.timestamp, pktHeader.data_link))
	{
		if (!light_get_next_packet((light_pcapng_t*)m_LightPcapNg, &pktHeader, &pktData))
		{
			LOG_DEBUG("Packet could not be read. Probably end-of-file");
			return false;
		}
	}

	uint8_t* myPacketData = new uint8_t[pktHeader.captured_length];
	memcpy(myPacketData, pktData, pktHeader.captured_length);
	if (!rawPacket.setRawData(myPacketData, pktHeader.captured_length, pktHeader.timestamp, static_cast<LinkLayerType>(pktHeader.data_link), pktHeader.original_length))
	{
		LOG_ERROR("Couldn't set data to raw packet");
		return false;
	}

	if (pktHeader.comment != NULL && pktHeader.comment_length > 0)
		packetComment = std::string(pktHeader.comment, pktHeader.comment_length);

	m_NumOfPacketsRead++;
	return true;
}

bool PcapNgFileReaderDevice::getNextPacket(RawPacket& rawPacket)
{
	std::string temp;
	return getNextPacket(rawPacket, temp);
}

void PcapNgFileReaderDevice::getStatistics(PcapStats& stats) const
{
	stats.packetsRecv = m_NumOfPacketsRead;
	stats.packetsDrop = m_NumOfPacketsNotParsed;
	stats.packetsDropByInterface = 0;
	LOG_DEBUG("Statistics received for pcapng reader device for filename '%s'", m_FileName.c_str());
}

bool PcapNgFileReaderDevice::setFilter(std::string filterAsString)
{
	return m_BpfWrapper.setFilter(filterAsString);
}

void PcapNgFileReaderDevice::close()
{
	if (m_LightPcapNg == NULL)
		return;

	light_pcapng_close((light_pcapng_t*)m_LightPcapNg);
	m_LightPcapNg = NULL;

	m_DeviceOpened = false;
	LOG_DEBUG("File reader closed for file '%s'", m_FileName.c_str());
}


std::string PcapNgFileReaderDevice::getOS() const
{
	if (m_LightPcapNg == NULL)
	{
		LOG_ERROR("Pcapng file device '%s' not opened", m_FileName.c_str());
		return "";
	}

	light_pcapng_file_info* fileInfo = light_pcang_get_file_info((light_pcapng_t*)m_LightPcapNg);
	char* res = fileInfo->os_desc;
	size_t len = fileInfo->os_desc_size;
	if (len == 0 || res == NULL)
		return "";

	return std::string(res, len);
}

std::string PcapNgFileReaderDevice::getHardware() const
{
	if (m_LightPcapNg == NULL)
	{
		LOG_ERROR("Pcapng file device '%s' not opened", m_FileName.c_str());
		return "";
	}

	light_pcapng_file_info* fileInfo = light_pcang_get_file_info((light_pcapng_t*)m_LightPcapNg);
	char* res = fileInfo->hardware_desc;
	size_t len = fileInfo->hardware_desc_size;
	if (len == 0 || res == NULL)
		return "";

	return std::string(res, len);
}

std::string PcapNgFileReaderDevice::getCaptureApplication() const
{
	if (m_LightPcapNg == NULL)
	{
		LOG_ERROR("Pcapng file device '%s' not opened", m_FileName.c_str());
		return "";
	}

	light_pcapng_file_info* fileInfo = light_pcang_get_file_info((light_pcapng_t*)m_LightPcapNg);
	char* res = fileInfo->user_app_desc;
	size_t len = fileInfo->user_app_desc_size;
	if (len == 0 || res == NULL)
		return "";

	return std::string(res, len);
}

std::string PcapNgFileReaderDevice::getCaptureFileComment() const
{
	if (m_LightPcapNg == NULL)
	{
		LOG_ERROR("Pcapng file device '%s' not opened", m_FileName.c_str());
		return "";
	}

	light_pcapng_file_info* fileInfo = light_pcang_get_file_info((light_pcapng_t*)m_LightPcapNg);
	char* res = fileInfo->file_comment;
	size_t len = fileInfo->file_comment_size;
	if (len == 0 || res == NULL)
		return "";

	return std::string(res, len);
}


// ~~~~~~~~~~~~~~~~~~~~~~~~~
// IFileWriterDevice members
// ~~~~~~~~~~~~~~~~~~~~~~~~~

IFileWriterDevice:: IFileWriterDevice(const std::string& fileName) : IFileDevice(fileName)
{
	m_NumOfPacketsNotWritten = 0;
	m_NumOfPacketsWritten = 0;
}


// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// PcapFileWriterDevice members
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~

PcapFileWriterDevice::PcapFileWriterDevice(const std::string& fileName, LinkLayerType linkLayerType) : IFileWriterDevice(fileName)
{
	m_PcapDumpHandler = NULL;
	m_NumOfPacketsNotWritten = 0;
	m_NumOfPacketsWritten = 0;
	m_PcapLinkLayerType = linkLayerType;
	m_AppendMode = false;
	m_File = NULL;
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
	pktHdr.len = ((RawPacket&)packet).getFrameLength();
	timespec packet_timestamp = ((RawPacket&)packet).getPacketTimeStamp();
	TIMESPEC_TO_TIMEVAL(&pktHdr.ts, &packet_timestamp);
	if (!m_AppendMode)
		pcap_dump((uint8_t*)m_PcapDumpHandler, &pktHdr, ((RawPacket&)packet).getRawData());
	else
	{
		// Below are actually the lines run by pcap_dump. The reason I had to put them instead pcap_dump is that on Windows using WinPcap/Npcap
		// you can't pass pointers between libraries compiled with different compilers. In this case - PcapPlusPlus and WinPcap/Npcap weren't
		// compiled with the same compiler so it's impossible to fopen a file in PcapPlusPlus, pass the pointer to WinPcap/Npcap and use the
		// FILE* pointer there. Doing this throws an exception. So the only option when implementing append to pcap is to write all relevant
		// WinPcap/Npcap code that handles opening/closing/writing to pcap files inside PcapPlusPlus code

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
	LOG_DEBUG("Packet written successfully to '%s'", m_FileName.c_str());
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
		case LINKTYPE_RAW:
		case LINKTYPE_DLT_RAW2:
			LOG_ERROR("The only Raw IP link type supported in libpcap/WinPcap/Npcap is LINKTYPE_DLT_RAW1, please use that instead");
			return false;
		default:
			break;
	}

	m_NumOfPacketsNotWritten = 0;
	m_NumOfPacketsWritten = 0;

	m_PcapDescriptor = pcap_open_dead(m_PcapLinkLayerType, PCPP_MAX_PACKET_SIZE);
	if (m_PcapDescriptor == NULL)
	{
		LOG_ERROR("Error opening file writer device for file '%s': pcap_open_dead returned NULL", m_FileName.c_str());
		m_DeviceOpened = false;
		return false;
	}


	m_PcapDumpHandler = pcap_dump_open(m_PcapDescriptor, m_FileName.c_str());
	if (m_PcapDumpHandler == NULL)
	{
		LOG_ERROR("Error opening file writer device for file '%s': pcap_dump_open returned NULL with error: '%s'",
				m_FileName.c_str(), pcap_geterr(m_PcapDescriptor));
		m_DeviceOpened = false;
		return false;
	}

	m_DeviceOpened = true;
	LOG_DEBUG("File writer device for file '%s' opened successfully", m_FileName.c_str());
	return true;
}

void PcapFileWriterDevice::flush()
{
	if (!m_DeviceOpened)
		return;

	if (!m_AppendMode && pcap_dump_flush(m_PcapDumpHandler) == -1)
	{
		LOG_ERROR("Error while flushing the packets to file");
	}
	// in append mode it's impossible to use pcap_dump_flush, see comment above pcap_dump
	else if (m_AppendMode && fflush(m_File) == EOF)
	{
		LOG_ERROR("Error while flushing the packets to file");
	}

}

void PcapFileWriterDevice::close()
{
	if (!m_DeviceOpened)
		return;

	flush();

	IFileDevice::close();

	if (!m_AppendMode && m_PcapDumpHandler != NULL)
	{
		pcap_dump_close(m_PcapDumpHandler);
	}
	else if (m_AppendMode && m_File != NULL)
	{
		// in append mode it's impossible to use pcap_dump_close, see comment above pcap_dump
		fclose(m_File);
	}

	m_PcapDumpHandler = NULL;
	m_File = NULL;
	LOG_DEBUG("File writer closed for file '%s'", m_FileName.c_str());
}

void PcapFileWriterDevice::getStatistics(PcapStats& stats) const
{
	stats.packetsRecv = m_NumOfPacketsWritten;
	stats.packetsDrop = m_NumOfPacketsNotWritten;
	stats.packetsDropByInterface = 0;
	LOG_DEBUG("Statistics received for writer device for filename '%s'", m_FileName.c_str());
}

bool PcapFileWriterDevice::open(bool appendMode)
{
	if (!appendMode)
		return open();

	m_AppendMode = appendMode;

#if !defined(WIN32) && !defined(WINx64)
	m_File = fopen(m_FileName.c_str(), "r+");
#else
	m_File = fopen(m_FileName.c_str(), "rb+");
#endif

	if (m_File == NULL)
	{
		LOG_ERROR("Cannot open '%s' for reading and writing", m_FileName.c_str());
		return false;
	}

	pcap_file_header pcapFileHeader;
	int amountRead = fread(&pcapFileHeader, 1, sizeof(pcapFileHeader), m_File);
	if (amountRead != sizeof(pcap_file_header))
	{
		if (ferror(m_File))
			LOG_ERROR("Cannot read pcap header from file '%s', error was: %d", m_FileName.c_str(), errno);
		else
			LOG_ERROR("Cannot read pcap header from file '%s', unknown error", m_FileName.c_str());

		closeFile();
		return false;
	}

	LinkLayerType linkLayerType = static_cast<LinkLayerType>(pcapFileHeader.linktype);
	if (linkLayerType != m_PcapLinkLayerType)
	{
		LOG_ERROR("Pcap file has a different link layer type than the one chosen in PcapFileWriterDevice c'tor, %d, %d", linkLayerType, m_PcapLinkLayerType);
		closeFile();
		return false;
	}

	if (fseek(m_File, 0, SEEK_END) == -1)
	{
		LOG_ERROR("Cannot read pcap file '%s' to it's end, error was: %d", m_FileName.c_str(), errno);
		closeFile();
		return false;
	}

	m_PcapDumpHandler = ((pcap_dumper_t *)m_File);

	m_DeviceOpened = true;
	LOG_DEBUG("File writer device for file '%s' opened successfully in append mode", m_FileName.c_str());
	return true;
}


// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// PcapNgFileWriterDevice members
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

PcapNgFileWriterDevice::PcapNgFileWriterDevice(const std::string& fileName, int compressionLevel) : IFileWriterDevice(fileName)
{
	m_LightPcapNg = NULL;
	m_CompressionLevel = compressionLevel;
}

bool PcapNgFileWriterDevice::open(const std::string& os, const std::string& hardware, const std::string& captureApp, const std::string& fileComment)
{
	if (m_LightPcapNg != NULL)
	{
		LOG_DEBUG("Pcap-ng descriptor already opened. Nothing to do");
		return true;
	}

	m_NumOfPacketsNotWritten = 0;
	m_NumOfPacketsWritten = 0;

	light_pcapng_file_info* info = light_create_file_info(os.c_str(), hardware.c_str(), captureApp.c_str(), fileComment.c_str());

	m_LightPcapNg = light_pcapng_open_write(m_FileName.c_str(), info, m_CompressionLevel);
	if (m_LightPcapNg == NULL)
	{
		LOG_ERROR("Error opening file writer device for file '%s': light_pcapng_open_write returned NULL", m_FileName.c_str());

		light_free_file_info(info);

		m_DeviceOpened = false;
		return false;
	}

	m_DeviceOpened = true;
	LOG_DEBUG("pcap-ng writer device for file '%s' opened successfully", m_FileName.c_str());
	return true;
}

bool PcapNgFileWriterDevice::writePacket(RawPacket const& packet, const std::string& comment)
{
	if (m_LightPcapNg == NULL)
	{
		LOG_ERROR("Device not opened");
		m_NumOfPacketsNotWritten++;
		return false;
	}

	if (!m_BpfWrapper.matchPacketWithFilter(&packet))
	{
		return false;
	}

	light_packet_header pktHeader;
	pktHeader.captured_length = ((RawPacket&)packet).getRawDataLen();
	pktHeader.original_length = ((RawPacket&)packet).getFrameLength();
	pktHeader.timestamp = ((RawPacket&)packet).getPacketTimeStamp();
	pktHeader.data_link = (uint16_t)packet.getLinkLayerType();
	pktHeader.interface_id = 0;
	if (!comment.empty())
	{
		pktHeader.comment = (char*)comment.c_str();
		pktHeader.comment_length = static_cast<uint16_t>(comment.size());
	}
	else
	{
		pktHeader.comment = NULL;
		pktHeader.comment_length = 0;
	}

	const uint8_t* pktData = ((RawPacket&)packet).getRawData();

	light_write_packet((light_pcapng_t*)m_LightPcapNg, &pktHeader, pktData);
	m_NumOfPacketsWritten++;
	return true;
}

bool PcapNgFileWriterDevice::writePacket(RawPacket const& packet)
{
	return writePacket(packet, std::string());
}

bool PcapNgFileWriterDevice::writePackets(const RawPacketVector& packets)
{
	for (RawPacketVector::ConstVectorIterator iter = packets.begin(); iter != packets.end(); iter++)
	{
		if (!writePacket(**iter))
			return false;
	}

	return true;
}

bool PcapNgFileWriterDevice::open()
{
	if (m_LightPcapNg != NULL)
	{
		LOG_DEBUG("Pcap-ng descriptor already opened. Nothing to do");
		return true;
	}

	m_NumOfPacketsNotWritten = 0;
	m_NumOfPacketsWritten = 0;

	light_pcapng_file_info* info = light_create_default_file_info();

	m_LightPcapNg = light_pcapng_open_write(m_FileName.c_str(), info, m_CompressionLevel);
	if (m_LightPcapNg == NULL)
	{
		LOG_ERROR("Error opening file writer device for file '%s': light_pcapng_open_write returned NULL", m_FileName.c_str());

		light_free_file_info(info);

		m_DeviceOpened = false;
		return false;
	}

	m_DeviceOpened = true;
	LOG_DEBUG("pcap-ng writer device for file '%s' opened successfully", m_FileName.c_str());
	return true;
}

bool PcapNgFileWriterDevice::open(bool appendMode)
{
	if (!appendMode)
		return open();

	m_NumOfPacketsNotWritten = 0;
	m_NumOfPacketsWritten = 0;

	m_LightPcapNg = light_pcapng_open_append(m_FileName.c_str());
	if (m_LightPcapNg == NULL)
	{
		LOG_ERROR("Error opening file writer device in append mode for file '%s': light_pcapng_open_append returned NULL", m_FileName.c_str());
		m_DeviceOpened = false;
		return false;
	}

	m_DeviceOpened = true;
	LOG_DEBUG("pcap-ng writer device for file '%s' opened successfully", m_FileName.c_str());
	return true;

}

void PcapNgFileWriterDevice::flush()
{
	if (!m_DeviceOpened || m_LightPcapNg == NULL)
		return;

	light_pcapng_flush((light_pcapng_t*)m_LightPcapNg);
	LOG_DEBUG("File writer flushed to file '%s'", m_FileName.c_str());
}

void PcapNgFileWriterDevice::close()
{
	if (m_LightPcapNg == NULL)
		return;

	light_pcapng_close((light_pcapng_t*)m_LightPcapNg);
	m_LightPcapNg = NULL;

	m_DeviceOpened = false;
	LOG_DEBUG("File writer closed for file '%s'", m_FileName.c_str());
}

void PcapNgFileWriterDevice::getStatistics(PcapStats& stats) const
{
	stats.packetsRecv = m_NumOfPacketsWritten;
	stats.packetsDrop = m_NumOfPacketsNotWritten;
	stats.packetsDropByInterface = 0;
	LOG_DEBUG("Statistics received for pcap-ng writer device for filename '%s'", m_FileName.c_str());
}

bool PcapNgFileWriterDevice::setFilter(std::string filterAsString)
{
	return m_BpfWrapper.setFilter(filterAsString);
}


} // namespace pcpp
