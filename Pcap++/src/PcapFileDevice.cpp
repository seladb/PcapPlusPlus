#define LOG_MODULE PcapLogModuleFileDevice

#include <cerrno>
#include "PcapFileDevice.h"
#include "light_pcapng_ext.h"
#include "Logger.h"
#include "TimespecTimeval.h"
#include "pcap.h"
#include <fstream>
#include "EndianPortable.h"

namespace pcpp
{
	namespace
	{
		/// @brief Converts a light_pcapng_t* to an opaque LightPcapNgHandle*.
		/// @param pcapngHandle The light_pcapng_t* to convert.
		/// @return An pointer to the opaque handle.
		internal::LightPcapNgHandle* toLightPcapNgHandle(light_pcapng_t* pcapngHandle)
		{
			return reinterpret_cast<internal::LightPcapNgHandle*>(pcapngHandle);
		}

		/// @brief Converts an opaque LightPcapNgHandle* to a light_pcapng_t*.
		/// @param pcapngHandle The LightPcapNgHandle* to convert.
		/// @return A pointer to the light_pcapng_t.
		light_pcapng_t* toLightPcapNgT(internal::LightPcapNgHandle* pcapngHandle)
		{
			return reinterpret_cast<light_pcapng_t*>(pcapngHandle);
		}
	}  // namespace

	template <typename T, size_t N> constexpr size_t ARRAY_SIZE(T (&)[N])
	{
		return N;
	}

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

	static bool checkNanoSupport()
	{
#if defined(PCAP_TSTAMP_PRECISION_NANO)
		return true;
#else
		PCPP_LOG_DEBUG(
		    "PcapPlusPlus was compiled without nano precision support which requires libpcap > 1.5.1. Please "
		    "recompile PcapPlusPlus with nano precision support to use this feature. Using default microsecond precision");
		return false;
#endif
	}

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
		if (m_PcapDescriptor != nullptr)
		{
			m_PcapDescriptor = nullptr;
			PCPP_LOG_DEBUG("Successfully closed file reader device for filename '" << m_FileName << "'");
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
		const auto extensionPos = fileName.find_last_of('.');
		const auto fileExtension = extensionPos != std::string::npos ? fileName.substr(extensionPos) : "";

		if (fileExtension == ".pcapng" || fileExtension == ".zstd" || fileExtension == ".zst")
			return new PcapNgFileReaderDevice(fileName);
		else if (fileExtension == ".snoop")
			return new SnoopFileReaderDevice(fileName);

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

		if (m_PcapDescriptor != nullptr)
		{
			PCPP_LOG_DEBUG("Pcap descriptor already opened. Nothing to do");
			return true;
		}

		char errbuf[PCAP_ERRBUF_SIZE];
#if defined(PCAP_TSTAMP_PRECISION_NANO)
		auto pcapDescriptor = internal::PcapHandle(
		    pcap_open_offline_with_tstamp_precision(m_FileName.c_str(), PCAP_TSTAMP_PRECISION_NANO, errbuf));
#else
		auto pcapDescriptor = internal::PcapHandle(pcap_open_offline(m_FileName.c_str(), errbuf));
#endif
		if (pcapDescriptor == nullptr)
		{
			PCPP_LOG_ERROR("Cannot open file reader device for filename '" << m_FileName << "': " << errbuf);
			m_DeviceOpened = false;
			return false;
		}

		int linkLayer = pcap_datalink(pcapDescriptor.get());
		if (!RawPacket::isLinkTypeValid(linkLayer))
		{
			PCPP_LOG_ERROR("Invalid link layer (" << linkLayer << ") for reader device filename '" << m_FileName
			                                      << "'");
			m_DeviceOpened = false;
			return false;
		}

		m_PcapLinkLayerType = static_cast<LinkLayerType>(linkLayer);

#if defined(PCAP_TSTAMP_PRECISION_NANO)
		m_Precision = static_cast<FileTimestampPrecision>(pcap_get_tstamp_precision(pcapDescriptor.get()));
		std::string precisionStr =
		    (m_Precision == FileTimestampPrecision::Nanoseconds) ? "nanoseconds" : "microseconds";
#else
		m_Precision = FileTimestampPrecision::Microseconds;
		std::string precisionStr = "microseconds";
#endif
		PCPP_LOG_DEBUG("Successfully opened file reader device for filename '" << m_FileName << "' with precision "
		                                                                       << precisionStr);
		m_PcapDescriptor = std::move(pcapDescriptor);
		m_DeviceOpened = true;
		return true;
	}

	bool PcapFileReaderDevice::isNanoSecondPrecisionSupported()
	{
		return checkNanoSupport();
	}

	void PcapFileReaderDevice::getStatistics(PcapStats& stats) const
	{
		stats.packetsRecv = m_NumOfPacketsRead;
		stats.packetsDrop = m_NumOfPacketsNotParsed;
		stats.packetsDropByInterface = 0;
		PCPP_LOG_DEBUG("Statistics received for reader device for filename '" << m_FileName << "'");
	}

	bool PcapFileReaderDevice::getNextPacket(RawPacket& rawPacket)
	{
		rawPacket.clear();
		if (m_PcapDescriptor == nullptr)
		{
			PCPP_LOG_ERROR("File device '" << m_FileName << "' not opened");
			return false;
		}
		pcap_pkthdr pkthdr;
		const uint8_t* pPacketData = pcap_next(m_PcapDescriptor.get(), &pkthdr);
		if (pPacketData == nullptr)
		{
			PCPP_LOG_DEBUG("Packet could not be read. Probably end-of-file");
			return false;
		}

		uint8_t* pMyPacketData = new uint8_t[pkthdr.caplen];
		memcpy(pMyPacketData, pPacketData, pkthdr.caplen);
#if defined(PCAP_TSTAMP_PRECISION_NANO)
		// because we opened with nano second precision 'tv_usec' is actually nanos
		timespec ts = { pkthdr.ts.tv_sec, static_cast<long>(pkthdr.ts.tv_usec) };
#else
		struct timeval ts = pkthdr.ts;
#endif
		if (!rawPacket.setRawData(pMyPacketData, pkthdr.caplen, ts, static_cast<LinkLayerType>(m_PcapLinkLayerType),
		                          pkthdr.len))
		{
			PCPP_LOG_ERROR("Couldn't set data to raw packet");
			return false;
		}
		m_NumOfPacketsRead++;
		return true;
	}

	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	// SnoopFileReaderDevice members
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	SnoopFileReaderDevice::~SnoopFileReaderDevice()
	{
		m_snoopFile.close();
	}

	bool SnoopFileReaderDevice::open()
	{
		m_NumOfPacketsRead = 0;
		m_NumOfPacketsNotParsed = 0;

		m_snoopFile.open(m_FileName.c_str(), std::ifstream::binary);
		if (!m_snoopFile.is_open())
		{
			PCPP_LOG_ERROR("Cannot open snoop reader device for filename '" << m_FileName << "'");
			m_snoopFile.close();
			return false;
		}

		snoop_file_header_t snoop_file_header;
		m_snoopFile.read((char*)&snoop_file_header, sizeof(snoop_file_header_t));
		if (!m_snoopFile)
		{
			PCPP_LOG_ERROR("Cannot read snoop file header for '" << m_FileName << "'");
			m_snoopFile.close();
			return false;
		}

		if (be64toh(snoop_file_header.identification_pattern) != 0x736e6f6f70000000 &&
		    be32toh(snoop_file_header.version_number) == 2)
			return false;

		// From https://datatracker.ietf.org/doc/html/rfc1761
		static const pcpp::LinkLayerType snoop_encap[] = {
			LINKTYPE_ETHERNET,   /// IEEE 802.3
			LINKTYPE_NULL,       /// IEEE 802.4 Token Bus
			LINKTYPE_IEEE802_5,  /// IEEE 802.5
			LINKTYPE_NULL,       /// IEEE 802.6 Metro Net
			LINKTYPE_ETHERNET,   /// Ethernet
			LINKTYPE_C_HDLC,     /// HDLC
			LINKTYPE_NULL,       /// Character Synchronous, e.g. bisync
			LINKTYPE_NULL,       /// IBM Channel-to-Channel
			LINKTYPE_FDDI        /// FDDI
		};
		uint32_t datalink_type = be32toh(snoop_file_header.datalink_type);
		if (datalink_type > ARRAY_SIZE(snoop_encap) - 1)
		{
			PCPP_LOG_ERROR("Cannot read data link type for '" << m_FileName << "'");
			m_snoopFile.close();
			return false;
		}

		m_PcapLinkLayerType = snoop_encap[datalink_type];

		PCPP_LOG_DEBUG("Successfully opened file reader device for filename '" << m_FileName << "'");
		m_DeviceOpened = true;
		return true;
	}

	void SnoopFileReaderDevice::getStatistics(PcapStats& stats) const
	{
		stats.packetsRecv = m_NumOfPacketsRead;
		stats.packetsDrop = m_NumOfPacketsNotParsed;
		stats.packetsDropByInterface = 0;
		PCPP_LOG_DEBUG("Statistics received for reader device for filename '" << m_FileName << "'");
	}

	bool SnoopFileReaderDevice::getNextPacket(RawPacket& rawPacket)
	{
		rawPacket.clear();
		if (m_DeviceOpened != true)
		{
			PCPP_LOG_ERROR("File device '" << m_FileName << "' not opened");
			return false;
		}
		snoop_packet_header_t snoop_packet_header;
		m_snoopFile.read((char*)&snoop_packet_header, sizeof(snoop_packet_header_t));
		if (!m_snoopFile)
		{
			return false;
		}
		size_t packetSize = be32toh(snoop_packet_header.included_length);
		if (packetSize > 15000)
		{
			return false;
		}
		std::unique_ptr<char[]> packetData = std::make_unique<char[]>(packetSize);
		m_snoopFile.read(packetData.get(), packetSize);
		if (!m_snoopFile)
		{
			return false;
		}
		timespec ts = { static_cast<time_t>(be32toh(snoop_packet_header.time_sec)),
			            static_cast<long>(be32toh(snoop_packet_header.time_usec)) * 1000 };
		if (!rawPacket.setRawData((const uint8_t*)packetData.release(), packetSize, ts,
		                          static_cast<LinkLayerType>(m_PcapLinkLayerType)))
		{
			PCPP_LOG_ERROR("Couldn't set data to raw packet");
			return false;
		}
		size_t pad = be32toh(snoop_packet_header.packet_record_length) -
		             (sizeof(snoop_packet_header_t) + be32toh(snoop_packet_header.included_length));
		m_snoopFile.ignore(pad);
		if (!m_snoopFile)
		{
			return false;
		}

		m_NumOfPacketsRead++;
		return true;
	}

	void SnoopFileReaderDevice::close()
	{
		m_snoopFile.close();
		m_DeviceOpened = false;
		PCPP_LOG_DEBUG("File reader closed for file '" << m_FileName << "'");
	}

	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	// PcapNgFileReaderDevice members
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	PcapNgFileReaderDevice::PcapNgFileReaderDevice(const std::string& fileName) : IFileReaderDevice(fileName)
	{
		m_LightPcapNg = nullptr;
	}

	bool PcapNgFileReaderDevice::open()
	{
		m_NumOfPacketsRead = 0;
		m_NumOfPacketsNotParsed = 0;

		if (m_LightPcapNg != nullptr)
		{
			PCPP_LOG_DEBUG("pcapng descriptor already opened. Nothing to do");
			return true;
		}

		m_LightPcapNg = toLightPcapNgHandle(light_pcapng_open_read(m_FileName.c_str(), LIGHT_FALSE));
		if (m_LightPcapNg == nullptr)
		{
			PCPP_LOG_ERROR("Cannot open pcapng reader device for filename '" << m_FileName << "'");
			m_DeviceOpened = false;
			return false;
		}

		PCPP_LOG_DEBUG("Successfully opened pcapng reader device for filename '" << m_FileName << "'");
		m_DeviceOpened = true;
		return true;
	}

	bool PcapNgFileReaderDevice::getNextPacket(RawPacket& rawPacket, std::string& packetComment)
	{
		rawPacket.clear();
		packetComment = "";

		if (m_LightPcapNg == nullptr)
		{
			PCPP_LOG_ERROR("Pcapng file device '" << m_FileName << "' not opened");
			return false;
		}

		light_packet_header pktHeader;
		const uint8_t* pktData = nullptr;

		if (!light_get_next_packet(toLightPcapNgT(m_LightPcapNg), &pktHeader, &pktData))
		{
			PCPP_LOG_DEBUG("Packet could not be read. Probably end-of-file");
			return false;
		}

		while (!m_BpfWrapper.matchPacketWithFilter(pktData, pktHeader.captured_length, pktHeader.timestamp,
		                                           pktHeader.data_link))
		{
			if (!light_get_next_packet(toLightPcapNgT(m_LightPcapNg), &pktHeader, &pktData))
			{
				PCPP_LOG_DEBUG("Packet could not be read. Probably end-of-file");
				return false;
			}
		}

		uint8_t* myPacketData = new uint8_t[pktHeader.captured_length];
		memcpy(myPacketData, pktData, pktHeader.captured_length);
		const LinkLayerType linkType = static_cast<LinkLayerType>(pktHeader.data_link);
		if (linkType == LinkLayerType::LINKTYPE_INVALID)
		{
			PCPP_LOG_ERROR("Link layer type of raw packet could not be determined");
		}

		if (!rawPacket.setRawData(myPacketData, pktHeader.captured_length, pktHeader.timestamp, linkType,
		                          pktHeader.original_length))
		{
			PCPP_LOG_ERROR("Couldn't set data to raw packet");
			return false;
		}

		if (pktHeader.comment != nullptr && pktHeader.comment_length > 0)
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
		PCPP_LOG_DEBUG("Statistics received for pcapng reader device for filename '" << m_FileName << "'");
	}

	bool PcapNgFileReaderDevice::setFilter(std::string filterAsString)
	{
		return m_BpfWrapper.setFilter(filterAsString);
	}

	void PcapNgFileReaderDevice::close()
	{
		if (m_LightPcapNg == nullptr)
			return;

		light_pcapng_close(toLightPcapNgT(m_LightPcapNg));
		m_LightPcapNg = nullptr;

		m_DeviceOpened = false;
		PCPP_LOG_DEBUG("File reader closed for file '" << m_FileName << "'");
	}

	std::string PcapNgFileReaderDevice::getOS() const
	{
		if (m_LightPcapNg == nullptr)
		{
			PCPP_LOG_ERROR("Pcapng file device '" << m_FileName << "' not opened");
			return {};
		}

		light_pcapng_file_info* fileInfo = light_pcang_get_file_info(toLightPcapNgT(m_LightPcapNg));
		if (fileInfo == nullptr || fileInfo->os_desc == nullptr || fileInfo->os_desc_size == 0)
			return {};

		return std::string(fileInfo->os_desc, fileInfo->os_desc_size);
	}

	std::string PcapNgFileReaderDevice::getHardware() const
	{
		if (m_LightPcapNg == nullptr)
		{
			PCPP_LOG_ERROR("Pcapng file device '" << m_FileName << "' not opened");
			return {};
		}

		light_pcapng_file_info* fileInfo = light_pcang_get_file_info(toLightPcapNgT(m_LightPcapNg));
		if (fileInfo == nullptr || fileInfo->hardware_desc == nullptr || fileInfo->hardware_desc_size == 0)
			return {};

		return std::string(fileInfo->hardware_desc, fileInfo->hardware_desc_size);
	}

	std::string PcapNgFileReaderDevice::getCaptureApplication() const
	{
		if (m_LightPcapNg == nullptr)
		{
			PCPP_LOG_ERROR("Pcapng file device '" << m_FileName << "' not opened");
			return {};
		}

		light_pcapng_file_info* fileInfo = light_pcang_get_file_info(toLightPcapNgT(m_LightPcapNg));
		if (fileInfo == nullptr || fileInfo->user_app_desc == nullptr || fileInfo->user_app_desc_size == 0)
			return {};

		return std::string(fileInfo->user_app_desc, fileInfo->user_app_desc_size);
	}

	std::string PcapNgFileReaderDevice::getCaptureFileComment() const
	{
		if (m_LightPcapNg == nullptr)
		{
			PCPP_LOG_ERROR("Pcapng file device '" << m_FileName << "' not opened");
			return {};
		}

		light_pcapng_file_info* fileInfo = light_pcang_get_file_info(toLightPcapNgT(m_LightPcapNg));
		if (fileInfo == nullptr || fileInfo->file_comment == nullptr || fileInfo->file_comment_size == 0)
			return {};

		return std::string(fileInfo->file_comment, fileInfo->file_comment_size);
	}

	// ~~~~~~~~~~~~~~~~~~~~~~~~~
	// IFileWriterDevice members
	// ~~~~~~~~~~~~~~~~~~~~~~~~~

	IFileWriterDevice::IFileWriterDevice(const std::string& fileName) : IFileDevice(fileName)
	{
		m_NumOfPacketsNotWritten = 0;
		m_NumOfPacketsWritten = 0;
	}

	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	// PcapFileWriterDevice members
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	PcapFileWriterDevice::PcapFileWriterDevice(const std::string& fileName, LinkLayerType linkLayerType,
	                                           bool nanosecondsPrecision)
	    : IFileWriterDevice(fileName)
	{
		m_PcapDumpHandler = nullptr;
		m_PcapLinkLayerType = linkLayerType;
		m_AppendMode = false;
#if defined(PCAP_TSTAMP_PRECISION_NANO)
		m_Precision = nanosecondsPrecision ? FileTimestampPrecision::Nanoseconds : FileTimestampPrecision::Microseconds;
#else
		if (nanosecondsPrecision)
		{
			PCPP_LOG_ERROR(
			    "PcapPlusPlus was compiled without nano precision support which requires libpcap > 1.5.1. Please "
			    "recompile PcapPlusPlus with nano precision support to use this feature. Using default microsecond precision");
		}
		m_Precision = FileTimestampPrecision::Microseconds;
#endif
		m_File = nullptr;
	}

	void PcapFileWriterDevice::closeFile()
	{
		if (m_AppendMode && m_File != nullptr)
		{
			fclose(m_File);
			m_File = nullptr;
		}
	}

	bool PcapFileWriterDevice::writePacket(RawPacket const& packet)
	{
		if ((!m_AppendMode && m_PcapDescriptor == nullptr) || (m_PcapDumpHandler == nullptr))
		{
			PCPP_LOG_ERROR("Device not opened");
			m_NumOfPacketsNotWritten++;
			return false;
		}

		if (packet.getLinkLayerType() != m_PcapLinkLayerType)
		{
			PCPP_LOG_ERROR("Cannot write a packet with a different link layer type");
			m_NumOfPacketsNotWritten++;
			return false;
		}

		pcap_pkthdr pktHdr;
		pktHdr.caplen = packet.getRawDataLen();
		pktHdr.len = packet.getFrameLength();
		timespec packet_timestamp = packet.getPacketTimeStamp();
#if defined(PCAP_TSTAMP_PRECISION_NANO)
		if (m_Precision != FileTimestampPrecision::Nanoseconds)
		{
			pktHdr.ts = internal::toTimeval(packet_timestamp);
		}
		else
		{
			pktHdr.ts.tv_sec = packet_timestamp.tv_sec;
			pktHdr.ts.tv_usec = packet_timestamp.tv_nsec;
		}
#else
		pktHdr.ts = internal::toTimeval(packet_timestamp);
#endif
		if (!m_AppendMode)
			pcap_dump(reinterpret_cast<uint8_t*>(m_PcapDumpHandler), &pktHdr, packet.getRawData());
		else
		{
			// Below are actually the lines run by pcap_dump. The reason I had to put them instead pcap_dump is that on
			// Windows using WinPcap/Npcap you can't pass pointers between libraries compiled with different compilers.
			// In this case - PcapPlusPlus and WinPcap/Npcap weren't compiled with the same compiler so it's impossible
			// to fopen a file in PcapPlusPlus, pass the pointer to WinPcap/Npcap and use the FILE* pointer there. Doing
			// this throws an exception. So the only option when implementing append to pcap is to write all relevant
			// WinPcap/Npcap code that handles opening/closing/writing to pcap files inside PcapPlusPlus code

			// the reason to create this packet_header struct is timeval has different sizes in 32-bit and 64-bit
			// systems, but pcap format uses the 32-bit timeval version, so we need to align timeval to that
			packet_header pktHdrTemp;
			pktHdrTemp.tv_sec = pktHdr.ts.tv_sec;
			pktHdrTemp.tv_usec = pktHdr.ts.tv_usec;
			pktHdrTemp.caplen = pktHdr.caplen;
			pktHdrTemp.len = pktHdr.len;
			fwrite(&pktHdrTemp, sizeof(pktHdrTemp), 1, m_File);
			fwrite(packet.getRawData(), pktHdrTemp.caplen, 1, m_File);
		}
		PCPP_LOG_DEBUG("Packet written successfully to '" << m_FileName << "'");
		m_NumOfPacketsWritten++;
		return true;
	}

	bool PcapFileWriterDevice::writePackets(const RawPacketVector& packets)
	{
		for (auto packet : packets)
		{
			if (!writePacket(*packet))
				return false;
		}

		return true;
	}

	bool PcapFileWriterDevice::isNanoSecondPrecisionSupported()
	{
		return checkNanoSupport();
	}

	bool PcapFileWriterDevice::open()
	{
		return open(false);
	}

	bool PcapFileWriterDevice::open(bool appendMode)
	{
		if (isOpened())
		{
			// TODO: Ambiguity in API
			//   If appendMode is required but the file is already opened in write mode.
			PCPP_LOG_DEBUG("Pcap descriptor already opened. Nothing to do");
			return true;
		}

		if (appendMode)
		{
			return openAppend();
		}
		else
		{
			return openWrite();
		}
	}

	bool PcapFileWriterDevice::openWrite()
	{
		m_AppendMode = false;

		switch (m_PcapLinkLayerType)
		{
		case LINKTYPE_RAW:
		case LINKTYPE_DLT_RAW2:
			PCPP_LOG_ERROR(
			    "The only Raw IP link type supported in libpcap/WinPcap/Npcap is LINKTYPE_DLT_RAW1, please use that instead");
			return false;
		default:
			break;
		}

		m_NumOfPacketsNotWritten = 0;
		m_NumOfPacketsWritten = 0;

#if defined(PCAP_TSTAMP_PRECISION_NANO)
		auto pcapDescriptor = internal::PcapHandle(pcap_open_dead_with_tstamp_precision(
		    m_PcapLinkLayerType, PCPP_MAX_PACKET_SIZE, static_cast<int>(m_Precision)));
#else
		auto pcapDescriptor = internal::PcapHandle(pcap_open_dead(m_PcapLinkLayerType, PCPP_MAX_PACKET_SIZE));
#endif
		if (pcapDescriptor == nullptr)
		{
			PCPP_LOG_ERROR("Error opening file writer device for file '" << m_FileName
			                                                             << "': pcap_open_dead returned nullptr");
			m_DeviceOpened = false;
			return false;
		}

		m_PcapDumpHandler = pcap_dump_open(pcapDescriptor.get(), m_FileName.c_str());
		if (m_PcapDumpHandler == nullptr)
		{
			PCPP_LOG_ERROR("Error opening file writer device for file '"
			               << m_FileName << "': pcap_dump_open returned nullptr with error: '"
			               << pcapDescriptor.getLastError() << "'");
			m_DeviceOpened = false;
			return false;
		}

		m_PcapDescriptor = std::move(pcapDescriptor);
		m_DeviceOpened = true;
		PCPP_LOG_DEBUG("File writer device for file '" << m_FileName << "' opened successfully");
		return true;
	}

	bool PcapFileWriterDevice::openAppend()
	{
		m_AppendMode = true;

#if !defined(_WIN32)
		m_File = fopen(m_FileName.c_str(), "r+");
#else
		m_File = fopen(m_FileName.c_str(), "rb+");
#endif

		if (m_File == nullptr)
		{
			PCPP_LOG_ERROR("Cannot open '" << m_FileName << "' for reading and writing");
			return false;
		}

		pcap_file_header pcapFileHeader;
		int amountRead = fread(&pcapFileHeader, 1, sizeof(pcapFileHeader), m_File);
		if (amountRead != sizeof(pcap_file_header))
		{
			if (ferror(m_File))
				PCPP_LOG_ERROR("Cannot read pcap header from file '" << m_FileName << "', error was: " << errno);
			else
				PCPP_LOG_ERROR("Cannot read pcap header from file '" << m_FileName << "', unknown error");

			closeFile();
			return false;
		}

		LinkLayerType linkLayerType = static_cast<LinkLayerType>(pcapFileHeader.linktype);
		if (linkLayerType != m_PcapLinkLayerType)
		{
			PCPP_LOG_ERROR(
			    "Pcap file has a different link layer type than the one chosen in PcapFileWriterDevice c'tor, "
			    << linkLayerType << ", " << m_PcapLinkLayerType);
			closeFile();
			return false;
		}

		if (fseek(m_File, 0, SEEK_END) == -1)
		{
			PCPP_LOG_ERROR("Cannot read pcap file '" << m_FileName << "' to it's end, error was: " << errno);
			closeFile();
			return false;
		}

		m_PcapDumpHandler = reinterpret_cast<pcap_dumper_t*>(m_File);

		m_DeviceOpened = true;
		PCPP_LOG_DEBUG("File writer device for file '" << m_FileName << "' opened successfully in append mode");
		return true;
	}

	void PcapFileWriterDevice::flush()
	{
		if (!m_DeviceOpened)
			return;

		if (!m_AppendMode && pcap_dump_flush(m_PcapDumpHandler) == -1)
		{
			PCPP_LOG_ERROR("Error while flushing the packets to file");
		}
		// in append mode it's impossible to use pcap_dump_flush, see comment above pcap_dump
		else if (m_AppendMode && fflush(m_File) == EOF)
		{
			PCPP_LOG_ERROR("Error while flushing the packets to file");
		}
	}

	void PcapFileWriterDevice::close()
	{
		if (!m_DeviceOpened)
			return;

		flush();

		IFileDevice::close();

		if (!m_AppendMode && m_PcapDumpHandler != nullptr)
		{
			pcap_dump_close(m_PcapDumpHandler);
		}
		else if (m_AppendMode && m_File != nullptr)
		{
			// in append mode it's impossible to use pcap_dump_close, see comment above pcap_dump
			fclose(m_File);
		}

		m_PcapDumpHandler = nullptr;
		m_File = nullptr;
		PCPP_LOG_DEBUG("File writer closed for file '" << m_FileName << "'");
	}

	void PcapFileWriterDevice::getStatistics(PcapStats& stats) const
	{
		stats.packetsRecv = m_NumOfPacketsWritten;
		stats.packetsDrop = m_NumOfPacketsNotWritten;
		stats.packetsDropByInterface = 0;
		PCPP_LOG_DEBUG("Statistics received for writer device for filename '" << m_FileName << "'");
	}

	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	// PcapNgFileWriterDevice members
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	PcapNgFileWriterDevice::PcapNgFileWriterDevice(const std::string& fileName, int compressionLevel)
	    : IFileWriterDevice(fileName)
	{
		m_LightPcapNg = nullptr;
		m_CompressionLevel = compressionLevel;
	}

	bool PcapNgFileWriterDevice::writePacket(RawPacket const& packet, const std::string& comment)
	{
		if (m_LightPcapNg == nullptr)
		{
			PCPP_LOG_ERROR("Device not opened");
			m_NumOfPacketsNotWritten++;
			return false;
		}

		if (!m_BpfWrapper.matchPacketWithFilter(&packet))
		{
			return false;
		}

		light_packet_header pktHeader;
		pktHeader.captured_length = packet.getRawDataLen();
		pktHeader.original_length = packet.getFrameLength();
		pktHeader.timestamp = packet.getPacketTimeStamp();
		pktHeader.data_link = static_cast<uint16_t>(packet.getLinkLayerType());
		pktHeader.interface_id = 0;
		if (!comment.empty())
		{
			pktHeader.comment = const_cast<char*>(comment.c_str());
			pktHeader.comment_length = static_cast<uint16_t>(comment.size());
		}
		else
		{
			pktHeader.comment = nullptr;
			pktHeader.comment_length = 0;
		}

		const uint8_t* pktData = packet.getRawData();

		light_write_packet(toLightPcapNgT(m_LightPcapNg), &pktHeader, pktData);
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
		return openWrite();
	}

	bool PcapNgFileWriterDevice::open(bool appendMode)
	{
		return appendMode ? openAppend() : openWrite();
	}

	bool PcapNgFileWriterDevice::open(const std::string& os, const std::string& hardware, const std::string& captureApp,
	                                  const std::string& fileComment)
	{
		PcapNgMetadata metadata;
		metadata.os = os;
		metadata.hardware = hardware;
		metadata.captureApplication = captureApp;
		metadata.comment = fileComment;
		return openWrite(&metadata);
	}

	bool PcapNgFileWriterDevice::openWrite(PcapNgMetadata const* metadata)
	{
		// TODO: Ambiguity in the API
		//   If the user calls open() and then open(true) - should we close the first one or report failure?
		//   Currently the method reports a success, but the opened device would not match the appendMode.
		if (m_LightPcapNg != nullptr)
		{
			PCPP_LOG_DEBUG("Pcap-ng descriptor already opened. Nothing to do");
			return true;
		}

		m_NumOfPacketsNotWritten = 0;
		m_NumOfPacketsWritten = 0;

		light_pcapng_file_info* info;
		if (metadata == nullptr)
		{
			info = light_create_default_file_info();
		}
		else
		{
			info = light_create_file_info(metadata->os.c_str(), metadata->hardware.c_str(),
			                              metadata->captureApplication.c_str(), metadata->comment.c_str());
		}

		m_LightPcapNg = toLightPcapNgHandle(light_pcapng_open_write(m_FileName.c_str(), info, m_CompressionLevel));
		if (m_LightPcapNg == nullptr)
		{
			PCPP_LOG_ERROR("Error opening file writer device for file '"
			               << m_FileName << "': light_pcapng_open_write returned nullptr");

			light_free_file_info(info);

			m_DeviceOpened = false;
			return false;
		}

		m_DeviceOpened = true;
		PCPP_LOG_DEBUG("pcap-ng writer device for file '" << m_FileName << "' opened successfully");
		return true;
	}

	bool PcapNgFileWriterDevice::openAppend()
	{
		// TODO: Ambiguity in the API
		//   If the user calls open() and then open(true) - should we close the first one or report failure?
		//   Currently the method reports a success, but the opened device would not match the appendMode.
		if (m_LightPcapNg != nullptr)
		{
			PCPP_LOG_DEBUG("Pcap-ng descriptor already opened. Nothing to do");
			return true;
		}

		m_NumOfPacketsNotWritten = 0;
		m_NumOfPacketsWritten = 0;

		m_LightPcapNg = toLightPcapNgHandle(light_pcapng_open_append(m_FileName.c_str()));
		if (m_LightPcapNg == nullptr)
		{
			PCPP_LOG_ERROR("Error opening file writer device in append mode for file '"
			               << m_FileName << "': light_pcapng_open_append returned nullptr");
			m_DeviceOpened = false;
			return false;
		}

		m_DeviceOpened = true;
		PCPP_LOG_DEBUG("pcap-ng writer device for file '" << m_FileName << "' opened successfully");
		return true;
	}

	void PcapNgFileWriterDevice::flush()
	{
		if (!m_DeviceOpened || m_LightPcapNg == nullptr)
			return;

		light_pcapng_flush(toLightPcapNgT(m_LightPcapNg));
		PCPP_LOG_DEBUG("File writer flushed to file '" << m_FileName << "'");
	}

	void PcapNgFileWriterDevice::close()
	{
		if (m_LightPcapNg == nullptr)
			return;

		light_pcapng_close(toLightPcapNgT(m_LightPcapNg));
		m_LightPcapNg = nullptr;

		m_DeviceOpened = false;
		PCPP_LOG_DEBUG("File writer closed for file '" << m_FileName << "'");
	}

	void PcapNgFileWriterDevice::getStatistics(PcapStats& stats) const
	{
		stats.packetsRecv = m_NumOfPacketsWritten;
		stats.packetsDrop = m_NumOfPacketsNotWritten;
		stats.packetsDropByInterface = 0;
		PCPP_LOG_DEBUG("Statistics received for pcap-ng writer device for filename '" << m_FileName << "'");
	}

	bool PcapNgFileWriterDevice::setFilter(std::string filterAsString)
	{
		return m_BpfWrapper.setFilter(filterAsString);
	}

}  // namespace pcpp
