#define LOG_MODULE PcapLogModuleFileDevice

#include <algorithm>
#include <iterator>

#include "PcapFileDevice.h"
#include "light_pcapng_ext.h"
#include "Logger.h"
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

	// Magic numbers for different pcap formats
	constexpr uint32_t TCPDUMP_MAGIC = 0xa1b2c3d4;
	constexpr uint32_t TCPDUMP_MAGIC_SWAPPED = 0xd4c3b2a1;
	constexpr uint32_t NSEC_TCPDUMP_MAGIC = 0xa1b23c4d;
	constexpr uint32_t NSEC_TCPDUMP_MAGIC_SWAPPED = 0x4d3cb2a1;

	constexpr uint16_t PCAP_MAJOR_VERSION = 2;
	constexpr uint16_t PCAP_MINOR_VERSION = 4;

#pragma pack(push, 1)
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

	static_assert(sizeof(pcap_file_header) == 24, "pcap_file_header must be 24 bytes long");

	struct packet_header
	{
		uint32_t tv_sec;
		uint32_t tv_usec;
		uint32_t caplen;
		uint32_t len;
	};
	static_assert(sizeof(packet_header) == 16, "packet_header must be 16 bytes long");
#pragma pack(pop)

	LinkLayerType toLinkLayerType(uint32_t value)
	{
		switch (value)
		{
		case LINKTYPE_NULL:
		case LINKTYPE_ETHERNET:
		case LINKTYPE_AX25:
		case LINKTYPE_IEEE802_5:
		case LINKTYPE_ARCNET_BSD:
		case LINKTYPE_SLIP:
		case LINKTYPE_PPP:
		case LINKTYPE_FDDI:
		case LINKTYPE_DLT_RAW1:
		case LINKTYPE_DLT_RAW2:
		case LINKTYPE_PPP_HDLC:
		case LINKTYPE_PPP_ETHER:
		case LINKTYPE_ATM_RFC1483:
		case LINKTYPE_RAW:
		case LINKTYPE_C_HDLC:
		case LINKTYPE_IEEE802_11:
		case LINKTYPE_FRELAY:
		case LINKTYPE_LOOP:
		case LINKTYPE_LINUX_SLL:
		case LINKTYPE_LTALK:
		case LINKTYPE_PFLOG:
		case LINKTYPE_IEEE802_11_PRISM:
		case LINKTYPE_IP_OVER_FC:
		case LINKTYPE_SUNATM:
		case LINKTYPE_IEEE802_11_RADIOTAP:
		case LINKTYPE_ARCNET_LINUX:
		case LINKTYPE_APPLE_IP_OVER_IEEE1394:
		case LINKTYPE_MTP2_WITH_PHDR:
		case LINKTYPE_MTP2:
		case LINKTYPE_MTP3:
		case LINKTYPE_SCCP:
		case LINKTYPE_DOCSIS:
		case LINKTYPE_LINUX_IRDA:
		case LINKTYPE_USER0:
		case LINKTYPE_USER1:
		case LINKTYPE_USER2:
		case LINKTYPE_USER3:
		case LINKTYPE_USER4:
		case LINKTYPE_USER5:
		case LINKTYPE_USER6:
		case LINKTYPE_USER7:
		case LINKTYPE_USER8:
		case LINKTYPE_USER9:
		case LINKTYPE_USER10:
		case LINKTYPE_USER11:
		case LINKTYPE_USER12:
		case LINKTYPE_USER13:
		case LINKTYPE_USER14:
		case LINKTYPE_USER15:
		case LINKTYPE_IEEE802_11_AVS:
		case LINKTYPE_BACNET_MS_TP:
		case LINKTYPE_PPP_PPPD:
		case LINKTYPE_GPRS_LLC:
		case LINKTYPE_GPF_T:
		case LINKTYPE_GPF_F:
		case LINKTYPE_LINUX_LAPD:
		case LINKTYPE_BLUETOOTH_HCI_H4:
		case LINKTYPE_USB_LINUX:
		case LINKTYPE_PPI:
		case LINKTYPE_IEEE802_15_4:
		case LINKTYPE_SITA:
		case LINKTYPE_ERF:
		case LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR:
		case LINKTYPE_AX25_KISS:
		case LINKTYPE_LAPD:
		case LINKTYPE_PPP_WITH_DIR:
		case LINKTYPE_C_HDLC_WITH_DIR:
		case LINKTYPE_FRELAY_WITH_DIR:
		case LINKTYPE_IPMB_LINUX:
		case LINKTYPE_IEEE802_15_4_NONASK_PHY:
		case LINKTYPE_USB_LINUX_MMAPPED:
		case LINKTYPE_FC_2:
		case LINKTYPE_FC_2_WITH_FRAME_DELIMS:
		case LINKTYPE_IPNET:
		case LINKTYPE_CAN_SOCKETCAN:
		case LINKTYPE_IPV4:
		case LINKTYPE_IPV6:
		case LINKTYPE_IEEE802_15_4_NOFCS:
		case LINKTYPE_DBUS:
		case LINKTYPE_DVB_CI:
		case LINKTYPE_MUX27010:
		case LINKTYPE_STANAG_5066_D_PDU:
		case LINKTYPE_NFLOG:
		case LINKTYPE_NETANALYZER:
		case LINKTYPE_NETANALYZER_TRANSPARENT:
		case LINKTYPE_IPOIB:
		case LINKTYPE_MPEG_2_TS:
		case LINKTYPE_NG40:
		case LINKTYPE_NFC_LLCP:
		case LINKTYPE_INFINIBAND:
		case LINKTYPE_SCTP:
		case LINKTYPE_USBPCAP:
		case LINKTYPE_RTAC_SERIAL:
		case LINKTYPE_BLUETOOTH_LE_LL:
		case LINKTYPE_NETLINK:
		case LINKTYPE_BLUETOOTH_LINUX_MONITOR:
		case LINKTYPE_BLUETOOTH_BREDR_BB:
		case LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR:
		case LINKTYPE_PROFIBUS_DL:
		case LINKTYPE_PKTAP:
		case LINKTYPE_EPON:
		case LINKTYPE_IPMI_HPM_2:
		case LINKTYPE_ZWAVE_R1_R2:
		case LINKTYPE_ZWAVE_R3:
		case LINKTYPE_WATTSTOPPER_DLM:
		case LINKTYPE_ISO_14443:
		case LINKTYPE_LINUX_SLL2:
		{
			return static_cast<LinkLayerType>(value);
		}

		default:
		{
			return LINKTYPE_INVALID;
		}
		}
	}

	static std::string toString(FileTimestampPrecision precision)
	{
		switch (precision)
		{
		case FileTimestampPrecision::Microseconds:
			return "Microseconds";
		case FileTimestampPrecision::Nanoseconds:
			return "Nanoseconds";
		default:
			return "Unknown";
		}
	}

	// ~~~~~~~~~~~~~~~~~~~
	// IFileDevice members
	// ~~~~~~~~~~~~~~~~~~~

	IFileDevice::IFileDevice(const std::string& fileName)
	{
		m_FileName = fileName;
	}

	std::string IFileDevice::getFileName() const
	{
		return m_FileName;
	}

	void IFileDevice::getStatistics(PcapStats& stats) const
	{
		PCPP_LOG_DEBUG("Statistics requested for file device for filename '" << m_FileName << "'");
		stats.packetsRecv = m_NumOfPacketsProcessed;
		stats.packetsDrop = m_NumOfPacketsDropped;
		stats.packetsDropByInterface = 0;
	}

	void IFileDevice::resetStatisticCounters()
	{
		m_NumOfPacketsProcessed = 0;
		m_NumOfPacketsDropped = 0;
	}

	bool IFileDevice::doUpdateFilter(std::string const* filterAsString)
	{
		if (filterAsString == nullptr)
		{
			return m_BpfWrapper.setFilter("");
		}

		return m_BpfWrapper.setFilter(*filterAsString);
	}

	// ~~~~~~~~~~~~~~~~~~~~~~~~~
	// IFileReaderDevice members
	// ~~~~~~~~~~~~~~~~~~~~~~~~~

	IFileReaderDevice::IFileReaderDevice(const std::string& fileName) : IFileDevice(fileName)
	{}

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

	// ~~~~~~~~~~~~~~~~~~~~~~~~~
	// IFileWriterDevice members
	// ~~~~~~~~~~~~~~~~~~~~~~~~~

	IFileWriterDevice::IFileWriterDevice(const std::string& fileName) : IFileDevice(fileName)
	{}

	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	// PcapFileReaderDevice members
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	namespace
	{
		uint16_t swap16(uint16_t value)
		{
			return static_cast<uint16_t>((value >> 8) | (value << 8));
		}

		uint32_t swap32(uint32_t value)
		{
			return (value >> 24) | ((value >> 8) & 0x0000FF00) | ((value << 8) & 0x00FF0000) | (value << 24);
		}

		enum class PcapReadHeaderStatus
		{
			Ok,
			NoData,
			MalformedData,
			UnsupportedFormat
		};

		/// @brief Reads a pcap file header from the given input stream and fills the provided header structure,
		/// timestamp precision, and byte swap flag.
		///
		/// The function will populate the file header structure and convert it to host byte order.
		///
		/// @param inStream The input stream to read from.
		/// @param header A pcap_file_header structure that will be filled with the header data read from the stream.
		/// @param precision The precision of the timestamps in the pcap file.
		/// @param needsSwap If the file contents need to be byte-swapped to match the host's endianness.
		/// @return The status of the reading operation.
		PcapReadHeaderStatus readPcapHeader(std::istream& inStream, pcap_file_header& header,
		                                    FileTimestampPrecision& precision, bool& needsSwap)
		{
			inStream.read(reinterpret_cast<char*>(&header), sizeof(header));

			auto readBytes = inStream.gcount();
			if (readBytes == 0)
			{
				return PcapReadHeaderStatus::NoData;
			}
			else if (readBytes < static_cast<std::streamsize>(sizeof(header)))
			{
				return PcapReadHeaderStatus::MalformedData;
			}

			switch (header.magic)
			{
			case TCPDUMP_MAGIC:
			{
				precision = FileTimestampPrecision::Microseconds;
				needsSwap = false;
				break;
			}
			case TCPDUMP_MAGIC_SWAPPED:
			{
				precision = FileTimestampPrecision::Microseconds;
				needsSwap = true;
				break;
			}
			case NSEC_TCPDUMP_MAGIC:
			{
				precision = FileTimestampPrecision::Nanoseconds;
				needsSwap = false;
				break;
			}
			case NSEC_TCPDUMP_MAGIC_SWAPPED:
			{
				precision = FileTimestampPrecision::Nanoseconds;
				needsSwap = true;
				break;
			}
			default:
			{
				return PcapReadHeaderStatus::UnsupportedFormat;
			}
			}

			if (needsSwap)
			{
				header.magic = swap32(header.magic);
				header.version_major = swap16(header.version_major);
				header.version_minor = swap16(header.version_minor);
				header.thiszone = swap32(header.thiszone);
				header.sigfigs = swap32(header.sigfigs);
				header.snaplen = swap32(header.snaplen);
				header.linktype = swap32(header.linktype);
			}

			return PcapReadHeaderStatus::Ok;
		}

		bool writePcapHeader(std::ostream& outStream, FileTimestampPrecision precision, uint32_t snaplen,
		                     LinkLayerType linkType)
		{
			pcap_file_header header{ precision == FileTimestampPrecision::Microseconds ? TCPDUMP_MAGIC
				                                                                       : NSEC_TCPDUMP_MAGIC,
				                     PCAP_MAJOR_VERSION,
				                     PCAP_MINOR_VERSION,
				                     0,
				                     0,
				                     snaplen,
				                     static_cast<uint32_t>(linkType) };

			outStream.write(reinterpret_cast<const char*>(&header), sizeof(header));

			if (!outStream.good())
			{
				PCPP_LOG_ERROR("Error writing pcap header");
				return false;
			}

			return true;
		}
	}  // namespace

	bool PcapFileReaderDevice::open()
	{
		if (m_PcapFile.is_open())
		{
			PCPP_LOG_ERROR("File already opened");
			return false;
		}

		resetStatisticCounters();

		std::ifstream pcapFile;
		pcapFile.open(m_FileName.c_str(), std::ifstream::binary);
		if (!pcapFile.is_open())
		{
			PCPP_LOG_ERROR("Cannot open pcap reader device for filename '" << m_FileName << "'");
			return false;
		}

		pcap_file_header pcapFileHeader{};
		auto status = readPcapHeader(pcapFile, pcapFileHeader, m_Precision, m_NeedsSwap);
		switch (status)
		{
		case PcapReadHeaderStatus::Ok:
			break;
		case PcapReadHeaderStatus::NoData:
		case PcapReadHeaderStatus::MalformedData:
		{
			PCPP_LOG_ERROR("Cannot read pcap file header");
			return false;
		}
		case PcapReadHeaderStatus::UnsupportedFormat:
		{
			PCPP_LOG_ERROR("Invalid magic number: 0x" << std::hex << pcapFileHeader.magic);
			return false;
		}
		default:
			throw std::logic_error("Unhandled PcapReadHeaderStatus value");
		}

		if (pcapFileHeader.version_major != 2 && pcapFileHeader.version_major != 543)
		{
			PCPP_LOG_ERROR("Unsupported pcap file version: " << std::to_string(pcapFileHeader.version_major) << "."
			                                                 << std::to_string(pcapFileHeader.version_minor));
			return false;
		}

		constexpr uint32_t MAX_SNAPLEN = 1024 * 1024;
		if (pcapFileHeader.snaplen == 0 || pcapFileHeader.snaplen > MAX_SNAPLEN)
		{
			PCPP_LOG_ERROR("Invalid snapshot length: " << std::to_string(pcapFileHeader.snaplen));
			return false;
		}

		m_PcapLinkLayerType = toLinkLayerType(pcapFileHeader.linktype);

		m_SnapshotLength = pcapFileHeader.snaplen;
		m_ReadBuffer.resize(m_SnapshotLength);

		m_PcapFile = std::move(pcapFile);
		return true;
	}

	bool PcapFileReaderDevice::getNextPacket(RawPacket& rawPacket)
	{
		timespec packetTimestamp;
		uint32_t capturedLength = 0, frameLength = 0;

		while (readNextPacket(packetTimestamp, m_ReadBuffer.data(), m_SnapshotLength, capturedLength, frameLength))
		{
			if (m_BpfWrapper.matches(m_ReadBuffer.data(), capturedLength, packetTimestamp, m_PcapLinkLayerType))
			{
				// TODO: Fixup tirage hack of adding 20 bytes buffer to pass fuzz.
				auto packetData = std::make_unique<uint8_t[]>(capturedLength /* + 200 */);
				std::copy(m_ReadBuffer.begin(), std::next(m_ReadBuffer.begin(), capturedLength), packetData.get());

				rawPacket.setRawData(capturedLength > 0 ? packetData.release() : nullptr, capturedLength, true,
				                     packetTimestamp, m_PcapLinkLayerType, frameLength);
				reportPacketProcessed();
				return true;
			}
			PCPP_LOG_DEBUG("Packet doesn't match filter");
		}

		return false;
	}

	void PcapFileReaderDevice::close()
	{
		m_PcapFile.close();
	}

	bool PcapFileReaderDevice::readNextPacket(timespec& packetTimestamp, uint8_t* packetData, uint32_t packetDataLen,
	                                          uint32_t& capturedLength, uint32_t& frameLength)
	{
		packet_header packetHeader{};
		m_PcapFile.read(reinterpret_cast<char*>(&packetHeader), sizeof(packetHeader));

		auto bytesRead = m_PcapFile.gcount();
		if (bytesRead == 0)
		{
			return false;
		}

		if (static_cast<size_t>(bytesRead) < sizeof(packetHeader))
		{
			PCPP_LOG_ERROR("Failed to read packet metadata");
			return false;
		}

		if (m_NeedsSwap)
		{
			packetHeader.tv_sec = swap32(packetHeader.tv_sec);
			packetHeader.tv_usec = swap32(packetHeader.tv_usec);
			packetHeader.caplen = swap32(packetHeader.caplen);
			packetHeader.len = swap32(packetHeader.len);
		}

		if (packetHeader.caplen > packetHeader.len)
		{
			PCPP_LOG_ERROR("Packet captured length " << packetHeader.caplen << " exceeds packet length "
			                                         << packetHeader.len);
			return false;
		}

		constexpr uint32_t MAX_PACKET_SIZE = 256 * 1024;
		if (packetHeader.caplen > MAX_PACKET_SIZE)
		{
			PCPP_LOG_ERROR("Packet captured length " << packetHeader.caplen << " is suspiciously large");
			return false;
		}

		if (m_Precision == FileTimestampPrecision::Nanoseconds)
		{
			constexpr uint32_t NANO_PER_SEC = 1'000'000'000;
			if (packetHeader.tv_usec >= NANO_PER_SEC)
			{
				PCPP_LOG_ERROR("Invalid nanosecond timestamp: " << std::to_string(packetHeader.tv_usec));
				return false;
			}
		}
		else
		{
			constexpr uint32_t MICRO_PER_SEC = 1'000'000;
			if (packetHeader.tv_usec >= MICRO_PER_SEC)
			{
				PCPP_LOG_ERROR("Invalid microsecond timestamp: " << std::to_string(packetHeader.tv_usec));
				return false;
			}
		}

		uint32_t bytesToDiscard = 0;
		if (packetHeader.caplen > packetDataLen)
		{
			PCPP_LOG_WARN("Packet captured length " << packetHeader.caplen << " exceeds file snapshot length "
			                                        << packetDataLen);
			bytesToDiscard = packetHeader.caplen - packetDataLen;
			packetHeader.caplen = packetDataLen;
		}

		if (packetHeader.caplen > 0 && !m_PcapFile.read(reinterpret_cast<char*>(packetData), packetHeader.caplen))
		{
			PCPP_LOG_ERROR("Failed to read packet data");
			return false;
		}

		if (bytesToDiscard && !m_PcapFile.ignore(bytesToDiscard))
		{
			PCPP_LOG_ERROR("Failed to read discarded packet data");
			return false;
		}

		capturedLength = packetHeader.caplen;
		frameLength = packetHeader.len;
		packetTimestamp = { static_cast<time_t>(packetHeader.tv_sec),
			                static_cast<long>(m_Precision == FileTimestampPrecision::Microseconds
			                                      ? packetHeader.tv_usec * 1000
			                                      : packetHeader.tv_usec) };
		return true;
	}

	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	// PcapFileWriterDevice members
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	PcapFileWriterDevice::PcapFileWriterDevice(const std::string& fileName, LinkLayerType linkLayerType,
	                                           bool nanosecondsPrecision)
	    : IFileWriterDevice(fileName),
	      m_Precision(nanosecondsPrecision ? FileTimestampPrecision::Nanoseconds : FileTimestampPrecision::Microseconds)
	{
		if (linkLayerType == LINKTYPE_DLT_RAW1 || linkLayerType == LINKTYPE_DLT_RAW2)
		{
			m_PcapLinkLayerType = LINKTYPE_RAW;
		}
		else
		{
			m_PcapLinkLayerType = linkLayerType;
		}
	}

	bool PcapFileWriterDevice::open()
	{
		return open(false);
	}

	bool PcapFileWriterDevice::open(bool appendMode)
	{
		if (m_PcapFile.is_open())
		{
			PCPP_LOG_ERROR("File already opened");
			return false;
		}

		auto flags = std::ios::binary | std::ios::out;
		if (appendMode)
		{
			flags |= std::ios::in | std::ios::app;
		}

		std::fstream pcapFile;
		pcapFile.open(m_FileName, flags);

		if (!pcapFile.is_open())
		{
			PCPP_LOG_ERROR("Failed to open file: " << m_FileName);
			return false;
		}

		m_NeedsSwap = false;
		bool shouldWriteHeader = true;

		if (appendMode)
		{
			// Using temporary to avoid modifying member variables in case of failure to read header
			bool needsSwap = false;
			FileTimestampPrecision precisionFromHeader;
			pcap_file_header header;
			auto status = readPcapHeader(pcapFile, header, precisionFromHeader, needsSwap);
			switch (status)
			{
			case PcapReadHeaderStatus::Ok:
			{
				// We have a valid header
				PCPP_LOG_DEBUG("Read existing pcap header file.");
				shouldWriteHeader = false;
				break;
			}
			case PcapReadHeaderStatus::NoData:
			{
				// Empty file - proceed as if we are creating a new file
				if(pcapFile.bad())
				{
					// badbit errors are generally unrecoverable.
					PCPP_LOG_ERROR("Error reading pcap file.");
					return false;
				}

				PCPP_LOG_DEBUG("File is empty. A new pcap header will be written.");
				pcapFile.clear();  // Clear EOF or failbit state to allow writing
				shouldWriteHeader = true;
				break;
			}
			case PcapReadHeaderStatus::MalformedData:
			{
				PCPP_LOG_ERROR("Cannot read pcap file header. File may be malformed or not a pcap file");
				return false;
			}
			case PcapReadHeaderStatus::UnsupportedFormat:
			{
				PCPP_LOG_ERROR("Cannot read pcap file header. Unsupported format or invalid magic number: 0x"
				               << std::hex << header.magic);
				return false;
			}
			default:
				throw std::logic_error("Unexpected PcapReadHeaderStatus value");
			}

			// If we have a header, validate that the file is compatible.
			if (!shouldWriteHeader)
			{
				m_NeedsSwap = needsSwap;

				if (precisionFromHeader != m_Precision)
				{
					PCPP_LOG_ERROR("Existing file precision (" + toString(precisionFromHeader) +
					               ") does not match the requested device precision (" + toString(m_Precision) + ")");
					return false;
				}

				if (header.version_major != PCAP_MAJOR_VERSION || header.version_minor != PCAP_MINOR_VERSION)
				{
					PCPP_LOG_ERROR("Unsupported pcap file version");
					return false;
				}

				if (header.linktype != static_cast<uint32_t>(m_PcapLinkLayerType))
				{
					PCPP_LOG_ERROR("Existing file link type does not match the requested device link type");
					return false;
				}

				// Move the file pointer to the end of the file for appending new packets
				pcapFile.seekg(0, std::ios::end);
			}
		}

		if (shouldWriteHeader && !writePcapHeader(pcapFile, m_Precision, PCPP_MAX_PACKET_SIZE, m_PcapLinkLayerType))
		{
			return false;
		}

		m_PcapFile = std::move(pcapFile);
		return true;
	}

	bool PcapFileWriterDevice::writePacket(RawPacket const& packet)
	{
		if (!m_PcapFile.is_open())
		{
			PCPP_LOG_ERROR("File is not open");
			return false;
		}

		if (packet.getLinkLayerType() != m_PcapLinkLayerType)
		{
			PCPP_LOG_ERROR("Cannot write a packet with a different link type");
			reportPacketDropped();
			return false;
		}

		if (!m_BpfWrapper.matches(packet))
		{
			PCPP_LOG_DEBUG("Packet doesn't match filter");
			return false;
		}

		packet_header packetHeader{};
		auto packetTimestamp = packet.getPacketTimeStamp();
		packetHeader.tv_sec = packetTimestamp.tv_sec;
		packetHeader.tv_usec = m_Precision == FileTimestampPrecision::Nanoseconds ? packetTimestamp.tv_nsec
		                                                                          : packetTimestamp.tv_nsec / 1000;
		packetHeader.caplen = packet.getRawDataLen();
		packetHeader.len = packet.getFrameLength();

		if (m_NeedsSwap)
		{
			packetHeader.tv_sec = swap32(packetHeader.tv_sec);
			packetHeader.tv_usec = swap32(packetHeader.tv_usec);
			packetHeader.caplen = swap32(packetHeader.caplen);
			packetHeader.len = swap32(packetHeader.len);
		}

		if (!m_PcapFile.write(reinterpret_cast<const char*>(&packetHeader), sizeof(packetHeader)))
		{
			PCPP_LOG_ERROR("Cannot write the packet header to file");
			reportPacketDropped();
			return false;
		}

		if (!m_PcapFile.write(reinterpret_cast<const char*>(packet.getRawData()), packet.getRawDataLen()))
		{
			PCPP_LOG_ERROR("Cannot write the packet to file");
			reportPacketDropped();
			return false;
		}

		reportPacketProcessed();
		return true;
	}

	bool PcapFileWriterDevice::writePackets(const RawPacketVector& packets)
	{
		if (!m_PcapFile.is_open())
		{
			PCPP_LOG_ERROR("File is not open");
			return false;
		}

		bool result = true;
		for (auto const& packet : packets)
		{
			if (!writePacket(*packet))
			{
				result = false;
			}
		}

		return result;
	}

	void PcapFileWriterDevice::flush()
	{
		if (!m_PcapFile.is_open())
		{
			return;
		}

		m_PcapFile.flush();
	}

	void PcapFileWriterDevice::close()
	{
		if (!m_PcapFile.is_open())
		{
			return;
		}

		m_PcapFile.close();
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
		resetStatisticCounters();

		if (m_LightPcapNg != nullptr)
		{
			PCPP_LOG_DEBUG("pcapng descriptor already opened. Nothing to do");
			return true;
		}

		m_LightPcapNg = toLightPcapNgHandle(light_pcapng_open_read(m_FileName.c_str(), LIGHT_FALSE));
		if (m_LightPcapNg == nullptr)
		{
			PCPP_LOG_ERROR("Cannot open pcapng reader device for filename '" << m_FileName << "'");
			return false;
		}

		PCPP_LOG_DEBUG("Successfully opened pcapng reader device for filename '" << m_FileName << "'");
		return true;
	}

	bool PcapNgFileReaderDevice::getNextPacket(RawPacket& rawPacket, std::string& packetComment)
	{
		return getNextPacketInternal(rawPacket, &packetComment);
	}

	bool PcapNgFileReaderDevice::getNextPacket(RawPacket& rawPacket)
	{
		return getNextPacketInternal(rawPacket, nullptr);
	}

	bool PcapNgFileReaderDevice::getNextPacketInternal(RawPacket& rawPacket, std::string* packetComment)
	{
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

		while (!m_BpfWrapper.matches(pktData, pktHeader.captured_length, pktHeader.timestamp, pktHeader.data_link))
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

		if (!rawPacket.setRawData(myPacketData, pktHeader.captured_length, true, pktHeader.timestamp, linkType,
		                          pktHeader.original_length))
		{
			PCPP_LOG_ERROR("Couldn't set data to raw packet");
			return false;
		}

		if (packetComment != nullptr)
		{
			if (pktHeader.comment != nullptr && pktHeader.comment_length > 0)
			{
				packetComment->assign(pktHeader.comment, pktHeader.comment_length);
			}
			else
			{
				packetComment->clear();
			}
		}

		reportPacketProcessed();
		return true;
	}

	void PcapNgFileReaderDevice::close()
	{
		if (m_LightPcapNg == nullptr)
			return;

		light_pcapng_close(toLightPcapNgT(m_LightPcapNg));
		m_LightPcapNg = nullptr;

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
			reportPacketDropped();
			return false;
		}

		if (!m_BpfWrapper.matches(packet))
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
		reportPacketProcessed();
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

		resetStatisticCounters();

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

			return false;
		}

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

		resetStatisticCounters();

		m_LightPcapNg = toLightPcapNgHandle(light_pcapng_open_append(m_FileName.c_str()));
		if (m_LightPcapNg == nullptr)
		{
			PCPP_LOG_ERROR("Error opening file writer device in append mode for file '"
			               << m_FileName << "': light_pcapng_open_append returned nullptr");
			return false;
		}

		PCPP_LOG_DEBUG("pcap-ng writer device for file '" << m_FileName << "' opened successfully");
		return true;
	}

	void PcapNgFileWriterDevice::flush()
	{
		if (!isOpened())
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

		PCPP_LOG_DEBUG("File writer closed for file '" << m_FileName << "'");
	}

	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	// SnoopFileReaderDevice members
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	SnoopFileReaderDevice::~SnoopFileReaderDevice()
	{
		m_SnoopFile.close();
	}

	bool SnoopFileReaderDevice::open()
	{
		if (m_SnoopFile.is_open())
		{
			PCPP_LOG_ERROR("File already open");
			return false;
		}

		resetStatisticCounters();

		std::ifstream snoopFile;
		snoopFile.open(m_FileName.c_str(), std::ifstream::binary);
		if (!snoopFile.is_open())
		{
			PCPP_LOG_ERROR("Cannot open snoop reader device for filename '" << m_FileName << "'");
			return false;
		}

		snoop_file_header_t snoop_file_header;
		snoopFile.read(reinterpret_cast<char*>(&snoop_file_header), sizeof(snoop_file_header_t));
		if (!snoopFile)
		{
			PCPP_LOG_ERROR("Cannot read snoop file header for '" << m_FileName << "'");
			return false;
		}

		if (be64toh(snoop_file_header.identification_pattern) != 0x736e6f6f70000000 ||
		    be32toh(snoop_file_header.version_number) != 2)
		{
			PCPP_LOG_ERROR("Malformed snoop file header for '" << m_FileName << "'");
			return false;
		}

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
			return false;
		}

		m_SnoopFile = std::move(snoopFile);
		m_PcapLinkLayerType = snoop_encap[datalink_type];

		PCPP_LOG_DEBUG("Successfully opened file reader device for filename '" << m_FileName << "'");
		return true;
	}

	bool SnoopFileReaderDevice::readNextPacket(timespec& packetTimestamp, uint8_t* packetData, uint32_t packetDataLen,
	                                           uint32_t& capturedLength, uint32_t& frameLength)
	{
		snoop_packet_header_t snoop_packet_header;
		m_SnoopFile.read(reinterpret_cast<char*>(&snoop_packet_header), sizeof(snoop_packet_header_t));
		if (!m_SnoopFile)
		{
			PCPP_LOG_ERROR("Failed to read packet metadata");
			return false;
		}

		capturedLength = be32toh(snoop_packet_header.included_length);
		if (capturedLength > packetDataLen)
		{
			PCPP_LOG_ERROR("Packet length " << capturedLength << " is too large");
			return false;
		}

		m_SnoopFile.read(reinterpret_cast<char*>(packetData), capturedLength);
		if (!m_SnoopFile)
		{
			PCPP_LOG_ERROR("Failed to read packet data");
			return false;
		}

		packetTimestamp = { static_cast<time_t>(be32toh(snoop_packet_header.time_sec)),
			                static_cast<long>(be32toh(snoop_packet_header.time_usec)) * 1000 };

		frameLength = be32toh(snoop_packet_header.original_length);

		auto pad = be32toh(snoop_packet_header.packet_record_length) -
		           (sizeof(snoop_packet_header_t) + be32toh(snoop_packet_header.included_length));

		m_SnoopFile.ignore(pad);

		return true;
	}

	bool SnoopFileReaderDevice::getNextPacket(RawPacket& rawPacket)
	{
		if (!isOpened())
		{
			PCPP_LOG_ERROR("File device not open");
			return false;
		}

		constexpr uint32_t maxPacketLength = 15'000;
		timespec packetTimestamp{};
		uint32_t capturedLength = 0, frameLength = 0;
		auto packetData = std::make_unique<uint8_t[]>(maxPacketLength);

		while (readNextPacket(packetTimestamp, packetData.get(), maxPacketLength, capturedLength, frameLength))
		{
			if (m_BpfWrapper.matches(packetData.get(), capturedLength, packetTimestamp, m_PcapLinkLayerType))
			{
				rawPacket.setRawData(capturedLength > 0 ? packetData.release() : nullptr, capturedLength, true,
				                     packetTimestamp, m_PcapLinkLayerType, frameLength);
				reportPacketProcessed();
				return true;
			}
			PCPP_LOG_DEBUG("Packet doesn't match filter");
		}

		return false;
	}

	void SnoopFileReaderDevice::close()
	{
		m_SnoopFile.close();
		PCPP_LOG_DEBUG("File reader closed for file '" << m_FileName << "'");
	}
}  // namespace pcpp
