#include "CaptureFileFormatDetector.h"

#include <array>
#include <cstdint>

namespace pcpp
{
	namespace
	{
		class StreamPositionCheckpoint
		{
		public:
			explicit StreamPositionCheckpoint(std::istream& stream)
			    : m_Stream(stream), m_State(stream.rdstate()), m_Pos(stream.tellg())
			{}

			~StreamPositionCheckpoint()
			{
				m_Stream.seekg(m_Pos);
				m_Stream.clear(m_State);
			}

		private:
			std::istream& m_Stream;
			std::ios_base::iostate m_State;
			std::streampos m_Pos;
		};

		/// @brief Check if a stream is seekable.
		/// @param stream The stream to check.
		/// @return True if the stream supports seek operations, false otherwise.
		bool isStreamSeekable(std::istream& stream)
		{
			auto pos = stream.tellg();
			if (stream.fail())
			{
				stream.clear();
				return false;
			}

			if (stream.seekg(pos).fail())
			{
				stream.clear();
				return false;
			}

			return true;
		}
	}  // namespace

	namespace internal
	{
		CaptureFileFormat CaptureFileFormatDetector::detectFormat(std::istream& content) const
		{
			// Check if the stream supports seeking.
			if (!isStreamSeekable(content))
			{
				throw std::runtime_error("Heuristic file format detection requires seekable stream");
			}

			CaptureFileFormat format = detectPcapFile(content);
			if (format != CaptureFileFormat::Unknown)
			{
				return format;
			}

			if (isPcapNgFile(content))
			{
				return CaptureFileFormat::PcapNG;
			}

			// PcapNG backend can support ZstdCompressed Pcap files, so we assume an archive is compressed PcapNG.
			if (isZstdArchive(content))
			{
				return CaptureFileFormat::PcapNGZstd;
			}

			if (isSnoopFile(content))
			{
				return CaptureFileFormat::Snoop;
			}

			return CaptureFileFormat::Unknown;
		}

		CaptureFileFormat CaptureFileFormatDetector::detectPcapFile(std::istream& content) const
		{
			// Pcap magic numbers are taken from: https://github.com/the-tcpdump-group/libpcap/blob/master/sf-pcap.c
			// There are some other reserved magic numbers but they are not supported by libpcap so we ignore them.
			// The order of the magic numbers in the array is important for format detection. See switch statement
			// below.
			constexpr std::array<uint32_t, 6> pcapMagicNumbers = {
				0xa1'b2'c3'd4,  // regular pcap, microsecond-precision
				0xd4'c3'b2'a1,  // regular pcap, microsecond-precision (byte-swapped)
				// Libpcap 0.9.1 and later support reading a modified pcap format that contains an extended header.
				// Format reference: https://wiki.wireshark.org/Development/LibpcapFileFormat#modified-pcap
				0xa1'b2'cd'34,  // Alexey Kuznetzov's modified libpcap format
				0x34'cd'b2'a1,  // Alexey Kuznetzov's modified libpcap format (byte-swapped)
				// Libpcap 1.5.0 and later support reading nanosecond-precision pcap files.
				0xa1'b2'3c'4d,  // regular pcap, nanosecond-precision
				0x4d'3c'b2'a1,  // regular pcap, nanosecond-precision (byte-swapped)
			};

			StreamPositionCheckpoint checkpoint(content);

			uint32_t magic = 0;
			content.read(reinterpret_cast<char*>(&magic), sizeof(magic));
			if (content.gcount() != sizeof(magic))
			{
				return CaptureFileFormat::Unknown;
			}

			auto it = std::find(pcapMagicNumbers.begin(), pcapMagicNumbers.end(), magic);
			if (it == pcapMagicNumbers.end())
			{
				return CaptureFileFormat::Unknown;
			}

			// Indices 0-3 are regular pcap (microsecond-precision or modified) files.
			// Indices 4-5 are nanosecond-precision pcap.
			// Modified pcap files are treated as regular pcap files by libpcap so they are folded.
			auto const selectedIdx = std::distance(pcapMagicNumbers.begin(), it);
			if (selectedIdx < 4)
			{
				return CaptureFileFormat::Pcap;
			}

			return CaptureFileFormat::PcapNano;
		}

		bool CaptureFileFormatDetector::isPcapNgFile(std::istream& content) const
		{
			constexpr std::array<uint32_t, 1> pcapMagicNumbers = {
				0x0A'0D'0D'0A,  // pcapng magic number (palindrome)
			};

			StreamPositionCheckpoint checkpoint(content);

			uint32_t magic = 0;
			content.read(reinterpret_cast<char*>(&magic), sizeof(magic));
			if (content.gcount() != sizeof(magic))
			{
				return false;
			}

			return std::find(pcapMagicNumbers.begin(), pcapMagicNumbers.end(), magic) != pcapMagicNumbers.end();
		}

		bool CaptureFileFormatDetector::isSnoopFile(std::istream& content) const
		{
			constexpr std::array<uint64_t, 2> snoopMagicNumbers = {
				0x73'6E'6F'6F'70'00'00'00,  // snoop magic number, "snoop" in ASCII
				0x00'00'00'70'6F'6F'6E'73   // snoop magic number, "snoop" in ASCII (byte-swapped)
			};

			StreamPositionCheckpoint checkpoint(content);

			uint64_t magic = 0;
			content.read(reinterpret_cast<char*>(&magic), sizeof(magic));
			if (content.gcount() != sizeof(magic))
			{
				return false;
			}

			return std::find(snoopMagicNumbers.begin(), snoopMagicNumbers.end(), magic) != snoopMagicNumbers.end();
		}

		bool CaptureFileFormatDetector::isZstdArchive(std::istream& content) const
		{
			constexpr std::array<uint32_t, 2> zstdMagicNumbers = {
				0x28'B5'2F'FD,  // zstd archive magic number
				0xFD'2F'B5'28,  // zstd archive magic number (byte-swapped)
			};

			StreamPositionCheckpoint checkpoint(content);

			uint32_t magic = 0;
			content.read(reinterpret_cast<char*>(&magic), sizeof(magic));
			if (content.gcount() != sizeof(magic))
			{
				return false;
			}

			return std::find(zstdMagicNumbers.begin(), zstdMagicNumbers.end(), magic) != zstdMagicNumbers.end();
		}
	}  // namespace internal
}  // namespace pcpp