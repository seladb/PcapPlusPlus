#pragma once

#include <istream>

namespace pcpp
{
	namespace internal
	{
		/// @brief An enumeration representing different capture file formats.
		enum class CaptureFileFormat
		{
			Unknown,
			Pcap,        // regular pcap with microsecond precision
			PcapNano,    // regular pcap with nanosecond precision
			PcapNG,      // uncompressed pcapng
			Snoop,       // solaris snoop
			ZstArchive,  // zstd compressed archive
		};

		/// @brief Heuristic file format detector that scans the magic number of the file format header.
		class CaptureFileFormatDetector
		{
		public:
			/// @brief Checks a content stream for the magic number and determines the type.
			/// @param content A content stream that contains the file content.
			/// @return A CaptureFileFormat value with the detected content type.
			CaptureFileFormat detectFormat(std::istream& content) const;

		private:
			CaptureFileFormat detectPcapFile(std::istream& content) const;

			bool isPcapNgFile(std::istream& content) const;

			bool isSnoopFile(std::istream& content) const;

			bool isZstdArchive(std::istream& content) const;
		};
	}  // namespace internal
}  // namespace pcpp
