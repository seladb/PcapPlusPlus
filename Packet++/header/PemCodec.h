#pragma once

#include <cstdint>
#include <string>
#include <vector>

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{

	/**
	 * @class PemCodec
	 * @brief A utility class for encoding and decoding data in Privacy-Enhanced Mail (PEM) format.
	 *
	 * The PemCodec class provides static methods to convert between binary data and PEM format, which is
	 * commonly used for cryptographic keys, certificates, and other security-related data. The PEM format
	 * uses base64 encoding with header and footer lines.
	 */
	class PemCodec
	{
	public:
		/**
		 * Encodes binary data into PEM format with the specified label
		 * @param[in] data The binary data to be encoded
		 * @param[in] label The label to be used in the PEM header/footer (e.g., "CERTIFICATE", "PRIVATE KEY")
		 * @return A string containing the PEM-encoded data with appropriate headers and line breaks
		 * @throws std::invalid_argument if the input data is empty or the label is empty
		 */
		static std::string encode(const std::vector<uint8_t>& data, const std::string& label);

		/**
		 * Decodes PEM-encoded data back to its binary form
		 * @param[in] pemData The PEM-encoded string to decode
		 * @param[in] expectedLabel Optional expected label that should be in the PEM header/footer.
		 * If provided and doesn't match, an exception will be thrown
		 * @return A vector containing the decoded binary data
		 * @throws std::invalid_argument if the input is not valid PEM format, if the label doesn't match or if base64
		 * decoding fails
		 */
		static std::vector<uint8_t> decode(const std::string& pemData, const std::string& expectedLabel = "");

	private:
		static constexpr const char* pemDelimiter = "-----";
		static constexpr const char* pemBegin = "-----BEGIN ";
		static constexpr const char* pemEnd = "-----END ";
		static constexpr size_t pemBeginLen = 11;
		static constexpr size_t pemEndLen = 9;
		static constexpr size_t pemDelimiterLen = 5;
		static constexpr size_t lineLength = 64;
	};
}  // namespace pcpp
