#pragma once

/// @file

#include "GeneralUtils.h"
#include "PemCodec.h"
#include <string>
#include <memory>
#include <fstream>

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	namespace internal
	{
		/// @class CryptoDataReader
		/// @brief A template helper class for reading and decoding cryptographic data in different formats (DER/PEM)
		/// @tparam CryptoDecoder The decoder type that will be used to process the cryptographic data.
		/// Must be a class that can be constructed with a byte array and a length, or a unique pointer to a byte array
		/// and a length
		template <typename CryptoDecoder> class CryptoDataReader
		{
		public:
			/// Creates a decoder from DER-encoded data
			/// @param[in] derData Pointer to the DER-encoded data
			/// @param[in] derDataLen Length of the DER-encoded data
			/// @param[in] ownDerData If true, the decoder will take ownership of the data and free it when the
			/// decoder class is destructed
			/// @return A unique pointer to the created decoder
			/// @throws An exception if the data is not a valid ASN.1 record
			static std::unique_ptr<CryptoDecoder> fromDER(uint8_t* derData, size_t derDataLen, bool ownDerData = false)
			{
				return std::unique_ptr<CryptoDecoder>(new CryptoDecoder(derData, derDataLen, ownDerData));
			}

			/// Creates a decoder from a hex string containing DER-encoded data
			/// @param[in] derData Hex string containing DER-encoded data
			/// @return A unique pointer to the created decoder
			/// @throws An exception if the data is not a valid ASN.1 record
			static std::unique_ptr<CryptoDecoder> fromDER(const std::string& derData)
			{
				size_t derDataBufferLen = derData.length() / 2;
				auto derDataBuffer = std::make_unique<uint8_t[]>(derDataBufferLen);
				hexStringToByteArray(derData, derDataBuffer.get(), derDataBufferLen);
				return std::unique_ptr<CryptoDecoder>(new CryptoDecoder(std::move(derDataBuffer), derDataBufferLen));
			}

			/// Creates a decoder from a file containing DER-encoded data
			/// @param[in] derFileName Path to the file containing DER-encoded data
			/// @return A unique pointer to the created decoder
			/// @throws An exception if the file doesn't exist, cannot be read or contains invalid data
			static std::unique_ptr<CryptoDecoder> fromDERFile(const std::string& derFileName)
			{
				std::ifstream derFile(derFileName, std::ios::binary);
				if (!derFile.good())
				{
					throw std::runtime_error("DER file doesn't exist or cannot be opened");
				}

				derFile.seekg(0, std::ios::end);
				std::streamsize derDataLen = derFile.tellg();
				if (derDataLen < 0)
				{
					throw std::runtime_error("Failed to determine DER file size");
				}
				derFile.seekg(0, std::ios::beg);

				auto derData = std::make_unique<uint8_t[]>(derDataLen);

				if (!derFile.read(reinterpret_cast<char*>(derData.get()), derDataLen))
				{
					throw std::runtime_error("Failed to read DER file");
				}
				return std::unique_ptr<CryptoDecoder>(new CryptoDecoder(std::move(derData), derDataLen));
			}

			/// Creates a decoder from PEM-encoded data
			/// @param[in] pemData PEM-encoded data
			/// @return A unique pointer to the created decoder
			/// @throws std::invalid_argument exception if the data is not a valid PEM-encoded data
			static std::unique_ptr<CryptoDecoder> fromPEM(const std::string& pemData)
			{
				auto derData = PemCodec::decode(pemData, CryptoDecoder::pemLabel);
				auto derDataBuffer = std::make_unique<uint8_t[]>(derData.size());
				std::copy(derData.begin(), derData.end(), derDataBuffer.get());
				return std::unique_ptr<CryptoDecoder>(new CryptoDecoder(std::move(derDataBuffer), derData.size()));
			}

			/// Creates a decoder from a file containing PEM-encoded data
			/// @param[in] pemFileName Path to the file containing PEM-encoded data
			/// @return A unique pointer to the created decoder
			/// @throws std::runtime_error exception if the file doesn't exist or cannot be read
			/// @throws std::invalid_argument exception if the data is not a valid PEM-encoded data
			static std::unique_ptr<CryptoDecoder> fromPEMFile(const std::string& pemFileName)
			{
				std::ifstream pemFile(pemFileName, std::ios::in | std::ios::binary);
				if (!pemFile.good())
				{
					throw std::runtime_error("PEM file doesn't exist or cannot be opened");
				}

				pemFile.seekg(0, std::ios::end);
				std::streamsize pemContentLen = pemFile.tellg();
				if (pemContentLen < 0)
				{
					throw std::runtime_error("Failed to determine PEM file size");
				}
				pemFile.seekg(0, std::ios::beg);

				std::string pemContent;
				pemContent.resize(static_cast<std::size_t>(pemContentLen));
				if (!pemFile.read(&pemContent[0], pemContentLen))
				{
					throw std::runtime_error("Failed to read PEM file");
				}

				return fromPEM(pemContent);
			}

		protected:
			~CryptoDataReader() = default;
		};
	}  // namespace internal
}  // namespace pcpp
