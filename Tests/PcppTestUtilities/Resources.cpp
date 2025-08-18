#include "Resources.hpp"

#include <fstream>

namespace pcpp_tests
{
	namespace utils
	{
		namespace
		{
			size_t getFileLength(std::ifstream& stream)
			{
				auto originalPos = stream.tellg();
				stream.seekg(0, std::ios::end);
				size_t length = static_cast<size_t>(stream.tellg());
				stream.seekg(originalPos, std::ios::beg);
				return length;
			}

			uint8_t hexCharToDigit(char c)
			{
				if (c >= '0' && c <= '9')
					return c - '0';
				if (c >= 'a' && c <= 'f')
					return c - 'a' + 10;
				if (c >= 'A' && c <= 'F')
					return c - 'A' + 10;
				throw std::invalid_argument("Invalid hex character");
			}

			uint8_t hexPairToByte(const char* pair)
			{
				return (hexCharToDigit(pair[0]) << 4) | hexCharToDigit(pair[1]);
			}

			std::vector<uint8_t> readHexResource(std::ifstream& stream)
			{
				std::vector<uint8_t> buffer;

				char hexPair[2];  // 0 - high, 1 - low
				while (stream.read(hexPair, 2))
				{
					buffer.push_back(hexPairToByte(hexPair));
				}
				return buffer;
			}
		}  // namespace

		ResourceProvider::ResourceProvider(std::string dataRoot) : m_DataRoot(std::move(dataRoot))
		{}

		Resource ResourceProvider::loadResource(const char* filename, ResourceType resourceType) const
		{
			// Somewhat inefficient as it copies the data into a vector first, but it should work for testing,
			// as it saves on code duplication.
			auto vecBuffer = loadResourceToVector(filename, resourceType);

			Resource resource;
			resource.length = vecBuffer.size();
			resource.data = std::make_unique<uint8_t[]>(vecBuffer.size());
			std::copy(vecBuffer.begin(), vecBuffer.end(), resource.data.get());
			return resource;
		}

		std::vector<uint8_t> ResourceProvider::loadResourceToVector(const char* filename,
		                                                            ResourceType resourceType) const
		{
			std::string fullPath;
			if (!m_DataRoot.empty())
			{
				fullPath = m_DataRoot + '/' + filename;
			}
			else
			{
				fullPath = filename;
			}

			auto const requireOpen = [filename](std::ifstream& fileStream) {
				if (!fileStream)
				{
					throw std::runtime_error(std::string("Failed to open file: ") + filename);
				}
			};

			switch (resourceType)
			{
			case ResourceType::BinaryData:
			{
				std::ifstream fileStream(fullPath, std::ios::binary);
				requireOpen(fileStream);

				size_t fileLength = getFileLength(fileStream);
				std::vector<uint8_t> buffer(fileLength);
				fileStream.read(reinterpret_cast<char*>(buffer.data()), fileLength);
				return buffer;
			}
			case ResourceType::HexData:
			{
				// The file is expected to contain text data in hexadecimal format
				std::ifstream fileStream(fullPath);
				requireOpen(fileStream);

				return readHexResource(fileStream);
			}
			default:
				throw std::invalid_argument("Unsupported resource type");
			}
		}
	}  // namespace utils

	namespace
	{
		utils::ResourceProvider* provider = nullptr;
	}

	void setDefaultResourceProvider(utils::ResourceProvider* resourceProvider)
	{
		provider = resourceProvider;
	}

	utils::ResourceProvider* getDefaultResourceProvider0()
	{
		if (provider == nullptr)
			throw std::runtime_error("Resource provider is not set");
		return provider;
	}
}  // namespace pcpp_tests
