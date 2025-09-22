#include "Resources.h"

#include <fstream>
#include <iterator>

namespace pcpp_tests
{
	namespace utils
	{
		namespace
		{
			constexpr char getOsPathSeparator()
			{
#ifdef _WIN32
				return '\\';
#else
				return '/';
#endif
			}

			size_t getFileLength(std::ifstream& stream)
			{
				auto originalPos = stream.tellg();
				stream.seekg(0, std::ios::end);
				size_t length = static_cast<size_t>(stream.tellg());
				stream.seekg(originalPos, std::ios::beg);
				return length;
			}

			std::vector<uint8_t> readHexResource(std::ifstream& stream)
			{
				size_t const fileLength = getFileLength(stream);
				if (fileLength % 2 != 0)
				{
					throw std::runtime_error("Hex file length is not even");
				}

				std::string hexString(std::istreambuf_iterator<char>(stream), {} /* end */);

				std::vector<uint8_t> buffer;
				buffer.reserve(fileLength / 2);

				// Length is even, so we can safely iterate in pairs
				for (size_t i = 0; i < hexString.size(); i += 2)
				{
					// todo: C++17 has std::from_chars, which is more efficient
					buffer.emplace_back(std::stoul(hexString.substr(i, 2), nullptr, 16));
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
				fullPath = m_DataRoot + getOsPathSeparator() + filename;
			}
			else
			{
				fullPath = filename;
			}

			auto const requireOpen = [filename](std::ifstream const& fileStream) {
				if (!fileStream)
				{
					throw std::runtime_error(std::string("Failed to open file: ") + filename);
				}
			};

			switch (resourceType)
			{
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

	utils::ResourceProvider* getDefaultResourceProvider()
	{
		if (provider == nullptr)
		{
			throw std::runtime_error("Resource provider is not set");
		}
		return provider;
	}

	std::vector<uint8_t> loadHexResourceToVector(const char* filename, utils::ResourceProvider* resourceProvider)
	{
		if (resourceProvider == nullptr)
		{
			resourceProvider = getDefaultResourceProvider();
		}

		return resourceProvider->loadResourceToVector(filename, utils::ResourceType::HexData);
	}
}  // namespace pcpp_tests
