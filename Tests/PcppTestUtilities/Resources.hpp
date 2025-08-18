#pragma once

#include <memory>
#include <vector>
#include <string>

#include <cstdint>

namespace pcpp_tests
{
	namespace utils
	{
		enum class ResourceType
		{
			BinaryData,  ///< Resource is a file containing binary data
			HexData,     ///< Resource is a file containing hex data
		};

		/// @brief Represents a resource loaded by the ResourceProvider.
		struct Resource
		{
			size_t length = 0;                          ///< Length of the resource data in bytes
			std::unique_ptr<uint8_t[]> data = nullptr;  ///< Pointer to the resource data
		};

		/// @brief Manages the loading of test resources such as files, saved packets, and buffers.
		class ResourceProvider
		{
		public:
			explicit ResourceProvider(std::string dataRoot);

			Resource loadResource(std::string const& filename, ResourceType resourceType) const
			{
				return loadResource(filename.c_str(), resourceType);
			}

			Resource loadResource(const char* filename, ResourceType resourceType) const;

			std::vector<uint8_t> loadResourceToVector(std::string const& filename, ResourceType resourceType) const
			{
				return loadResourceToVector(filename.c_str(), resourceType);
			}

			std::vector<uint8_t> loadResourceToVector(const char* filename, ResourceType resourceType) const;

		private:
			std::string m_DataRoot;  ///< The root directory for test data files
		};

	}  // namespace utils

	void setDefaultResourceProvider(utils::ResourceProvider* resourceProvider);
	utils::ResourceProvider* getDefaultResourceProvider();
}  // namespace pcpp_tests
