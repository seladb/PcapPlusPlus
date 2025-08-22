#pragma once

#include <memory>
#include <vector>
#include <string>

#include <cstdint>

namespace pcpp_tests
{
	namespace utils
	{
		/// @brief Enum representing different types of resources that can be loaded.
		enum class ResourceType
		{
			HexData,  ///< Resource is a file containing hex data
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
			/// @brief Constructs a ResourceProvider with a specified data root directory.
			/// @param dataRoot The root directory from which resources will be loaded.
			explicit ResourceProvider(std::string dataRoot);

			/// @brief Loads a resource from resource provider.
			/// @param filename The name of the resource file to load.
			/// @param resourceType The type of the loaded resource. Determines how the resource is processed.
			/// @return Resource object containing the loaded data and its length.
			Resource loadResource(const char* filename, ResourceType resourceType) const;

			/// @brief Loads a resource from the resource provider into a vector.
			/// @param filename The name of the resource file to load.
			/// @param resourceType The type of the loaded resource. Determines how the resource is processed.
			/// @return A vector containing the loaded data.
			std::vector<uint8_t> loadResourceToVector(const char* filename, ResourceType resourceType) const;

		private:
			std::string m_DataRoot;  ///< The root directory for test data files
		};

	}  // namespace utils

	/// @brief Sets the default resource provider for all operations when no explicit provider is set.
	///
	/// It is the user's responsibility to ensure that the provider is valid for the duration of its use.
	///
	/// @param resourceProvider Pointer to the ResourceProvider to set as default.
	void setDefaultResourceProvider(utils::ResourceProvider* resourceProvider);

	/// @brief Retrieves the default resource provider.
	/// @return A pointer to the default ResourceProvider.
	utils::ResourceProvider* getDefaultResourceProvider();
}  // namespace pcpp_tests
