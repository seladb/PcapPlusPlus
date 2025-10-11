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
			/// @param frozen If true, the provider is read-only and does not allow saving resources.
			explicit ResourceProvider(std::string dataRoot, bool frozen = true);

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

			/// @brief Saves a resource to the resource provider.
			/// @param resourceType The type of the resource being saved.
			/// @param filename The name of the file to save the resource to.
			/// @param data Pointer to the data to be saved.
			/// @param length The length of the data in bytes.
			/// @throw std::runtime_error if the provider is frozen and does not allow saving.
			void saveResource(ResourceType resourceType, const char* filename, const uint8_t* data,
			                  size_t length) const;

		private:
			std::string m_DataRoot;  ///< The root directory for test data files
			bool m_Frozen = true;    ///< Indicates if the provider is frozen (no modifications allowed)
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

	/// @brief Loads a hex resource file into a vector of bytes.
	/// @param filename The name of the hex resource file to load.
	/// @param resourceProvider Optional pointer to a ResourceProvider. If nullptr, the default provider is used.
	/// @return A vector containing the loaded hex data.
	std::vector<uint8_t> loadHexResourceToVector(const char* filename,
	                                             utils::ResourceProvider* resourceProvider = nullptr);
}  // namespace pcpp_tests
