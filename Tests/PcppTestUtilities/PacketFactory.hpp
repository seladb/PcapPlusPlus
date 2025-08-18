#pragma once

#include <memory>
#include <vector>

#include "RawPacket.h"
#include "Resources.hpp"

namespace pcpp_tests
{
	namespace utils
	{
		class PacketFactory
		{
		public:
			/// @brief The time used for creating packets in the factory.
			timespec factoryTime;
			/// @brief The default link layer type for packets created by this factory.
			pcpp::LinkLayerType defaultLinkType = pcpp::LinkLayerType::LINKTYPE_ETHERNET;

			/// @brief Creates a new PacketFactory instance with the current time as factoryTime.
			PacketFactory();
			explicit PacketFactory(timespec time);
			explicit PacketFactory(timeval time);
			explicit PacketFactory(pcpp::LinkLayerType linkType);

			PacketFactory withTime(timespec time);
			PacketFactory withTime(timeval time);
			PacketFactory withLinkType(pcpp::LinkLayerType linkType);

			// TODO: RawPacket requires a move constructor to return by value efficiently.
			/// @brief Creates a RawPacket from a vector of bytes.
			/// @param buffer A unique pointer to a buffer containing the raw packet data.
			/// @param bufferLen The length of the buffer in bytes.
			/// @return A RawPacket object created from the buffer.
			std::unique_ptr<pcpp::RawPacket> createFromBuffer(std::unique_ptr<uint8_t[]> buffer,
			                                                  size_t bufferLen) const;

			/// @brief Creates a RawPacket from a vector of bytes without taking ownership of the data.
			/// @param buffer A vector containing the raw packet data.
			/// @return A RawPacket object created from the buffer.
			std::unique_ptr<pcpp::RawPacket> createFromBufferNonOwning(std::vector<uint8_t> const& buffer) const;

			/// @brief Creates a RawPacket from a buffer without taking ownership of the data.
			/// @param buffer A pointer to the raw packet data.
			/// @param bufferLen The length of the buffer in bytes.
			/// @return A RawPacket object created from the buffer.
			std::unique_ptr<pcpp::RawPacket> createFromBufferNonOwning(const uint8_t* buffer, size_t bufferLen) const;
		};

		/// @brief Creates a RawPacket from a resource file.
		/// @param resourceName The name of the resource file to read the packet data from.
		/// @param factory The PacketFactory to use for creating the RawPacket.
		/// @param resourceProvider An optional ResourceProvider to use for loading the resource file.
		///   Uses the default resource provider if not provided.
		/// @return A RawPacket object created from the resource file.
		std::unique_ptr<pcpp::RawPacket> createPacketFromHexResource(
		    const std::string& resourceName, const PacketFactory& factory = PacketFactory(),
		    ResourceProvider const* resourceProvider = nullptr);
	}  // namespace utils
}  // namespace pcpp_tests
