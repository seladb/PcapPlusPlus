#pragma once

#include <memory>
#include <vector>

#include "RawPacket.h"

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
			PacketFactory(timespec time);
			PacketFactory(timeval time);
			PacketFactory(pcpp::LinkLayerType linkType);

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
	}  // namespace utils
}  // namespace pcpp_test
