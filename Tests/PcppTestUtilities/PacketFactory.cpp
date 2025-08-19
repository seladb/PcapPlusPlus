#include "PacketFactory.hpp"

#include <stdexcept>

#include "SystemUtils.h"
#include "TimespecTimeval.h"

namespace pcpp_tests
{
	using namespace pcpp;

	namespace utils
	{
		PacketFactory::PacketFactory()
		{
			timeval factoryTimeTV;
			// Initialize factoryTime to the current time
			gettimeofday(&factoryTimeTV, nullptr);
			factoryTime = internal::toTimespec(factoryTimeTV);
		}

		PacketFactory::PacketFactory(timespec time) : factoryTime(time)
		{}

		PacketFactory::PacketFactory(timeval time) : PacketFactory(internal::toTimespec(time))
		{}

		PacketFactory::PacketFactory(LinkLayerType linkType) : PacketFactory()
		{
			// Call to the default constructor to initialize factoryTime to the current time
			defaultLinkType = linkType;
		}

		PacketFactory PacketFactory::withTime(timespec time)
		{
			auto factoryCopy = *this;
			factoryCopy.factoryTime = time;
			return factoryCopy;
		}

		PacketFactory PacketFactory::withTime(timeval time)
		{
			return withTime(internal::toTimespec(time));
		}

		PacketFactory PacketFactory::withLinkType(LinkLayerType linkType)
		{
			auto factoryCopy = *this;
			factoryCopy.defaultLinkType = linkType;
			return factoryCopy;
		}

		std::unique_ptr<RawPacket> PacketFactory::createFromBuffer(std::unique_ptr<uint8_t[]> buffer,
		                                                           size_t bufferLen) const
		{
			if (buffer == nullptr || bufferLen == 0)
			{
				throw std::invalid_argument("Buffer cannot be null and length must be greater than zero");
			}

			return std::make_unique<RawPacket>(buffer.release(), static_cast<int>(bufferLen), factoryTime, true,
			                                   defaultLinkType);
		}

		std::unique_ptr<RawPacket> PacketFactory::createFromBufferNonOwning(std::vector<uint8_t> const& buffer) const
		{
			return createFromBufferNonOwning(buffer.data(), buffer.size());
		}

		std::unique_ptr<RawPacket> PacketFactory::createFromBufferNonOwning(const uint8_t* buffer,
		                                                                    size_t bufferLen) const
		{
			if (buffer == nullptr || bufferLen == 0)
			{
				throw std::invalid_argument("Buffer cannot be null and length must be greater than zero");
			}

			return std::make_unique<RawPacket>(buffer, static_cast<int>(bufferLen), factoryTime, false,
			                                   defaultLinkType);
		}

		std::unique_ptr<pcpp::RawPacket> createPacketFromHexResource(const std::string& resourceName,
		                                                             const PacketFactory& factory,
		                                                             ResourceProvider const* resourceProvider)
		{
			if (resourceProvider == nullptr)
			{
				resourceProvider = getDefaultResourceProvider();
			}

			auto resource = resourceProvider->loadResource(resourceName.c_str(), ResourceType::HexData);
			return factory.createFromBuffer(std::move(resource.data), resource.length);
		}

		PacketAndBuffer createPacketAndBufferFromHexResource(const std::string& resourceName,
		                                                     const PacketFactory& factory,
		                                                     ResourceProvider const* resourceProvider)
		{
			if (resourceProvider == nullptr)
			{
				resourceProvider = getDefaultResourceProvider();
			}

			PacketAndBuffer packetAndBuffer;
			packetAndBuffer.resourceBuffer = resourceProvider->loadResource(resourceName, ResourceType::HexData);
			// Resource keeps ownership of the buffer
			packetAndBuffer.packet = factory.createFromBufferNonOwning(packetAndBuffer.resourceBuffer.data.get(),
			                                                           packetAndBuffer.resourceBuffer.length);
			return packetAndBuffer;
		}
	}  // namespace utils
}  // namespace pcpp_tests
