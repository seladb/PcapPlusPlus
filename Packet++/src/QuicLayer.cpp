#include "QuicLayer.h"
#include "PayloadLayer.h"
#include "GeneralUtils.h"
#include "SystemUtils.h"
#include <algorithm>

namespace pcpp
{
	QuicV1Layer* QuicV1Layer::parseQuicLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	{
		if (data == nullptr || dataLen <= sizeof(quic_common_header))
		{
			return nullptr;
		}

		auto headerForm = static_cast<QuicHeaderForm>(reinterpret_cast<quic_common_header*>(data)->headerForm);

		if (headerForm == QuicHeaderForm::ShortHeader && QuicOneRttLayer::isDataValid(data, dataLen))
		{
			return new QuicOneRttLayer(data, dataLen, prevLayer, packet);
		}

		if (headerForm == QuicHeaderForm::LongHeader && QuicV1LongHeaderLayer::isDataValid(data, dataLen))
		{
			auto header = reinterpret_cast<quic_long_header*>(data);
			if (header->version == 0x00000000)
			{
				return new QuicV1VersionNegotiationLayer(data, dataLen, prevLayer, packet);
			}
			switch (header->longPacketType)
			{
			case static_cast<uint8_t>(QuicPacketType::Initial):
			{
				return new QuicV1InitialLayer(data, dataLen, prevLayer, packet);
			}
			case static_cast<uint8_t>(QuicPacketType::Handshake):
			{
				return new QuicV1HandshakeLayer(data, dataLen, prevLayer, packet);
			}
			case static_cast<uint8_t>(QuicPacketType::ZeroRTT):
			{
				return new QuicV1ZeroRttLayer(data, dataLen, prevLayer, packet);
			}
			case static_cast<uint8_t>(QuicPacketType::Retry):
			{
				return new QuicV1RetryLayer(data, dataLen, prevLayer, packet);
			}
			default:
			{
				return nullptr;
			}
			}
		}

		return nullptr;
	}

	void QuicV1Layer::parseNextLayer()
	{
		auto headerLen = getHeaderLen();

		if (headerLen < m_DataLen)
		{
			tryConstructNextLayerFromFactoryWithFallback<PayloadLayer>(parseQuicLayer, m_Data + headerLen, m_DataLen - headerLen);
		}
	}

	QuicV1Layer::QuicHeaderForm QuicV1Layer::getHeaderForm() const
	{
		return static_cast<QuicHeaderForm>(getCommonHeader()->headerForm);
	}

	uint8_t QuicV1Layer::getFixedBit() const
	{
		return getCommonHeader()->fixedBit;
	}

	std::string QuicV1Layer::toString() const
	{
		std::string packetType;

		switch (getPacketType())
		{
		case QuicPacketType::Initial:
		{
			packetType = "Initial";
			break;
		}
		case QuicPacketType::Handshake:
		{
			packetType = "Handshake";
			break;
		}
		case QuicPacketType::ZeroRTT:
		{
			packetType = "0-RTT";
			break;
		}
		case QuicPacketType::Retry:
		{
			packetType = "Retry";
			break;
		}
		case QuicPacketType::OneRtt:
		{
			packetType = "1-RTT";
			break;
		}
		case QuicPacketType::VersionNegotiation:
		{
			packetType = "Version Negotiation";
			break;
		}
		default:
		{
			packetType = "Unknown";
			break;
		}
		}

		return "QUIC v1 Layer, " + packetType + " message";
	}

	std::string QuicV1LongHeaderLayer::ByteArray::toString() const
	{
		return byteArrayToHexString(this->data(), this->size());
	}

	bool QuicV1LongHeaderLayer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		return data != nullptr && dataLen >= sizeof(quic_long_header);
	}

	QuicV1Layer::QuicPacketType QuicV1LongHeaderLayer::getPacketType() const
	{
		auto packetType = getLongHeader()->longPacketType;
		if (packetType <= static_cast<uint8_t>(QuicPacketType::Retry))
		{
			return static_cast<QuicPacketType>(packetType);
		}

		return QuicPacketType::Unknown;
	}

	uint32_t QuicV1LongHeaderLayer::getVersion() const
	{
		return netToHost32(getLongHeader()->version);
	}

	constexpr int QuicV1LongHeaderLayer::destinationConnectionIdOffset;

	QuicV1LongHeaderLayer::OffsetAndLength QuicV1LongHeaderLayer::getDestConIdOffsetAndLength() const
	{
		if (m_DataLen <= destinationConnectionIdOffset)
		{
			throw std::out_of_range("Not enough data to read destination connection ID length");
		}

		auto length = (std::min)(static_cast<size_t>(getLongHeader()->destinationConnectionIdLength), m_DataLen - destinationConnectionIdOffset);
		return {length, destinationConnectionIdOffset};
	}

	QuicV1LongHeaderLayer::ByteArray QuicV1LongHeaderLayer::getDestinationConnectionId() const
	{
		try
		{
			auto offsetAndLength = getDestConIdOffsetAndLength();
			return {m_Data + offsetAndLength.offset, m_Data + offsetAndLength.offset + offsetAndLength.length};
		}
		catch (std::out_of_range&)
		{
			return {};
		}
	}

	QuicV1LongHeaderLayer::OffsetAndLength QuicV1LongHeaderLayer::getSrcConIdOffsetAndLength() const
	{
		auto destOffsetAndLength = getDestConIdOffsetAndLength();
		auto sourceConnectionIdLengthOffset = destOffsetAndLength.offset + destOffsetAndLength.length;
		if (m_DataLen <= sourceConnectionIdLengthOffset + sizeof(uint8_t))
		{
			throw std::out_of_range("Not enough data to read source connection ID length");
		}

		auto offset = sourceConnectionIdLengthOffset + sizeof(uint8_t);
		auto length = (std::min)(static_cast<size_t>(m_Data[sourceConnectionIdLengthOffset]), m_DataLen - offset);

		return {length, offset};
	}

	QuicV1LongHeaderLayer::ByteArray QuicV1LongHeaderLayer::getSourceConnectionId() const
	{
		try
		{
			auto offsetAndLength = getSrcConIdOffsetAndLength();
			return {m_Data + offsetAndLength.offset, m_Data + offsetAndLength.offset + offsetAndLength.length};
		}
		catch (std::out_of_range&)
		{
			return {};
		}
	}

	size_t QuicV1EstablishmentLayer::getLengthOffset() const
	{
		auto srcConOffsetAndLength = getSrcConIdOffsetAndLength();
		if (srcConOffsetAndLength.offset + srcConOffsetAndLength.length + sizeof(uint8_t) > m_DataLen)
		{
			throw std::out_of_range("Not enough data to read length offset");
		}

		return srcConOffsetAndLength.offset + srcConOffsetAndLength.length;
	}

	QuicV1EstablishmentLayer::VarintValueAndSize QuicV1EstablishmentLayer::getVarintValueAndSize(size_t offset) const
	{
		uint8_t prefix = (m_Data[offset] & 0xc0) >> 6;
		auto size = static_cast<size_t>(1) << prefix;

		if (offset + size > m_DataLen)
		{
			throw std::out_of_range("Not enough data to read varint value");
		}

		uint64_t value = m_Data[offset] & 0x3f;
		for (size_t i = 1; i < size; i++)
		{
			value = (value << 8) | m_Data[offset + i];
		}

		return {value, size};
	}

	uint64_t QuicV1EstablishmentLayer::getLength() const
	{
		try
		{
			auto offset = getLengthOffset();
			auto valueAndSize = getVarintValueAndSize(offset);
			return valueAndSize.value;
		}
		catch (std::out_of_range&)
		{
			return 0;
		}
	}

	size_t QuicV1EstablishmentLayer::getHeaderLen() const
	{
		try
		{
			auto offset = getLengthOffset();
			auto lengthValueAndSize = getVarintValueAndSize(offset);
			return (std::min)(static_cast<size_t>(offset + lengthValueAndSize.size + lengthValueAndSize.value), m_DataLen);
		}
		catch (std::out_of_range&)
		{
			return m_DataLen;
		}
	}

	QuicV1LongHeaderLayer::ByteArray QuicV1InitialLayer::getToken() const
	{
		try
		{
			auto tokenLengthOffset = getTokenLengthOffset();
			auto tokenLengthValueAndSize = getVarintValueAndSize(tokenLengthOffset);
			if (tokenLengthValueAndSize.value == 0 || tokenLengthOffset + tokenLengthValueAndSize.size + tokenLengthValueAndSize.value > m_DataLen)
			{
				return {};
			}
			auto tokenOffset = m_Data + tokenLengthOffset + tokenLengthValueAndSize.size;
			return {tokenOffset, tokenOffset + tokenLengthValueAndSize.value};
		}
		catch (std::out_of_range&)
		{
			return {};
		}
	}

	size_t QuicV1InitialLayer::getLengthOffset() const
	{
		auto tokenLengthOffset = getTokenLengthOffset();
		auto tokenLengthValueAndSize = getVarintValueAndSize(tokenLengthOffset);
		if (tokenLengthOffset + tokenLengthValueAndSize.size + tokenLengthValueAndSize.value > m_DataLen)
		{
			throw std::out_of_range("Not enough data to read length offset");
		}
		return tokenLengthOffset + tokenLengthValueAndSize.size + tokenLengthValueAndSize.value;
	}

	size_t QuicV1InitialLayer::getTokenLengthOffset() const
	{
		auto srcConOffsetAndLength = getSrcConIdOffsetAndLength();
		if (srcConOffsetAndLength.offset + srcConOffsetAndLength.length + sizeof(uint8_t) > m_DataLen)
		{
			throw std::out_of_range("Not enough data to read token length offset");
		}
		return srcConOffsetAndLength.offset + srcConOffsetAndLength.length;
	}

	size_t QuicV1RetryLayer::getRetryTokenOffset() const
	{
		try
		{
			auto offsetAndLength = getSrcConIdOffsetAndLength();
			return offsetAndLength.offset + offsetAndLength.length;
		}
		catch (std::out_of_range&)
		{
			return m_DataLen;
		}
	}

	QuicV1LongHeaderLayer::ByteArray QuicV1RetryLayer::getRetryToken() const
	{
		auto retryTokenOffset = getRetryTokenOffset();
		if (m_DataLen - retryTokenOffset < retryIntegritySize)
		{
			return {};
		}

		return {m_Data + retryTokenOffset, m_Data + m_DataLen - retryIntegritySize};
	}

	QuicV1LongHeaderLayer::ByteArray QuicV1RetryLayer::getRetryIntegrityTag() const
	{
		auto retryTokenOffset = getRetryTokenOffset();
		if (m_DataLen - retryTokenOffset < retryIntegritySize)
		{
			return {};
		}

		return {m_Data + m_DataLen - retryIntegritySize, m_Data + m_DataLen};
	}

	std::vector<uint32_t> QuicV1VersionNegotiationLayer::getSupportedVersions() const
	{
		try
		{
			auto offsetAndLength = getSrcConIdOffsetAndLength();
			auto supportedVersionsOffset = offsetAndLength.offset + offsetAndLength.length;
			std::vector<uint32_t> supportedVersions;
			while (supportedVersionsOffset < m_DataLen)
			{
				if (m_DataLen - supportedVersionsOffset < sizeof(uint32_t))
				{
					break;
				}
				uint32_t version;
				memcpy(&version, m_Data + supportedVersionsOffset, sizeof(uint32_t));
				supportedVersions.push_back(netToHost32(version));
				supportedVersionsOffset += sizeof(uint32_t);
			}
			return supportedVersions;
		}
		catch (std::out_of_range&)
		{
			return {};
		}

	}

	bool QuicOneRttLayer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		return data != nullptr && dataLen >= sizeof(quic_short_header);
	}
}