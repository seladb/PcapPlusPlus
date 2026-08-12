#include "QuicLayer.h"
#include "PayloadLayer.h"
#include "GeneralUtils.h"
#include "SystemUtils.h"
#include <algorithm>

namespace pcpp
{
	QuicLayer* QuicLayer::parseQuicLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
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

		if (headerForm == QuicHeaderForm::LongHeader && QuicLongHeaderLayer::isDataValid(data, dataLen))
		{
			auto header = reinterpret_cast<quic_long_header*>(data);
			switch (header->longPacketType)
			{
			case static_cast<uint8_t>(QuicPacketType::Initial):
			{
				return new QuicInitialLayer(data, dataLen, prevLayer, packet);
			}
			case static_cast<uint8_t>(QuicPacketType::Handshake):
			{
				return new QuicHandshakeLayer(data, dataLen, prevLayer, packet);
			}
			case static_cast<uint8_t>(QuicPacketType::ZeroRTT):
			{
				return new QuicZeroRttLayer(data, dataLen, prevLayer, packet);
			}
			default:
			{
				return nullptr;
			}
			}
		}

		return nullptr;
	}

	void QuicLayer::parseNextLayer()
	{
		auto headerLen = getHeaderLen();

		if (headerLen < m_DataLen)
		{
			tryConstructNextLayerFromFactoryWithFallback<PayloadLayer>(parseQuicLayer, m_Data + headerLen, m_DataLen - headerLen);
		}
	}

	QuicLayer::QuicHeaderForm QuicLayer::getHeaderForm() const
	{
		return static_cast<QuicHeaderForm>(getCommonHeader()->headerForm);
	}

	uint8_t QuicLayer::getFixedBit() const
	{
		return getCommonHeader()->fixedBit;
	}

	std::string QuicLongHeaderLayer::ByteArray::toString() const
	{
		return byteArrayToHexString(this->data(), this->size());
	}

	bool QuicLongHeaderLayer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		return data != nullptr && dataLen >= sizeof(quic_long_header);
	}

	QuicLayer::QuicPacketType QuicLongHeaderLayer::getPacketType() const
	{
		auto packetType = getLongHeader()->longPacketType;
		if (packetType <= static_cast<uint8_t>(QuicPacketType::Retry))
		{
			return static_cast<QuicPacketType>(packetType);
		}

		return QuicPacketType::Unknown;
	}

	uint32_t QuicLongHeaderLayer::getVersion() const
	{
		return netToHost32(getLongHeader()->version);
	}

	constexpr int QuicLongHeaderLayer::destinationConnectionIdOffset;

	std::unique_ptr<QuicLongHeaderLayer::OffsetAndLength> QuicLongHeaderLayer::getDestConIdOffsetAndLength() const
	{
		if (m_DataLen <= destinationConnectionIdOffset)
		{
			return nullptr;
		}

		auto length = (std::min)(static_cast<size_t>(getLongHeader()->destinationConnectionIdLength), m_DataLen - destinationConnectionIdOffset);
		return std::make_unique<OffsetAndLength>(length, destinationConnectionIdOffset);
	}

	QuicLongHeaderLayer::ByteArray QuicLongHeaderLayer::getDestinationConnectionId() const
	{
		auto offsetAndLength = getDestConIdOffsetAndLength();
		if (offsetAndLength  == nullptr)
		{
			return {};

		}

		return {m_Data + offsetAndLength->offset, m_Data + offsetAndLength->offset + offsetAndLength->length};
	}

	std::unique_ptr<QuicLongHeaderLayer::OffsetAndLength> QuicLongHeaderLayer::getSrcConIdOffsetAndLength() const
	{
		auto destOffsetAndLength = getDestConIdOffsetAndLength();
		if (destOffsetAndLength == nullptr)
		{
			return nullptr;
		}

		auto sourceConnectionIdLengthOffset = destOffsetAndLength->offset + destOffsetAndLength->length;
		if (m_DataLen <= sourceConnectionIdLengthOffset + sizeof(uint8_t))
		{
			return nullptr;
		}

		auto offset = sourceConnectionIdLengthOffset + sizeof(uint8_t);
		auto length = (std::min)(static_cast<size_t>(m_Data[sourceConnectionIdLengthOffset]), m_DataLen - offset);

		return std::make_unique<OffsetAndLength>(length, offset);
	}

	QuicLongHeaderLayer::ByteArray QuicLongHeaderLayer::getSourceConnectionId() const
	{
		auto offsetAndLength = getSrcConIdOffsetAndLength();
		if (offsetAndLength == nullptr)
		{
			return {};
		}

		return {m_Data + offsetAndLength->offset, m_Data + offsetAndLength->offset + offsetAndLength->length};
	}

	std::unique_ptr<size_t> QuicEstablishmentLayer::getLengthOffset() const
	{
		auto srcConOffsetAndLength = getSrcConIdOffsetAndLength();
		if (srcConOffsetAndLength == nullptr || srcConOffsetAndLength->offset + srcConOffsetAndLength->length + sizeof(uint8_t) > m_DataLen)
		{
			return nullptr;
		}

		auto lengthOffset = srcConOffsetAndLength->offset + srcConOffsetAndLength->length;
		return std::make_unique<size_t>(lengthOffset);
	}

	std::unique_ptr<QuicEstablishmentLayer::VarintValueAndSize> QuicEstablishmentLayer::getVarintValueAndSize(size_t offset) const
	{
		uint8_t prefix = (m_Data[offset] & 0xc0) >> 6;
		auto size = static_cast<size_t>(1) << prefix;

		if (offset + size > m_DataLen)
		{
			return nullptr;
		}

		uint64_t value = m_Data[offset] & 0x3f;
		for (size_t i = 1; i < size; i++)
		{
			value = (value << 8) | m_Data[offset + i];
		}

		return std::make_unique<VarintValueAndSize>(value, size);
	}

	uint64_t QuicEstablishmentLayer::getLength() const
	{
		auto offset = getLengthOffset();
		if (offset == nullptr)
		{
			return 0;
		}

		auto valueAndSize = getVarintValueAndSize(*offset);
		if (valueAndSize == nullptr)
		{
			return 0;
		}
		return valueAndSize->value;
	}

	size_t QuicEstablishmentLayer::getHeaderLen() const
	{
		auto offset = getLengthOffset();
		if (offset == nullptr)
		{
			return m_DataLen;
		}

		auto lengthValueAndSize = getVarintValueAndSize(*offset);
		if (lengthValueAndSize == nullptr)
		{
			return m_DataLen;
		}

		return (std::min)(static_cast<size_t>(*offset + lengthValueAndSize->size + lengthValueAndSize->value), m_DataLen);
	}

	QuicLongHeaderLayer::ByteArray QuicInitialLayer::getToken() const
	{
		auto tokenLengthOffset = getTokenLengthOffset();
		if (tokenLengthOffset == nullptr)
		{
			return {};
		}
		auto tokenLengthValueAndSize = getVarintValueAndSize(*tokenLengthOffset);
		if (tokenLengthValueAndSize == nullptr || tokenLengthValueAndSize->value == 0 || *tokenLengthOffset + tokenLengthValueAndSize->size + tokenLengthValueAndSize->value > m_DataLen)
		{
			return {};
		}

		auto tokenOffset = m_Data + *tokenLengthOffset + tokenLengthValueAndSize->size;
		return {tokenOffset, tokenOffset + tokenLengthValueAndSize->value};
	}

	std::unique_ptr<size_t> QuicInitialLayer::getLengthOffset() const
	{
		auto tokenLengthOffset = getTokenLengthOffset();
		if (tokenLengthOffset == nullptr)
		{
			return nullptr;
		}

		auto tokenLengthValueAndSize = getVarintValueAndSize(*tokenLengthOffset);

		if (tokenLengthValueAndSize == nullptr || *tokenLengthOffset + tokenLengthValueAndSize->size + tokenLengthValueAndSize->value > m_DataLen)
		{
			return nullptr;
		}

		return std::make_unique<size_t>(*tokenLengthOffset + tokenLengthValueAndSize->size + tokenLengthValueAndSize->value);
	}

	std::unique_ptr<size_t> QuicInitialLayer::getTokenLengthOffset() const
	{
		auto srcConOffsetAndLength = getSrcConIdOffsetAndLength();
		if (srcConOffsetAndLength == nullptr || srcConOffsetAndLength->offset + srcConOffsetAndLength->length + sizeof(uint8_t) > m_DataLen)
		{
			return nullptr;
		}

		return std::make_unique<size_t>(srcConOffsetAndLength->offset + srcConOffsetAndLength->length);
	}

	bool QuicOneRttLayer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		return data != nullptr && dataLen >= sizeof(quic_short_header);
	}
}