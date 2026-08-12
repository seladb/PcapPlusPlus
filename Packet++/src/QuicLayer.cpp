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

	QuicLongHeaderLayer::OffsetAndLength QuicLongHeaderLayer::getDestConIdOffsetAndLength() const
	{
		if (m_DataLen <= destinationConnectionIdOffset)
		{
			throw std::out_of_range("Not enough data to read destination connection ID length");
		}

		auto length = (std::min)(static_cast<size_t>(getLongHeader()->destinationConnectionIdLength), m_DataLen - destinationConnectionIdOffset);
		return {length, destinationConnectionIdOffset};
	}

	QuicLongHeaderLayer::ByteArray QuicLongHeaderLayer::getDestinationConnectionId() const
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

	QuicLongHeaderLayer::OffsetAndLength QuicLongHeaderLayer::getSrcConIdOffsetAndLength() const
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

	QuicLongHeaderLayer::ByteArray QuicLongHeaderLayer::getSourceConnectionId() const
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

	size_t QuicEstablishmentLayer::getLengthOffset() const
	{
		auto srcConOffsetAndLength = getSrcConIdOffsetAndLength();
		if (srcConOffsetAndLength.offset + srcConOffsetAndLength.length + sizeof(uint8_t) > m_DataLen)
		{
			throw std::out_of_range("Not enough data to read length offset");
		}

		return srcConOffsetAndLength.offset + srcConOffsetAndLength.length;
	}

	QuicEstablishmentLayer::VarintValueAndSize QuicEstablishmentLayer::getVarintValueAndSize(size_t offset) const
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

	uint64_t QuicEstablishmentLayer::getLength() const
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

	size_t QuicEstablishmentLayer::getHeaderLen() const
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

	QuicLongHeaderLayer::ByteArray QuicInitialLayer::getToken() const
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

	size_t QuicInitialLayer::getLengthOffset() const
	{
		auto tokenLengthOffset = getTokenLengthOffset();
		auto tokenLengthValueAndSize = getVarintValueAndSize(tokenLengthOffset);
		if (tokenLengthOffset + tokenLengthValueAndSize.size + tokenLengthValueAndSize.value > m_DataLen)
		{
			throw std::out_of_range("Not enough data to read length offset");
		}
		return tokenLengthOffset + tokenLengthValueAndSize.size + tokenLengthValueAndSize.value;
	}

	size_t QuicInitialLayer::getTokenLengthOffset() const
	{
		auto srcConOffsetAndLength = getSrcConIdOffsetAndLength();
		if (srcConOffsetAndLength.offset + srcConOffsetAndLength.length + sizeof(uint8_t) > m_DataLen)
		{
			throw std::out_of_range("Not enough data to read token length offset");
		}
		return srcConOffsetAndLength.offset + srcConOffsetAndLength.length;
	}

	bool QuicOneRttLayer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		return data != nullptr && dataLen >= sizeof(quic_short_header);
	}
}