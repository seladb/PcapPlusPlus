#include "QuicLayer.h"
#include "PayloadLayer.h"
#include "GeneralUtils.h"
#include "SystemUtils.h"
#include <algorithm>
#include <cstring>

namespace pcpp
{
	QuicV1Layer* QuicV1Layer::parseQuicLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	{
		if (data == nullptr || dataLen <= sizeof(quic_common_header))
		{
			return nullptr;
		}

		auto headerForm = static_cast<QuicHeaderForm>(reinterpret_cast<quic_common_header*>(data)->headerForm);

		if (headerForm == QuicHeaderForm::ShortHeader && QuicV1OneRttLayer::isDataValid(data, dataLen))
		{
			return new QuicV1OneRttLayer(data, dataLen, prevLayer, packet);
		}

		if (headerForm == QuicHeaderForm::LongHeader && QuicV1LongHeaderLayer::isDataValid(data, dataLen))
		{
			auto header = reinterpret_cast<quic_long_header*>(data);
			if (header->version == 0x00000000)
			{
				return new QuicV1VersionNegotiationLayer(data, dataLen, prevLayer, packet);
			}
			if (netToHost32(header->version) != 0x00000001)
			{
				return nullptr;
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
			default:  // QuicPacketType::Retry
			{
				return new QuicV1RetryLayer(data, dataLen, prevLayer, packet);
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
			tryConstructNextLayerFromFactoryWithFallback<PayloadLayer>(parseQuicLayer, m_Data + headerLen,
			                                                           m_DataLen - headerLen);
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

	static std::string quicPacketTypeToString(QuicV1Layer::QuicPacketType packetType)
	{
		switch (packetType)
		{
		case QuicV1Layer::QuicPacketType::Initial:
			return "Initial";
		case QuicV1Layer::QuicPacketType::Handshake:
			return "Handshake";
		case QuicV1Layer::QuicPacketType::ZeroRTT:
			return "0-RTT";
		case QuicV1Layer::QuicPacketType::Retry:
			return "Retry";
		case QuicV1Layer::QuicPacketType::OneRtt:
			return "1-RTT";
		default:  // QuicPacketType::VersionNegotiation
			return "Version Negotiation";
		}
	}

	std::string QuicV1Layer::toString() const
	{
		return "QUIC v1 Layer, " + quicPacketTypeToString(getPacketType()) + " message";
	}

	const FieldDescriptor QuicV1Layer::SerializedFields::PacketType{ Layer::SerializedFields::MaxID + 1, "packetType" };
	const FieldDescriptor QuicV1Layer::SerializedFields::HeaderForm{ Layer::SerializedFields::MaxID + 2, "headerForm" };
	const FieldDescriptor QuicV1Layer::SerializedFields::FixedBit{ Layer::SerializedFields::MaxID + 3, "fixedBit" };

	void QuicV1Layer::serializeLayer(ObjectScope& serializer) const
	{
		serializer.writeField(SerializedFields::PacketType, quicPacketTypeToString(getPacketType()));
		serializer.writeField(SerializedFields::HeaderForm,
		                      getHeaderForm() == QuicHeaderForm::LongHeader ? "Long" : "Short");
		serializer.writeField(SerializedFields::FixedBit, getFixedBit());
	}

	bool QuicV1LongHeaderLayer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		return data != nullptr && dataLen >= sizeof(quic_long_header);
	}

	QuicV1Layer::QuicPacketType QuicV1LongHeaderLayer::getPacketType() const
	{
		return static_cast<QuicPacketType>(getLongHeader()->longPacketType);
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

		auto length = static_cast<size_t>(getLongHeader()->destinationConnectionIdLength);
		if (destinationConnectionIdOffset + length > m_DataLen)
		{
			throw std::out_of_range("Not enough data to read destination connection ID");
		}

		return { length, destinationConnectionIdOffset };
	}

	std::vector<uint8_t> QuicV1LongHeaderLayer::getDestinationConnectionId() const
	{
		try
		{
			auto offsetAndLength = getDestConIdOffsetAndLength();
			return { m_Data + offsetAndLength.offset, m_Data + offsetAndLength.offset + offsetAndLength.length };
		}
		catch (std::out_of_range&)
		{
			return {};
		}
	}

	std::string QuicV1LongHeaderLayer::getDestinationConnectionIdAsString() const
	{
		auto connectionId = getDestinationConnectionId();
		return byteArrayToHexString(connectionId.data(), connectionId.size());
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
		auto length = static_cast<size_t>(m_Data[sourceConnectionIdLengthOffset]);
		if (offset + length > m_DataLen)
		{
			throw std::out_of_range("Not enough data to read source connection ID");
		}

		return { length, offset };
	}

	std::vector<uint8_t> QuicV1LongHeaderLayer::getSourceConnectionId() const
	{
		try
		{
			auto offsetAndLength = getSrcConIdOffsetAndLength();
			return { m_Data + offsetAndLength.offset, m_Data + offsetAndLength.offset + offsetAndLength.length };
		}
		catch (std::out_of_range&)
		{
			return {};
		}
	}

	std::string QuicV1LongHeaderLayer::getSourceConnectionIdAsString() const
	{
		auto connectionId = getSourceConnectionId();
		return byteArrayToHexString(connectionId.data(), connectionId.size());
	}

	const FieldDescriptor QuicV1LongHeaderLayer::SerializedFields::Version{ QuicV1Layer::SerializedFields::MaxID + 1,
		                                                                    "version" };
	const FieldDescriptor QuicV1LongHeaderLayer::SerializedFields::DestinationConnectionId{
		QuicV1Layer::SerializedFields::MaxID + 2, "destinationConnectionId"
	};
	const FieldDescriptor QuicV1LongHeaderLayer::SerializedFields::SourceConnectionId{
		QuicV1Layer::SerializedFields::MaxID + 3, "sourceConnectionId"
	};

	void QuicV1LongHeaderLayer::serializeLayer(ObjectScope& serializer) const
	{
		QuicV1Layer::serializeLayer(serializer);
		serializer.writeHexField(SerializedFields::Version, getVersion());
		serializer.writeField(SerializedFields::DestinationConnectionId, getDestinationConnectionIdAsString());
		serializer.writeField(SerializedFields::SourceConnectionId, getSourceConnectionIdAsString());
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

		return { value, size };
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
			return (std::min)(static_cast<size_t>(offset + lengthValueAndSize.size + lengthValueAndSize.value),
			                  m_DataLen);
		}
		catch (std::out_of_range&)
		{
			return m_DataLen;
		}
	}

	QuicV1EstablishmentLayer::ProtectedPayload QuicV1EstablishmentLayer::getProtectedPayload() const
	{
		try
		{
			auto lengthOffset = getLengthOffset();
			auto lengthValueAndSize = getVarintValueAndSize(lengthOffset);

			auto payloadOffset = lengthOffset + lengthValueAndSize.size;
			auto payloadLength = static_cast<size_t>(lengthValueAndSize.value);

			payloadLength = (std::min)(payloadLength, m_DataLen - payloadOffset);

			return { m_Data + payloadOffset, payloadLength };
		}
		catch (std::out_of_range&)
		{
			return { nullptr, 0 };
		}
	}

	const FieldDescriptor QuicV1EstablishmentLayer::SerializedFields::PayloadLength{
		QuicV1LongHeaderLayer::SerializedFields::MaxID + 1, "payloadLength"
	};

	void QuicV1EstablishmentLayer::serializeLayer(ObjectScope& serializer) const
	{
		QuicV1LongHeaderLayer::serializeLayer(serializer);
		serializer.writeField(SerializedFields::PayloadLength, getLength());
	}

	std::vector<uint8_t> QuicV1InitialLayer::getToken() const
	{
		try
		{
			auto tokenLengthOffset = getTokenLengthOffset();
			auto tokenLengthValueAndSize = getVarintValueAndSize(tokenLengthOffset);
			if (tokenLengthValueAndSize.value == 0 ||
			    tokenLengthOffset + tokenLengthValueAndSize.size + tokenLengthValueAndSize.value > m_DataLen)
			{
				return {};
			}
			auto tokenOffset = m_Data + tokenLengthOffset + tokenLengthValueAndSize.size;
			return { tokenOffset, tokenOffset + tokenLengthValueAndSize.value };
		}
		catch (std::out_of_range&)
		{
			return {};
		}
	}

	std::string QuicV1InitialLayer::getTokenAsString() const
	{
		auto token = getToken();
		return byteArrayToHexString(token.data(), token.size());
	}

	const FieldDescriptor QuicV1InitialLayer::SerializedFields::Token{
		QuicV1EstablishmentLayer::SerializedFields::MaxID + 1, "token"
	};

	void QuicV1InitialLayer::serializeLayer(ObjectScope& serializer) const
	{
		QuicV1EstablishmentLayer::serializeLayer(serializer);
		serializer.writeField(SerializedFields::Token, getTokenAsString());
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

	std::vector<uint8_t> QuicV1RetryLayer::getRetryToken() const
	{
		auto retryTokenOffset = getRetryTokenOffset();
		if (m_DataLen - retryTokenOffset < retryIntegritySize)
		{
			return {};
		}

		return { m_Data + retryTokenOffset, m_Data + m_DataLen - retryIntegritySize };
	}

	std::string QuicV1RetryLayer::getRetryTokenAsString() const
	{
		auto retryToken = getRetryToken();
		return byteArrayToHexString(retryToken.data(), retryToken.size());
	}

	std::vector<uint8_t> QuicV1RetryLayer::getRetryIntegrityTag() const
	{
		auto retryTokenOffset = getRetryTokenOffset();
		if (m_DataLen - retryTokenOffset < retryIntegritySize)
		{
			return {};
		}

		return { m_Data + m_DataLen - retryIntegritySize, m_Data + m_DataLen };
	}

	std::string QuicV1RetryLayer::getRetryIntegrityTagAsString() const
	{
		auto retryIntegrityTag = getRetryIntegrityTag();
		return byteArrayToHexString(retryIntegrityTag.data(), retryIntegrityTag.size());
	}

	const FieldDescriptor QuicV1RetryLayer::SerializedFields::RetryToken{
		QuicV1LongHeaderLayer::SerializedFields::MaxID + 1, "retryToken"
	};
	const FieldDescriptor QuicV1RetryLayer::SerializedFields::RetryIntegrityTag{
		QuicV1LongHeaderLayer::SerializedFields::MaxID + 2, "retryIntegrityTag"
	};

	void QuicV1RetryLayer::serializeLayer(ObjectScope& serializer) const
	{
		QuicV1LongHeaderLayer::serializeLayer(serializer);
		serializer.writeField(SerializedFields::RetryToken, getRetryTokenAsString());
		serializer.writeField(SerializedFields::RetryIntegrityTag, getRetryIntegrityTagAsString());
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
				std::memcpy(&version, m_Data + supportedVersionsOffset, sizeof(uint32_t));
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

	const FieldDescriptor QuicV1VersionNegotiationLayer::SerializedFields::SupportedVersions{
		QuicV1LongHeaderLayer::SerializedFields::MaxID + 1, "supportedVersions"
	};
	const FieldDescriptor QuicV1VersionNegotiationLayer::SerializedFields::SupportedVersion{ 0, "supportedVersion" };

	void QuicV1VersionNegotiationLayer::serializeLayer(ObjectScope& serializer) const
	{
		QuicV1LongHeaderLayer::serializeLayer(serializer);
		auto versions = serializer.writeArray(SerializedFields::SupportedVersions);
		for (auto version : getSupportedVersions())
		{
			versions.writeHexField(SerializedFields::SupportedVersion, version);
		}
	}

	QuicV1Layer::ProtectedPayload QuicV1OneRttLayer::getProtectedPayload() const
	{
		return { m_Data + sizeof(quic_short_header), m_DataLen - sizeof(quic_short_header) };
	}

	bool QuicV1OneRttLayer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		return data != nullptr && dataLen >= sizeof(quic_short_header);
	}

	const FieldDescriptor QuicV1OneRttLayer::SerializedFields::SpinBit{ QuicV1Layer::SerializedFields::MaxID + 1,
		                                                                "spinBit" };
	const FieldDescriptor QuicV1OneRttLayer::SerializedFields::KeyPhaseBit{ QuicV1Layer::SerializedFields::MaxID + 2,
		                                                                    "keyPhaseBit" };

	void QuicV1OneRttLayer::serializeLayer(ObjectScope& serializer) const
	{
		QuicV1Layer::serializeLayer(serializer);
		serializer.writeField(SerializedFields::SpinBit, getSpinBit());
		serializer.writeField(SerializedFields::KeyPhaseBit, getKeyPhaseBit());
	}
}  // namespace pcpp
