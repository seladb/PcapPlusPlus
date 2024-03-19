#include "Asn1BerDecoder.h"
#include "GeneralUtils.h"
#include <iostream>
#include <cmath>

namespace pcpp {

	std::string Asn1BerRecord::getValueAsString() const
	{
		return byteArrayToHexString(m_Value, m_ValueLength);
	}

	Asn1BerRecord Asn1BerRecord::decode(const uint8_t* data, size_t dataLen)
	{
		Asn1BerRecord decodedRecord;
		auto tagLen = decodedRecord.decodeTag(data, dataLen);

		if (dataLen - tagLen < 0)
		{
			throw std::invalid_argument("Cannot decode ASN.1 BER record, data is shorter than tag len");
		}

		auto lengthLen = decodedRecord.decodeLength(data + tagLen, dataLen - tagLen);

		if (dataLen - tagLen - lengthLen - decodedRecord.m_ValueLength < 0)
		{
			throw std::invalid_argument("Cannot decode ASN.1 BER record, data doesn't contain the entire record");
		}

		decodedRecord.m_TotalLength = tagLen + lengthLen + decodedRecord.m_ValueLength;

		decodedRecord.m_Value = data + tagLen + lengthLen;

		decodedRecord.decodeChildren();

		return decodedRecord;

		// TODO

//		else if (!isValidTlv) {
//			if (allowConstructedIfMultipleTlvs)
//			{
//				if (currentReadIndex != tlv.size() && currentReadIndex != tlv.size() + 2)
//				{
//					const int lengthInt = tlv.size();
//					if (lengthInt > 0)
//					{
//						isValidTlv = true;
//
//						// this is a group of tags, so we add them as children and consider this a constructed tag
//						children.push_back(*this);
//
//						int currentReadIndexChildren = currentReadIndex;
//						while (currentReadIndexChildren < lengthInt)
//						{
//							Asn1BerRecord nextTag;
//							nextTag.decode(tlv.substr(currentReadIndexChildren), false);
//							if (nextTag.isValidTlv)
//							{
//								children.push_back(nextTag);
//							}
//							currentReadIndexChildren += nextTag.currentReadIndex;
//						}
//
//						// If nothing else in the TLV was considered valid, we go back to having the first valid TLV as the only one
//						if (children.size() > 1)
//						{
//							tagType = BerTagType::CONSTRUCTED;
//
//							tag.clear();
//							value = tlv;
//							length.clear();
//							tagClass = BerTagClass::UNIVERSAL;
//						}
//						else
//						{
//							children.clear();
//							isValidTlv = false;
//						}
//					}
//				}
//			}
//			else if (hasMoreAfterValue)
//			{
//				isValidTlv = true; // this is part of a group of tags not inside a constructed tag, so we consider this as valid and will continue to evalute the rest of the tlv
//			}
//		}
	}

	int Asn1BerRecord::decodeTag(const uint8_t* data, size_t dataLen)
	{
		if (dataLen < 1)
		{
			throw std::invalid_argument("Cannot decode ASN.1 BER record tag");
		}

		// Check first 2 bits
		auto tagClassBits = data[0] & 0xc0;
		if (tagClassBits == 0)
		{
			m_TagClass = BerTagClass::Universal;
		}
		else if ((tagClassBits & 0xc0) == 0xc0)
		{
			m_TagClass = BerTagClass::Private;
		}
		else if ((tagClassBits & 0x80) == 0x80)
		{
			m_TagClass = BerTagClass::ContextSpecific;
		}
		else if ((tagClassBits & 0x40) == 0x40)
		{
			m_TagClass = BerTagClass::Application;
		}

		// Check bit 6
		auto tagTypeBits = data[0] & 0x20;
		m_BerTagType = (tagTypeBits == 0 ? BerTagType::Primitive : BerTagType::Constructed);

		// Check last 5 bits
		auto tagType = data[0] & 0x1f;
		m_Asn1TagType = static_cast<Asn1TagType>(tagType);

		return 1;
		// TODO
//		// Check if the tag is using more than one byte
//		if (tagNumber >= 31)
//		{
//			for (auto i = 1; i < 1000; i++)
//				// Check first bit
//				const bool hasNextByte = data[i] & 0x80;
//				if (!hasNextByte)
//				{
//					break;
//				}
//			}
//		}
	}

	int Asn1BerRecord::decodeLength(const uint8_t* data, size_t dataLen)
	{
		if (dataLen < 1)
		{
			throw std::invalid_argument("Cannot decode ASN.1 BER record length");
		}

		// Check 8th bit
		auto lengthForm = data[0] & 0x80;

		auto numberLengthBytes = 1;

		// Check if the tag is using more than one byte
		// 8th bit at 0 means the length only uses one byte
		// 8th bit at 1 means the length uses more than one byte. The number of bytes is encoded in the other 7 bits
		if (lengthForm != 0)
		{
			auto additionalLengthBytes = data[0] & 0x7F;
			if (static_cast<int>(dataLen) < additionalLengthBytes + 1)
			{
				throw std::invalid_argument("Cannot decode ASN.1 BER record length");
			}
			for (auto index = additionalLengthBytes; index > 0; --index)
			{
				m_ValueLength += data[index] * static_cast<int>(std::pow(256, (additionalLengthBytes - index)));
			}
			numberLengthBytes += additionalLengthBytes;
		}
		else
		{
			m_ValueLength = data[0];
		}

		return numberLengthBytes;
	}

	void Asn1BerRecord::decodeChildren()
	{
		if (m_BerTagType != BerTagType::Constructed || !m_ValueLength)
		{
			return;
		}

		auto value = m_Value;
		auto valueLen = m_ValueLength;

		while (valueLen > 0)
		{
			auto childTag = Asn1BerRecord::decode(value, valueLen);
			value += childTag.getTotalLength();
			valueLen -= childTag.getTotalLength();
			m_Children.push_back(childTag);
		}
	}
}