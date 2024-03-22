#include "Asn1BerDecoder.h"
#include "GeneralUtils.h"
#include "EndianPortable.h"
#include <iostream>
#include <cmath>

namespace pcpp {
	std::unique_ptr<Asn1BerRecord> Asn1BerRecord::decode(const uint8_t* data, size_t dataLen)
	{
		auto record = decodeInternal(data, dataLen);
		return std::unique_ptr<Asn1BerRecord>(record);
	}

	Asn1BerRecord* Asn1BerRecord::decodeInternal(const uint8_t* data, size_t dataLen)
	{
		int tagLen = 1;
		if (dataLen < static_cast<size_t>(tagLen))
		{
			throw std::invalid_argument("Cannot decode ASN.1 BER record, data is shorter than tag len");
		}

		auto decodedRecord = decodeTagAndCreateRecord(data, dataLen);

		auto lengthLen = decodedRecord->decodeLength(data + tagLen, dataLen - tagLen);

		if (dataLen - tagLen - lengthLen - decodedRecord->m_ValueLength < 0)
		{
			throw std::invalid_argument("Cannot decode ASN.1 BER record, data doesn't contain the entire record");
		}

		decodedRecord->m_TotalLength = tagLen + lengthLen + decodedRecord->m_ValueLength;

		decodedRecord->m_Value = data + tagLen + lengthLen;

		decodedRecord->additionalDecode();

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

	Asn1UniversalTagType Asn1BerRecord::getAsn1UniversalTagType() const
	{
		if (m_TagClass == BerTagClass::Universal)
		{
			return static_cast<Asn1UniversalTagType>(m_TagType);
		}

		return Asn1UniversalTagType::NotApplicable;
	}

	Asn1BerRecord* Asn1BerRecord::decodeTagAndCreateRecord(const uint8_t* data, size_t dataLen)
	{
		if (dataLen < 1)
		{
			throw std::invalid_argument("Cannot decode ASN.1 BER record tag");
		}

		BerTagClass tagClass = BerTagClass::Universal;

		// Check first 2 bits
		auto tagClassBits = data[0] & 0xc0;
		if (tagClassBits == 0)
		{
			tagClass = BerTagClass::Universal;
		}
		else if ((tagClassBits & 0xc0) == 0xc0)
		{
			tagClass = BerTagClass::Private;
		}
		else if ((tagClassBits & 0x80) == 0x80)
		{
			tagClass = BerTagClass::ContextSpecific;
		}
		else if ((tagClassBits & 0x40) == 0x40)
		{
			tagClass = BerTagClass::Application;
		}

		// Check bit 6
		auto tagTypeBits = data[0] & 0x20;
		BerTagType berTagType = (tagTypeBits == 0 ? BerTagType::Primitive : BerTagType::Constructed);

		// Check last 5 bits
		auto tagType = data[0] & 0x1f;

		Asn1BerRecord* newRecord;

		if (berTagType == BerTagType::Constructed)
		{
			if (tagClass == BerTagClass::Universal)
			{
				switch (static_cast<Asn1UniversalTagType>(tagType))
				{
					case Asn1UniversalTagType::Sequence:
					{
						newRecord = new Asn1SequenceRecord();
						break;
					}
					case Asn1UniversalTagType::Set:
					{
						newRecord = new Asn1SetRecord();
						break;
					}
					default:
					{
						newRecord = new Asn1BerConstructedRecord();
					}
				}
			}
			else
			{
				newRecord = new Asn1BerConstructedRecord();
			}
		}
		else
		{
			if (tagClass == BerTagClass::Universal)
			{
				auto asn1UniversalTagType = static_cast<Asn1UniversalTagType>(tagType);
				switch (asn1UniversalTagType)
				{
					case Asn1UniversalTagType::Integer:
					{
						newRecord = new Asn1IntegerRecord();
						break;
					}
					case Asn1UniversalTagType::Enumerated:
					{
						newRecord = new Asn1EnumeratedRecord();
						break;
					}
					case Asn1UniversalTagType::OctetString:
					{
						newRecord = new Asn1OctetStringRecord();
						break;
					}
					case Asn1UniversalTagType::Boolean:
					{
						newRecord = new Asn1BooleanRecord();
						break;
					}
					case Asn1UniversalTagType::Null:
					{
						newRecord = new Asn1NullRecord();
						break;
					}
					default:
					{
						newRecord = new Asn1BerRecord();
					}
				}
			}
			else
			{
				newRecord = new Asn1BerRecord();
			}
		}

		newRecord->m_TagClass = tagClass;
		newRecord->m_BerTagType = berTagType;
		newRecord->m_TagType = tagType;

		return newRecord;
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

	void Asn1BerConstructedRecord::additionalDecode()
	{
		if (!m_ValueLength)
		{
			return;
		}

		auto value = m_Value;
		auto valueLen = m_ValueLength;

		while (valueLen > 0)
		{
			auto childTag = Asn1BerRecord::decodeInternal(value, valueLen);
			value += childTag->getTotalLength();
			valueLen -= childTag->getTotalLength();

			m_Children.pushBack(childTag);
		}
	}

	int Asn1IntegerRecord::getValue() const
	{
		switch (m_ValueLength)
		{
			case 1:
			{
				return *(uint8_t*)m_Value;
			}
			case 2:
			{
				return be16toh(*(uint16_t*)m_Value);
			}
			case 3:
			{
				uint8_t tempData[4] = {0};
				memcpy(tempData + 1, m_Value, 3);
				return be32toh(*(uint32_t*)tempData);
			}
			case 4:
			{
				return be32toh(*(uint32_t*)m_Value);
			}
			default:
			{
				throw std::runtime_error("An integer ASN.1 record of more than 4 bytes is not supported");
			}
		}
	}

	std::string Asn1OctetStringRecord::getValue() const
	{
		return {m_Value, m_Value + m_ValueLength};
	}

	bool Asn1BooleanRecord::getValue() const
	{
		return m_Value[0] != 0;
	}
}