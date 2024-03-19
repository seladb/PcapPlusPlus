#pragma once

#include <string>
#include <vector>

namespace pcpp
{
	enum class BerTagClass : uint8_t
	{
		Universal,
		Application,
		ContextSpecific,
		Private
	};

	enum class BerTagType : uint8_t
	{
		Primitive,
		Constructed
	};

	enum class Asn1TagType : uint8_t
	{
		EndOfContent = 0,
		Boolean = 1,
		Integer = 2,
		BitString = 3,
		OctetString = 4,
		Null = 5,
		ObjectIdentifier = 6,
		ObjectDescriptor = 7,
		External = 8,
		Real = 9,
		Enumerated = 10,
		EmbeddedPDV = 11,
		UTF8String = 12,
		RelativeOID = 13,
		Time = 14,
		Reserved = 15,
		Sequence = 16,
		Set = 17,
		NumericString = 18,
		PrintableString = 19,
		T61String = 20,
		VideotexString = 21,
		IA5String = 22,
		UTCTime = 23,
		GeneralizedTime = 24,
		GraphicString = 25,
		VisibleString = 26,
		GeneralString = 27,
		UniversalString = 28,
		CharacterString = 29,
		BMPString = 30,
		Date = 31,
		TimeOfDay = 32,
		DateTime = 33,
		Duration = 34,
		OidIri = 35,
		RelativeOidIri = 36
	};

	class Asn1BerRecord
	{
	public:
		Asn1BerRecord(const uint8_t* data, size_t dataLen);

		size_t getValueLength() const { return m_ValueLength; }
		size_t getTotalLength() const { return m_TotalLength; }
		std::string getValueAsString() const;

		BerTagClass getTagClass() const { return m_TagClass; }
		BerTagType getBerTagType() const { return m_BerTagType; }
		Asn1TagType getAsn1TagType() const { return m_Asn1TagType; }

		bool isValid() const { return m_IsValid; }

		std::vector<Asn1BerRecord> getChildren() const;

	private:
		BerTagClass m_TagClass = BerTagClass::Universal;
		BerTagType m_BerTagType = BerTagType::Primitive;
		Asn1TagType m_Asn1TagType;

		const uint8_t* m_Value;
		size_t m_ValueLength = 0;
		size_t m_TotalLength = 0;

		bool m_IsValid = true;
		std::vector<Asn1BerRecord> m_Children;

//		bool hasMoreAfterValue = false;

		Asn1BerRecord() = default;

		void decode(const uint8_t* data, size_t dataLen, bool allowConstructedIfMultipleTlvs);

		int decodeTag(const uint8_t* data, size_t dataLen);

		int decodeLength(const uint8_t* data, size_t dataLen);
	};

}
