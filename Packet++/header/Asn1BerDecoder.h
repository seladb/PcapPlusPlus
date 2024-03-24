#pragma once

#include <string>
#include <memory>
#include "PointerVector.h"

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

	enum class Asn1UniversalTagType : uint8_t
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
		RelativeOidIri = 36,
		NotApplicable = 255
	};

	class Asn1BerRecord
	{
	public:
		size_t getValueLength() const { return m_ValueLength; }
		size_t getTotalLength() const { return m_TotalLength; }

		BerTagClass getTagClass() const { return m_TagClass; }
		BerTagType getBerTagType() const { return m_BerTagType; }
		Asn1UniversalTagType getAsn1UniversalTagType() const;
		uint8_t getTagType() const { return m_TagType; }

		template <class Asn1BerRecordType>
		const Asn1BerRecordType* castAs() const { return dynamic_cast<const Asn1BerRecordType*>(this); }

		std::vector<uint8_t> encode();

		static std::unique_ptr<Asn1BerRecord> decode(const uint8_t* data, size_t dataLen);

		virtual ~Asn1BerRecord() = default;

	protected:
		BerTagClass m_TagClass = BerTagClass::Universal;
		BerTagType m_BerTagType = BerTagType::Primitive;
		uint8_t m_TagType = 0;

		size_t m_ValueLength = 0;
		size_t m_TotalLength = 0;

		Asn1BerRecord() = default;

		static Asn1BerRecord* decodeInternal(const uint8_t* data, size_t dataLen);

		virtual void decodeValue(uint8_t* data) = 0;
		virtual std::vector<uint8_t> encodeValue() const = 0;

		static Asn1BerRecord* decodeTagAndCreateRecord(const uint8_t* data, size_t dataLen);
		int decodeLength(const uint8_t* data, size_t dataLen);

		uint8_t encodeTag();
		std::vector<uint8_t> encodeLength() const;
	};

	class Asn1GenericRecord : public Asn1BerRecord
	{
		friend class Asn1BerRecord;

	public:
		Asn1GenericRecord(BerTagClass tagClass, BerTagType berTagType, uint8_t tagType, const uint8_t* value, size_t valueLen);
		virtual ~Asn1GenericRecord();
		const uint8_t* getValue() const { return m_Value; }

	protected:
		Asn1GenericRecord() = default;

		void decodeValue(uint8_t* data) override;
		std::vector<uint8_t> encodeValue() const override;

	private:
		uint8_t* m_Value;
		bool m_FreeValueOnDestruction = false;
	};

	class Asn1BerConstructedRecord : public Asn1BerRecord
	{
		friend class Asn1BerRecord;

	public:
		Asn1BerConstructedRecord(BerTagClass tagClass, uint8_t tagType, const std::vector<Asn1BerRecord*> children);
		const PointerVector<Asn1BerRecord>& getChildren() const { return m_Children; };

	protected:
		Asn1BerConstructedRecord() = default;

		void decodeValue(uint8_t* data) override;
		std::vector<uint8_t> encodeValue() const override;

	private:
		PointerVector<Asn1BerRecord> m_Children;
	};

	class Asn1SequenceRecord : public Asn1BerConstructedRecord
	{
		friend class Asn1BerRecord;

	private:
		Asn1SequenceRecord() = default;
	};

	class Asn1SetRecord : public Asn1BerConstructedRecord
	{
		friend class Asn1BerRecord;

	private:
		Asn1SetRecord() = default;
	};

	class Asn1PrimitiveRecord : public Asn1BerRecord
	{
		friend class Asn1BerRecord;

	protected:
		Asn1PrimitiveRecord() = default;
		explicit Asn1PrimitiveRecord(uint8_t tagType);
	};

	class Asn1IntegerRecord : public Asn1PrimitiveRecord
	{
		friend class Asn1BerRecord;

	public:
		Asn1IntegerRecord(uint32_t value);
		uint32_t getValue() const { return m_Value; }

	protected:
		Asn1IntegerRecord() = default;

		void decodeValue(uint8_t* data) override;
		std::vector<uint8_t> encodeValue() const override;

	private:
		uint32_t m_Value;
	};

	class Asn1EnumeratedRecord : public Asn1IntegerRecord
	{
		friend class Asn1BerRecord;

	public:
		Asn1EnumeratedRecord(uint32_t value);

	private:
		Asn1EnumeratedRecord() = default;
	};

	class Asn1OctetStringRecord : public Asn1PrimitiveRecord
	{
		friend class Asn1BerRecord;

	public:
		Asn1OctetStringRecord(const std::string& value);
		std::string getValue() const { return m_Value; };

	protected:
		void decodeValue(uint8_t* data) override;
		std::vector<uint8_t> encodeValue() const override;

	private:
		std::string m_Value;

		Asn1OctetStringRecord() = default;

	};

	class Asn1BooleanRecord : public Asn1PrimitiveRecord
	{
		friend class Asn1BerRecord;

	public:
		bool getValue() const { return m_Value; };
		Asn1BooleanRecord(bool value);

	protected:
		void decodeValue(uint8_t* data) override;
		std::vector<uint8_t> encodeValue() const override;

	private:
		Asn1BooleanRecord() = default;

		bool m_Value;
	};

	class Asn1NullRecord : public Asn1PrimitiveRecord
	{
		friend class Asn1BerRecord;

	public:
		Asn1NullRecord();

	protected:
		void decodeValue(uint8_t* data) override {}
		std::vector<uint8_t> encodeValue() const override { return {}; }
	};
}
