#pragma once

#include <string>
#include <memory>
#include "PointerVector.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
	/**
	 * An enum for representing ASN.1 tag class
	 */
	enum class Asn1TagClass : uint8_t
	{
		/** The Universal tag class */
		Universal,
		/** The Application tag class */
		Application,
		/** The Context-Specific tag class */
		ContextSpecific,
		/** The Private tag class */
		Private
	};

	/**
	 * An enum for representing ASN.1 Universal tag types
	 */
	enum class Asn1UniversalTagType : uint8_t
	{
		/** The reserved identifier for the End-of-Contents marker in an indefinite length encoding */
		EndOfContent = 0,
		/** The universal tag type for Boolean */
		Boolean = 1,
		/** The universal tag type for Integer */
		Integer = 2,
		/** The universal tag type for Bit String */
		BitString = 3,
		/** The universal tag type for Octet String */
		OctetString = 4,
		/** The universal tag type for Null */
		Null = 5,
		/** The universal tag type for Object Identifier */
		ObjectIdentifier = 6,
		/** The universal tag type for Object Descriptor */
		ObjectDescriptor = 7,
		/** The universal tag type for External */
		External = 8,
		/** The universal tag type for Real */
		Real = 9,
		/** The universal tag type for Enumerated */
		Enumerated = 10,
		/** The universal tag type for Embedded-PDV */
		EmbeddedPDV = 11,
		/** The universal tag type for UTF8 String */
		UTF8String = 12,
		/** The universal tag type for Relative Object Identifier */
		RelativeObjectIdentifier = 13,
		/** The universal tag type for Time */
		Time = 14,
		/** A reserved value */
		Reserved = 15,
		/** The universal tag type Sequence */
		Sequence = 16,
		/** The universal tag type for Set */
		Set = 17,
		/** The universal tag type for Numeric String */
		NumericString = 18,
		/** The universal tag type for Printable String */
		PrintableString = 19,
		/** The universal tag type for T61String */
		T61String = 20,
		/** The universal tag type for Videotex String */
		VideotexString = 21,
		/** The universal tag type for IA5String */
		IA5String = 22,
		/** The universal tag type for UTC time */
		UTCTime = 23,
		/** The universal tag type for Generalized time */
		GeneralizedTime = 24,
		/** The universal tag type for GraphicString */
		GraphicString = 25,
		/** The universal tag type for VisibleString */
		VisibleString = 26,
		/** The universal tag type for GeneralString */
		GeneralString = 27,
		/** The universal tag type for UniversalString */
		UniversalString = 28,
		/** The universal tag type for CharacterString */
		CharacterString = 29,
		/** The universal tag type for BMPString */
		BMPString = 30,
		/** The universal tag type for Date */
		Date = 31,
		/** The universal tag type for Time of Day */
		TimeOfDay = 32,
		/** The universal tag type for Date-Time */
		DateTime = 33,
		/** The universal tag type for Duration */
		Duration = 34,
		/** The universal tag type for Object Identifier Internationalized Resource Identifier (IRI) */
		ObjectIdentifierIRI = 35,
		/** The universal tag type for Relative Object Identifier Internationalized Resource Identifier (IRI) */
		RelativeObjectIdentifierIRI = 36,
		/** A non-applicable value */
		NotApplicable = 255
	};

	/**
	 * @class Asn1Record
	 * This class represents an ASN.1 record, as described in ITU-T Recommendation X.680
	 */
	class Asn1Record
	{
	public:
		size_t getValueLength() const { return m_ValueLength; }
		size_t getTotalLength() const { return m_TotalLength; }

		Asn1TagClass getTagClass() const { return m_TagClass; }
		bool isConstructed() const { return m_IsConstructed; }
		Asn1UniversalTagType getAsn1UniversalTagType() const;
		uint8_t getTagType() const { return m_TagType; }

		template <class Asn1RecordType>
		Asn1RecordType* castAs()
		{
			auto result = dynamic_cast<Asn1RecordType*>(this);
			if (result == nullptr)
			{
				throw std::runtime_error("Cast failed, instance isn't of the requested type");
			}
			return result;
		}

		std::vector<uint8_t> encode();

		static std::unique_ptr<Asn1Record> decode(const uint8_t* data, size_t dataLen, bool lazy = true);

		virtual ~Asn1Record() = default;

	protected:
		Asn1TagClass m_TagClass = Asn1TagClass::Universal;
		bool m_IsConstructed = false;
		uint8_t m_TagType = 0;

		size_t m_ValueLength = 0;
		size_t m_TotalLength = 0;

		uint8_t* m_EncodedValue = nullptr;

		Asn1Record() = default;

		static Asn1Record* decodeInternal(const uint8_t* data, size_t dataLen, bool lazy);

		virtual void decodeValue(uint8_t* data, bool lazy) = 0;
		virtual std::vector<uint8_t> encodeValue() const = 0;

		static Asn1Record* decodeTagAndCreateRecord(const uint8_t* data, size_t dataLen, int& tagLen);
		int decodeLength(const uint8_t* data, size_t dataLen);
		void decodeValueIfNeeded();

		uint8_t encodeTag();
		std::vector<uint8_t> encodeLength() const;
	};

	/**
	 * @class Asn1GenericRecord
	 * This class represents a generic ASN.1 record, either of an unknown type or of a known type that doesn't
	 * have a parser yet
	 */
	class Asn1GenericRecord : public Asn1Record
	{
		friend class Asn1Record;

	public:
		Asn1GenericRecord(Asn1TagClass tagClass, bool isConstructed, uint8_t tagType, const uint8_t* value, size_t valueLen);
		~Asn1GenericRecord() override;
		const uint8_t* getValue() { decodeValueIfNeeded(); return m_Value; }

	protected:
		Asn1GenericRecord() = default;

		void decodeValue(uint8_t* data, bool lazy) override;
		std::vector<uint8_t> encodeValue() const override;

	private:
		uint8_t* m_Value = nullptr;
		bool m_FreeValueOnDestruction = false;
	};

	class Asn1ConstructedRecord : public Asn1Record
	{
		friend class Asn1Record;

	public:
		Asn1ConstructedRecord(Asn1TagClass tagClass, uint8_t tagType, const std::vector<Asn1Record*>& subRecords);
		PointerVector<Asn1Record>& getSubRecords() { decodeValueIfNeeded(); return m_SubRecords; };

	protected:
		Asn1ConstructedRecord() = default;

		void decodeValue(uint8_t* data, bool lazy) override;
		std::vector<uint8_t> encodeValue() const override;

	private:
		PointerVector<Asn1Record> m_SubRecords;
	};

	class Asn1SequenceRecord : public Asn1ConstructedRecord
	{
		friend class Asn1Record;

	public:
		explicit Asn1SequenceRecord(const std::vector<Asn1Record*>& subRecords);

	private:
		Asn1SequenceRecord() = default;
	};

	class Asn1SetRecord : public Asn1ConstructedRecord
	{
		friend class Asn1Record;

	public:
		explicit Asn1SetRecord(const std::vector<Asn1Record*>& subRecords);

	private:
		Asn1SetRecord() = default;
	};

	class Asn1PrimitiveRecord : public Asn1Record
	{
		friend class Asn1Record;

	protected:
		Asn1PrimitiveRecord() = default;
		explicit Asn1PrimitiveRecord(uint8_t tagType);
	};

	class Asn1IntegerRecord : public Asn1PrimitiveRecord
	{
		friend class Asn1Record;

	public:
		explicit Asn1IntegerRecord(uint32_t value);
		uint32_t getValue() { decodeValueIfNeeded(); return m_Value; }

	protected:
		Asn1IntegerRecord() = default;

		void decodeValue(uint8_t* data, bool lazy) override;
		std::vector<uint8_t> encodeValue() const override;

	private:
		uint32_t m_Value = 0;
	};

	class Asn1EnumeratedRecord : public Asn1IntegerRecord
	{
		friend class Asn1Record;

	public:
		explicit Asn1EnumeratedRecord(uint32_t value);

	private:
		Asn1EnumeratedRecord() = default;
	};

	class Asn1OctetStringRecord : public Asn1PrimitiveRecord
	{
		friend class Asn1Record;

	public:
		explicit Asn1OctetStringRecord(const std::string& value);
		std::string getValue() { decodeValueIfNeeded(); return m_Value; };

	protected:
		void decodeValue(uint8_t* data, bool lazy) override;
		std::vector<uint8_t> encodeValue() const override;

	private:
		std::string m_Value;

		Asn1OctetStringRecord() = default;

	};

	class Asn1BooleanRecord : public Asn1PrimitiveRecord
	{
		friend class Asn1Record;

	public:
		bool getValue() { decodeValueIfNeeded(); return m_Value; };
		explicit Asn1BooleanRecord(bool value);

	protected:
		void decodeValue(uint8_t* data, bool lazy) override;
		std::vector<uint8_t> encodeValue() const override;

	private:
		Asn1BooleanRecord() = default;

		bool m_Value = false;
	};

	class Asn1NullRecord : public Asn1PrimitiveRecord
	{
		friend class Asn1Record;

	public:
		Asn1NullRecord();

	protected:
		void decodeValue(uint8_t* data, bool lazy) override {}
		std::vector<uint8_t> encodeValue() const override { return {}; }
	};
}
