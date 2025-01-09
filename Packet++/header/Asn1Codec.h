#pragma once

#include <string>
#include <memory>
#include <typeinfo>
#include <stdexcept>
#include "PointerVector.h"

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	/// An enum for representing ASN.1 tag class
	enum class Asn1TagClass : uint8_t
	{
		/// The Universal tag class
		Universal = 0,
		/// The Application tag class
		Application = 1,
		/// The Context-Specific tag class
		ContextSpecific = 2,
		/// The Private tag class
		Private = 3,
	};

	/// An enum for representing ASN.1 Universal tag types
	enum class Asn1UniversalTagType : uint8_t
	{
		/// The reserved identifier for the End-of-Contents marker in an indefinite length encoding
		EndOfContent = 0,
		/// The universal tag type for Boolean
		Boolean = 1,
		/// The universal tag type for Integer
		Integer = 2,
		/// The universal tag type for Bit String
		BitString = 3,
		/// The universal tag type for Octet String
		OctetString = 4,
		/// The universal tag type for Null
		Null = 5,
		/// The universal tag type for Object Identifier
		ObjectIdentifier = 6,
		/// The universal tag type for Object Descriptor
		ObjectDescriptor = 7,
		/// The universal tag type for External
		External = 8,
		/// The universal tag type for Real
		Real = 9,
		/// The universal tag type for Enumerated
		Enumerated = 10,
		/// The universal tag type for Embedded-PDV
		EmbeddedPDV = 11,
		/// The universal tag type for UTF8 String
		UTF8String = 12,
		/// The universal tag type for Relative Object Identifier
		RelativeObjectIdentifier = 13,
		/// The universal tag type for Time
		Time = 14,
		/// A reserved value
		Reserved = 15,
		/// The universal tag type Sequence
		Sequence = 16,
		/// The universal tag type for Set
		Set = 17,
		/// The universal tag type for Numeric String
		NumericString = 18,
		/// The universal tag type for Printable String
		PrintableString = 19,
		/// The universal tag type for T61String
		T61String = 20,
		/// The universal tag type for Videotex String
		VideotexString = 21,
		/// The universal tag type for IA5String
		IA5String = 22,
		/// The universal tag type for UTC time
		UTCTime = 23,
		/// The universal tag type for Generalized time
		GeneralizedTime = 24,
		/// The universal tag type for GraphicString
		GraphicString = 25,
		/// The universal tag type for VisibleString
		VisibleString = 26,
		/// The universal tag type for GeneralString
		GeneralString = 27,
		/// The universal tag type for UniversalString
		UniversalString = 28,
		/// The universal tag type for CharacterString
		CharacterString = 29,
		/// The universal tag type for BMPString
		BMPString = 30,
		/// The universal tag type for Date
		Date = 31,
		/// The universal tag type for Time of Day
		TimeOfDay = 32,
		/// The universal tag type for Date-Time
		DateTime = 33,
		/// The universal tag type for Duration
		Duration = 34,
		/// The universal tag type for Object Identifier Internationalized Resource Identifier (IRI)
		ObjectIdentifierIRI = 35,
		/// The universal tag type for Relative Object Identifier Internationalized Resource Identifier (IRI)
		RelativeObjectIdentifierIRI = 36,
		/// A non-applicable value
		NotApplicable = 255
	};

	/// @class Asn1Record
	/// Represents an ASN.1 record, as described in ITU-T Recommendation X.680:
	/// <https://www.itu.int/rec/T-REC-X.680/en>
	/// <https://en.wikipedia.org/wiki/ASN.1>
	class Asn1Record
	{
	public:
		/// A static method to decode a byte array into an Asn1Record
		/// @param data A byte array to decode
		/// @param dataLen The byte array length
		/// @param lazy Use lazy decoding, set to true by default. Lazy decoding entails delaying the decoding
		/// of the record value until it is accessed
		/// @return A smart pointer to the decoded ASN.1 record. If the byte stream is not a valid ASN.1 record
		/// an exception is thrown
		static std::unique_ptr<Asn1Record> decode(const uint8_t* data, size_t dataLen, bool lazy = true);

		/// Encode this record and convert it to a byte stream
		/// @return A vector of bytes representing the record
		std::vector<uint8_t> encode();

		/// @return The ASN.1 tag class
		Asn1TagClass getTagClass() const
		{
			return m_TagClass;
		}

		/// @return True if it's a constructed record, or false if it's a primitive record
		bool isConstructed() const
		{
			return m_IsConstructed;
		}

		/// @return The ASN.1 Universal tag type if the record is of class Universal, otherwise
		/// Asn1UniversalTagType#NotApplicable
		Asn1UniversalTagType getUniversalTagType() const;

		/// @return The ASN.1 tag type value
		uint8_t getTagType() const
		{
			return m_TagType;
		}

		/// @return The length of the record value
		size_t getValueLength() const
		{
			return m_ValueLength;
		}

		/// @return The total length of the record
		size_t getTotalLength() const
		{
			return m_TotalLength;
		}

		/// @return A string representation of the record
		std::string toString();

		/// A templated method that accepts a class derived from Asn1Record as its template argument and attempts
		/// to cast the current instance to that type
		/// @tparam Asn1RecordType The type to cast to
		/// @return A pointer to the type after casting
		template <class Asn1RecordType> Asn1RecordType* castAs()
		{
			auto result = dynamic_cast<Asn1RecordType*>(this);
			if (result == nullptr)
			{
				throw std::bad_cast();
			}
			return result;
		}

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

		static Asn1Record* decodeTagAndCreateRecord(const uint8_t* data, size_t dataLen, uint8_t& tagLen);
		uint8_t decodeLength(const uint8_t* data, size_t dataLen);
		void decodeValueIfNeeded();

		uint8_t encodeTag();
		std::vector<uint8_t> encodeLength() const;

		virtual std::vector<std::string> toStringList();

		friend class Asn1ConstructedRecord;
	};

	/// @class Asn1GenericRecord
	/// Represents a generic ASN.1 record, either of an unknown type or of a known type that doesn't
	/// have a dedicated parser yet
	class Asn1GenericRecord : public Asn1Record
	{
		friend class Asn1Record;

	public:
		/// A constructor to create a generic record
		/// @param tagClass The record tag class
		/// @param isConstructed A flag to indicate if the record is constructed or primitive
		/// @param tagType The record tag type value
		/// @param value A byte array of the tag value
		/// @param valueLen The length of the value byte array
		Asn1GenericRecord(Asn1TagClass tagClass, bool isConstructed, uint8_t tagType, const uint8_t* value,
		                  size_t valueLen);

		/// A constructor to create a generic record
		/// @param tagClass The record tag class
		/// @param isConstructed A flag to indicate if the record is constructed or primitive
		/// @param tagType The record tag type value
		/// @param value A string representing the tag value
		Asn1GenericRecord(Asn1TagClass tagClass, bool isConstructed, uint8_t tagType, const std::string& value);

		~Asn1GenericRecord() override;

		/// @return A pointer to the tag value
		const uint8_t* getValue()
		{
			decodeValueIfNeeded();
			return m_Value;
		}

	protected:
		Asn1GenericRecord() = default;

		void decodeValue(uint8_t* data, bool lazy) override;
		std::vector<uint8_t> encodeValue() const override;

	private:
		uint8_t* m_Value = nullptr;

		void init(Asn1TagClass tagClass, bool isConstructed, uint8_t tagType, const uint8_t* value, size_t valueLen);
	};

	/// @class Asn1ConstructedRecord
	/// Represents a constructed ASN.1 record, which is a record that has sub-records
	class Asn1ConstructedRecord : public Asn1Record
	{
		friend class Asn1Record;

	public:
		/// A constructor to create a constructed record
		/// @param tagClass The record tag class
		/// @param tagType The record tag type value
		/// @param subRecords A list of sub-records to assign as the record value
		explicit Asn1ConstructedRecord(Asn1TagClass tagClass, uint8_t tagType,
		                               const std::vector<Asn1Record*>& subRecords);

		/// A constructor to create a constructed record
		/// @param tagClass The record tag class
		/// @param tagType The record tag type value
		/// @param subRecords A PointerVector of sub-records to assign as the record value
		explicit Asn1ConstructedRecord(Asn1TagClass tagClass, uint8_t tagType,
		                               const PointerVector<Asn1Record>& subRecords);

		/// @return A reference to the list of sub-records. It's important to note that any modifications made to
		/// this list will directly affect the internal structure
		PointerVector<Asn1Record>& getSubRecords()
		{
			decodeValueIfNeeded();
			return m_SubRecords;
		};

	protected:
		Asn1ConstructedRecord() = default;

		void decodeValue(uint8_t* data, bool lazy) override;
		std::vector<uint8_t> encodeValue() const override;

		std::vector<std::string> toStringList() override;

		template <typename Iterator> void init(Asn1TagClass tagClass, uint8_t tagType, Iterator begin, Iterator end)
		{
			m_TagType = tagType;
			m_TagClass = tagClass;
			m_IsConstructed = true;

			size_t recordValueLength = 0;
			for (Iterator recordIter = begin; recordIter != end; ++recordIter)
			{
				auto encodedRecord = (*recordIter)->encode();
				auto copyRecord = Asn1Record::decode(encodedRecord.data(), encodedRecord.size(), false);
				m_SubRecords.pushBack(std::move(copyRecord));
				recordValueLength += encodedRecord.size();
			}

			m_ValueLength = recordValueLength;
			m_TotalLength = recordValueLength + 1 + (m_ValueLength < 128 ? 1 : 2);
		}

	private:
		PointerVector<Asn1Record> m_SubRecords;
	};

	/// @class Asn1SequenceRecord
	/// Represents an ASN.1 record with a value of type Sequence
	class Asn1SequenceRecord : public Asn1ConstructedRecord
	{
		friend class Asn1Record;

	public:
		/// A constructor to create a record of type Sequence
		/// @param subRecords A list of sub-records to assign as the record value
		explicit Asn1SequenceRecord(const std::vector<Asn1Record*>& subRecords);

		/// A constructor to create a record of type Sequence
		/// @param subRecords A PointerVector of sub-records to assign as the record value
		explicit Asn1SequenceRecord(const PointerVector<Asn1Record>& subRecords);

	private:
		Asn1SequenceRecord() = default;
	};

	/// @class Asn1SetRecord
	/// Represents an ASN.1 record with a value of type Set
	class Asn1SetRecord : public Asn1ConstructedRecord
	{
		friend class Asn1Record;

	public:
		/// A constructor to create a record of type Set
		/// @param subRecords A list of sub-records to assign as the record value
		explicit Asn1SetRecord(const std::vector<Asn1Record*>& subRecords);

		/// A constructor to create a record of type Set
		/// @param subRecords A PointerVector of sub-records to assign as the record value
		explicit Asn1SetRecord(const PointerVector<Asn1Record>& subRecords);

	private:
		Asn1SetRecord() = default;
	};

	/// @class Asn1PrimitiveRecord
	/// Represents a primitive ASN.1 record, meaning a record that doesn't have sub-records.
	/// This is an abstract class that cannot be instantiated
	class Asn1PrimitiveRecord : public Asn1Record
	{
		friend class Asn1Record;

	protected:
		Asn1PrimitiveRecord() = default;
		explicit Asn1PrimitiveRecord(Asn1UniversalTagType tagType);
	};

	/// @class Asn1IntegerRecord
	/// Represents an ASN.1 record with a value of type Integer
	class Asn1IntegerRecord : public Asn1PrimitiveRecord
	{
		friend class Asn1Record;

	public:
		/// A constructor to create a record of type Integer
		/// @param value An integer to set as the record value
		explicit Asn1IntegerRecord(uint32_t value);

		/// @return The integer value of this record
		uint32_t getValue()
		{
			decodeValueIfNeeded();
			return m_Value;
		}

	protected:
		Asn1IntegerRecord() = default;

		void decodeValue(uint8_t* data, bool lazy) override;
		std::vector<uint8_t> encodeValue() const override;

		std::vector<std::string> toStringList() override;

	private:
		uint32_t m_Value = 0;
	};

	/// @class Asn1EnumeratedRecord
	/// Represents an ASN.1 record with a value of type Enumerated
	class Asn1EnumeratedRecord : public Asn1IntegerRecord
	{
		friend class Asn1Record;

	public:
		/// A constructor to create a record of type Enumerated
		/// @param value An integer to set as the record value
		explicit Asn1EnumeratedRecord(uint32_t value);

	private:
		Asn1EnumeratedRecord() = default;
	};

	/// @class Asn1OctetStringRecord
	/// Represents an ASN.1 record with a value of type Octet String
	class Asn1OctetStringRecord : public Asn1PrimitiveRecord
	{
		friend class Asn1Record;

	public:
		/// A constructor to create a record of type Octet String from a printable value
		/// @param value A string to set as the record value
		explicit Asn1OctetStringRecord(const std::string& value);

		/// A constructor to create a record of type Octet String from a non-printable value
		/// @param value A byte array to set as the record value
		/// @param valueLength The length of the byte array
		explicit Asn1OctetStringRecord(const uint8_t* value, size_t valueLength);

		/// @return The string value of this record
		std::string getValue()
		{
			decodeValueIfNeeded();
			return m_Value;
		};

	protected:
		void decodeValue(uint8_t* data, bool lazy) override;
		std::vector<uint8_t> encodeValue() const override;

		std::vector<std::string> toStringList() override;

	private:
		std::string m_Value;
		bool m_IsPrintable = true;

		Asn1OctetStringRecord() = default;
	};

	/// @class Asn1BooleanRecord
	/// Represents an ASN.1 record with a value of type Boolean
	class Asn1BooleanRecord : public Asn1PrimitiveRecord
	{
		friend class Asn1Record;

	public:
		/// A constructor to create a record of type Boolean
		/// @param value A boolean to set as the record value
		explicit Asn1BooleanRecord(bool value);

		/// @return The boolean value of this record
		bool getValue()
		{
			decodeValueIfNeeded();
			return m_Value;
		};

	protected:
		void decodeValue(uint8_t* data, bool lazy) override;
		std::vector<uint8_t> encodeValue() const override;

		std::vector<std::string> toStringList() override;

	private:
		Asn1BooleanRecord() = default;

		bool m_Value = false;
	};

	/// @class Asn1NullRecord
	/// Represents an ASN.1 record with a value of type Null
	class Asn1NullRecord : public Asn1PrimitiveRecord
	{
		friend class Asn1Record;

	public:
		/// A constructor to create a record of type Null
		Asn1NullRecord();

	protected:
		void decodeValue(uint8_t* data, bool lazy) override
		{}
		std::vector<uint8_t> encodeValue() const override
		{
			return {};
		}
	};
}  // namespace pcpp
