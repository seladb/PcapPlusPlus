#pragma once

#include <string>
#include <memory>
#include <typeinfo>
#include <stdexcept>
#include <sstream>
#include <chrono>
#include <bitset>
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
		template <typename T>
		using EnableIfUnsignedIntegral =
		    std::enable_if_t<std::is_integral<T>::value && std::is_unsigned<T>::value, int>;

		/// A constructor to create a record of type Integer
		/// @param value An integer to set as the record value
		explicit Asn1IntegerRecord(uint64_t value);

		/// A constructor to create a record of type Integer
		/// @param value An integer represented as a hex stream to set as the record value
		/// @throw std::invalid_argument if the value isn't a valid hex stream
		explicit Asn1IntegerRecord(const std::string& value);

		/// @return The integer value of this record
		/// @throw std::invalid_argument if the value doesn't fit the requested integer size
		template <typename T, EnableIfUnsignedIntegral<T> = 0> T getIntValue()
		{
			decodeValueIfNeeded();
			return m_Value.getInt<T>();
		}

		/// @deprecated This method is deprecated, please use getIntValue()
		PCPP_DEPRECATED("Use getIntValue instead")
		uint32_t getValue()
		{
			return getIntValue<uint32_t>();
		}

		/// @return A hex string representation of the record value
		std::string getValueAsString()
		{
			decodeValueIfNeeded();
			return m_Value.toString();
		}

	protected:
		Asn1IntegerRecord() = default;

		void decodeValue(uint8_t* data, bool lazy) override;
		std::vector<uint8_t> encodeValue() const override;

		std::vector<std::string> toStringList() override;

	private:
		class BigInt
		{
		public:
			BigInt() = default;

			template <typename T, EnableIfUnsignedIntegral<T> = 0> explicit BigInt(T value)
			{
				m_Value = initFromInt(value);
			}

			explicit BigInt(const std::string& value);
			BigInt(const BigInt& other);

			template <typename T, EnableIfUnsignedIntegral<T> = 0> BigInt& operator=(T value)
			{
				m_Value = initFromInt(value);
				return *this;
			}
			BigInt& operator=(const std::string& value);
			size_t size() const;

			template <typename T, EnableIfUnsignedIntegral<T> = 0> T getInt() const
			{
				if (!canFit<T>())
				{
					throw std::overflow_error("Value cannot fit into requested int type");
				}

				std::stringstream sstream;
				sstream << std::hex << m_Value;

				uint64_t result;
				sstream >> result;
				return static_cast<T>(result);
			}

			template <typename T, EnableIfUnsignedIntegral<T> = 0> bool canFit() const
			{
				return sizeof(T) >= (m_Value.size() + 1) / 2;
			}

			std::string toString() const;
			std::vector<uint8_t> toBytes() const;

		private:
			std::string m_Value;

			static std::string initFromString(const std::string& value);

			template <typename T, EnableIfUnsignedIntegral<T> = 0> static std::string initFromInt(T value)
			{
				std::stringstream ss;
				ss << std::hex << static_cast<uint64_t>(value);
				return ss.str();
			}
		};

		BigInt m_Value;
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

	/// @class Asn1StringRecord
	/// An abstract class for representing ASN.1 string records.
	/// This class is not instantiable, users should use the derived classes
	template <Asn1UniversalTagType TagType> class Asn1StringRecord : public Asn1PrimitiveRecord
	{
	public:
		/// @return The string value of this record
		std::string getValue()
		{
			decodeValueIfNeeded();
			return m_Value;
		};

	protected:
		Asn1StringRecord() : Asn1PrimitiveRecord(TagType)
		{}

		explicit Asn1StringRecord(const std::string& value) : Asn1PrimitiveRecord(TagType), m_Value(value)
		{
			m_ValueLength = value.size();
			m_TotalLength = m_ValueLength + 2;
		}

		void decodeValue(uint8_t* data, bool lazy) override
		{
			m_Value = std::string(reinterpret_cast<char*>(data), m_ValueLength);
		}
		std::vector<uint8_t> encodeValue() const override
		{
			return { m_Value.begin(), m_Value.end() };
		}

		std::vector<std::string> toStringList() override
		{
			return { Asn1Record::toStringList().front() + ", Value: " + getValue() };
		}

		std::string m_Value;
	};

	/// @class Asn1OctetStringRecord
	/// Represents an ASN.1 record with a value of type Octet String
	class Asn1OctetStringRecord : public Asn1StringRecord<Asn1UniversalTagType::OctetString>
	{
		friend class Asn1Record;

	public:
		using Asn1StringRecord::Asn1StringRecord;

		/// A constructor to create a record of type Octet String from a non-printable value
		/// @param value A byte array to set as the record value
		/// @param valueLength The length of the byte array
		explicit Asn1OctetStringRecord(const uint8_t* value, size_t valueLength);

		/// A constructor to create a record from a printable string value
		/// @param value A string to set as the record value
		explicit Asn1OctetStringRecord(const std::string& value) : Asn1StringRecord(value)
		{}

	protected:
		void decodeValue(uint8_t* data, bool lazy) override;
		std::vector<uint8_t> encodeValue() const override;

	private:
		Asn1OctetStringRecord() = default;

		bool m_IsPrintable = true;
	};

	/// @class Asn1UTF8StringRecord
	/// Represents an ASN.1 record with a value of type UTF8 String
	class Asn1UTF8StringRecord : public Asn1StringRecord<Asn1UniversalTagType::UTF8String>
	{
		friend class Asn1Record;

	public:
		/// A constructor to create a record from a printable string value
		/// @param value A string to set as the record value
		explicit Asn1UTF8StringRecord(const std::string& value) : Asn1StringRecord(value)
		{}

	private:
		Asn1UTF8StringRecord() = default;
	};

	/// @class Asn1PrintableStringRecord
	/// Represents an ASN.1 record with a value of type Printable String
	class Asn1PrintableStringRecord : public Asn1StringRecord<Asn1UniversalTagType::PrintableString>
	{
		friend class Asn1Record;

	public:
		/// A constructor to create a record from a printable string value
		/// @param value A string to set as the record value
		explicit Asn1PrintableStringRecord(const std::string& value) : Asn1StringRecord(value)
		{}

	private:
		Asn1PrintableStringRecord() = default;
	};

	/// @class Asn1IA5StringRecord
	/// Represents an ASN.1 record with a value of type IA5 String
	class Asn1IA5StringRecord : public Asn1StringRecord<Asn1UniversalTagType::IA5String>
	{
		friend class Asn1Record;

	public:
		/// A constructor to create a record from a printable string value
		/// @param value A string to set as the record value
		explicit Asn1IA5StringRecord(const std::string& value) : Asn1StringRecord(value)
		{}

	private:
		Asn1IA5StringRecord() = default;
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

	/// @class Asn1ObjectIdentifier
	/// Represents an ASN.1 Object Identifier (OID).
	class Asn1ObjectIdentifier
	{
		friend class Asn1ObjectIdentifierRecord;

	public:
		/// Construct an OID from an encoded byte buffer
		/// @param[in] data The byte buffer of the encoded OID data
		/// @param[in] dataLen The byte buffer size
		explicit Asn1ObjectIdentifier(const uint8_t* data, size_t dataLen);

		/// Construct an OID from its string representation (e.g., "1.2.840.113549").
		/// @param[in] oidString The string representation of the OID
		/// @throws std::invalid_argument if the string is malformed or contains invalid components
		explicit Asn1ObjectIdentifier(const std::string& oidString);

		/// @return A const reference to the internal vector of components
		const std::vector<uint32_t>& getComponents() const
		{
			return m_Components;
		}

		/// Equality operator to compare two OIDs
		/// @param[in] other Another Asn1ObjectIdentifier instance
		bool operator==(const Asn1ObjectIdentifier& other) const
		{
			return m_Components == other.m_Components;
		}

		/// Inequality operator to compare two OIDs
		/// @param[in] other Another Asn1ObjectIdentifier instance
		bool operator!=(const Asn1ObjectIdentifier& other) const
		{
			return m_Components != other.m_Components;
		}

		/// Convert the OID to its string representation (e.g., "1.2.840.113549")
		/// @return A string representing the OID
		std::string toString() const;

		/// Encode the OID to a byte buffer
		/// @return A byte buffer containing the encoded OID value
		std::vector<uint8_t> toBytes() const;

		friend std::ostream& operator<<(std::ostream& os, const Asn1ObjectIdentifier& oid)
		{
			return os << oid.toString();
		}

	protected:
		Asn1ObjectIdentifier() = default;

	private:
		std::vector<uint32_t> m_Components;
	};

	/// @class Asn1ObjectIdentifierRecord
	/// Represents an ASN.1 record with a value of type ObjectIdentifier
	class Asn1ObjectIdentifierRecord : public Asn1PrimitiveRecord
	{
		friend class Asn1Record;

	public:
		/// A constructor to create a ObjectIdentifier record
		/// @param[in] value The ObjectIdentifier (OID) to set as the record value
		explicit Asn1ObjectIdentifierRecord(const Asn1ObjectIdentifier& value);

		/// @return The OID value of this record
		const Asn1ObjectIdentifier& getValue()
		{
			decodeValueIfNeeded();
			return m_Value;
		}

	protected:
		void decodeValue(uint8_t* data, bool lazy) override;
		std::vector<uint8_t> encodeValue() const override;

		std::vector<std::string> toStringList() override;

	private:
		Asn1ObjectIdentifier m_Value;

		Asn1ObjectIdentifierRecord() = default;
	};

	/// @class Asn1TimeRecord
	/// An abstract class for representing ASN.1 time records (UTCTime and GeneralizedTime).
	/// This class is not instantiable, users should use either Asn1UtcTimeRecord or Asn1GeneralizedTimeRecord
	class Asn1TimeRecord : public Asn1PrimitiveRecord
	{
	public:
		/// @param[in] timezone A timezone string - should be in the format of "Z" for UTC or +=HHMM for other
		/// timezones. The default value is UTC
		/// @return The time-point value of this record
		/// @throws std::invalid_argument if timezone is not in the correct format
		std::chrono::system_clock::time_point getValue(const std::string& timezone = "Z")
		{
			decodeValueIfNeeded();
			return adjustTimezones(m_Value, "Z", timezone);
		};

		/// @param[in] format Requested value format
		/// @param[in] timezone A timezone string - should be in the format of "Z" for UTC or +=HHMM for other
		/// timezones. The default value is UTC
		/// @param[in] includeMilliseconds Should Include milliseconds in the returned string
		/// @return The value as string
		/// @throws std::invalid_argument if timezone is not in the correct format
		std::string getValueAsString(const std::string& format = "%Y-%m-%d %H:%M:%S", const std::string& timezone = "Z",
		                             bool includeMilliseconds = false);

	protected:
		Asn1TimeRecord() = default;
		explicit Asn1TimeRecord(Asn1UniversalTagType tagType, const std::chrono::system_clock::time_point& value,
		                        const std::string& timezone);

		std::chrono::system_clock::time_point m_Value;

		std::vector<std::string> toStringList() override;

		static void validateTimezone(const std::string& timezone);
		static std::chrono::system_clock::time_point adjustTimezones(const std::chrono::system_clock::time_point& value,
		                                                             const std::string& fromTimezone,
		                                                             const std::string& toTimezone);
	};

	/// @class Asn1UtcTimeRecord
	/// Represents an ASN.1 record with a value of type UTCTime
	class Asn1UtcTimeRecord : public Asn1TimeRecord
	{
		friend class Asn1Record;

	public:
		/// A constructor to create a record of type UTC time
		/// @param[in] value A time-point to set as the record value
		/// @param[in] withSeconds Should write the ASN.1 record with second precision. The default is true
		explicit Asn1UtcTimeRecord(const std::chrono::system_clock::time_point& value, bool withSeconds = true);

	protected:
		void decodeValue(uint8_t* data, bool lazy) override;
		std::vector<uint8_t> encodeValue() const override;

	private:
		Asn1UtcTimeRecord() = default;
		bool m_WithSeconds = true;
	};

	/// @class Asn1GeneralizedTimeRecord
	/// Represents an ASN.1 record with a value of type GeneralizedTime
	class Asn1GeneralizedTimeRecord : public Asn1TimeRecord
	{
		friend class Asn1Record;

	public:
		/// A constructor to create a record of type generalized time
		/// @param[in] value A time-point to set as the record value
		/// @param[in] timezone The time-point's timezone - should be in the format of "Z" for UTC or +=HHMM for other
		/// timezones. If not provided it's assumed the timezone is UTC
		/// @throws std::invalid_argument if timezone is not in the correct format
		explicit Asn1GeneralizedTimeRecord(const std::chrono::system_clock::time_point& value,
		                                   const std::string& timezone = "Z");

	protected:
		void decodeValue(uint8_t* data, bool lazy) override;
		std::vector<uint8_t> encodeValue() const override;

	private:
		Asn1GeneralizedTimeRecord() = default;
		std::string m_Timezone;
	};

	/// @class Asn1BitStringRecord
	/// Represents an ASN.1 record with a value of type BitString
	class Asn1BitStringRecord : public Asn1PrimitiveRecord
	{
		friend class Asn1Record;

	public:
		/// A constructor to create a record of type BitString
		/// @param value A bit string to set as the record value
		/// @throw std::invalid_argument if the string is not a valid bit string
		explicit Asn1BitStringRecord(const std::string& value);

		/// @return The bit string value of this record
		std::string getValue()
		{
			decodeValueIfNeeded();
			return m_Value.toString();
		};

	protected:
		void decodeValue(uint8_t* data, bool lazy) override;
		std::vector<uint8_t> encodeValue() const override;

		std::vector<std::string> toStringList() override;

	private:
		class BitSet
		{
		public:
			BitSet() = default;
			explicit BitSet(const std::string& value);
			BitSet(const uint8_t* data, size_t numBits);

			BitSet& operator=(const std::string& value);

			size_t sizeInBytes() const;
			std::string toString() const;
			std::vector<uint8_t> toBytes() const;
			size_t getNumBits() const
			{
				return m_NumBits;
			}

		private:
			void initFromString(const std::string& value);

			std::vector<std::bitset<8>> m_Data;
			size_t m_NumBits = 0;
		};

		Asn1BitStringRecord() = default;

		BitSet m_Value;
	};
}  // namespace pcpp
