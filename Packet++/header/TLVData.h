#pragma once

#include "Layer.h"
#include "IpAddress.h"
#include <string.h>

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
	/**
	 * @class TLVRecord
	 * A wrapper class for a Type-Length-Value (TLV) record. This class does not create or modify TLV records, but
	 * rather serves as a wrapper and provides useful methods for retrieving data from them. This class has several
	 * abstract methods that should be implemented in derived classes. These methods are for record length value
	 * calculation (the 'L' in TLV) which is implemented differently in different protocols
	 */
	template <typename TRecType, typename TRecLen> class TLVRecord
	{
	protected:
		/** A struct representing the TLV construct */
		struct TLVRawData
		{
			/** Record type */
			TRecType recordType;
			/** Record length in bytes */
			TRecLen recordLen;
			/** Record value (variable size) */
			uint8_t recordValue[];
		};

		TLVRawData* m_Data;

	public:
		/**
		 * A c'tor for this class that gets a pointer to the TLV record raw data (byte array)
		 * @param[in] recordRawData A pointer to the TLV record raw data
		 */
		TLVRecord(uint8_t* recordRawData)
		{
			assign(recordRawData);
		}

		/**
		 * A copy c'tor for this class. This copy c'tor doesn't copy the TLV data, but only the pointer to it,
		 * which means that after calling it both the old and the new instance will point to the same TLV raw data
		 * @param[in] other The TLVRecord instance to copy from
		 */
		TLVRecord(const TLVRecord& other)
		{
			m_Data = other.m_Data;
		}

		/**
		 * A d'tor for this class, currently does nothing
		 */
		virtual ~TLVRecord() = default;

		/**
		 * Assign a pointer to the TLV record raw data (byte array)
		 * @param[in] recordRawData A pointer to the TLV record raw data
		 */
		void assign(uint8_t* recordRawData)
		{
			m_Data = reinterpret_cast<TLVRawData*>(recordRawData);
		}

		/**
		 * Check if a pointer can be assigned to the TLV record data
		 * @param[in] recordRawData A pointer to the TLV record raw data
		 * @param[in] tlvDataLen The size of the TLV record raw data
		 * @return True if data is valid and can be assigned
		 */
		static bool canAssign(const uint8_t* recordRawData, size_t tlvDataLen)
		{
			return recordRawData != nullptr &&
			       tlvDataLen >= (sizeof(TLVRawData::recordType) + sizeof(TLVRawData::recordLen));
		}

		/**
		 * Overload of the assignment operator. This operator doesn't copy the TLV data, but rather copies the pointer
		 * to it, which means that after calling it both the old and the new instance will point to the same TLV raw
		 * data
		 * @param[in] other The TLVRecord instance to assign
		 */
		TLVRecord& operator=(const TLVRecord& other)
		{
			m_Data = other.m_Data;
			return *this;
		}

		/**
		 * Overload of the equality operator. Two record are equal if both of them point to the same data, or if they
		 * point to different data but their total size is equal and the raw data they both contain is similar.
		 * @param[in] rhs The object to compare to
		 * @return True if both objects are equal, false otherwise
		 */
		bool operator==(const TLVRecord& rhs) const
		{
			if (m_Data == rhs.m_Data)
				return true;

			if (getTotalSize() != rhs.getTotalSize())
				return false;

			if (isNull() || ((TLVRecord&)rhs).isNull())
				return false;

			return (memcmp(m_Data, rhs.m_Data, getTotalSize()) == 0);
		}

		/**
		 * Overload of the not equal operator.
		 * @param[in] rhs The object to compare to
		 * @return True if objects are not equal, false otherwise
		 */
		bool operator!=(const TLVRecord& rhs) const
		{
			return !operator==(rhs);
		}

		/**
		 * @return The type field of the record (the 'T' in __Type__-Length-Value)
		 */
		TRecType getType() const
		{
			if (m_Data == nullptr)
				return 0;

			return m_Data->recordType;
		}

		/**
		 * @return A pointer to the value of the record as byte array (the 'V' in Type-Length- __Value__)
		 */
		uint8_t* getValue() const
		{
			if (m_Data == nullptr)
				return nullptr;

			return m_Data->recordValue;
		}

		/**
		 * @return True if the TLV record raw data is nullptr, false otherwise
		 */
		bool isNull() const
		{
			return (m_Data == nullptr);
		}

		/**
		 * @return True if the TLV record raw data is not nullptr, false otherwise
		 */
		bool isNotNull() const
		{
			return (m_Data != nullptr);
		}

		/**
		 * @return A pointer to the TLV record raw data byte stream
		 */
		uint8_t* getRecordBasePtr() const
		{
			return reinterpret_cast<uint8_t*>(m_Data);
		}

		/**
		 * Free the memory of the TLV record raw data
		 */
		void purgeRecordData()
		{
			if (!isNull())
			{
				delete[] m_Data;
				m_Data = nullptr;
			}
		}

		/**
		 * A templated method to retrieve the record data as a certain type T. For example, if record data is 4B long
		 * (integer) then this method should be used as getValueAs<int>() and it will return the record data as an
		 * integer.<BR> Notice this return value is a copy of the data, not a pointer to the actual data
		 * @param[in] offset The offset in the record data to start reading the value from. Useful for cases when you
		 * want to read some of the data that doesn't start at offset 0. This is an optional parameter and the default
		 * value is 0, meaning start reading the value at the beginning of the record data
		 * @return The record data as type T
		 */
		template <typename T> T getValueAs(size_t offset = 0) const
		{
			if (getDataSize() - offset < sizeof(T))
				return 0;

			T result;
			memcpy(&result, m_Data->recordValue + offset, sizeof(T));
			return result;
		}

		/**
		 * A templated method to copy data of type T into the TLV record data. For example: if record data is 4[Bytes]
		 * long use this method with \<int\> to set an integer value into the record data: setValue<int>(num)
		 * @param[in] newValue The value of type T to copy to the record data
		 * @param[in] valueOffset An optional parameter that specifies where to start setting the record data (default
		 * set to 0). For example: if record data is 20 bytes long and you only need to set the 4 last bytes as integer
		 * then use this method like this: setValue<int>(num, 16)
		 * @return True if value was set successfully or false if the size of T is larger than the record data size
		 */
		template <typename T> bool setValue(T newValue, int valueOffset = 0)
		{
			if (getDataSize() < sizeof(T))
				return false;

			memcpy(m_Data->recordValue + valueOffset, &newValue, sizeof(T));
			return true;
		}

		/**
		 * @return The total size of the TLV record (in bytes)
		 */
		virtual size_t getTotalSize() const = 0;

		/**
		 * @return The size of the record value (meaning the size of the 'V' part in TLV)
		 */
		virtual size_t getDataSize() const = 0;
	};

	/**
	 * @class TLVRecordReader
	 * A class for reading TLV records data out of a byte stream. This class contains helper methods for retrieving and
	 * counting TLV records. This is a template class that expects template argument class derived from TLVRecord.
	 */
	template <typename TLVRecordType> class TLVRecordReader
	{
	private:
		mutable size_t m_RecordCount;

	public:
		/**
		 * A default c'tor for this class
		 */
		TLVRecordReader()
		{
			m_RecordCount = static_cast<size_t>(-1);
		}

		/**
		 * A default copy c'tor for this class
		 */
		TLVRecordReader(const TLVRecordReader& other)
		{
			m_RecordCount = other.m_RecordCount;
		}

		/**
		 * A d'tor for this class which currently does nothing
		 */
		virtual ~TLVRecordReader() = default;

		/**
		 * Overload of the assignment operator for this class
		 * @param[in] other The TLVRecordReader instance to assign
		 */
		TLVRecordReader& operator=(const TLVRecordReader& other)
		{
			m_RecordCount = other.m_RecordCount;
			return *this;
		}

		/**
		 * Get the first TLV record out of a byte stream
		 * @param[in] tlvDataBasePtr A pointer to the TLV data byte stream
		 * @param[in] tlvDataLen The TLV data byte stream length
		 * @return An instance of type TLVRecordType that contains the first TLV record. If tlvDataBasePtr is nullptr or
		 * tlvDataLen is zero the returned TLVRecordType instance will be logically null, meaning
		 * TLVRecordType.isNull() will return true
		 */
		TLVRecordType getFirstTLVRecord(uint8_t* tlvDataBasePtr, size_t tlvDataLen) const
		{
			TLVRecordType resRec(nullptr);  // for NRVO optimization
			if (!TLVRecordType::canAssign(tlvDataBasePtr, tlvDataLen))
				return resRec;

			resRec.assign(tlvDataBasePtr);
			// resRec pointer is out-bounds of the TLV records memory
			if (resRec.getRecordBasePtr() + resRec.getTotalSize() > tlvDataBasePtr + tlvDataLen)
				resRec.assign(nullptr);

			// check if there are records at all and the total size is not zero
			if (!resRec.isNull() && (tlvDataLen == 0 || resRec.getTotalSize() == 0))
				resRec.assign(nullptr);

			return resRec;
		}

		/**
		 * Get a TLV record that follows a given TLV record in a byte stream
		 * @param[in] record A given TLV record
		 * @param[in] tlvDataBasePtr A pointer to the TLV data byte stream
		 * @param[in] tlvDataLen The TLV data byte stream length
		 * @return An instance of type TLVRecordType that wraps the record following the record given as input. If the
		 * input record.isNull() is true or if the next record is out of bounds of the byte stream, a logical null
		 * instance of TLVRecordType will be returned, meaning TLVRecordType.isNull() will return true
		 */
		TLVRecordType getNextTLVRecord(TLVRecordType& record, const uint8_t* tlvDataBasePtr, size_t tlvDataLen) const
		{
			TLVRecordType resRec(nullptr);  // for NRVO optimization

			if (record.isNull())
				return resRec;

			if (!TLVRecordType::canAssign(record.getRecordBasePtr() + record.getTotalSize(),
			                              tlvDataBasePtr - record.getRecordBasePtr() + tlvDataLen -
			                                  record.getTotalSize()))
				return resRec;

			resRec.assign(record.getRecordBasePtr() + record.getTotalSize());

			if (resRec.getTotalSize() == 0)
				resRec.assign(nullptr);

			// resRec pointer is out-bounds of the TLV records memory
			if ((resRec.getRecordBasePtr() - tlvDataBasePtr) < 0)
				resRec.assign(nullptr);

			// resRec pointer is out-bounds of the TLV records memory
			if (!resRec.isNull() && resRec.getRecordBasePtr() + resRec.getTotalSize() > tlvDataBasePtr + tlvDataLen)
				resRec.assign(nullptr);

			return resRec;
		}

		/**
		 * Search for the first TLV record that corresponds to a given record type (the 'T' in __Type__-Length-Value)
		 * @param[in] recordType The record type to search for
		 * @param[in] tlvDataBasePtr A pointer to the TLV data byte stream
		 * @param[in] tlvDataLen The TLV data byte stream length
		 * @return An instance of type TLVRecordType that contains the result record. If record was not found a logical
		 * null instance of TLVRecordType will be returned, meaning TLVRecordType.isNull() will return true
		 */
		TLVRecordType getTLVRecord(uint32_t recordType, uint8_t* tlvDataBasePtr, size_t tlvDataLen) const
		{
			TLVRecordType curRec = getFirstTLVRecord(tlvDataBasePtr, tlvDataLen);
			while (!curRec.isNull())
			{
				if (curRec.getType() == recordType)
				{
					return curRec;
				}

				curRec = getNextTLVRecord(curRec, tlvDataBasePtr, tlvDataLen);
			}

			curRec.assign(nullptr);
			return curRec;  // for NRVO optimization
		}

		/**
		 * Get the TLV record count in a given TLV data byte stream. For efficiency purposes the count is being cached
		 * so only the first call to this method will go over all the TLV records, while all consequent calls will
		 * return the cached number. This implies that if there is a change in the number of records, it's the user's
		 * responsibility to call changeTLVRecordCount() with the record count change
		 * @param[in] tlvDataBasePtr A pointer to the TLV data byte stream
		 * @param[in] tlvDataLen The TLV data byte stream length
		 * @return The TLV record count
		 */
		size_t getTLVRecordCount(uint8_t* tlvDataBasePtr, size_t tlvDataLen) const
		{
			if (m_RecordCount != static_cast<size_t>(-1))
				return m_RecordCount;

			m_RecordCount = 0;
			TLVRecordType curRec = getFirstTLVRecord(tlvDataBasePtr, tlvDataLen);
			while (!curRec.isNull())
			{
				m_RecordCount++;
				curRec = getNextTLVRecord(curRec, tlvDataBasePtr, tlvDataLen);
			}

			return m_RecordCount;
		}

		/**
		 * As described in getTLVRecordCount(), the TLV record count is being cached for efficiency purposes. So if the
		 * number of TLV records change, it's the user's responsibility to call this method with the number of TLV
		 * records being added or removed. If records were added the change should be a positive number, or a negative
		 * number if records were removed
		 * @param[in] changedBy Number of records that were added or removed
		 */
		void changeTLVRecordCount(int changedBy)
		{
			if (m_RecordCount != static_cast<size_t>(-1))
				m_RecordCount += changedBy;
		}
	};

	/**
	 * @class TLVRecordBuilder
	 * A base class for building Type-Length-Value (TLV) records. This builder receives the record parameters in its
	 * c'tor, builds the record raw buffer and provides a method to build a TLVRecord object out of it. Please notice
	 * this is a base class that lacks the capability of actually building TLVRecord objects and also cannot be
	 * instantiated. The reason for that is that different protocols build TLV records in different ways, so these
	 * missing capabilities will be implemented by the derived classes which are specific to each protocol. This class
	 * only provides the common infrastructure that will be used by them
	 */
	class TLVRecordBuilder
	{
	protected:
		TLVRecordBuilder();

		TLVRecordBuilder(uint32_t recType, const uint8_t* recValue, uint8_t recValueLen);

		TLVRecordBuilder(uint32_t recType, uint8_t recValue);

		TLVRecordBuilder(uint32_t recType, uint16_t recValue);

		TLVRecordBuilder(uint32_t recType, uint32_t recValue);

		TLVRecordBuilder(uint32_t recType, const IPv4Address& recValue);

		TLVRecordBuilder(uint32_t recType, const std::string& recValue, bool valueIsHexString = false);

		TLVRecordBuilder(const TLVRecordBuilder& other);

		TLVRecordBuilder& operator=(const TLVRecordBuilder& other);

		virtual ~TLVRecordBuilder();

		void init(uint32_t recType, const uint8_t* recValue, size_t recValueLen);

		uint8_t* m_RecValue;
		size_t m_RecValueLen;
		uint32_t m_RecType;

	private:
		void copyData(const TLVRecordBuilder& other);
	};
}  // namespace pcpp
