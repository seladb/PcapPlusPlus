#ifndef PACKETPP_TLV_DATA
#define PACKETPP_TLV_DATA

#include "Layer.h"
#include "IPAddress.h"
#include <string.h>

namespace pcpp
{
	/**
	 * @struct TLVRecord
	 * A struct representing a Type-Length-Value (TLV) record. These type of records are used inside Hop-By-Hop and Destinations IPv6
	 * extensions
	 */
	class TLVRecord
	{
	protected:

		struct TLVRawData
		{
			/** Record type */
			uint8_t recordType;
			/** record length in bytes, not including TLVRecord#recordType field and this field */
			uint8_t recordLen;
			/** Record value (variable size) */
			uint8_t recordValue[];
		};

		TLVRawData* m_Data;

	public:

		TLVRecord(uint8_t* recordRawData)
		{
			if (recordRawData == NULL)
				m_Data = NULL;
			else
				m_Data = (TLVRawData*)recordRawData;
		}

		TLVRecord(const TLVRecord& other)
		{
			m_Data = other.m_Data;
		}

		virtual ~TLVRecord() { }

		TLVRecord& operator=(const TLVRecord& other)
		{
			m_Data = other.m_Data;
			return *this;
		}

		uint8_t getType() { return m_Data->recordType; }

		uint8_t* getValue() { return m_Data->recordValue; }

		bool isNull() { return (m_Data == NULL); }

		uint8_t* getRecordBasePtr() { return (uint8_t*)m_Data; }

		void purgeRecordData() { if (!isNull()) delete m_Data; }

		/**
		 * A templated method to retrieve the record data as a certain type T. For example, if record data is 4B long
		 * (integer) then this method should be used as getValueAs<int>() and it will return the record data as an integer.<BR>
		 * Notice this return value is a copy of the data, not a pointer to the actual data
		 * @return The record data as type T
		 */
		template<typename T>
		T getValueAs()
		{
			if (getDataSize() < sizeof(T))
				return 0;

			T result;
			memcpy(&result, m_Data->recordValue, sizeof(T));
			return result;
		}

		/**
		 * @return The total size of this record (in bytes)
		 */
		virtual size_t getTotalSize() const = 0;

		/**
		 * @return The size of the record data
		 */
		virtual size_t getDataSize() = 0;

	};


	template<typename TLVRecordType>
	class TLVRecordReader
	{
	private:
		size_t m_RecordCount;

	public:

		TLVRecordReader() { m_RecordCount = (size_t)-1; }

		virtual ~TLVRecordReader() { }

		TLVRecordType getFirstTLVRecord(uint8_t* tlvRecordsBasePtr, size_t offsetToTLVRecordBase, size_t totalLen)
		{
			// check if there are records at all
			if (totalLen <= offsetToTLVRecordBase)
				return TLVRecordType(NULL);

			return TLVRecordType(tlvRecordsBasePtr);
		}

		TLVRecordType getNextTLVRecord(TLVRecordType& record, uint8_t* tlvRecordsBasePtr, size_t offsetToTLVRecordBase, size_t totalLen)
		{
			if (record.isNull())
				return TLVRecordType(NULL);

			// record pointer is out-bounds of the TLV records memory
			if ((record.getRecordBasePtr() - tlvRecordsBasePtr) < 0)
				return TLVRecordType(NULL);

			// record pointer is out-bounds of the TLV records memory
			if ((int)offsetToTLVRecordBase + record.getRecordBasePtr() - tlvRecordsBasePtr + (int)record.getTotalSize()  >= (int)totalLen)
				return TLVRecordType(NULL);

			return TLVRecordType(record.getRecordBasePtr() + record.getTotalSize());
		}

		TLVRecordType getTLVRecord(uint8_t recordType, uint8_t* tlvRecordsBasePtr, size_t offsetToTLVRecordBase, size_t totalLen)
		{
			// check if there are records at all
			if (totalLen <= offsetToTLVRecordBase)
				return TLVRecordType(NULL);

			TLVRecordType curRec = getFirstTLVRecord(tlvRecordsBasePtr, offsetToTLVRecordBase, totalLen);
			while (!curRec.isNull())
			{
				if (curRec.getType() == recordType)
					return curRec;

				curRec = getNextTLVRecord(curRec, tlvRecordsBasePtr, offsetToTLVRecordBase, totalLen);
			}

			return TLVRecordType(NULL);
		}

		size_t getTLVRecordCount(uint8_t* tlvRecordsBasePtr, size_t offsetToTLVRecordBase, size_t totalLen)
		{
			if (m_RecordCount != (size_t)-1)
				return m_RecordCount;

			m_RecordCount = 0;
			TLVRecordType curRec = getFirstTLVRecord(tlvRecordsBasePtr, offsetToTLVRecordBase, totalLen);
			while (!curRec.isNull())
			{
				m_RecordCount++;
				curRec = getNextTLVRecord(curRec, tlvRecordsBasePtr, offsetToTLVRecordBase, totalLen);
			}

			return m_RecordCount;
		}

		void changeTLVRecordCount(int changeBy) { m_RecordCount += changeBy; }
	};


	/**
	 * A class for building Type-Length-Value (TLV) records of type TLVRecord. This builder gets the record parameters in its c'tor,
	 * builds the record raw buffer and provides a method to build a TLVRecord object out of it
	 */
	class TLVRecordBuilder
	{
	protected:

		// unimplemented empty c'tor
		TLVRecordBuilder();

		/**
		 * A c'tor which gets the record type, record length and a buffer containing the record value and builds
		 * the record raw buffer which can later be casted to TLVRecord object using the build() method
		 * @param[in] recType Record type
		 * @param[in] recDataLen Record length in bytes
		 * @param[in] recValue A buffer containing the record data. This buffer is read-only and isn't modified in any way
		 */
		TLVRecordBuilder(uint8_t recType, const uint8_t* recValue, uint8_t recValueLen);

		/**
		 * A c'tor which gets the record type, a 1-byte record value (which length is 1) and builds
		 * the record raw buffer which can later be casted to TLVRecord object using the build() method
		 * @param[in] recType Record type
		 * @param[in] recValue A 1-byte record value
		 */
		TLVRecordBuilder(uint8_t recType, uint8_t recValue);

		/**
		 * A c'tor which gets the record type, a 2-byte record value (which length is 2) and builds
		 * the record raw buffer which can later be casted to TLVRecord object using the build() method
		 * @param[in] recType Record type
		 * @param[in] recValue A 2-byte record value
		 */
		TLVRecordBuilder(uint8_t recType, uint16_t recValue);


		TLVRecordBuilder(uint8_t recType, uint32_t recValue);

		TLVRecordBuilder(uint8_t recType, const IPv4Address& recValue);

		TLVRecordBuilder(uint8_t recType, const std::string& recValue);

		/**
		 * A copy c'tor which copies all the data from another instance of TLVRecordBuilder
		 * @param[in] other The instance to copy from
		 */
		TLVRecordBuilder(const TLVRecordBuilder& other);

		/**
		 * A d'tor for this class, frees all allocated memory
		 */
		virtual ~TLVRecordBuilder();

		uint8_t* m_RecValue;
		uint8_t m_RecValueLen;
		uint8_t m_RecType;

		void init(uint8_t recType, const uint8_t* recValue, uint8_t recValueLen);
	};
}
#endif // PACKETPP_TLV_DATA
