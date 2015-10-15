#ifndef PCAPPP_RAW_PACKET
#define PCAPPP_RAW_PACKET

#include <stdint.h>
#include <sys/time.h>
#include <stddef.h>

/// @file

/**
 * Max packet size supported
 */
#define MAX_PACKET_SIZE 65536

/**
 * @class RawPacket
 * This class holds the packet as raw (not parsed) data. The data is held as byte array. In addition to the data itself
 * every instance also holds a timestamp representing the time the packet was received by the NIC.
 * RawPacket instance isn't read only. The user can change the packet data, add or remove data, etc.
 */
class RawPacket
{
protected:
	uint8_t* m_pRawData;
	int m_RawDataLen;
	timeval m_TimeStamp;
	bool m_DeleteRawDataAtDestructor;
	bool m_RawPacketSet;
	void Init();
	void copyDataFrom(const RawPacket& other, bool allocateData = true);
public:
	/**
	 * A constructor that receives a pointer to the raw data (allocated elsewhere). This constructor is usually used when packet
	 * is captured using a packet capturing engine (like libPcap. WinPcap, PF_RING, etc.). The capturing engine allocates the raw data
	 * memory and give the user a pointer to it + a timestamp it has arrived to the device
	 * @param[in] pRawData A pointer to the raw data
	 * @param[in] rawDataLen The raw data length in bytes
	 * @param[in] timestamp The timestamp packet was received by the NIC
	 * @param[in] deleteRawDataAtDestructor An indicator whether raw data pointer should be freed when the instance is freed or not. If set
	 * to 'true' than pRawData will be freed when instanced is being freed
	 */
	RawPacket(const uint8_t* pRawData, int rawDataLen, timeval timestamp, bool deleteRawDataAtDestructor);

	/**
	 * A default constructor that initializes class'es attributes to default value:
	 * - data pointer is set to NULL
	 * - data length is set to 0
	 * - deleteRawDataAtDestructor is set to 'true'
	 * @todo timestamp isn't set here to a default value
	 */
	RawPacket();

	/**
	 * A destructor for this class. Frees the raw data if deleteRawDataAtDestructor was set to 'true'
	 */
	virtual ~RawPacket();

	/**
	 * A copy constructor that copies all data from another instance. Notice all raw data is copied (using memcpy), so when the original or
	 * the other instance are freed, the other won't be affected
	 * @param[in] other The instance to copy from
	 */
	RawPacket(const RawPacket& other);

	/**
	 * Assignment operator overload for this class. When using this operator on an already initialized RawPacket instance,
	 * the original raw data is freed first. Then the other instance is copied to this instance, the same way the copy constructor works
	 * @todo free raw data only if deleteRawDataAtDestructor was set to 'true'
	 * @param[in] other The instance to copy from
	 */
	RawPacket& operator=(const RawPacket& other);

	/**
	 * Set a raw data. If data was already set and deleteRawDataAtDestructor was set to 'true' the old data will be freed first
	 * @param[in] pRawData A pointer to the new raw data
	 * @param[in] rawDataLen The new raw data length in bytes
	 * @param[in] timestamp The timestamp packet was received by the NIC
	 * @return True if raw data was set successfully, false otherwise
	 */
	virtual bool setRawData(const uint8_t* pRawData, int rawDataLen, timeval timestamp);

	/**
	 * Get raw data pointer
	 * @return A pointer to the raw data
	 */
	const uint8_t* getRawData();

	/**
	 * Get read only raw data pointer
	 * @return A read-only pointer to the raw data
	 */
	const uint8_t* getRawDataReadOnly() const;

	/**
	 * Get raw data length in bytes
	 * @return Raw data length in bytes
	 */
	int getRawDataLen() const;

	/**
	 * Get raw data timestamp
	 * @return Raw data timestamp
	 */
	timeval getPacketTimeStamp();

	/**
	 * Get an indication whether raw data was already set for this instance.
	 * @return True if raw data was set for this instance. Raw data can be set using the non-default constructor, using setRawData(), using
	 * the copy constructor or using the assignment operator. Returns false otherwise, for example: if the instance was created using the
	 * default constructor or clear() was called
	 */
	inline bool isPacketSet() { return m_RawPacketSet; }

	/**
	 * Clears all members of this instance, meaning setting raw data to NULL, raw data length to 0, etc. Currently raw data is always freed,
	 * even if deleteRawDataAtDestructor was set to 'false'
	 * @todo deleteRawDataAtDestructor was set to 'true', don't free the raw data
	 * @todo set timestamp to a default value as well
	 */
	virtual void clear();

	/**
	 * Append data to the end of current data. This method works without allocating more memory, it just uses memcpy() to copy dataToAppend at
	 * the end of the current data. This means that the method assumes this memory was already allocated by the user. If it isn't the case then
	 * this method will cause memory corruption
	 * @param[in] dataToAppend A pointer to the data to append to current raw data
	 * @param[in] dataToAppendLen Length in bytes of dataToAppend
	 */
	virtual void appendData(const uint8_t* dataToAppend, size_t dataToAppendLen);

	/**
	 * Insert new data at some index of the current data and shift the remaining old data to the end. This method works without allocating more memory,
	 * it just copies dataToAppend at the relevant index and shifts the remaining data to the end. This means that the method assumes this memory was
	 * already allocated by the user. If it isn't the case then this method will cause memory corruption
	 * @param[in] atIndex The index to insert the new data to
	 * @param[in] dataToInsert A pointer to the new data to insert
	 * @param[in] dataToInsertLen Length in bytes of dataToInsert
	 */
	virtual void insertData(int atIndex, const uint8_t* dataToInsert, size_t dataToInsertLen);

	/**
	 * Remove certain number of bytes from current raw data buffer. All data after the removed bytes will be shifted back
	 * @param[in] atIndex The index to start removing bytes from
	 * @param[in] numOfBytesToRemove Number of bytes to remove
	 * @return True if all bytes were removed successfully, or false if atIndex+numOfBytesToRemove is out-of-bounds of the raw data buffer
	 */
	virtual bool removeData(int atIndex, size_t numOfBytesToRemove);

	/**
	 * Re-allocate raw packet buffer meaning add size to it without losing the current packet data. This method allocates the required buffer size as instructed
	 * by the use and then copies the raw data from the current allocated buffer to the new one. This method can become useful if the user wants to insert or
	 * append data to the raw data, and the previous allocated buffer is too small, so the user wants to allocate a larger buffer and get RawPacket instance to
	 * point to it
	 * @param[in] newBufferLength The new buffer length as required by the user. The method is responsible to allocate the memory
	 * @return True if data was reallocated successfully, false otherwise
	 */
	virtual bool reallocateData(size_t newBufferLength);
};

#endif
