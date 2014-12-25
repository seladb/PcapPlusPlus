#ifndef PCAPPP_RAW_PACKET
#define PCAPPP_RAW_PACKET

#include <stdint.h>
#include <sys/time.h>
#include <stddef.h>

class RawPacket
{
private:
	uint8_t* m_pRawData;
	int m_RawDataLen;
	timeval m_TimeStamp;
	bool m_DeleteRawDataAtDestructor;
	bool m_RawPacketSet;
	void Init();
	void copyDataFrom(const RawPacket& other);
public:
	RawPacket(const uint8_t* pRawData, int rawDataLen, timeval timestamp, bool deleteRawDataAtDestructor);
	RawPacket();
	~RawPacket();

	// copy c'tor
	RawPacket(const RawPacket& other);
	RawPacket& operator=(const RawPacket& other);

	void setRawData(const uint8_t* pRawData, int rawDataLen, timeval timestamp);
	const uint8_t* getRawData();
	int getRawDataLen();
	timeval getPacketTimeStamp();
	bool isPacketSet() { return m_RawPacketSet; }
	void clear();
	void appendData(const uint8_t* dataToAppend, size_t dataToAppendLen);
	void insertData(int atIndex, const uint8_t* dataToAppend, size_t dataToAppendLen);
	bool removeData(int atIndex, size_t numOfBytesToRemove);
	void reallocateData(uint8_t* newBuffer);
};

#define MAX_PACKET_SIZE 65536

#endif
