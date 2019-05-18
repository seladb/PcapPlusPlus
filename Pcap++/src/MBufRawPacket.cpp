#ifdef USE_DPDK

#define LOG_MODULE PcapLogModuleDpdkDevice

#define __STDC_LIMIT_MACROS
#define __STDC_FORMAT_MACROS

#include "rte_mbuf.h"
#include "rte_mempool.h"
#include "rte_errno.h"

#include "MBufRawPacket.h"
#include "Logger.h"
#include "DpdkDevice.h"
#include "KniDevice.h"

#include <string>
#include <stdint.h>
#include <unistd.h>

#ifndef MBUF_DATA_SIZE
#	define MBUF_DATA_SIZE 2048
#endif

enum { MBUF_SIZE = MBUF_DATA_SIZE + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM };

namespace pcpp
{

/**
 * ===================
 * Class MBufRawPacket
 * ===================
 */

MBufRawPacket::~MBufRawPacket()
{
	if (m_MBuf != NULL && m_FreeMbuf)
	{
		rte_pktmbuf_free(m_MBuf);
	}
}

bool MBufRawPacket::init(DpdkDevice* device)
{
	if (m_MBuf != NULL)
	{
		LOG_ERROR("MBufRawPacket already initialized");
		return false;
	}

	m_MBuf = rte_pktmbuf_alloc(device->m_MBufMempool);
	if (m_MBuf == NULL)
	{
		LOG_ERROR("Couldn't allocate mbuf");
		return false;
	}

	m_Device = device;

	return true;
}

bool MBufRawPacket::initFromRawPacket(const RawPacket* rawPacket, DpdkDevice* device)
{
	if (!init(device))
		return false;

	m_RawPacketSet = false;

	// mbuf is allocated with length of 0, need to adjust it to the size of other
	if (rte_pktmbuf_append(m_MBuf, rawPacket->getRawDataLen()) == NULL)
	{
		LOG_ERROR("Couldn't append %d bytes to mbuf", rawPacket->getRawDataLen());
		return false;
	}

	m_RawData = rte_pktmbuf_mtod(m_MBuf, uint8_t*);
	m_RawDataLen = rte_pktmbuf_pkt_len(m_MBuf);

	copyDataFrom(*rawPacket, false);

	return true;
}

MBufRawPacket::MBufRawPacket(const MBufRawPacket& other)
{
	m_DeleteRawDataAtDestructor = false;
	m_MBuf = NULL;
	m_RawDataLen = 0;
	m_RawPacketSet = false;
	m_RawData = NULL;
	m_Device = other.m_Device;

	rte_mbuf* newMbuf = rte_pktmbuf_alloc(other.m_MBuf->pool);
	if (newMbuf == NULL)
	{
		LOG_ERROR("Couldn't allocate mbuf");
		return;
	}

	// mbuf is allocated with length of 0, need to adjust it to the size of other
	if (rte_pktmbuf_append(newMbuf, other.m_RawDataLen) == NULL)
	{
		LOG_ERROR("Couldn't append %d bytes to mbuf", other.m_RawDataLen);
		return;
	}

	setMBuf(newMbuf, other.m_TimeStamp);

	m_RawPacketSet = false;

	copyDataFrom(other, false);
}

MBufRawPacket& MBufRawPacket::operator=(const MBufRawPacket& other)
{
	if (m_MBuf == NULL)
	{
		LOG_ERROR("MBufRawPacket isn't initialized");
		return *this;
	}

	// adjust the size of the mbuf to the new data
	if (m_RawDataLen < other.m_RawDataLen)
	{
		if (rte_pktmbuf_append(m_MBuf, other.m_RawDataLen - m_RawDataLen) == NULL)
		{
			LOG_ERROR("Couldn't append %d bytes to mbuf", other.m_RawDataLen - m_RawDataLen);
			return *this;
		}
	}
	else if (m_RawDataLen > other.m_RawDataLen)
	{
		if (rte_pktmbuf_adj(m_MBuf, m_RawDataLen - other.m_RawDataLen) == NULL)
		{
			LOG_ERROR("Couldn't remove %d bytes to mbuf", m_RawDataLen - other.m_RawDataLen);
			return *this;
		}
	}

	m_RawPacketSet = false;

	copyDataFrom(other, false);

	return *this;
}

bool MBufRawPacket::setRawData(const uint8_t* pRawData, int rawDataLen, timeval timestamp, LinkLayerType layerType, int frameLength)
{
	if (rawDataLen > MBUF_DATA_SIZE)
	{
		LOG_ERROR("Cannot set raw data which length is larger than mBuf max size. mBuf max length: %d; requested length: %d", MBUF_DATA_SIZE, rawDataLen);
		return false;
	}

	if (m_MBuf == NULL)
	{
		if (!(init(m_Device)))
		{
			LOG_ERROR("Couldn't allocate new mBuf");
			return false;
		}
	}

	// adjust the size of the mbuf to the new data
	if (m_RawDataLen < rawDataLen)
	{
		if (rte_pktmbuf_append(m_MBuf, rawDataLen - m_RawDataLen) == NULL)
		{
			LOG_ERROR("Couldn't append %d bytes to mbuf", rawDataLen - m_RawDataLen);
			return false;
		}
	}
	else if (m_RawDataLen > rawDataLen)
	{
		if (rte_pktmbuf_adj(m_MBuf, m_RawDataLen - rawDataLen) == NULL)
		{
			LOG_ERROR("Couldn't remove %d bytes to mbuf", m_RawDataLen - rawDataLen);
			return false;
		}
	}

	m_RawData = rte_pktmbuf_mtod(m_MBuf, uint8_t*);
	m_RawDataLen = rte_pktmbuf_pkt_len(m_MBuf);
	memcpy(m_RawData, pRawData, m_RawDataLen);
	delete [] pRawData;
	m_TimeStamp = timestamp;
	m_RawPacketSet = true;
	m_FrameLength = frameLength;
	m_LinkLayerType = layerType;

	return true;
}

void MBufRawPacket::clear()
{
	if (m_MBuf != NULL && m_FreeMbuf)
	{
		rte_pktmbuf_free(m_MBuf);
	}

	m_MBuf = NULL;

	m_RawData = NULL;

	RawPacket::clear();
}

void MBufRawPacket::appendData(const uint8_t* dataToAppend, size_t dataToAppendLen)
{
	if (m_MBuf == NULL)
	{
		LOG_ERROR("MBufRawPacket not initialized. Please call the init() method");
		return; //TODO: need to return false here or something
	}

	char* startOfNewlyAppendedData = rte_pktmbuf_append(m_MBuf, dataToAppendLen);
	if (startOfNewlyAppendedData == NULL)
	{
		LOG_ERROR("Couldn't append %d bytes to RawPacket - not enough room in mBuf", (int)dataToAppendLen);
		return; //TODO: need to return false here or something
	}

	RawPacket::appendData(dataToAppend, dataToAppendLen);

	LOG_DEBUG("Appended %d bytes to MBufRawPacket", (int)dataToAppendLen);
}

void MBufRawPacket::insertData(int atIndex, const uint8_t* dataToInsert, size_t dataToInsertLen)
{
	if (m_MBuf == NULL)
	{
		LOG_ERROR("MBufRawPacket not initialized. Please call the init() method");
		return; //TODO: need to return false here or something
	}

	char* startOfNewlyAppendedData = rte_pktmbuf_append(m_MBuf, dataToInsertLen);
	if (startOfNewlyAppendedData == NULL)
	{
		LOG_ERROR("Couldn't append %d bytes to RawPacket - not enough room in mBuf", (int)dataToInsertLen);
		return; //TODO: need to return false here or something
	}

	RawPacket::insertData(atIndex, dataToInsert, dataToInsertLen);

	LOG_DEBUG("Inserted %d bytes to MBufRawPacket", (int)dataToInsertLen);
}

bool MBufRawPacket::removeData(int atIndex, size_t numOfBytesToRemove)
{
	if (m_MBuf == NULL)
	{
		LOG_ERROR("MBufRawPacket not initialized. Please call the init() method");
		return false;
	}

	if (!RawPacket::removeData(atIndex, numOfBytesToRemove))
		return false;

	if (rte_pktmbuf_trim(m_MBuf, numOfBytesToRemove) != 0)
	{
		LOG_ERROR("Couldn't trim the mBuf");
		return false;
	}

	LOG_DEBUG("Trimmed %d bytes from MBufRawPacket", (int)numOfBytesToRemove);

	return true;
}

bool MBufRawPacket::reallocateData(size_t newBufferLength)
{
	if ((int)newBufferLength < m_RawDataLen)
	{
		LOG_ERROR("Cannot reallocate mBuf raw packet to a smaller size. Current data length: %d; requested length: %d", m_RawDataLen, (int)newBufferLength);
		return false;
	}

	if (newBufferLength > MBUF_DATA_SIZE)
	{
		LOG_ERROR("Cannot reallocate mBuf raw packet to a size larger than mBuf data. mBuf max length: %d; requested length: %d", MBUF_DATA_SIZE, (int)newBufferLength);
		return false;
	}

	// no need to do any memory allocation because mbuf is already allocated

	return true;
}

void MBufRawPacket::setMBuf(struct rte_mbuf* mBuf, timeval timestamp)
{
	if (m_MBuf != NULL && m_FreeMbuf)
		rte_pktmbuf_free(m_MBuf);

	if (mBuf == NULL)
	{
		LOG_ERROR("mbuf to set is NULL");
		return;
	}

	m_MBuf = mBuf;
	RawPacket::setRawData(rte_pktmbuf_mtod(mBuf, const uint8_t*), rte_pktmbuf_pkt_len(mBuf), timestamp, LINKTYPE_ETHERNET);
}

} // namespace pcpp
#endif  /* USE_DPDK */