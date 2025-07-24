// GCOVR_EXCL_START

#define LOG_MODULE PcapLogModuleMBufRawPacket

#define __STDC_LIMIT_MACROS
#define __STDC_FORMAT_MACROS

#include "rte_mbuf.h"
#include "rte_mempool.h"
#include "rte_errno.h"

#include "MBufRawPacket.h"
#include "Logger.h"
#include "DpdkDevice.h"
#ifdef USE_DPDK_KNI
#	include "KniDevice.h"
#endif

#include <string>
#include <stdint.h>
#include <unistd.h>

namespace pcpp
{

	/// ===================
	/// Class MBufRawPacket
	/// ===================

	MBufRawPacket::~MBufRawPacket()
	{
		if (m_MBuf != nullptr && m_FreeMbuf)
		{
			rte_pktmbuf_free(m_MBuf);
		}
	}

	bool MBufRawPacket::init(struct rte_mempool* mempool)
	{
		if (m_MBuf != nullptr)
		{
			PCPP_LOG_ERROR("MBufRawPacket already initialized");
			return false;
		}

		if (mempool == nullptr)
		{
			PCPP_LOG_ERROR("Could not initialize MBufRawPacket no mempool provided");
			return false;
		}

		m_MBuf = rte_pktmbuf_alloc(mempool);
		if (m_MBuf == nullptr)
		{
			PCPP_LOG_ERROR("Couldn't allocate mbuf");
			return false;
		}

		m_Mempool = mempool;
		return true;
	}

	bool MBufRawPacket::init(DpdkDevice* device)
	{
		m_MbufDataSize = device->m_MBufDataSize;
		return init(device->m_MBufMempool);
	}

#ifdef USE_DPDK_KNI
	bool MBufRawPacket::init(KniDevice* device)
	{
		return init(device->m_MBufMempool);
	}
#endif

	bool MBufRawPacket::initFromRawPacket(const RawPacket* rawPacket, struct rte_mempool* mempool)
	{
		if (!init(mempool))
			return false;

		m_RawPacketSet = false;

		// mbuf is allocated with length of 0, need to adjust it to the size of other
		if (rte_pktmbuf_append(m_MBuf, rawPacket->getRawDataLen()) == nullptr)
		{
			PCPP_LOG_ERROR("Couldn't append " << rawPacket->getRawDataLen() << " bytes to mbuf");
			return false;
		}

		m_RawData = rte_pktmbuf_mtod(m_MBuf, uint8_t*);
		m_RawDataLen = rte_pktmbuf_pkt_len(m_MBuf);

		copyDataFrom(*rawPacket, false);

		return true;
	}

	bool MBufRawPacket::initFromRawPacket(const RawPacket* rawPacket, DpdkDevice* device)
	{
		return initFromRawPacket(rawPacket, device->m_MBufMempool);
	}

#ifdef USE_DPDK_KNI
	bool MBufRawPacket::initFromRawPacket(const RawPacket* rawPacket, KniDevice* device)
	{
		return initFromRawPacket(rawPacket, device->m_MBufMempool);
	}
#endif

	MBufRawPacket::MBufRawPacket(const MBufRawPacket& other)
	{
		m_DeleteRawDataAtDestructor = false;
		m_MBuf = nullptr;
		m_RawDataLen = 0;
		m_RawPacketSet = false;
		m_RawData = nullptr;
		m_Mempool = other.m_Mempool;
		m_MbufDataSize = other.m_MbufDataSize;

		rte_mbuf* newMbuf = rte_pktmbuf_alloc(m_Mempool);
		if (newMbuf == nullptr)
		{
			PCPP_LOG_ERROR("Couldn't allocate mbuf");
			return;
		}

		// mbuf is allocated with length of 0, need to adjust it to the size of other
		if (rte_pktmbuf_append(newMbuf, other.m_RawDataLen) == nullptr)
		{
			PCPP_LOG_ERROR("Couldn't append " << other.m_RawDataLen << " bytes to mbuf");
			return;
		}

		setMBuf(newMbuf, other.m_TimeStamp);

		m_RawPacketSet = false;

		copyDataFrom(other, false);
	}

	MBufRawPacket& MBufRawPacket::operator=(const MBufRawPacket& other)
	{
		if (m_MBuf == nullptr)
		{
			PCPP_LOG_ERROR("MBufRawPacket isn't initialized");
			return *this;
		}

		// adjust the size of the mbuf to the new data
		if (m_RawDataLen < other.m_RawDataLen)
		{
			if (rte_pktmbuf_append(m_MBuf, other.m_RawDataLen - m_RawDataLen) == nullptr)
			{
				PCPP_LOG_ERROR("Couldn't append " << (other.m_RawDataLen - m_RawDataLen) << " bytes to mbuf");
				return *this;
			}
		}
		else if (m_RawDataLen > other.m_RawDataLen)
		{
			if (rte_pktmbuf_adj(m_MBuf, m_RawDataLen - other.m_RawDataLen) == nullptr)
			{
				PCPP_LOG_ERROR("Couldn't remove " << m_RawDataLen - other.m_RawDataLen << " bytes to mbuf");
				return *this;
			}
		}

		m_RawPacketSet = false;

		copyDataFrom(other, false);

		return *this;
	}

	MBufRawPacket* MBufRawPacket::clone() const
	{
		return new MBufRawPacket(*this);
	}

	bool MBufRawPacket::setRawData(const uint8_t* pRawData, int rawDataLen, timespec timestamp, LinkLayerType layerType,
	                               int frameLength)
	{
		if (rawDataLen > m_MbufDataSize)
		{
			PCPP_LOG_ERROR("Cannot set raw data which length is larger than mBuf max size. mBuf max length: "
			               << m_MbufDataSize << "; requested length: " << rawDataLen);
			return false;
		}

		if (m_MBuf == nullptr)
		{
			if (!(init(m_Mempool)))
			{
				PCPP_LOG_ERROR("Couldn't allocate new mBuf");
				return false;
			}
		}

		// adjust the size of the mbuf to the new data
		if (m_RawDataLen < rawDataLen)
		{
			if (rte_pktmbuf_append(m_MBuf, rawDataLen - m_RawDataLen) == nullptr)
			{
				PCPP_LOG_ERROR("Couldn't append " << (rawDataLen - m_RawDataLen) << " bytes to mbuf");
				return false;
			}
		}
		else if (m_RawDataLen > rawDataLen)
		{
			if (rte_pktmbuf_adj(m_MBuf, m_RawDataLen - rawDataLen) == nullptr)
			{
				PCPP_LOG_ERROR("Couldn't remove " << (m_RawDataLen - rawDataLen) << " bytes to mbuf");
				return false;
			}
		}

		m_RawData = rte_pktmbuf_mtod(m_MBuf, uint8_t*);
		m_RawDataLen = rte_pktmbuf_pkt_len(m_MBuf);
		memcpy(m_RawData, pRawData, m_RawDataLen);
		delete[] pRawData;
		m_TimeStamp = timestamp;
		m_RawPacketSet = true;
		m_FrameLength = frameLength;
		m_LinkLayerType = layerType;

		return true;
	}

	void MBufRawPacket::clear()
	{
		if (m_MBuf != nullptr && m_FreeMbuf)
		{
			rte_pktmbuf_free(m_MBuf);
		}

		m_MBuf = nullptr;

		m_RawData = nullptr;

		RawPacket::clear();
	}

	void MBufRawPacket::appendData(const uint8_t* dataToAppend, size_t dataToAppendLen)
	{
		if (m_MBuf == nullptr)
		{
			PCPP_LOG_ERROR("MBufRawPacket not initialized. Please call the init() method");
			return;  // TODO: need to return false here or something
		}

		char* startOfNewlyAppendedData = rte_pktmbuf_append(m_MBuf, dataToAppendLen);
		if (startOfNewlyAppendedData == nullptr)
		{
			PCPP_LOG_ERROR("Couldn't append " << dataToAppendLen << " bytes to RawPacket - not enough room in mBuf");
			return;  // TODO: need to return false here or something
		}

		RawPacket::appendData(dataToAppend, dataToAppendLen);

		PCPP_LOG_DEBUG("Appended " << dataToAppendLen << " bytes to MBufRawPacket");
	}

	void MBufRawPacket::insertData(int atIndex, const uint8_t* dataToInsert, size_t dataToInsertLen)
	{
		if (m_MBuf == nullptr)
		{
			PCPP_LOG_ERROR("MBufRawPacket not initialized. Please call the init() method");
			return;  // TODO: need to return false here or something
		}

		char* startOfNewlyAppendedData = rte_pktmbuf_append(m_MBuf, dataToInsertLen);
		if (startOfNewlyAppendedData == nullptr)
		{
			PCPP_LOG_ERROR("Couldn't append " << dataToInsertLen << " bytes to RawPacket - not enough room in mBuf");
			return;  // TODO: need to return false here or something
		}

		RawPacket::insertData(atIndex, dataToInsert, dataToInsertLen);

		PCPP_LOG_DEBUG("Inserted " << dataToInsertLen << " bytes to MBufRawPacket");
	}

	bool MBufRawPacket::removeData(int atIndex, size_t numOfBytesToRemove)
	{
		if (m_MBuf == nullptr)
		{
			PCPP_LOG_ERROR("MBufRawPacket not initialized. Please call the init() method");
			return false;
		}

		if (!RawPacket::removeData(atIndex, numOfBytesToRemove))
			return false;

		if (rte_pktmbuf_trim(m_MBuf, numOfBytesToRemove) != 0)
		{
			PCPP_LOG_ERROR("Couldn't trim the mBuf");
			return false;
		}

		PCPP_LOG_DEBUG("Trimmed " << numOfBytesToRemove << " bytes from MBufRawPacket");

		return true;
	}

	bool MBufRawPacket::reallocateData(size_t newBufferLength)
	{
		if ((int)newBufferLength < m_RawDataLen)
		{
			PCPP_LOG_ERROR("Cannot reallocate mBuf raw packet to a smaller size. Current data length: "
			               << m_RawDataLen << "; requested length: " << newBufferLength);
			return false;
		}

		if ((int)newBufferLength > m_MbufDataSize)
		{
			PCPP_LOG_ERROR("Cannot reallocate mBuf raw packet to a size larger than mBuf data. mBuf max length: "
			               << m_MbufDataSize << "; requested length: " << newBufferLength);
			return false;
		}

		// no need to do any memory allocation because mbuf is already allocated

		return true;
	}

	void MBufRawPacket::setMBuf(struct rte_mbuf* mBuf, timespec timestamp)
	{
		if (m_MBuf != nullptr && m_FreeMbuf)
			rte_pktmbuf_free(m_MBuf);

		if (mBuf == nullptr)
		{
			PCPP_LOG_ERROR("mbuf to set is nullptr");
			return;
		}

		RawPacket::setRawData(rte_pktmbuf_mtod(mBuf, const uint8_t*), rte_pktmbuf_pkt_len(mBuf), timestamp,
		                      LINKTYPE_ETHERNET);
		m_MBuf = mBuf;
	}

}  // namespace pcpp

// GCOVR_EXCL_STOP
