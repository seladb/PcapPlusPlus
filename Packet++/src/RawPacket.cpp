#define LOG_MODULE PacketLogModuleRawPacket

#include "RawPacket.h"
#include "Logger.h"
#include "TimespecTimeval.h"
#include <cstring>

namespace pcpp
{
	namespace
	{
		timespec toTimespec(timeval value)
		{
			timespec nsec_time = {};
			TIMEVAL_TO_TIMESPEC(&value, &nsec_time);
			return nsec_time;
		}
	}  // namespace

	bool IRawPacket::setPacketTimeStamp(timeval timestamp)
	{
		return setPacketTimeStamp(toTimespec(timestamp));
	}

	bool IRawPacket::setRawData(RawPacketBufferPolicy bufPolicy, uint8_t* pRawData, int rawDataLen, timeval timestamp,
	                            LinkLayerType layerType, int frameLength)
	{
		return setRawData(bufPolicy, pRawData, rawDataLen, toTimespec(timestamp), layerType, frameLength);
	}

	RawPacketBase::RawPacketBase(timespec timestamp, LinkLayerType layerType)
	    : m_TimeStamp(timestamp), m_LinkLayerType(layerType)
	{}

	RawPacketBase::RawPacketBase(timeval timestamp, LinkLayerType layerType)
	    : m_TimeStamp(toTimespec(timestamp)), m_LinkLayerType(layerType)
	{}

	bool RawPacketBase::setPacketTimeStamp(timespec timestamp)
	{
		m_TimeStamp = timestamp;
		return true;
	}

	RawPacket::RawPacket(const uint8_t* pRawData, int rawDataLen, timeval timestamp, bool deleteRawDataAtDestructor,
	                     LinkLayerType layerType)
	    : RawPacket(pRawData, rawDataLen, toTimespec(timestamp), deleteRawDataAtDestructor, layerType)
	{}

	RawPacket::RawPacket(const uint8_t* pRawData, int rawDataLen, timespec timestamp, bool deleteRawDataAtDestructor,
	                     LinkLayerType layerType)
	    : RawPacketBase(timestamp, layerType), m_RawData(const_cast<uint8_t*>(pRawData)), m_RawDataLen(rawDataLen),
	      m_FrameLength(rawDataLen), m_RawDataCapacity(rawDataLen),
	      m_DeleteRawDataAtDestructor(deleteRawDataAtDestructor), m_RawPacketSet(true)
	{}

	RawPacket::RawPacket(RawPacketBufferPolicy bufPolicy, uint8_t* pRawData, int rawDataLen, timeval timestamp,
	                     LinkLayerType layerType)
	    : RawPacket(bufPolicy, pRawData, rawDataLen, toTimespec(timestamp), layerType)
	{}

	RawPacket::RawPacket(RawPacketBufferPolicy bufPolicy, uint8_t* pRawData, int rawDataLen, timespec timestamp,
	                     LinkLayerType layerType)
	    : RawPacketBase(timestamp, layerType)
	{
		switch (bufPolicy)
		{
		case RawPacketBufferPolicy::Copy:
		{
			m_RawData = new uint8_t[rawDataLen];
			m_DeleteRawDataAtDestructor = true;
			std::memcpy(m_RawData, pRawData, rawDataLen);
			break;
		}
		case RawPacketBufferPolicy::Move:
		{
			m_RawData = pRawData;
			m_DeleteRawDataAtDestructor = true;
			break;
		}
		case RawPacketBufferPolicy::StrictReference:
		{
			// StrictReference does not allow reallocation, so we set the flag to false
			m_ReallocationsAllowed = false;
			// fall through
		}
		case RawPacketBufferPolicy::SoftReference:
		{
			m_RawData = pRawData;
			m_DeleteRawDataAtDestructor = false;  // no deletion of raw data at destructor
			break;
		}
		default:
			throw std::invalid_argument("Invalid RawPacketBufferPolicy. Use Copy, Move, or Reference.");
		}

		m_RawDataLen = rawDataLen;
		m_FrameLength = rawDataLen;
		m_RawDataCapacity = rawDataLen;
		m_RawPacketSet = true;
	}

	RawPacket::~RawPacket()
	{
		clear();
	}

	RawPacket::RawPacket(const RawPacket& other)
	{
		m_RawData = nullptr;
		copyDataFrom(other, true);
	}

	RawPacket& RawPacket::operator=(const RawPacket& other)
	{
		if (this != &other)
		{
			clear();

			copyDataFrom(other, true);
		}

		return *this;
	}

	RawPacket* RawPacket::clone() const
	{
		return new RawPacket(*this);
	}

	void RawPacket::copyDataFrom(const RawPacket& other, bool allocateData)
	{
		if (!other.m_RawPacketSet)
			return;

		setPacketTimeStamp(other.getPacketTimeStamp());

		if (allocateData)
		{
			m_DeleteRawDataAtDestructor = true;
			m_RawData = new uint8_t[other.m_RawDataLen];
			m_RawDataLen = other.m_RawDataLen;
		}

		memcpy(m_RawData, other.m_RawData, other.m_RawDataLen);
		setLinkLayerType(other.getLinkLayerType());
		m_FrameLength = other.m_FrameLength;
		m_RawPacketSet = true;
	}

	bool RawPacket::setRawData(const uint8_t* pRawData, int rawDataLen, timeval timestamp, LinkLayerType layerType,
	                           int frameLength)
	{
		// Legacy method for compatibility with older code. The method was used when assigning a raw buffer that is
		// externally managed.
		// Deprecation due to ambiguity on buffer ownership as it assumes the buffer matches the previous buffer's
		// policy.
		RawPacketBufferPolicy policy =
		    m_DeleteRawDataAtDestructor ? RawPacketBufferPolicy::Move : RawPacketBufferPolicy::SoftReference;
		return setRawData(policy, const_cast<uint8_t*>(pRawData), rawDataLen, timestamp, layerType, frameLength);
	}

	bool RawPacket::setRawData(const uint8_t* pRawData, int rawDataLen, timespec timestamp, LinkLayerType layerType,
	                           int frameLength)
	{
		// Legacy method for compatibility with older code. The method was used when assigning a raw buffer that is
		// externally managed.
		// Deprecation due to ambiguity on buffer ownership as it assumes the buffer matches the previous buffer's
		// policy.
		RawPacketBufferPolicy policy =
		    m_DeleteRawDataAtDestructor ? RawPacketBufferPolicy::Move : RawPacketBufferPolicy::SoftReference;
		return setRawData(policy, const_cast<uint8_t*>(pRawData), rawDataLen, timestamp, layerType, frameLength);
	}

	bool RawPacket::setRawData(RawPacketBufferPolicy bufPolicy, uint8_t* pRawData, int rawDataLen, timespec timestamp,
	                           LinkLayerType layerType, int frameLength)
	{
		// Early check to maintain previous data if policy is invalid.
		switch (bufPolicy)
		{
		case RawPacketBufferPolicy::Copy:
		case RawPacketBufferPolicy::Move:
		case RawPacketBufferPolicy::SoftReference:
		case RawPacketBufferPolicy::StrictReference:
			break;
		default:
			PCPP_LOG_ERROR("Invalid RawPacketBufferPolicy. Use Copy, Move, or Reference.");
			return false;
		}

		clear();

		switch (bufPolicy)
		{
		case RawPacketBufferPolicy::Copy:
		{
			// TODO: Consider reusing previous allocated buffer if the packet owns it and capacity is enough.
			m_RawData = new uint8_t[rawDataLen];
			m_DeleteRawDataAtDestructor = true;
			std::memcpy(m_RawData, pRawData, rawDataLen);
			break;
		}
		case RawPacketBufferPolicy::Move:
		{
			m_RawData = pRawData;
			m_DeleteRawDataAtDestructor = true;
			break;
		}
		case RawPacketBufferPolicy::StrictReference:
		{
			// StrictReference does not allow reallocation, so we set the flag to false
			m_ReallocationsAllowed = false;
			// fall through
		}
		case RawPacketBufferPolicy::SoftReference:
		{
			m_RawData = pRawData;
			m_DeleteRawDataAtDestructor = false;
			break;
		}
		}

		m_RawDataLen = rawDataLen;
		m_FrameLength = (frameLength == -1) ? rawDataLen : frameLength;
		m_RawDataCapacity = rawDataLen;
		setPacketTimeStamp(timestamp);
		setLinkLayerType(layerType);
		m_RawPacketSet = true;
		return true;
	}

	bool RawPacket::initWithRawData(const uint8_t* pRawData, int rawDataLen, timespec timestamp,
	                                LinkLayerType layerType)
	{
		// Legacy method for compatibility with older code. The method was used when assigning a raw buffer that is
		// externally managed.
		return setRawData(RawPacketBufferPolicy::SoftReference, const_cast<uint8_t*>(pRawData), rawDataLen, timestamp,
		                  layerType);
	}

	void RawPacket::clear()
	{
		if (m_RawData != nullptr && m_DeleteRawDataAtDestructor)
			delete[] m_RawData;

		m_RawData = nullptr;
		m_RawDataLen = 0;
		m_FrameLength = 0;
		m_RawDataCapacity = 0;
		m_RawPacketSet = false;
	}

	size_t RawPacket::appendData(const uint8_t* dataToAppend, size_t dataToAppendLen)
	{
		if (dataToAppend == nullptr || dataToAppendLen == 0)
			return 0;

		if (dataToAppendLen + m_RawDataLen > m_RawDataCapacity)
		{
			if (!m_ReallocationsAllowed)
			{
				PCPP_LOG_ERROR("Cannot append data to raw packet because reallocation is not allowed");
				return 0;
			}
			if (!reallocateData(m_RawDataLen + dataToAppendLen))
			{
				PCPP_LOG_ERROR("Failed to reallocate raw packet data buffer for appending new data");
				return 0;
			}
		}

		std::memcpy(m_RawData + m_RawDataLen, dataToAppend, dataToAppendLen);
		m_RawDataLen += dataToAppendLen;
		m_FrameLength = m_RawDataLen;
		return dataToAppendLen;
	}

	size_t RawPacket::insertData(int atIndex, const uint8_t* dataToInsert, size_t dataToInsertLen)
	{
		if (dataToInsert == nullptr || dataToInsertLen == 0)
			return 0;

		// Insert an empty data block at the specified index
		if (insertUninitializedData(atIndex, dataToInsertLen) != dataToInsertLen)
		{
			PCPP_LOG_ERROR("Failed to insert uninitialized data into raw packet");
			return 0;
		}

		// Insert the actual data into the raw packet at the specified index
		std::memcpy(m_RawData + atIndex, dataToInsert, dataToInsertLen);
		return dataToInsertLen;
	}

	size_t RawPacket::insertUninitializedData(int atIndex, size_t length)
	{
		if (length == 0)
			return 0;

		if (atIndex < 0 || atIndex > m_RawDataLen)
		{
			PCPP_LOG_ERROR("Index to insert uninitialized data is out of raw packet bound");
			return 0;
		}

		if (length + m_RawDataLen > m_RawDataCapacity)
		{
			if (!m_ReallocationsAllowed)
			{
				PCPP_LOG_ERROR("Cannot insert data to raw packet because reallocation is not allowed");
				return 0;
			}
			if (!reallocateData(length + m_RawDataLen))
			{
				PCPP_LOG_ERROR("Failed to reallocate raw packet data buffer for inserting new data");
				return 0;
			}
		}

		// memmove copies data as if there was an intermediate buffer in between - so it allows for copying processes on
		// overlapping src/dest ptrs if insertData is called with atIndex == m_RawDataLen, then no data is being moved.
		// The data of the raw packet is still extended by dataToInsertLen
		std::memmove(m_RawData + atIndex + length, m_RawData + atIndex, m_RawDataLen - atIndex);

		m_RawDataLen += length;
		m_FrameLength = m_RawDataLen;
		return length;
	}

	bool RawPacket::reallocateData(size_t newBufferLength)
	{
		if (newBufferLength == static_cast<size_t>(m_RawDataLen))
			return true;

		if (newBufferLength < static_cast<size_t>(m_RawDataLen))
		{
			PCPP_LOG_ERROR("Cannot reallocate raw packet to a smaller size. Current data length: "
			               << m_RawDataLen << "; requested length: " << newBufferLength);
			return false;
		}

		reserve(newBufferLength);
		return true;
	}

	bool RawPacket::reserve(size_t newCapacity)
	{
		if (newCapacity <= m_RawDataCapacity)
			return true;

		if (!m_ReallocationsAllowed)
		{
			PCPP_LOG_ERROR("Cannot reserve more space in raw packet because reallocation is not allowed");
			return false;
		}

		std::unique_ptr<uint8_t[]> newBuffer = std::make_unique<uint8_t[]>(newCapacity);

		// Copy the existing data to the new buffer if there is any
		if (m_RawData != nullptr && m_RawDataLen > 0)
		{
			std::memcpy(newBuffer.get(), m_RawData, m_RawDataLen);
		}

		// Zero out the rest of the new buffer. Is this necessary?
		std::memset(newBuffer.get() + m_RawDataLen, 0, newCapacity - m_RawDataLen);

		// Deallocates the old buffer if it was allocated and we own it
		if (m_RawData != nullptr && m_DeleteRawDataAtDestructor)
			delete[] m_RawData;

		// Sets the new buffer as the raw data buffer
		m_RawData = newBuffer.release();
		m_DeleteRawDataAtDestructor = true;
		m_RawDataCapacity = newCapacity;
		return true;
	}

	bool RawPacket::removeData(int atIndex, size_t numOfBytesToRemove)
	{
		if ((atIndex + (int)numOfBytesToRemove) > m_RawDataLen)
		{
			PCPP_LOG_ERROR("Remove section is out of raw packet bound");
			return false;
		}

		// only move data if we are removing data somewhere in the layer, not at the end of the last layer
		// this is so that resizing of the last layer can occur fast by just reducing the fictional length of the packet
		// (m_RawDataLen) by the given amount
		if ((atIndex + (int)numOfBytesToRemove) != m_RawDataLen)
			// memmove copies data as if there was an intermediate buffer in between - so it allows for copying
			// processes on overlapping src/dest ptrs
			memmove((uint8_t*)m_RawData + atIndex, (uint8_t*)m_RawData + atIndex + numOfBytesToRemove,
			        m_RawDataLen - (atIndex + numOfBytesToRemove));

		m_RawDataLen -= numOfBytesToRemove;
		m_FrameLength = m_RawDataLen;
		return true;
	}

	bool IRawPacket::isLinkTypeValid(int linkTypeValue)
	{
		if ((linkTypeValue < 0 || linkTypeValue > 264) && linkTypeValue != 276)
			return false;

		switch (static_cast<LinkLayerType>(linkTypeValue))
		{
		case LINKTYPE_ETHERNET:
		case LINKTYPE_LINUX_SLL:
		case LINKTYPE_RAW:
		case LINKTYPE_DLT_RAW1:
		case LINKTYPE_DLT_RAW2:
		case LINKTYPE_NULL:
		case LINKTYPE_AX25:
		case LINKTYPE_IEEE802_5:
		case LINKTYPE_ARCNET_BSD:
		case LINKTYPE_SLIP:
		case LINKTYPE_PPP:
		case LINKTYPE_FDDI:
		case LINKTYPE_PPP_HDLC:
		case LINKTYPE_PPP_ETHER:
		case LINKTYPE_ATM_RFC1483:
		case LINKTYPE_C_HDLC:
		case LINKTYPE_IEEE802_11:
		case LINKTYPE_FRELAY:
		case LINKTYPE_LOOP:
		case LINKTYPE_LTALK:
		case LINKTYPE_PFLOG:
		case LINKTYPE_IEEE802_11_PRISM:
		case LINKTYPE_IP_OVER_FC:
		case LINKTYPE_SUNATM:
		case LINKTYPE_IEEE802_11_RADIOTAP:
		case LINKTYPE_ARCNET_LINUX:
		case LINKTYPE_APPLE_IP_OVER_IEEE1394:
		case LINKTYPE_MTP2_WITH_PHDR:
		case LINKTYPE_MTP2:
		case LINKTYPE_MTP3:
		case LINKTYPE_SCCP:
		case LINKTYPE_DOCSIS:
		case LINKTYPE_LINUX_IRDA:
		case LINKTYPE_IEEE802_11_AVS:
		case LINKTYPE_BACNET_MS_TP:
		case LINKTYPE_PPP_PPPD:
		case LINKTYPE_GPRS_LLC:
		case LINKTYPE_GPF_T:
		case LINKTYPE_GPF_F:
		case LINKTYPE_LINUX_LAPD:
		case LINKTYPE_BLUETOOTH_HCI_H4:
		case LINKTYPE_USB_LINUX:
		case LINKTYPE_PPI:
		case LINKTYPE_IEEE802_15_4:
		case LINKTYPE_SITA:
		case LINKTYPE_ERF:
		case LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR:
		case LINKTYPE_AX25_KISS:
		case LINKTYPE_LAPD:
		case LINKTYPE_PPP_WITH_DIR:
		case LINKTYPE_C_HDLC_WITH_DIR:
		case LINKTYPE_FRELAY_WITH_DIR:
		case LINKTYPE_IPMB_LINUX:
		case LINKTYPE_IEEE802_15_4_NONASK_PHY:
		case LINKTYPE_USB_LINUX_MMAPPED:
		case LINKTYPE_FC_2:
		case LINKTYPE_FC_2_WITH_FRAME_DELIMS:
		case LINKTYPE_IPNET:
		case LINKTYPE_CAN_SOCKETCAN:
		case LINKTYPE_IPV4:
		case LINKTYPE_IPV6:
		case LINKTYPE_IEEE802_15_4_NOFCS:
		case LINKTYPE_DBUS:
		case LINKTYPE_DVB_CI:
		case LINKTYPE_MUX27010:
		case LINKTYPE_STANAG_5066_D_PDU:
		case LINKTYPE_NFLOG:
		case LINKTYPE_NETANALYZER:
		case LINKTYPE_NETANALYZER_TRANSPARENT:
		case LINKTYPE_IPOIB:
		case LINKTYPE_MPEG_2_TS:
		case LINKTYPE_NG40:
		case LINKTYPE_NFC_LLCP:
		case LINKTYPE_INFINIBAND:
		case LINKTYPE_SCTP:
		case LINKTYPE_USBPCAP:
		case LINKTYPE_RTAC_SERIAL:
		case LINKTYPE_BLUETOOTH_LE_LL:
		case LINKTYPE_NETLINK:
		case LINKTYPE_BLUETOOTH_LINUX_MONITOR:
		case LINKTYPE_BLUETOOTH_BREDR_BB:
		case LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR:
		case LINKTYPE_PROFIBUS_DL:
		case LINKTYPE_PKTAP:
		case LINKTYPE_EPON:
		case LINKTYPE_IPMI_HPM_2:
		case LINKTYPE_ZWAVE_R1_R2:
		case LINKTYPE_ZWAVE_R3:
		case LINKTYPE_WATTSTOPPER_DLM:
		case LINKTYPE_ISO_14443:
		case LINKTYPE_LINUX_SLL2:
			return true;
		default:
			return false;
		}
	}

}  // namespace pcpp
