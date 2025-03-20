#define LOG_MODULE PacketLogModuleRawPacket

#include "RawPacket.h"
#include "Logger.h"
#include "TimespecTimeval.h"
#include <cstring>

namespace pcpp
{

	void RawPacket::init(bool deleteRawDataAtDestructor)
	{
		m_RawData = nullptr;
		m_RawDataLen = 0;
		m_FrameLength = 0;
		m_DeleteRawDataAtDestructor = deleteRawDataAtDestructor;
		m_RawPacketSet = false;
		m_LinkLayerType = LINKTYPE_ETHERNET;
	}

	RawPacket::RawPacket(const uint8_t* pRawData, int rawDataLen, timeval timestamp, bool deleteRawDataAtDestructor,
	                     LinkLayerType layerType)
	{
		timespec nsec_time = {};
		TIMEVAL_TO_TIMESPEC(&timestamp, &nsec_time);
		init(deleteRawDataAtDestructor);
		setRawData(pRawData, rawDataLen, nsec_time, layerType);
	}

	RawPacket::RawPacket(const uint8_t* pRawData, int rawDataLen, timespec timestamp, bool deleteRawDataAtDestructor,
	                     LinkLayerType layerType)
	{
		init(deleteRawDataAtDestructor);
		setRawData(pRawData, rawDataLen, timestamp, layerType);
	}

	RawPacket::RawPacket()
	{
		init();
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

		m_TimeStamp = other.m_TimeStamp;

		if (allocateData)
		{
			m_DeleteRawDataAtDestructor = true;
			m_RawData = new uint8_t[other.m_RawDataLen];
			m_RawDataLen = other.m_RawDataLen;
		}

		memcpy(m_RawData, other.m_RawData, other.m_RawDataLen);
		m_LinkLayerType = other.m_LinkLayerType;
		m_FrameLength = other.m_FrameLength;
		m_RawPacketSet = true;
	}

	bool RawPacket::setRawData(const uint8_t* pRawData, int rawDataLen, timeval timestamp, LinkLayerType layerType,
	                           int frameLength)
	{
		timespec nsec_time;
		TIMEVAL_TO_TIMESPEC(&timestamp, &nsec_time);
		return setRawData(pRawData, rawDataLen, nsec_time, layerType, frameLength);
	}

	bool RawPacket::setRawData(const uint8_t* pRawData, int rawDataLen, timespec timestamp, LinkLayerType layerType,
	                           int frameLength)
	{
		clear();

		m_FrameLength = (frameLength == -1) ? rawDataLen : frameLength;
		m_RawData = (uint8_t*)pRawData;
		m_RawDataLen = rawDataLen;
		m_TimeStamp = timestamp;
		m_RawPacketSet = true;
		m_LinkLayerType = layerType;
		return true;
	}

	bool RawPacket::initWithRawData(const uint8_t* pRawData, int rawDataLen, timespec timestamp,
	                                LinkLayerType layerType)
	{
		init(false);
		return setRawData(pRawData, rawDataLen, timestamp, layerType);
	}

	void RawPacket::clear()
	{
		if (m_RawData != nullptr && m_DeleteRawDataAtDestructor)
			delete[] m_RawData;

		m_RawData = nullptr;
		m_RawDataLen = 0;
		m_FrameLength = 0;
		m_RawPacketSet = false;
	}

	void RawPacket::appendData(const uint8_t* dataToAppend, size_t dataToAppendLen)
	{
		memcpy((uint8_t*)m_RawData + m_RawDataLen, dataToAppend, dataToAppendLen);
		m_RawDataLen += dataToAppendLen;
		m_FrameLength = m_RawDataLen;
	}

	void RawPacket::insertData(int atIndex, const uint8_t* dataToInsert, size_t dataToInsertLen)
	{
		// memmove copies data as if there was an intermediate buffer in between - so it allows for copying processes on
		// overlapping src/dest ptrs if insertData is called with atIndex == m_RawDataLen, then no data is being moved.
		// The data of the raw packet is still extended by dataToInsertLen
		memmove((uint8_t*)m_RawData + atIndex + dataToInsertLen, (uint8_t*)m_RawData + atIndex, m_RawDataLen - atIndex);

		if (dataToInsert != nullptr)
		{
			// insert data
			memcpy((uint8_t*)m_RawData + atIndex, dataToInsert, dataToInsertLen);
		}

		m_RawDataLen += dataToInsertLen;
		m_FrameLength = m_RawDataLen;
	}

	bool RawPacket::reallocateData(size_t newBufferLength)
	{
		if ((int)newBufferLength == m_RawDataLen)
			return true;

		if ((int)newBufferLength < m_RawDataLen)
		{
			PCPP_LOG_ERROR("Cannot reallocate raw packet to a smaller size. Current data length: "
			               << m_RawDataLen << "; requested length: " << newBufferLength);
			return false;
		}

		uint8_t* newBuffer = new uint8_t[newBufferLength];
		memset(newBuffer, 0, newBufferLength);
		memcpy(newBuffer, m_RawData, m_RawDataLen);
		if (m_DeleteRawDataAtDestructor)
			delete[] m_RawData;

		m_DeleteRawDataAtDestructor = true;
		m_RawData = newBuffer;

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

	bool RawPacket::setPacketTimeStamp(timeval timestamp)
	{
		timespec nsec_time;
		TIMEVAL_TO_TIMESPEC(&timestamp, &nsec_time);
		return setPacketTimeStamp(nsec_time);
	}

	bool RawPacket::setPacketTimeStamp(timespec timestamp)
	{
		m_TimeStamp = timestamp;
		return true;
	}

	bool RawPacket::isLinkTypeValid(int linkTypeValue)
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
