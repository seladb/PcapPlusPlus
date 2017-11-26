#define LOG_MODULE PacketLogModuleIgmpLayer

#include "IgmpLayer.h"
#include "IpUtils.h"
#include "Logger.h"
#include <string.h>
#ifdef WIN32 //for using ntohl, ntohs, etc.
#include <winsock2.h>
#elif LINUX
#include <in.h> //for using ntohl, ntohs, etc.
#elif MAC_OS_X
#include <arpa/inet.h> //for using ntohl, ntohs, etc.
#endif

namespace pcpp
{

/*************
 * IgmpLayer
 *************/

IgmpLayer::IgmpLayer(IgmpType type, const IPv4Address& groupAddr, uint8_t maxResponseTime, ProtocolType igmpVer)
{
	m_DataLen = getHeaderSizeByVerAndType(igmpVer, type);
	m_Data = new uint8_t[m_DataLen];
	memset(m_Data, 0, m_DataLen);
	m_Protocol = igmpVer;

	setType(type);
	if (groupAddr != IPv4Address::Zero)
		setGroupAddress(groupAddr);

	getIgmpHeader()->maxResponseTime = maxResponseTime;
}

void IgmpLayer::setGroupAddress(const IPv4Address& groupAddr)
{
	igmp_header* hdr = getIgmpHeader();
	hdr->groupAddress = groupAddr.toInt();
}

IgmpType IgmpLayer::getType()
{
	uint8_t type = getIgmpHeader()->type;
	if (type < (uint8_t)IgmpType_MembershipQuery ||
			(type > (uint8_t)IgmpType_LeaveGroup && type < (uint8_t)IgmpType_MulticastTracerouteResponse) ||
			(type > (uint8_t)IgmpType_MulticastTraceroute && type < (uint8_t)IgmpType_MembershipReportV3) ||
			(type > (uint8_t)IgmpType_MembershipReportV3 && type < (uint8_t)IgmpType_MulticastRouterAdvertisement) ||
			type > IgmpType_MulticastRouterTermination)
		return IgmpType_Unknown;

	return (IgmpType)type;
}

void IgmpLayer::setType(IgmpType type)
{
	if (type == IgmpType_Unknown)
		return;

	igmp_header* hdr = getIgmpHeader();
	hdr->type = type;
}

ProtocolType IgmpLayer::getIGMPVerFromData(uint8_t* data, size_t dataLen, bool& isQuery)
{
	isQuery = false;

	if (dataLen < 8 || data == NULL)
		return UnknownProtocol;

	switch ((int)data[0])
	{
	case IgmpType_MembershipReportV2:
	case IgmpType_LeaveGroup:
		return IGMPv2;
	case IgmpType_MembershipReportV1:
		return IGMPv1;
	case IgmpType_MembershipReportV3:
		return IGMPv3;
	case IgmpType_MembershipQuery:
	{
		isQuery = true;

		if (dataLen >= sizeof(igmpv3_query_header))
			return IGMPv3;

		if (data[1] == 0)
			return IGMPv1;
		else
			return IGMPv2;
	}
	default:
		return UnknownProtocol;
	}
}

uint16_t IgmpLayer::calculateChecksum()
{
	ScalarBuffer<uint16_t> buffer;
	buffer.buffer = (uint16_t*)getIgmpHeader();
	buffer.len = getHeaderLen();
	return compute_checksum(&buffer, 1);
}

size_t IgmpLayer::getHeaderSizeByVerAndType(ProtocolType igmpVer, IgmpType igmpType)
{
	if (igmpVer == IGMPv1 || igmpVer == IGMPv2)
		return sizeof(igmp_header);

	if (igmpVer == IGMPv3)
	{
		if (igmpType == IgmpType_MembershipQuery)
			return sizeof(igmpv3_query_header);
		else if (igmpType == IgmpType_MembershipReportV3)
			return sizeof(igmpv3_report_header);
	}

	return 0;
}

std::string IgmpLayer::toString()
{
	std::string igmpVer = "";
	switch (getProtocol())
	{
	case IGMPv1:
		igmpVer = "1";
		break;
	case IGMPv2:
		igmpVer = "2";
		break;
	default:
		igmpVer = "3";
	}

	std::string msgType;

	switch (getType())
	{
	case IgmpType_MembershipQuery:
		msgType = "Membership Query";
		break;
	case IgmpType_MembershipReportV1:
		msgType = "Membership Report";
		break;
	case IgmpType_DVMRP:
		msgType = "DVMRP";
		break;
	case IgmpType_P1Mv1:
		msgType = "PIMv1";
		break;
	case IgmpType_CiscoTrace:
		msgType = "Cisco Trace";
		break;
	case IgmpType_MembershipReportV2:
		msgType = "Membership Report";
		break;
	case IgmpType_LeaveGroup:
		msgType = "Leave Group";
		break;
	case IgmpType_MulticastTracerouteResponse:
		msgType = "Multicast Traceroute Response";
		break;
	case IgmpType_MulticastTraceroute:
		msgType = "Multicast Traceroute";
		break;
	case IgmpType_MembershipReportV3:
		msgType = "Membership Report";
		break;
	case IgmpType_MulticastRouterAdvertisement:
		msgType = "Multicast Router Advertisement";
		break;
	case IgmpType_MulticastRouterSolicitation:
		msgType = "Multicast Router Solicitation";
		break;
	case IgmpType_MulticastRouterTermination:
		msgType = "Multicast Router Termination";
		break;
	default:
		msgType = "Unknown";
		break;
	}

	std::string result = "IGMPv" + igmpVer + " Layer, " + msgType + " message";
	return result;
}




/*************
 * IgmpV1Layer
 *************/

IgmpV1Layer::IgmpV1Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) :
		IgmpLayer(data, dataLen, prevLayer, packet, IGMPv1)
{
}

IgmpV1Layer::IgmpV1Layer(IgmpType type, const IPv4Address& groupAddr) :
		IgmpLayer(type, groupAddr, 0, IGMPv1)
{
}

void IgmpV1Layer::computeCalculateFields()
{
	igmp_header* hdr = getIgmpHeader();
	hdr->checksum = 0;
	hdr->checksum = htons(calculateChecksum());
	hdr->maxResponseTime = 0;
}





/*************
 * IgmpV2Layer
 *************/

IgmpV2Layer::IgmpV2Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) :
		IgmpLayer(data, dataLen, prevLayer, packet, IGMPv2)
{
}

IgmpV2Layer::IgmpV2Layer(IgmpType type, const IPv4Address& groupAddr, uint8_t maxResponseTime) :
		IgmpLayer(type, groupAddr, maxResponseTime, IGMPv2)
{
}

void IgmpV2Layer::computeCalculateFields()
{
	igmp_header* hdr = getIgmpHeader();
	hdr->checksum = 0;
	hdr->checksum = htons(calculateChecksum());
}





/******************
 * IgmpV3QueryLayer
 ******************/


IgmpV3QueryLayer::IgmpV3QueryLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) :
		IgmpLayer(data, dataLen, prevLayer, packet, IGMPv3)
{
}

IgmpV3QueryLayer::IgmpV3QueryLayer(const IPv4Address& multicastAddr, uint8_t maxResponseTime, uint8_t s_qrv) :
		IgmpLayer(IgmpType_MembershipQuery, multicastAddr, maxResponseTime, IGMPv3)
{
	getIgmpV3QueryHeader()->s_qrv = s_qrv;
}

uint16_t IgmpV3QueryLayer::getSourceAddressCount()
{
	return ntohs(getIgmpV3QueryHeader()->numOfSources);
}

IPv4Address IgmpV3QueryLayer::getSourceAddressAtIndex(int index)
{
	uint16_t numOfSources = getSourceAddressCount();
	if (index < 0 || index >= numOfSources)
		return IPv4Address::Zero;

	// verify numOfRecords is a reasonable number that points to data within the packet
	int ptrOffset = index * sizeof(uint32_t) + sizeof(igmpv3_query_header);
	if (ptrOffset + sizeof(uint32_t) > getDataLen())
		return IPv4Address::Zero;

	uint8_t* ptr = m_Data + ptrOffset;
	return IPv4Address(*(uint32_t*)ptr);
}

size_t IgmpV3QueryLayer::getHeaderLen()
{
	uint16_t numOfSources = getSourceAddressCount();

	int headerLen = numOfSources * sizeof(uint32_t) + sizeof(igmpv3_query_header);

	// verify numOfRecords is a reasonable number that points to data within the packet
	if ((size_t)headerLen > getDataLen())
		return getDataLen();

	return (size_t)headerLen;
}

void IgmpV3QueryLayer::computeCalculateFields()
{
	igmpv3_query_header* hdr = getIgmpV3QueryHeader();
	hdr->checksum = 0;
	hdr->checksum = htons(calculateChecksum());
}

bool IgmpV3QueryLayer::addSourceAddress(const IPv4Address& addr)
{
	return addSourceAddressAtIndex(addr, getSourceAddressCount());
}

bool IgmpV3QueryLayer::addSourceAddressAtIndex(const IPv4Address& addr, int index)
{
	uint16_t sourceAddrCount = getSourceAddressCount();

	if (index < 0 || index > (int)sourceAddrCount)
	{
		LOG_ERROR("Cannot add source address at index %d, index is out of bounds", index);
		return false;
	}

	size_t offset = sizeof(igmpv3_query_header) + index * sizeof(uint32_t);
	if (offset > getHeaderLen())
	{
		LOG_ERROR("Cannot add source address at index %d, index is out of packet bounds", index);
		return false;
	}

	if (!extendLayer(offset, sizeof(uint32_t)))
	{
		LOG_ERROR("Cannot add source address at index %d, didn't manage to extend layer", index);
		return false;
	}

	uint32_t addrAsInt = addr.toInt();
	memcpy(m_Data + offset, &addrAsInt, sizeof(uint32_t));

	getIgmpV3QueryHeader()->numOfSources = htons(sourceAddrCount+1);

	return true;
}

bool IgmpV3QueryLayer::removeSourceAddressAtIndex(int index)
{
	uint16_t sourceAddrCount = getSourceAddressCount();

	if (index < 0 || index > (int)sourceAddrCount-1)
	{
		LOG_ERROR("Cannot remove source address at index %d, index is out of bounds", index);
		return false;
	}

	size_t offset = sizeof(igmpv3_query_header) + index * sizeof(uint32_t);
	if (offset >= getHeaderLen())
	{
		LOG_ERROR("Cannot remove source address at index %d, index is out of packet bounds", index);
		return false;
	}

	if (!shortenLayer(offset, sizeof(uint32_t)))
	{
		LOG_ERROR("Cannot remove source address at index %d, didn't manage to shorten layer", index);
		return false;
	}

	getIgmpV3QueryHeader()->numOfSources = htons(sourceAddrCount-1);

	return true;
}

bool IgmpV3QueryLayer::removeAllSourceAddresses()
{
	size_t offset = sizeof(igmpv3_query_header);
	size_t numOfBytesToShorted = getHeaderLen() - offset;

	if (!shortenLayer(offset, numOfBytesToShorted))
	{
		LOG_ERROR("Cannot remove all source addresses, didn't manage to shorten layer");
		return false;
	}

	getIgmpV3QueryHeader()->numOfSources = 0;

	return true;
}





/*******************
 * IgmpV3ReportLayer
 *******************/

IgmpV3ReportLayer::IgmpV3ReportLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) :
		IgmpLayer(data, dataLen, prevLayer, packet, IGMPv3)
{
}

IgmpV3ReportLayer::IgmpV3ReportLayer() :
		IgmpLayer(IgmpType_MembershipReportV3, IPv4Address::Zero, 0, IGMPv3)
{
}

uint16_t IgmpV3ReportLayer::getGroupRecordCount()
{
	return ntohs(getReportHeader()->numOfGroupRecords);

}

igmpv3_group_record* IgmpV3ReportLayer::getFirstGroupRecord()
{
	// check if there are group records at all
	if (getHeaderLen() <= sizeof(igmpv3_report_header))
		return NULL;

	uint8_t* curGroupPtr = m_Data + sizeof(igmpv3_report_header);
	return (igmpv3_group_record*)curGroupPtr;
}

igmpv3_group_record* IgmpV3ReportLayer::getNextGroupRecord(igmpv3_group_record* groupRecord)
{
	if (groupRecord == NULL)
		return NULL;

	// prev group was the last group
	if ((uint8_t*)groupRecord + groupRecord->getRecordLen() - m_Data >= (int)getHeaderLen())
		return NULL;

	igmpv3_group_record* nextGroup = (igmpv3_group_record*)((uint8_t*)groupRecord + groupRecord->getRecordLen());

	return nextGroup;
}

size_t IgmpV3ReportLayer::getHeaderLen()
{
	return m_DataLen;
}

void IgmpV3ReportLayer::computeCalculateFields()
{
	igmpv3_report_header* hdr = getReportHeader();
	hdr->checksum = 0;
	hdr->checksum = htons(calculateChecksum());
}

igmpv3_group_record* IgmpV3ReportLayer::addGroupRecordAt(uint8_t recordType, const IPv4Address& multicastAddress, const std::vector<IPv4Address>& sourceAddresses, int offset)
{
	if (offset > (int)getHeaderLen())
	{
		LOG_ERROR("Cannot add group record, offset is out of layer bounds");
		return NULL;
	}

	size_t groupRecordSize = sizeof(igmpv3_group_record) + sizeof(uint32_t)*sourceAddresses.size();

	if (!extendLayer(offset, groupRecordSize))
	{
		LOG_ERROR("Cannot add group record, cannot extend layer");
		return NULL;
	}

	uint8_t* groupRecordBuffer = new uint8_t[groupRecordSize];
	memset(groupRecordBuffer, 0, groupRecordSize);
	igmpv3_group_record* newGroupRecord = (igmpv3_group_record*)groupRecordBuffer;
	newGroupRecord->multicastAddress = multicastAddress.toInt();
	newGroupRecord->recordType = recordType;
	newGroupRecord->auxDataLen = 0;
	newGroupRecord->numOfSources = htons(sourceAddresses.size());

	int srcAddrOffset = 0;
	for (std::vector<IPv4Address>::const_iterator iter = sourceAddresses.begin(); iter != sourceAddresses.end(); iter++)
	{
		uint32_t addrAsInt = iter->toInt();
		memcpy(newGroupRecord->sourceAddresses + srcAddrOffset, &addrAsInt, sizeof(uint32_t));
		srcAddrOffset += sizeof(uint32_t);
	}

	memcpy(m_Data + offset, groupRecordBuffer, groupRecordSize);

	delete[] groupRecordBuffer;

	getReportHeader()->numOfGroupRecords = htons(getGroupRecordCount() + 1);

	return (igmpv3_group_record*)(m_Data + offset);
}

igmpv3_group_record* IgmpV3ReportLayer::addGroupRecord(uint8_t recordType, const IPv4Address& multicastAddress, const std::vector<IPv4Address>& sourceAddresses)
{
	return addGroupRecordAt(recordType, multicastAddress, sourceAddresses, (int)getHeaderLen());
}

igmpv3_group_record* IgmpV3ReportLayer::addGroupRecordAtIndex(uint8_t recordType, const IPv4Address& multicastAddress, const std::vector<IPv4Address>& sourceAddresses, int index)
{
	int groupCnt = (int)getGroupRecordCount();

	if (index < 0 || index > groupCnt)
	{
		LOG_ERROR("Cannot add group record, index %d out of bounds", index);
		return NULL;
	}

	size_t offset = sizeof(igmpv3_report_header);

	igmpv3_group_record* curRecord = getFirstGroupRecord();
	for (int i = 0; i < index; i++)
	{
		if (curRecord == NULL)
		{
			LOG_ERROR("Cannot add group record, cannot find group record at index %d", i);
			return NULL;
		}

		offset += curRecord->getRecordLen();
		curRecord = getNextGroupRecord(curRecord);
	}

	return addGroupRecordAt(recordType, multicastAddress, sourceAddresses, (int)offset);
}

bool IgmpV3ReportLayer::removeGroupRecordAtIndex(int index)
{
	int groupCnt = (int)getGroupRecordCount();

	if (index < 0 || index >= groupCnt)
	{
		LOG_ERROR("Cannot remove group record, index %d is out of bounds", index);
		return false;
	}

	size_t offset = sizeof(igmpv3_report_header);

	igmpv3_group_record* curRecord = getFirstGroupRecord();
	for (int i = 0; i < index; i++)
	{
		if (curRecord == NULL)
		{
			LOG_ERROR("Cannot remove group record at index %d, cannot find group record at index %d", index, i);
			return false;
		}

		offset += curRecord->getRecordLen();
		curRecord = getNextGroupRecord(curRecord);
	}

	if (!shortenLayer((int)offset, curRecord->getRecordLen()))
	{
		LOG_ERROR("Cannot remove group record at index %d, cannot shorted layer", index);
		return false;
	}

	getReportHeader()->numOfGroupRecords = htons(groupCnt-1);

	return true;
}

bool IgmpV3ReportLayer::removeAllGroupRecords()
{
	int offset = (int)sizeof(igmpv3_report_header);

	if (!shortenLayer(offset, getHeaderLen()-offset))
	{
		LOG_ERROR("Cannot remove all group records, cannot shorted layer");
		return false;
	}

	getReportHeader()->numOfGroupRecords = 0;
	return true;
}






/*********************
 * igmpv3_group_record
 *********************/

IPv4Address igmpv3_group_record::getMulticastAddress()
{
	return IPv4Address(multicastAddress);
}

uint16_t igmpv3_group_record::getSourceAdressCount()
{
	return ntohs(numOfSources);
}

IPv4Address igmpv3_group_record::getSoruceAddressAtIndex(int index)
{
	uint16_t numOfRecords = getSourceAdressCount();
	if (index < 0 || index >= numOfRecords)
		return IPv4Address::Zero;

	int offset = index * sizeof(uint32_t);
	uint8_t* ptr = sourceAddresses + offset;
	return IPv4Address(*(uint32_t*)ptr);
}

size_t igmpv3_group_record::getRecordLen()
{
	uint16_t numOfRecords = getSourceAdressCount();

	int headerLen = numOfRecords * sizeof(uint32_t) + sizeof(igmpv3_group_record);
	return (size_t)headerLen;
}

}
