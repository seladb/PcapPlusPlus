#define LOG_MODULE PacketLogModuleBgpLayer

#include <string.h>
#include "Logger.h"
#include "BgpLayer.h"
#include "EndianPortable.h"
#include "GeneralUtils.h"

namespace pcpp
{
// ~~~~~~~~
// BgpLayer
// ~~~~~~~~

size_t BgpLayer::getHeaderLen() const
{
	if (m_DataLen < sizeof(bgp_common_header))
	{
		return m_DataLen;
	}

	uint16_t messageLen = be16toh(getBasicHeader()->length);
	if (m_DataLen < messageLen)
	{
		return m_DataLen;
	}

	return (size_t)messageLen;
}

BgpLayer* BgpLayer::parseBgpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
{
	if (dataLen < sizeof(bgp_common_header))
		return NULL;

	bgp_common_header* bgpHeader = (bgp_common_header*)data;

	// illegal header data - length is too small
	if (be16toh(bgpHeader->length) < static_cast<uint16_t>(sizeof(bgp_common_header)))
		return NULL;

	switch (bgpHeader->messageType)
	{
	case 1: // OPEN
		return new BgpOpenMessageLayer(data, dataLen, prevLayer, packet);
	case 2: // UPDATE
		return new BgpUpdateMessageLayer(data, dataLen, prevLayer, packet);
	case 3: // NOTIFICATION
		return new BgpNotificationMessageLayer(data, dataLen, prevLayer, packet);
	case 4: // KEEPALIVE
		return new BgpKeepaliveMessageLayer(data, dataLen, prevLayer, packet);
	case 5: // ROUTE-REFRESH
		return new BgpRouteRefreshMessageLayer(data, dataLen, prevLayer, packet);
	default:
		return NULL;
	}
}

std::string BgpLayer::getMessageTypeAsString() const
{
	switch (getBgpMessageType())
	{
		case BgpLayer::Open:
			return "OPEN";
		case BgpLayer::Update:
			return "UPDATE";
		case BgpLayer::Notification:
			return "NOTIFICATION";
		case BgpLayer::Keepalive:
			return "KEEPALIVE";
		case BgpLayer::RouteRefresh:
			return "ROUTE-REFRESH";
		default:
			return "Unknown";
	}
}

void BgpLayer::parseNextLayer()
{
	size_t headerLen = getHeaderLen();
	if (m_DataLen <= headerLen || headerLen == 0)
		return;

	uint8_t* payload = m_Data + headerLen;
	size_t payloadLen = m_DataLen - headerLen;

	m_NextLayer = BgpLayer::parseBgpLayer(payload, payloadLen, this, m_Packet);
}

std::string BgpLayer::toString() const
{
	return "BGP Layer, " + getMessageTypeAsString() + " message";
}

void BgpLayer::computeCalculateFields()
{
	bgp_common_header* bgpHeader = getBasicHeader();
	memset(bgpHeader->marker, 0xff, 16*sizeof(uint8_t));
	bgpHeader->messageType = (uint8_t)getBgpMessageType();
	bgpHeader->length = htobe16(getHeaderLen());
}

void BgpLayer::setBgpFields(size_t messageLen)
{
	bgp_common_header* bgpHdr = getBasicHeader();
	memset(bgpHdr->marker, 0xff, 16*sizeof(uint8_t));
	bgpHdr->messageType = (uint8_t)getBgpMessageType();
	if (messageLen != 0)
	{
		bgpHdr->length = htobe16((uint16_t)messageLen);
	}
	else
	{
		bgpHdr->length = m_DataLen;
	}
}



// ~~~~~~~~~~~~~~~~~~~~
// BgpOpenMessageLayer
// ~~~~~~~~~~~~~~~~~~~~

BgpOpenMessageLayer::optional_parameter::optional_parameter(uint8_t typeVal, std::string valueAsHexString)
{
	type = typeVal;
	length = hexStringToByteArray(valueAsHexString, value, 32);
}

BgpOpenMessageLayer::BgpOpenMessageLayer(uint16_t myAutonomousSystem, uint16_t holdTime, const IPv4Address& bgpId,
		const std::vector<optional_parameter>& optionalParams)
{
	uint8_t optionalParamsData[1500];
	size_t optionalParamsDataLen = optionalParamsToByteArray(optionalParams, optionalParamsData, 1500);

	const size_t headerLen = sizeof(bgp_open_message) + optionalParamsDataLen;
	m_DataLen = headerLen;
	m_Data = new uint8_t[headerLen];
	memset(m_Data, 0, headerLen);
	setBgpFields(headerLen);

	bgp_open_message* msgHdr = getOpenMsgHeader();
	msgHdr->version = 4;
	msgHdr->myAutonomousSystem = htobe16(myAutonomousSystem);
	msgHdr->holdTime = htobe16(holdTime);
	msgHdr->bgpId = bgpId.toInt();
	msgHdr->optionalParameterLength = optionalParamsDataLen;
	if (optionalParamsDataLen > 0)
	{
		memcpy(m_Data + sizeof(bgp_open_message), optionalParamsData, optionalParamsDataLen);
	}

	m_Protocol = BGP;
}

size_t BgpOpenMessageLayer::optionalParamsToByteArray(const std::vector<optional_parameter>& optionalParams, uint8_t* resultByteArr, size_t maxByteArrSize)
{
	if (resultByteArr == NULL || maxByteArrSize == 0)
	{
		return 0;
	}

	size_t dataLen = 0;

	for (std::vector<optional_parameter>::const_iterator iter = optionalParams.begin(); iter != optionalParams.end(); iter++)
	{
		if (iter->length > 32)
		{
			PCPP_LOG_ERROR("Illegal optional parameter length " << (int)iter->length << ", must be 32 bytes or less");
			break; // illegal value
		}

		size_t curDataSize = 2*sizeof(uint8_t) + (size_t)iter->length;

		if (dataLen + curDataSize > maxByteArrSize)
		{
			break;
		}

		resultByteArr[0] = iter->type;
		resultByteArr[1] = iter->length;
		if (iter->length > 0)
		{
			memcpy(resultByteArr + 2*sizeof(uint8_t), iter->value, iter->length);
		}

		dataLen += curDataSize;
		resultByteArr += curDataSize;
	}

	return dataLen;
}

void BgpOpenMessageLayer::setBgpId(const IPv4Address& newBgpId)
{
	if (!newBgpId.isValid())
	{
		return;
	}

	bgp_open_message* msgHdr = getOpenMsgHeader();
	if (msgHdr == NULL)
	{
		return;
	}

	msgHdr->bgpId = newBgpId.toInt();
}

void BgpOpenMessageLayer::getOptionalParameters(std::vector<optional_parameter>& optionalParameters)
{
	bgp_open_message* msgHdr = getOpenMsgHeader();
	if (msgHdr == NULL || msgHdr->optionalParameterLength == 0)
	{
		return;
	}

	size_t optionalParamsLen = (size_t)be16toh(msgHdr->optionalParameterLength);

	if (optionalParamsLen > getHeaderLen() - sizeof(bgp_open_message))
	{
		optionalParamsLen = getHeaderLen() - sizeof(bgp_open_message);
	}

	uint8_t* dataPtr = m_Data + sizeof(bgp_open_message);
	size_t byteCount = 0;
	while (byteCount < optionalParamsLen)
	{
		optional_parameter op;
		op.type = dataPtr[0];
		op.length = dataPtr[1];

		if (op.length > optionalParamsLen - byteCount)
		{
			PCPP_LOG_ERROR("Optional parameter length is out of bounds: " << (int)op.length);
			break;
		}

		if (op.length > 0)
		{
			memcpy(op.value, dataPtr + 2*sizeof(uint8_t), (op.length > 32 ? 32 : op.length));
		}

		optionalParameters.push_back(op);
		size_t totalLen = 2 + (size_t)op.length;
		byteCount += totalLen;
		dataPtr += totalLen;
	}
}

size_t BgpOpenMessageLayer::getOptionalParametersLength()
{
	bgp_open_message* msgHdr = getOpenMsgHeader();
	if (msgHdr != NULL)
	{
		return (size_t)(msgHdr->optionalParameterLength);
	}

	return 0;
}

bool BgpOpenMessageLayer::setOptionalParameters(const std::vector<optional_parameter>& optionalParameters)
{
	uint8_t newOptionalParamsData[1500];
	size_t newOptionalParamsDataLen = optionalParamsToByteArray(optionalParameters, newOptionalParamsData, 1500);
	size_t curOptionalParamsDataLen = getOptionalParametersLength();

	if (newOptionalParamsDataLen > curOptionalParamsDataLen)
	{
		bool res = extendLayer(sizeof(bgp_open_message), newOptionalParamsDataLen - curOptionalParamsDataLen);
		if (!res)
		{
			PCPP_LOG_ERROR("Couldn't extend BGP open layer to include the additional optional parameters");
			return res;
		}
	}
	else if (newOptionalParamsDataLen < curOptionalParamsDataLen)
	{
		bool res = shortenLayer(sizeof(bgp_open_message), curOptionalParamsDataLen - newOptionalParamsDataLen);
		if (!res)
		{
			PCPP_LOG_ERROR("Couldn't shorten BGP open layer to set the right size of the optional parameters data");
			return res;
		}
	}

	if (newOptionalParamsDataLen > 0)
	{
		memcpy(m_Data + sizeof(bgp_open_message), newOptionalParamsData, newOptionalParamsDataLen);
	}

	getOpenMsgHeader()->optionalParameterLength = (uint8_t)newOptionalParamsDataLen;
	getOpenMsgHeader()->length = htobe16(sizeof(bgp_open_message) + newOptionalParamsDataLen);

	return true;
}

bool BgpOpenMessageLayer::clearOptionalParameters()
{
	return setOptionalParameters(std::vector<optional_parameter>());
}



// ~~~~~~~~~~~~~~~~~~~~~
// BgpUpdateMessageLayer
// ~~~~~~~~~~~~~~~~~~~~~

BgpUpdateMessageLayer::path_attribute::path_attribute(uint8_t flagsVal, uint8_t typeVal, std::string dataAsHexString)
{
	flags = flagsVal;
	type = typeVal;
	length = hexStringToByteArray(dataAsHexString, data, 32);
}

BgpUpdateMessageLayer::BgpUpdateMessageLayer(
		const std::vector<prefix_and_ip>& withdrawnRoutes,
		const std::vector<path_attribute>& pathAttributes,
		const std::vector<prefix_and_ip>& nlri)
{
	uint8_t withdrawnRoutesData[1500];
	uint8_t pathAttributesData[1500];
	uint8_t nlriData[1500];
	size_t withdrawnRoutesDataLen = prefixAndIPDataToByteArray(withdrawnRoutes, withdrawnRoutesData, 1500);
	size_t pathAttributesDataLen = pathAttributesToByteArray(pathAttributes, pathAttributesData, 1500);
	size_t nlriDataLen = prefixAndIPDataToByteArray(nlri, nlriData, 1500);

	size_t headerLen = sizeof(bgp_common_header) + 2*sizeof(uint16_t) + withdrawnRoutesDataLen + pathAttributesDataLen + nlriDataLen;
	m_DataLen = headerLen;
	m_Data = new uint8_t[headerLen];
	memset(m_Data, 0, headerLen);
	setBgpFields(headerLen);

	uint8_t* dataPtr = m_Data + sizeof(bgp_common_header);

	// copy withdrawn routes data
	uint16_t withdrawnRoutesDataLenBE = htobe16(withdrawnRoutesDataLen);
	memcpy(dataPtr, &withdrawnRoutesDataLenBE, sizeof(uint16_t));
	dataPtr += sizeof(uint16_t);
	if (withdrawnRoutesDataLen > 0)
	{
		memcpy(dataPtr, withdrawnRoutesData, withdrawnRoutesDataLen);
		dataPtr += withdrawnRoutesDataLen;
	}

	// copy path attributes data
	uint16_t pathAttributesDataLenBE = htobe16(pathAttributesDataLen);
	memcpy(dataPtr, &pathAttributesDataLenBE, sizeof(uint16_t));
	dataPtr += sizeof(uint16_t);
	if (pathAttributesDataLen > 0)
	{
		memcpy(dataPtr, pathAttributesData, pathAttributesDataLen);
		dataPtr += pathAttributesDataLen;
	}

	// copy nlri data
	if (nlriDataLen > 0)
	{
		memcpy(dataPtr, nlriData, nlriDataLen);
	}

	m_Protocol = BGP;
}

void BgpUpdateMessageLayer::parsePrefixAndIPData(uint8_t* dataPtr, size_t dataLen, std::vector<prefix_and_ip>& result)
{
	size_t byteCount = 0;
	while (byteCount < dataLen)
	{
		prefix_and_ip wr;
		wr.prefix = dataPtr[0];
		size_t curByteCount = 1;
		if (wr.prefix == 32)
		{
			uint8_t octets[4] = { dataPtr[1], dataPtr[2], dataPtr[3], dataPtr[4] };
			wr.ipAddr = IPv4Address(octets);
			curByteCount += 4;
		}
		else if (wr.prefix == 24)
		{
			uint8_t octets[4] = { dataPtr[1], dataPtr[2], dataPtr[3], 0 };
			wr.ipAddr = IPv4Address(octets);
			curByteCount += 3;
		}
		else if (wr.prefix == 16)
		{
			uint8_t octets[4] = { dataPtr[1], dataPtr[2], 0, 0 };
			wr.ipAddr = IPv4Address(octets);
			curByteCount += 2;
		}
		else if (wr.prefix == 8)
		{
			uint8_t octets[4] = { dataPtr[1], 0, 0, 0 };
			wr.ipAddr = IPv4Address(octets);
			curByteCount += 1;
		}
		else
		{
			PCPP_LOG_DEBUG("Illegal prefix value " << (int)wr.prefix);
			break; // illegal value
		}

		result.push_back(wr);
		dataPtr += curByteCount;
		byteCount += curByteCount;
	}
}

size_t BgpUpdateMessageLayer::prefixAndIPDataToByteArray(const std::vector<prefix_and_ip>& prefixAndIpData, uint8_t* resultByteArr, size_t maxByteArrSize)
{
	if (resultByteArr == NULL || maxByteArrSize == 0)
	{
		return 0;
	}

	size_t dataLen = 0;

	for (std::vector<prefix_and_ip>::const_iterator iter = prefixAndIpData.begin(); iter != prefixAndIpData.end(); iter++)
	{
		uint8_t curData[5];
		curData[0] = iter->prefix;
		size_t curDataSize = 1;
		const uint8_t* octets = iter->ipAddr.toBytes();
		if (iter->prefix == 32)
		{
			curDataSize += 4;
			curData[1] = octets[0];
			curData[2] = octets[1];
			curData[3] = octets[2];
			curData[4] = octets[3];
		}
		else if (iter->prefix == 24)
		{
			curDataSize += 3;
			curData[1] = octets[0];
			curData[2] = octets[1];
			curData[3] = octets[2];
		}
		else if (iter->prefix == 16)
		{
			curDataSize += 2;
			curData[1] = octets[0];
			curData[2] = octets[1];
		}
		else if (iter->prefix == 8)
		{
			curDataSize += 1;
			curData[1] = octets[0];
		}
		else
		{
			PCPP_LOG_ERROR("Illegal prefix value " << (int)iter->prefix);
			break; // illegal value
		}

		if (dataLen + curDataSize > maxByteArrSize)
		{
			break;
		}

		dataLen += curDataSize;

		memcpy(resultByteArr, curData, curDataSize);
		resultByteArr += curDataSize;
	}

	return dataLen;
}

size_t BgpUpdateMessageLayer::pathAttributesToByteArray(const std::vector<path_attribute>& pathAttributes, uint8_t* resultByteArr, size_t maxByteArrSize)
{
	if (resultByteArr == NULL || maxByteArrSize == 0)
	{
		return 0;
	}

	size_t dataLen = 0;

	for (std::vector<path_attribute>::const_iterator iter = pathAttributes.begin(); iter != pathAttributes.end(); iter++)
	{
		if (iter->length > 32)
		{
			PCPP_LOG_ERROR("Illegal path attribute length " << (int)iter->length);
			break; // illegal value
		}

		size_t curDataSize = 3*sizeof(uint8_t) + (size_t)iter->length;

		if (dataLen + curDataSize > maxByteArrSize)
		{
			break;
		}

		resultByteArr[0] = iter->flags;
		resultByteArr[1] = iter->type;
		resultByteArr[2] = iter->length;
		if (iter->length > 0)
		{
			memcpy(resultByteArr + 3*sizeof(uint8_t), iter->data, iter->length);
		}

		dataLen += curDataSize;
		resultByteArr += curDataSize;
	}

	return dataLen;
}

size_t BgpUpdateMessageLayer::getWithdrawnRoutesLength() const
{
	size_t headerLen = getHeaderLen();
	size_t minLen = sizeof(bgp_common_header) + sizeof(uint16_t);
	if (headerLen >= minLen)
	{
		uint16_t res = be16toh(*(uint16_t*)(m_Data + sizeof(bgp_common_header)));
		if ((size_t)res > headerLen - minLen)
		{
			return headerLen - minLen;
		}

		return (size_t)res;
	}

	return 0;
}

void BgpUpdateMessageLayer::getWithdrawnRoutes(std::vector<prefix_and_ip>& withdrawnRoutes)
{
	size_t withdrawnRouteLen = getWithdrawnRoutesLength();
	if (withdrawnRouteLen == 0)
	{
		return;
	}

	uint8_t* dataPtr = m_Data + sizeof(bgp_common_header) + sizeof(uint16_t);
	parsePrefixAndIPData(dataPtr, withdrawnRouteLen, withdrawnRoutes);
}

size_t BgpUpdateMessageLayer::getPathAttributesLength() const
{
	size_t headerLen = getHeaderLen();
	size_t minLen = sizeof(bgp_common_header) + 2*sizeof(uint16_t);
	if (headerLen >= minLen)
	{
		size_t withdrawnRouteLen = getWithdrawnRoutesLength();
		uint16_t res = be16toh(*(uint16_t*)(m_Data + sizeof(bgp_common_header) + sizeof(uint16_t) + withdrawnRouteLen));
		if ((size_t)res > headerLen - minLen - withdrawnRouteLen)
		{
			return headerLen - minLen - withdrawnRouteLen;
		}

		return (size_t)res;
	}

	return 0;
}

bool BgpUpdateMessageLayer::setWithdrawnRoutes(const std::vector<prefix_and_ip>& withdrawnRoutes)
{
	uint8_t newWithdrawnRoutesData[1500];
	size_t newWithdrawnRoutesDataLen = prefixAndIPDataToByteArray(withdrawnRoutes, newWithdrawnRoutesData, 1500);
	size_t curWithdrawnRoutesDataLen = getWithdrawnRoutesLength();

	if (newWithdrawnRoutesDataLen > curWithdrawnRoutesDataLen)
	{
		bool res = extendLayer(sizeof(bgp_common_header) + sizeof(uint16_t), newWithdrawnRoutesDataLen - curWithdrawnRoutesDataLen);
		if (!res)
		{
			PCPP_LOG_ERROR("Couldn't extend BGP update layer to include the additional withdrawn routes");
			return res;
		}
	}
	else if (newWithdrawnRoutesDataLen < curWithdrawnRoutesDataLen)
	{
		bool res = shortenLayer(sizeof(bgp_common_header) + sizeof(uint16_t), curWithdrawnRoutesDataLen - newWithdrawnRoutesDataLen);
		if (!res)
		{
			PCPP_LOG_ERROR("Couldn't shorten BGP update layer to set the right size of the withdrawn routes data");
			return res;
		}
	}

	if (newWithdrawnRoutesDataLen > 0)
	{
		memcpy(m_Data + sizeof(bgp_common_header) + sizeof(uint16_t), newWithdrawnRoutesData, newWithdrawnRoutesDataLen);
	}

	getBasicHeader()->length = htobe16(be16toh(getBasicHeader()->length) + newWithdrawnRoutesDataLen - curWithdrawnRoutesDataLen);

	uint16_t newWithdrawnRoutesDataLenBE = htobe16(newWithdrawnRoutesDataLen);
	memcpy(m_Data + sizeof(bgp_common_header), &newWithdrawnRoutesDataLenBE, sizeof(uint16_t));

	return true;
}

bool BgpUpdateMessageLayer::clearWithdrawnRoutes()
{
	return setWithdrawnRoutes(std::vector<prefix_and_ip>());
}

void BgpUpdateMessageLayer::getPathAttributes(std::vector<path_attribute>& pathAttributes)
{
	size_t pathAttrLen = getPathAttributesLength();
	if (pathAttrLen == 0)
	{
		return;
	}

	uint8_t* dataPtr = m_Data + sizeof(bgp_common_header) + 2*sizeof(uint16_t) + getWithdrawnRoutesLength();
	size_t byteCount = 0;
	while (byteCount < pathAttrLen)
	{
		path_attribute pa;
		pa.flags = dataPtr[0];
		pa.type = dataPtr[1];
		pa.length = dataPtr[2];
		size_t curByteCount = 3 + pa.length;
		if (pa.length > 0)
		{
			size_t dataLenToCopy = (pa.length <= 32 ? pa.length : 32);
			memcpy(pa.data, dataPtr+3, dataLenToCopy);
		}

		pathAttributes.push_back(pa);
		dataPtr += curByteCount;
		byteCount += curByteCount;
	}
}

bool BgpUpdateMessageLayer::setPathAttributes(const std::vector<path_attribute>& pathAttributes)
{
	uint8_t newPathAttributesData[1500];
	size_t newPathAttributesDataLen = pathAttributesToByteArray(pathAttributes, newPathAttributesData, 1500);
	size_t curPathAttributesDataLen = getPathAttributesLength();
	size_t curWithdrawnRoutesDataLen = getWithdrawnRoutesLength();

	if (newPathAttributesDataLen > curPathAttributesDataLen)
	{
		bool res = extendLayer(sizeof(bgp_common_header) + 2*sizeof(uint16_t) + curWithdrawnRoutesDataLen, newPathAttributesDataLen - curPathAttributesDataLen);
		if (!res)
		{
			PCPP_LOG_ERROR("Couldn't extend BGP update layer to include the additional path attributes");
			return res;
		}
	}
	else if (newPathAttributesDataLen < curPathAttributesDataLen)
	{
		bool res = shortenLayer(sizeof(bgp_common_header) + 2*sizeof(uint16_t) + curWithdrawnRoutesDataLen, curPathAttributesDataLen - newPathAttributesDataLen);
		if (!res)
		{
			PCPP_LOG_ERROR("Couldn't shorten BGP update layer to set the right size of the path attributes data");
			return res;
		}
	}

	if (newPathAttributesDataLen > 0)
	{
		memcpy(m_Data + sizeof(bgp_common_header) + 2*sizeof(uint16_t) + curWithdrawnRoutesDataLen, newPathAttributesData, newPathAttributesDataLen);
	}

	getBasicHeader()->length = htobe16(be16toh(getBasicHeader()->length) + newPathAttributesDataLen - curPathAttributesDataLen);

	uint16_t newWithdrawnRoutesDataLenBE = htobe16(newPathAttributesDataLen);
	memcpy(m_Data + sizeof(bgp_common_header) + sizeof(uint16_t) + curWithdrawnRoutesDataLen, &newWithdrawnRoutesDataLenBE, sizeof(uint16_t));

	return true;
}

bool BgpUpdateMessageLayer::clearPathAttributes()
{
	return setPathAttributes(std::vector<path_attribute>());
}

size_t BgpUpdateMessageLayer::getNetworkLayerReachabilityInfoLength() const
{
	size_t headerLen = getHeaderLen();
	size_t minLen = sizeof(bgp_common_header) + 2*sizeof(uint16_t);
	if (headerLen >= minLen)
	{
		size_t withdrawnRouteLen = getWithdrawnRoutesLength();
		size_t pathAttrLen = getPathAttributesLength();
		int nlriSize = headerLen - minLen - withdrawnRouteLen - pathAttrLen;
		if (nlriSize >= 0)
		{
			return (size_t)nlriSize;
		}

		return 0;
	}

	return 0;
}

void BgpUpdateMessageLayer::getNetworkLayerReachabilityInfo(std::vector<prefix_and_ip>& nlri)
{
	size_t nlriSize = getNetworkLayerReachabilityInfoLength();
	if (nlriSize == 0)
	{
		return;
	}

	uint8_t* dataPtr = m_Data + sizeof(bgp_common_header) + 2*sizeof(uint16_t) + getWithdrawnRoutesLength() + getPathAttributesLength();
	parsePrefixAndIPData(dataPtr, nlriSize, nlri);
}

bool BgpUpdateMessageLayer::setNetworkLayerReachabilityInfo(const std::vector<prefix_and_ip>& nlri)
{
	uint8_t newNlriData[1500];
	size_t newNlriDataLen = prefixAndIPDataToByteArray(nlri, newNlriData, 1500);
	size_t curNlriDataLen = getNetworkLayerReachabilityInfoLength();
	size_t curPathAttributesDataLen = getPathAttributesLength();
	size_t curWithdrawnRoutesDataLen = getWithdrawnRoutesLength();

	if (newNlriDataLen > curNlriDataLen)
	{
		bool res = extendLayer(sizeof(bgp_common_header) + 2*sizeof(uint16_t) + curWithdrawnRoutesDataLen + curPathAttributesDataLen, newNlriDataLen - curNlriDataLen);
		if (!res)
		{
			PCPP_LOG_ERROR("Couldn't extend BGP update layer to include the additional NLRI data");
			return res;
		}
	}
	else if (newNlriDataLen < curNlriDataLen)
	{
		bool res = shortenLayer(sizeof(bgp_common_header) + 2*sizeof(uint16_t) + curWithdrawnRoutesDataLen + curPathAttributesDataLen, curNlriDataLen - newNlriDataLen);
		if (!res)
		{
			PCPP_LOG_ERROR("Couldn't shorten BGP update layer to set the right size of the NLRI data");
			return res;
		}
	}

	if (newNlriDataLen > 0)
	{
		memcpy(m_Data + sizeof(bgp_common_header) + 2*sizeof(uint16_t) + curWithdrawnRoutesDataLen + curPathAttributesDataLen, newNlriData, newNlriDataLen);
	}

	getBasicHeader()->length = htobe16(be16toh(getBasicHeader()->length) + newNlriDataLen - curNlriDataLen);

	return true;
}

bool BgpUpdateMessageLayer::clearNetworkLayerReachabilityInfo()
{
	return setNetworkLayerReachabilityInfo(std::vector<prefix_and_ip>());
}




// ~~~~~~~~~~~~~~~~~~~~~~~~~~~
// BgpNotificationMessageLayer
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~

BgpNotificationMessageLayer::BgpNotificationMessageLayer(uint8_t errorCode, uint8_t errorSubCode)
{
	initMessageData(errorCode, errorSubCode, NULL, 0);
}

BgpNotificationMessageLayer::BgpNotificationMessageLayer(uint8_t errorCode, uint8_t errorSubCode, const uint8_t* notificationData, size_t notificationDataLen)
{
	initMessageData(errorCode, errorSubCode, notificationData, notificationDataLen);
}

BgpNotificationMessageLayer::BgpNotificationMessageLayer(uint8_t errorCode, uint8_t errorSubCode, const std::string& notificationData)
{
	uint8_t notificationDataByteArr[1500];
	size_t notificationDataLen = hexStringToByteArray(notificationData, notificationDataByteArr, 1500);
	initMessageData(errorCode, errorSubCode, notificationDataByteArr, notificationDataLen);
}

void BgpNotificationMessageLayer::initMessageData(uint8_t errorCode, uint8_t errorSubCode, const uint8_t* notificationData, size_t notificationDataLen)
{
	size_t headerLen = sizeof(bgp_notification_message);
	if (notificationData != NULL && notificationDataLen > 0)
	{
		headerLen += notificationDataLen;
	}
	m_DataLen = headerLen;
	m_Data = new uint8_t[headerLen];
	memset(m_Data, 0, headerLen);
	setBgpFields(headerLen);
	bgp_notification_message* msgHdr = getNotificationMsgHeader();
	msgHdr->errorCode = errorCode;
	msgHdr->errorSubCode = errorSubCode;
	memcpy(m_Data + sizeof(bgp_notification_message), notificationData, notificationDataLen);
	m_Protocol = BGP;
}

size_t BgpNotificationMessageLayer::getNotificationDataLen() const
{
	size_t headerLen = getHeaderLen();
	if (headerLen > sizeof(bgp_notification_message))
	{
		return headerLen - sizeof(bgp_notification_message);
	}

	return 0;
}

uint8_t* BgpNotificationMessageLayer::getNotificationData() const
{
	if (getNotificationDataLen() > 0)
	{
		return m_Data + sizeof(bgp_notification_message);
	}

	return NULL;
}

std::string BgpNotificationMessageLayer::getNotificationDataAsHexString() const
{
	uint8_t* notificationData = getNotificationData();
	if (notificationData == NULL)
	{
		return "";
	}

	return byteArrayToHexString(notificationData, getNotificationDataLen());
}

bool BgpNotificationMessageLayer::setNotificationData(const uint8_t* newNotificationData, size_t newNotificationDataLen)
{
	if (newNotificationData == NULL)
	{
		newNotificationDataLen = 0;
	}

	size_t curNotificationDataLen = getNotificationDataLen();

	if (newNotificationDataLen > curNotificationDataLen)
	{
		bool res = extendLayer(sizeof(bgp_notification_message), newNotificationDataLen - curNotificationDataLen);
		if (!res)
		{
			PCPP_LOG_ERROR("Couldn't extend BGP notification layer to include the additional notification data");
			return res;
		}
	}
	else if (newNotificationDataLen < curNotificationDataLen)
	{
		bool res = shortenLayer(sizeof(bgp_notification_message), curNotificationDataLen - newNotificationDataLen);
		if (!res)
		{
			PCPP_LOG_ERROR("Couldn't shorten BGP notification layer to set the right size of the notification data");
			return res;
		}
	}

	if (newNotificationDataLen > 0)
	{
		memcpy(m_Data + sizeof(bgp_notification_message), newNotificationData, newNotificationDataLen);
	}

	getNotificationMsgHeader()->length = htobe16(sizeof(bgp_notification_message) + newNotificationDataLen);

	return true;
}

bool BgpNotificationMessageLayer::setNotificationData(const std::string& newNotificationDataAsHexString)
{
	if (newNotificationDataAsHexString.empty())
	{
		return setNotificationData(NULL, 0);
	}

	uint8_t newNotificationData[1500];
	size_t newNotificationDataLen = hexStringToByteArray(newNotificationDataAsHexString, newNotificationData, 1500);

	if (newNotificationDataLen == 0)
	{
		PCPP_LOG_ERROR("newNotificationDataAsHexString is not a valid hex string");
		return false;
	}

	return setNotificationData(newNotificationData, newNotificationDataLen);
}



// ~~~~~~~~~~~~~~~~~~~~~~~~
// BgpKeepaliveMessageLayer
// ~~~~~~~~~~~~~~~~~~~~~~~~

BgpKeepaliveMessageLayer::BgpKeepaliveMessageLayer() : BgpLayer()
{
	const size_t headerLen = sizeof(bgp_common_header);
	m_DataLen = headerLen;
	m_Data = new uint8_t[headerLen];
	memset(m_Data, 0, headerLen);
	setBgpFields(headerLen);
	m_Protocol = BGP;
}



// ~~~~~~~~~~~~~~~~~~~~~~~~~~~
// BgpRouteRefreshMessageLayer
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~

BgpRouteRefreshMessageLayer::BgpRouteRefreshMessageLayer(uint16_t afi, uint8_t safi)
{
	const size_t headerLen = sizeof(bgp_route_refresh_message);
	m_DataLen = headerLen;
	m_Data = new uint8_t[headerLen];
	memset(m_Data, 0, headerLen);
	setBgpFields(headerLen);
	bgp_route_refresh_message* msgHdr = getRouteRefreshHeader();
	msgHdr->afi = htobe16(afi);
	msgHdr->safi = safi;
	m_Protocol = BGP;
}

}
