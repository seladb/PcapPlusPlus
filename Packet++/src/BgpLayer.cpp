#define LOG_MODULE PacketLogModuleBgpLayer

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
  if (m_DataLen < sizeof(bgp_basic_header))
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
  if (dataLen < sizeof(bgp_basic_header))
    return NULL;
  
  bgp_basic_header* bgpHeader = (bgp_basic_header*)data;
  
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
	if (m_DataLen <= headerLen)
		return;

	uint8_t* payload = m_Data + headerLen;
	size_t payloadLen = m_DataLen - headerLen;

  m_NextLayer = BgpLayer::parseBgpLayer(payload, payloadLen, this, m_Packet);
}

std::string BgpLayer::toString() const
{
  return "BGP Layer, " + getMessageTypeAsString() + " message";
}

void BgpLayer::computeGeneralBGPCalculateFields()
{
	bgp_basic_header* bgpHeader = getBasicHeader();
  memset(bgpHeader->marker, 1, 16*sizeof(uint8_t));
  bgpHeader->messageType = (uint8_t)getBgpMessageType();
  bgpHeader->length = htobe16(getHeaderLen());
}


// ~~~~~~~~~~~~~~~~~~~~~
// BgpUpdateMessageLayer
// ~~~~~~~~~~~~~~~~~~~~~

size_t BgpUpdateMessageLayer::getWithdrawnRoutesLength() const
{
  size_t headerLen = getHeaderLen();
  size_t minLen = sizeof(bgp_basic_header) + sizeof(uint16_t);
  if (headerLen >= minLen)
  {
    uint16_t res = be16toh(*(uint16_t*)(m_Data + sizeof(bgp_basic_header)));
    if ((size_t)res > headerLen - minLen)
    {
      return headerLen - minLen;
    }

    return (size_t)res;
  }

  return 0;
}

void BgpUpdateMessageLayer::getWithdrawnRoutes(std::vector<withdrawn_route>& withdrawnRoutes)
{
  size_t withdrawnRouteLen = getWithdrawnRoutesLength();
  if (withdrawnRouteLen == 0)
  {
    return;
  }

  uint8_t* dataPtr = m_Data + sizeof(bgp_basic_header) + sizeof(uint16_t);
  size_t byteCount = 0;
  while (byteCount < withdrawnRouteLen)
  {
    withdrawn_route wr;
    wr.prefix = dataPtr[0];
    size_t curByteCount = 1;
    if (wr.prefix == 32)
    {
      wr.ipAddr = IPv4Address(dataPtr[1], dataPtr[2], dataPtr[3], dataPtr[4]);
      curByteCount += 4;
    }
    else if (wr.prefix == 24)
    {
      wr.ipAddr = IPv4Address(dataPtr[1], dataPtr[2], dataPtr[3], 0);
      curByteCount += 3;
    }
    else if (wr.prefix == 16)
    {
      wr.ipAddr = IPv4Address(dataPtr[1], dataPtr[2], 0, 0);
      curByteCount += 2;
    }
    else if (wr.prefix == 8)
    {
      wr.ipAddr = IPv4Address(dataPtr[1], 0, 0, 0);
      curByteCount += 1;
    }
    else
    {
      LOG_DEBUG("Illegal prefix value %d", (int)wr.prefix);
      break; // illegal value
    }

    withdrawnRoutes.push_back(wr);
    dataPtr += curByteCount;
    byteCount += curByteCount;
  }
}

size_t BgpUpdateMessageLayer::getPathAttributesLength() const
{
  size_t headerLen = getHeaderLen();
  size_t minLen = sizeof(bgp_basic_header) + 2*sizeof(uint16_t);
  if (headerLen >= minLen)
  {
    size_t withdrawnRouteLen = getWithdrawnRoutesLength();
    uint16_t res = be16toh(*(uint16_t*)(m_Data + sizeof(bgp_basic_header) + sizeof(uint16_t) + withdrawnRouteLen));
    if ((size_t)res > headerLen - minLen - withdrawnRouteLen)
    {
      return headerLen - minLen - withdrawnRouteLen;
    }

    return (size_t)res;
  }

  return 0;
}

void BgpUpdateMessageLayer::getPathAttributes(std::vector<path_attribute>& pathAttributes)
{
  size_t pathAttrLen = getPathAttributesLength();
  if (pathAttrLen == 0)
  {
    return;
  }

  uint8_t* dataPtr = m_Data + sizeof(bgp_basic_header) + 2*sizeof(uint16_t) + getWithdrawnRoutesLength();
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


// ~~~~~~~~~~~~~~~~~~~~~~~~~~~
// BgpNotificationMessageLayer
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~

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

}
