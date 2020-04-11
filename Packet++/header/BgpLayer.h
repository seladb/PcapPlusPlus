#ifndef PACKETPP_BGP_LAYER
#define PACKETPP_BGP_LAYER

#include <vector>
#include "Layer.h"
#include "IpAddress.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

/**
 * @struct radius_header
 * Represents a RADIUS protocol header
 */
#pragma pack(push, 1)
	struct bgp_basic_header
	{
		/** 16-octet marker */
		uint8_t marker[16];
		/** Total length of the message, including the header */
		uint16_t length;
		/** BGP message type */
		uint8_t messageType;
	};
#pragma pack(pop)

/**
 * @typedef bpg_keepalive_message
 * BGP KEEPALIVE message structure
 */
typedef bgp_basic_header bpg_keepalive_message;

/**
 * @struct bgp_open_message
 * BGP OPEN message structure
 */
#pragma pack(push, 1)
	typedef struct : bgp_basic_header
	{
		/** BGP version number */
		uint8_t version;
    /** Autonomous System number of the sender */
    uint16_t myAutonomousSystem;
    /** The number of seconds the sender proposes for the value of the Hold Timer */
    uint16_t holdTime;
    /** BGP Identifier of the sender */
    uint32_t bgpId;
    /** The total length of the Optional Parameters field */
    uint8_t optionalParameterLength;
	} bgp_open_message;
#pragma pack(pop)

/**
 * @struct bgp_notification_message
 * BGP NOTIFICATION message structure
 */
#pragma pack(push, 1)
	typedef struct : bgp_basic_header
	{
		/** BGP notification error code */
		uint8_t errorCode;
    /** BGP notification error sub-code */
    uint8_t errorSubCode;
	} bgp_notification_message;
#pragma pack(pop)

/**
 * @struct bgp_route_refresh_message
 * BGP ROUTE-REFRESH message structure
 */
#pragma pack(push, 1)
	typedef struct : bgp_basic_header
	{
		/** Address Family Identifier */
		uint16_t afi;
    /** Reserved field */
    uint8_t reserved;
    /** Subsequent Address Family Identifier */
    uint16_t safi;
	} bgp_route_refresh_message;
#pragma pack(pop)


/**
 * @class BgpLayer
 * Represents an BGP v4 protocol layer
 */
class BgpLayer : public Layer
{
public:

  enum BgpMessageType
  {
    Unknown = 0,
    Open = 1,
    Update = 2,
    Notification = 3,
    Keepalive = 4,
    RouteRefresh = 5,
  };

  /**
   * @return BGP message type
   */
  virtual BgpMessageType getBgpMessageType() const = 0;

  /**
   * @return BGP message type as string. Return value can be one of the following options:
   * "OPEN", "UPDATE", "NOTIFICATION", "KEEPALIVE", "ROUTE-REFRESH", "Unknown"
   */
  std::string getMessageTypeAsString() const;

  /**
   * A static method that checks whether the port is considered as BGP
   * @param[in] port The port number to be checked
   */
  static bool isBgpPort(uint16_t portSrc, uint16_t portDst) { return portSrc == 179 || portDst == 179; }

  /**
   * A method that creates a BGP layer from an existing packet raw data
   * @param[in] data A pointer to the raw data (will be casted to @ref arphdr)
   * @param[in] dataLen Size of the data in bytes
   * @param[in] prevLayer A pointer to the previous layer
   * @param[in] packet A pointer to the Packet instance where layer will be stored in
   * @return A newly allocated BGP layer of one of the following types (according to the message type):
   * BgpOpenMessageLayer, BgpUpdateMessageLayer, BgpNotificationMessageLayer, BgpKeepaliveMessageLayer, 
   * BgpRouteRefreshMessageLayer
   */
  static BgpLayer* parseBgpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

  // implement abstract methods

  /**
   * @return The size of the BGP message
   */
  size_t getHeaderLen() const;

  /**
   * Multiple BGP messages can reside in a single packet, and the only layer that can come after a BGP message
   * is another BGP message. This method checks for remaining data and parses it as another BGP layer
   */
  void parseNextLayer();

  std::string toString() const;

  OsiModelLayer getOsiModelLayer() const { return OsiModelApplicationLayer; }

protected:

  // protected c'tors, this class cannot be instanciated by users

  BgpLayer();

  BgpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet) { m_Protocol = BGP; }

  bgp_basic_header* getBasicHeader() const { return (bgp_basic_header*)m_Data; }

  void computeGeneralBGPCalculateFields();

};



/**
 * @class BgpOpenMessageLayer
 * Represents an BGP v4 OPEN message
 */
class BgpOpenMessageLayer : public BgpLayer
{
public:
  /**
   * A constructor that creates the layer from an existing packet raw data
   * @param[in] data A pointer to the raw data (will be casted to @ref arphdr)
   * @param[in] dataLen Size of the data in bytes
   * @param[in] prevLayer A pointer to the previous layer
   * @param[in] packet A pointer to the Packet instance where layer will be stored in
   */
  BgpOpenMessageLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : BgpLayer(data, dataLen, prevLayer, packet) {}

  bgp_open_message* getOpenMsgHeader() const { return (bgp_open_message*)m_Data; }

  IPv4Address getBgpIdAsIPv4Address() const { return IPv4Address(getOpenMsgHeader()->bgpId); }

  // implement abstract methods

  BgpMessageType getBgpMessageType() const { return BgpLayer::Open; }

  /**
   * Calculates the basic BGP fields:
   * - Set marker to all ones
   * - Set message type as OPEN (1)
   * - Set message length
   * ................
   */
  void computeCalculateFields() { computeGeneralBGPCalculateFields(); }

};



/**
 * @class BgpUpdateMessageLayer
 * Represents an BGP v4 UPDATE message
 */
class BgpUpdateMessageLayer : public BgpLayer
{
public:

  struct withdrawn_route
  {
    uint8_t prefix;
    IPv4Address ipAddr;
    withdrawn_route(): prefix(0), ipAddr(IPv4Address::Zero) {}
  };

  struct path_attribute
  {
    uint8_t flags;
    uint8_t type;
    uint8_t length;
    uint8_t data[32];
  };

  /**
   * A constructor that creates the layer from an existing packet raw data
   * @param[in] data A pointer to the raw data (will be casted to @ref arphdr)
   * @param[in] dataLen Size of the data in bytes
   * @param[in] prevLayer A pointer to the previous layer
   * @param[in] packet A pointer to the Packet instance where layer will be stored in
   */
  BgpUpdateMessageLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : BgpLayer(data, dataLen, prevLayer, packet) {}

  bgp_basic_header* getBasicMsgHeader() const { return (bgp_basic_header*)m_Data; }

  size_t getWithdrawnRoutesLength() const;

  void getWithdrawnRoutes(std::vector<withdrawn_route>& withdrawnRoutes);

  size_t getPathAttributesLength() const;

  void getPathAttributes(std::vector<path_attribute>& pathAttributes);

  // implement abstract methods

  BgpMessageType getBgpMessageType() const { return BgpLayer::Update; }

  /**
   * Calculates the basic BGP fields:
   * - Set marker to all ones
   * - Set message type as UPDATE (2)
   * - Set message length
   * ................
   */
  void computeCalculateFields() { computeGeneralBGPCalculateFields(); }

};



/**
 * @class BgpNotificationMessageLayer
 * Represents an BGP v4 NOTIFICATION message
 */
class BgpNotificationMessageLayer : public BgpLayer
{
public:
  /**
   * A constructor that creates the layer from an existing packet raw data
   * @param[in] data A pointer to the raw data (will be casted to @ref arphdr)
   * @param[in] dataLen Size of the data in bytes
   * @param[in] prevLayer A pointer to the previous layer
   * @param[in] packet A pointer to the Packet instance where layer will be stored in
   */
  BgpNotificationMessageLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : BgpLayer(data, dataLen, prevLayer, packet) {}

  bgp_notification_message* getNotificationMsgHeader() const { return (bgp_notification_message*)m_Data; }

  size_t getNotificationDataLen() const;

  uint8_t* getNotificationData() const;

  std::string getNotificationDataAsHexString() const;

  // implement abstract methods

  BgpMessageType getBgpMessageType() const { return BgpLayer::Notification; }

  /**
   * Calculates the basic BGP fields:
   * - Set marker to all ones
   * - Set message type as NOTIFICATION (3)
   * - Set message length
   * ................
   */
  void computeCalculateFields() { computeGeneralBGPCalculateFields(); }

};



/**
 * @class BgpKeepaliveMessageLayer
 * Represents an BGP v4 KEEPALIVE message
 */
class BgpKeepaliveMessageLayer : public BgpLayer
{
public:
  /**
   * A constructor that creates the layer from an existing packet raw data
   * @param[in] data A pointer to the raw data (will be casted to @ref arphdr)
   * @param[in] dataLen Size of the data in bytes
   * @param[in] prevLayer A pointer to the previous layer
   * @param[in] packet A pointer to the Packet instance where layer will be stored in
   */
  BgpKeepaliveMessageLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : BgpLayer(data, dataLen, prevLayer, packet) {}

  bpg_keepalive_message* getKeepaliveHeader() const { return (bpg_keepalive_message*)getBasicHeader(); }

  // implement abstract methods

  BgpMessageType getBgpMessageType() const { return BgpLayer::Keepalive; }

  /**
   * Calculates the basic BGP fields:
   * - Set marker to all ones
   * - Set message type as KEEPALIVE (4)
   * - Set message length
   */
  void computeCalculateFields() { computeGeneralBGPCalculateFields(); }

};



/**
 * @class BgpRouteRefreshMessageLayer
 * Represents an BGP v4 ROUTE-REFRESH message
 */
class BgpRouteRefreshMessageLayer : public BgpLayer
{
public:
  /**
   * A constructor that creates the layer from an existing packet raw data
   * @param[in] data A pointer to the raw data (will be casted to @ref arphdr)
   * @param[in] dataLen Size of the data in bytes
   * @param[in] prevLayer A pointer to the previous layer
   * @param[in] packet A pointer to the Packet instance where layer will be stored in
   */
  BgpRouteRefreshMessageLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : BgpLayer(data, dataLen, prevLayer, packet) {}

  bgp_route_refresh_message* getRouteRefreshHeader() const { return (bgp_route_refresh_message*)getBasicHeader(); }

  // implement abstract methods

  BgpMessageType getBgpMessageType() const { return BgpLayer::RouteRefresh; }

  /**
   * Calculates the basic BGP fields:
   * - Set marker to all ones
   * - Set message type as ROUTE-REFRESH (5)
   * - Set message length
   */
  void computeCalculateFields() { computeGeneralBGPCalculateFields(); }

};

}

#endif //PACKETPP_BGP_LAYER