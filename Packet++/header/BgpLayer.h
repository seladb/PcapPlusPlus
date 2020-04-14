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
 * @class BgpLayer
 * Represents an BGP v4 protocol layer
 */
class BgpLayer : public Layer
{
public:

  /**
   * An enum representing BGP message types
   */
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
   * @struct bgp_common_header
   * Represents the common field of every BGP 4 message
   */
  #pragma pack(push, 1)
  struct bgp_common_header
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

  BgpLayer() {}

  BgpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet) { m_Protocol = BGP; }

  bgp_common_header* getBasicHeader() const { return (bgp_common_header*)m_Data; }

  void setBgpFields(size_t messageLen = 0);

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
   * @struct bgp_open_message
   * BGP OPEN message structure
   */
  #pragma pack(push, 1)
  typedef struct : bgp_common_header
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

  struct optional_parameter
  {
    uint8_t type;
    uint8_t length;
    uint8_t value[32];

    optional_parameter() {}

    optional_parameter(uint8_t typeVal, std::string valueAsHexString);
  };

  /**
   * A constructor that creates the layer from an existing packet raw data
   * @param[in] data A pointer to the raw data (will be casted to @ref arphdr)
   * @param[in] dataLen Size of the data in bytes
   * @param[in] prevLayer A pointer to the previous layer
   * @param[in] packet A pointer to the Packet instance where layer will be stored in
   */
  BgpOpenMessageLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : BgpLayer(data, dataLen, prevLayer, packet) {}

  BgpOpenMessageLayer(uint16_t myAutonomousSystem, uint16_t holdTime, const IPv4Address& bgpId, 
    const std::vector<optional_parameter>& optionalParams = std::vector<optional_parameter>());

  bgp_open_message* getOpenMsgHeader() const { return (bgp_open_message*)m_Data; }

  IPv4Address getBgpIdAsIPv4Address() const { return IPv4Address(getOpenMsgHeader()->bgpId); }

  void getOptionalParameters(std::vector<optional_parameter>& optionalParameters);

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

private:

  size_t optionalParamsToByteArray(const std::vector<optional_parameter>& optionalParams, uint8_t* resultByteArr, size_t maxByteArrSize);

};



/**
 * @class BgpUpdateMessageLayer
 * Represents an BGP v4 UPDATE message
 */
class BgpUpdateMessageLayer : public BgpLayer
{
public:

  /**
   * @struct prefix_and_ip
   * A structure that contains IPv4 address and IP address mask (prefix) information. 
   * It's used to represent BGP Withdrawn Routes and Network Layer Reachability Information (NLRI)
   */
  struct prefix_and_ip
  {
    /** IPv4 address mask, must contain one of the values: 8, 16, 24, 32 */
    uint8_t prefix;
    /** IPv4 address */
    IPv4Address ipAddr;

    /**
     * A default c'tor that zeroes all data
     */
    prefix_and_ip(): prefix(0), ipAddr(IPv4Address::Zero) {}

    /**
     * A c'tor that initializes the values of the struct
     * @param[in] prefixVal IPv4 address mask value
     * @param[in] ipAddrVal IPv4 address
     */
    prefix_and_ip(uint8_t prefixVal, const std::string& ipAddrVal): prefix(prefixVal), ipAddr(ipAddrVal) {}
  };


  /**
   * @struct path_attribute
   * A structure that represents BGP Path Attributes information
   */
  struct path_attribute
  {
    /** Path attribute flags */
    uint8_t flags;
    /** Path attribute type */
    uint8_t type;
    /** Path attribute length */
    uint8_t length;
    /** Path attribute data. Max supported data length is 32 bytes */
    uint8_t data[32];

    /**
     * A default c'tor that zeroes all data
     */
    path_attribute() {}

    /**
     * A c'tor that initializes the values of the struct
     * @param[in] flagsVal Path attribute flags value
     * @param[in] typeVal Path attribute type value
     * @param[in] dataAsHexString Path attribute data as hex string. The length field will be set accordingly. 
     * If this parameter is not a valid hex string the data will remain zeroed and length will be also zero
     */
    path_attribute(uint8_t flagsVal, uint8_t typeVal, std::string dataAsHexString);
  };

  /**
   * A constructor that creates the layer from an existing packet raw data
   * @param[in] data A pointer to the raw data (will be casted to @ref arphdr)
   * @param[in] dataLen Size of the data in bytes
   * @param[in] prevLayer A pointer to the previous layer
   * @param[in] packet A pointer to the Packet instance where layer will be stored in
   */
  BgpUpdateMessageLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : BgpLayer(data, dataLen, prevLayer, packet) {}

  /**
   * A c'tor that creates a new BGP Update message
   * @param[in] withdrawnRoutes A vector of withdrawn routes data. If left empty (which is the default value) no withdrawn route information will be written to message
   * @param[in] pathAttributes A vector of path attributes data. If left empty (which is the default value) no path attribute information will be written to message
   * @param[in] nlri A vector of network layer reachability data. If left empty (which is the default value) no reachability information will be written to message
   */
  BgpUpdateMessageLayer(
    const std::vector<prefix_and_ip>& withdrawnRoutes = std::vector<prefix_and_ip>(),
    const std::vector<path_attribute>& pathAttributes = std::vector<path_attribute>(),
    const std::vector<prefix_and_ip>& nlri = std::vector<prefix_and_ip>());

  bgp_common_header* getBasicMsgHeader() const { return (bgp_common_header*)m_Data; }

  size_t getWithdrawnRoutesLength() const;

  void getWithdrawnRoutes(std::vector<prefix_and_ip>& withdrawnRoutes);

  size_t getPathAttributesLength() const;

  void getPathAttributes(std::vector<path_attribute>& pathAttributes);

  size_t getNetworkLayerReachabilityInfoLength() const;

  void getNetworkLayerReachabilityInfo(std::vector<prefix_and_ip>& nlri);

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

private:

  void parsePrefixAndIPData(uint8_t* dataPtr, size_t dataLen, std::vector<prefix_and_ip>& result);

  size_t prefixAndIPDataToByteArray(const std::vector<prefix_and_ip>& prefixAndIpData, uint8_t* resultByteArr, size_t maxByteArrSize);

  size_t pathAttributesToByteArray(const std::vector<path_attribute>& pathAttributes, uint8_t* resultByteArr, size_t maxByteArrSize);

};



/**
 * @class BgpNotificationMessageLayer
 * Represents an BGP v4 NOTIFICATION message
 */
class BgpNotificationMessageLayer : public BgpLayer
{
public:

  /**
   * @struct bgp_notification_message
   * BGP NOTIFICATION message structure
   */
  #pragma pack(push, 1)
  typedef struct : bgp_common_header
  {
    /** BGP notification error code */
    uint8_t errorCode;
    /** BGP notification error sub-code */
    uint8_t errorSubCode;
  } bgp_notification_message;
  #pragma pack(pop)

  /**
   * A constructor that creates the layer from an existing packet raw data
   * @param[in] data A pointer to the raw data (will be casted to @ref arphdr)
   * @param[in] dataLen Size of the data in bytes
   * @param[in] prevLayer A pointer to the previous layer
   * @param[in] packet A pointer to the Packet instance where layer will be stored in
   */
  BgpNotificationMessageLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : BgpLayer(data, dataLen, prevLayer, packet) {}

  /**
   * A c'tor that creates a new BGP Notification message
   * @param[in] errorCode BGP notification error code
   * @param[in] errorSubCode BGP notification error sub code
   */
  BgpNotificationMessageLayer(uint8_t errorCode, uint8_t errorSubCode);

  /**
   * A c'tor that creates a new BGP Notification message
   * @param[in] errorCode BGP notification error code
   * @param[in] errorSubCode BGP notification error sub code
   * @param[in] notificationData A byte array that contains the notification data
   * @param[in] notificationDataLen The size of the byte array that contains the notification data
   */
  BgpNotificationMessageLayer(uint8_t errorCode, uint8_t errorSubCode, const uint8_t* notificationData, size_t notificationDataLen);

  /**
   * A c'tor that creates a new BGP Notification message
   * @param[in] errorCode BGP notification error code
   * @param[in] errorSubCode BGP notification error sub code
   * @param[in] notificationData A hex string that contains the notification data. This string will be converted to a byte array that will be
   * added to the message. If the input isn't a valid hex string notification data will remain empty and an error will be printed to log
   */
  BgpNotificationMessageLayer(uint8_t errorCode, uint8_t errorSubCode, const std::string& notificationData);

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

private:

  void initMessageData(uint8_t errorCode, uint8_t errorSubCode, const uint8_t* notificationData, size_t notificationDataLen);

};



/**
 * @class BgpKeepaliveMessageLayer
 * Represents an BGP v4 KEEPALIVE message
 */
class BgpKeepaliveMessageLayer : public BgpLayer
{
public:

  /**
   * @typedef bpg_keepalive_message
   * BGP KEEPALIVE message structure
   */
  typedef bgp_common_header bpg_keepalive_message;

  /**
   * A constructor that creates the layer from an existing packet raw data
   * @param[in] data A pointer to the raw data (will be casted to @ref arphdr)
   * @param[in] dataLen Size of the data in bytes
   * @param[in] prevLayer A pointer to the previous layer
   * @param[in] packet A pointer to the Packet instance where layer will be stored in
   */
  BgpKeepaliveMessageLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : BgpLayer(data, dataLen, prevLayer, packet) {}

  /**
   * A c'tor that creates a new BGP KeepAlive message
   */
  BgpKeepaliveMessageLayer();

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
   * @struct bgp_route_refresh_message
   * BGP ROUTE-REFRESH message structure
   */
  #pragma pack(push, 1)
  typedef struct : bgp_common_header
  {
    /** Address Family Identifier */
    uint16_t afi;
    /** Reserved field */
    uint8_t reserved;
    /** Subsequent Address Family Identifier */
    uint8_t safi;
  } bgp_route_refresh_message;
  #pragma pack(pop)

  /**
   * A constructor that creates the layer from an existing packet raw data
   * @param[in] data A pointer to the raw data (will be casted to @ref arphdr)
   * @param[in] dataLen Size of the data in bytes
   * @param[in] prevLayer A pointer to the previous layer
   * @param[in] packet A pointer to the Packet instance where layer will be stored in
   */
  BgpRouteRefreshMessageLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : BgpLayer(data, dataLen, prevLayer, packet) {}

  /**
   * A c'tor that creates a new BGP Route-Refresh message
   * @param[in] afi The Address Family Identifier (AFI) value to set in the message
   * @param[in] safi The Subsequent Address Family Identifier (SAFI) value to set in the message
   */
  BgpRouteRefreshMessageLayer(uint16_t afi, uint8_t safi);

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