#pragma once

#include <vector>
#include "Layer.h"
#include "IpAddress.h"

/// @file
/// This file contains classes for parsing, creating and editing Border Gateway Protocol (BGP) version 4 packets.
/// It contains an abstract class named BgpLayer which has common functionality and 5 inherited classes that
/// represent the different BGP message types: OPEN, UPDATE, NOTIFICATION, KEEPALIVE and ROUTE-REFRESH.
/// Each of these classes contains unique functionality for parsing. creating and editing of these message.

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{

	/// @class BgpLayer
	/// Represents Border Gateway Protocol (BGP) v4 protocol layer. This is an abstract class that cannot be
	/// instantiated, and contains functionality which is common to all BGP message types.
	class BgpLayer : public Layer
	{
	public:
		/// An enum representing BGP message types
		enum BgpMessageType
		{
			/// BGP OPEN message
			Open = 1,
			/// BGP UPDATE message
			Update = 2,
			/// BGP NOTIFICATION message
			Notification = 3,
			/// BGP KEEPALIVE message
			Keepalive = 4,
			/// BGP ROUTE-REFRESH message
			RouteRefresh = 5,
		};

#pragma pack(push, 1)
		/// @struct bgp_common_header
		/// Represents the common fields of a BGP 4 message
		struct bgp_common_header
		{
			/// 16-octet marker
			uint8_t marker[16];
			/// Total length of the message, including the header
			uint16_t length;
			/// BGP message type
			uint8_t messageType;
		};
#pragma pack(pop)
		static_assert(sizeof(bgp_common_header) == 19, "bgp_common_header size is not 19 bytes");

		/// @return BGP message type
		virtual BgpMessageType getBgpMessageType() const = 0;

		/// @return BGP message type as string. Return value can be one of the following:
		/// "OPEN", "UPDATE", "NOTIFICATION", "KEEPALIVE", "ROUTE-REFRESH", "Unknown"
		std::string getMessageTypeAsString() const;

		/// A static method that checks whether a source or dest port match those associated with the BGP protocol
		/// @param[in] portSrc Source port number to check
		/// @param[in] portDst Dest port number to check
		/// @return True if the source or dest port match those associated with the BGP protocol
		static bool isBgpPort(uint16_t portSrc, uint16_t portDst)
		{
			return portSrc == 179 || portDst == 179;
		}

		/// A method that creates a BGP layer from packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored
		/// @return A newly allocated BGP layer of one of the following types (according to the message type):
		/// BgpOpenMessageLayer, BgpUpdateMessageLayer, BgpNotificationMessageLayer, BgpKeepaliveMessageLayer,
		/// BgpRouteRefreshMessageLayer
		static BgpLayer* parseBgpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		// implement abstract methods

		/// @return The size of the BGP message
		size_t getHeaderLen() const override;

		/// Multiple BGP messages can reside in a single packet, and the only layer that can come after a BGP message
		/// is another BGP message. This method checks for remaining data and parses it as another BGP layer
		void parseNextLayer() override;

		std::string toString() const override;

		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelApplicationLayer;
		}

		/// Calculates the basic BGP fields:
		/// - Set marker to all ones
		/// - Set message type value
		/// - Set message length
		void computeCalculateFields() override;

	protected:
		// protected c'tors, this class cannot be instantiated by users
		BgpLayer()
		{}
		BgpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, BGP)
		{}

		bgp_common_header* getBasicHeader() const
		{
			return reinterpret_cast<bgp_common_header*>(m_Data);
		}

		void setBgpFields(size_t messageLen = 0);
	};

	/// @class BgpOpenMessageLayer
	/// Represents a BGP v4 OPEN message
	class BgpOpenMessageLayer : public BgpLayer
	{
	public:
#pragma pack(push, 1)
		/// @struct bgp_open_message
		/// BGP OPEN message structure
		typedef struct bgp_open_message : bgp_common_header
		{
			/// BGP version number
			uint8_t version;
			/// Autonomous System number of the sender
			uint16_t myAutonomousSystem;
			/// The number of seconds the sender proposes for the value of the Hold Timer
			uint16_t holdTime;
			/// BGP Identifier of the sender
			uint32_t bgpId;
			/// The total length of the Optional Parameters field
			uint8_t optionalParameterLength;
		} bgp_open_message;
#pragma pack(pop)

		/// @struct optional_parameter
		/// A structure that represents BGP OPEN message optional parameters
		struct optional_parameter
		{
			/// Parameter type
			uint8_t type;
			/// Parameter length
			uint8_t length;
			/// Parameter data
			uint8_t value[32];

			// FIXME: This does not actually zero the data.
			/// A default c'tor that zeroes all data
			optional_parameter()
			{}

			/// A c'tor that initializes the values of the struct
			/// @param[in] typeVal Parameter type value
			/// @param[in] valueAsHexString Parameter data as hex string. The length field will be set accordingly.
			/// If this parameter is not a valid hex string the data will remain zeroed and length will be also zero
			optional_parameter(uint8_t typeVal, const std::string& valueAsHexString);
		};

		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		BgpOpenMessageLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : BgpLayer(data, dataLen, prevLayer, packet)
		{}

		/// A c'tor that creates a new BGP OPEN message
		/// @param[in] myAutonomousSystem The Autonomous System number of the sender
		/// @param[in] holdTime The number of seconds the sender proposes for the value of the Hold Timer
		/// @param[in] bgpId The BGP Identifier of the sender
		/// @param[in] optionalParams A vector of optional parameters. This parameter is optional and if not provided no
		/// parameters will be set on the message
		BgpOpenMessageLayer(uint16_t myAutonomousSystem, uint16_t holdTime, const IPv4Address& bgpId,
		                    const std::vector<optional_parameter>& optionalParams = std::vector<optional_parameter>());

		/// Get a pointer to the open message data. Notice this points directly to the data, so any change will modify
		/// the actual packet data
		/// @return A pointer to a bgp_open_message structure containing the data
		bgp_open_message* getOpenMsgHeader() const
		{
			return reinterpret_cast<bgp_open_message*>(m_Data);
		}

		/// @return The BGP identifier as IPv4Address object
		IPv4Address getBgpId() const
		{
			return IPv4Address(getOpenMsgHeader()->bgpId);
		}

		/// Set the BGP identifier
		/// @param[in] newBgpId BGP identifier to set. If value is not a valid IPv4 address it won't be set
		void setBgpId(const IPv4Address& newBgpId);

		/// Get a vector of the optional parameters in the message
		/// @param[out] optionalParameters The vector where the optional parameters will be written to. This method
		/// doesn't remove any existing data on this vector before pushing data to it
		void getOptionalParameters(std::vector<optional_parameter>& optionalParameters);

		/// @return The length in [bytes] of the optional parameters data in the message
		size_t getOptionalParametersLength();

		/// Set optional parameters in the message. This method will override all existing optional parameters currently
		/// in the message. If the input is an empty vector all optional parameters will be cleared. This method
		/// automatically sets the bgp_common_header#length and the bgp_open_message#optionalParameterLength fields on
		/// the message
		/// @param[in] optionalParameters A vector of new optional parameters to set in the message
		/// @return True if all optional parameters were set successfully or false otherwise. In case of an error an
		/// appropriate message will be printed to log
		bool setOptionalParameters(const std::vector<optional_parameter>& optionalParameters);

		/// Clear all optional parameters currently in the message. This is equivalent to calling
		/// setOptionalParameters() with an empty vector as a parameter
		/// @return True if all optional parameters were successfully cleared or false otherwise. In case of an error an
		/// appropriate message will be printed to log
		bool clearOptionalParameters();

		// implement abstract methods

		BgpMessageType getBgpMessageType() const override
		{
			return BgpLayer::Open;
		}

	private:
		size_t optionalParamsToByteArray(const std::vector<optional_parameter>& optionalParams, uint8_t* resultByteArr,
		                                 size_t maxByteArrSize);
	};

	/// @class BgpUpdateMessageLayer
	/// Represents a BGP v4 UPDATE message
	class BgpUpdateMessageLayer : public BgpLayer
	{
	public:
		/// @struct prefix_and_ip
		/// A structure that contains IPv4 address and IP address mask (prefix) information.
		/// It's used to represent BGP Withdrawn Routes and Network Layer Reachability Information (NLRI)
		struct prefix_and_ip
		{
			/// IPv4 address mask, must contain one of the values: 8, 16, 24, 32
			uint8_t prefix;
			/// IPv4 address
			IPv4Address ipAddr;

			/// A default c'tor that zeroes all data
			prefix_and_ip() : prefix(0), ipAddr(IPv4Address::Zero)
			{}

			/// A c'tor that initializes the values of the struct
			/// @param[in] prefixVal IPv4 address mask value
			/// @param[in] ipAddrVal IPv4 address
			prefix_and_ip(uint8_t prefixVal, const std::string& ipAddrVal) : prefix(prefixVal), ipAddr(ipAddrVal)
			{}
		};

		/// @struct path_attribute
		/// A structure that represents BGP OPEN message Path Attributes information
		struct path_attribute
		{
			/// Path attribute flags
			uint8_t flags;
			/// Path attribute type
			uint8_t type;
			/// Path attribute length
			uint8_t length;
			/// Path attribute data. Max supported data length is 32 bytes
			uint8_t data[32];

			// FIXME: This does not actually zero the data.
			/// A default c'tor that zeroes all data
			path_attribute()
			{}

			/// A c'tor that initializes the values of the struct
			/// @param[in] flagsVal Path attribute flags value
			/// @param[in] typeVal Path attribute type value
			/// @param[in] dataAsHexString Path attribute data as hex string. The path_attribute#length field will be
			/// set accordingly. If this parameter is not a valid hex string the data will remain zeroed and length will
			/// be also set to zero
			path_attribute(uint8_t flagsVal, uint8_t typeVal, const std::string& dataAsHexString);
		};

		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		BgpUpdateMessageLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : BgpLayer(data, dataLen, prevLayer, packet)
		{}

		/// A static method that takes a byte array and detects whether it is a BgpUpdateMessage
		/// @param[in] data A byte array
		/// @param[in] dataSize The byte array size (in bytes)
		/// @return True if the data looks like a valid BgpUpdateMessage layer
		static bool isDataValid(const uint8_t* data, size_t dataSize);

		/// A c'tor that creates a new BGP UPDATE message
		/// @param[in] withdrawnRoutes A vector of withdrawn routes data. If left empty (which is the default value) no
		/// withdrawn route information will be written to the message
		/// @param[in] pathAttributes A vector of path attributes data. If left empty (which is the default value) no
		/// path attribute information will be written to the message
		/// @param[in] nlri A vector of network layer reachability data. If left empty (which is the default value) no
		/// reachability information will be written to the message
		explicit BgpUpdateMessageLayer(
		    const std::vector<prefix_and_ip>& withdrawnRoutes = std::vector<prefix_and_ip>(),
		    const std::vector<path_attribute>& pathAttributes = std::vector<path_attribute>(),
		    const std::vector<prefix_and_ip>& nlri = std::vector<prefix_and_ip>());

		/// Get a pointer to the basic BGP message data. Notice this points directly to the data, so any change will
		/// modify the actual packet data
		/// @return A pointer to a bgp_common_header structure containing the data
		bgp_common_header* getBasicMsgHeader() const
		{
			return reinterpret_cast<bgp_common_header*>(m_Data);
		}

		/// @return The size in [bytes] of the Withdrawn Routes data
		size_t getWithdrawnRoutesLength() const;

		/// Get a vector of the Withdrawn Routes currently in the message
		/// @param[out] withdrawnRoutes A reference to a vector the Withdrawn Routes data will be written to
		void getWithdrawnRoutes(std::vector<prefix_and_ip>& withdrawnRoutes);

		/// Set Withdrawn Routes in this message. This method will override any existing Withdrawn Routes in the
		/// message. If the input is an empty vector all Withdrawn Routes will be removed. This method automatically
		/// sets the bgp_common_header#length and the Withdrawn Routes length fields in the message
		/// @param[in] withdrawnRoutes New Withdrawn Routes to set in the message
		/// @return True if all Withdrawn Routes were set successfully or false otherwise. In case of an error an
		/// appropriate message will be printed to log
		bool setWithdrawnRoutes(const std::vector<prefix_and_ip>& withdrawnRoutes);

		/// Clear all Withdrawn Routes data currently in the message. This is equivalent to calling setWithdrawnRoutes()
		/// with an empty vector as a parameter
		/// @return True if all Withdrawn Routes were successfully cleared or false otherwise. In case of an error an
		/// appropriate message will be printed to log
		bool clearWithdrawnRoutes();

		/// @return The size in [bytes] of the Path Attributes data
		size_t getPathAttributesLength() const;

		/// Get a vector of the Path Attributes currently in the message
		/// @param[out] pathAttributes A reference to a vector the Path Attributes data will be written to
		void getPathAttributes(std::vector<path_attribute>& pathAttributes);

		/// Set Path Attributes in this message. This method will override any existing Path Attributes in the message.
		/// If the input is an empty vector all Path Attributes will be removed. This method automatically sets the
		/// bgp_common_header#length and the Path Attributes length fields in the message
		/// @param[in] pathAttributes New Path Attributes to set in the message
		/// @return True if all Path Attributes were set successfully or false otherwise. In case of an error an
		/// appropriate message will be printed to log
		bool setPathAttributes(const std::vector<path_attribute>& pathAttributes);

		/// Clear all Path Attributes data currently in the message. This is equivalent to calling setPathAttributes()
		/// with an empty vector as a parameter
		/// @return True if all Path Attributes were successfully cleared or false otherwise. In case of an error an
		/// appropriate message will be printed to log
		bool clearPathAttributes();

		/// @return The size in [bytes] of the Network Layer Reachability Info
		size_t getNetworkLayerReachabilityInfoLength() const;

		/// Get a vector of the Network Layer Reachability Info currently in the message
		/// @param[out] nlri A reference to a vector the NLRI data will be written to
		void getNetworkLayerReachabilityInfo(std::vector<prefix_and_ip>& nlri);

		/// Set NLRI data in this message. This method will override any existing NLRI data in the message.
		/// If the input is an empty vector all NLRI data will be removed. This method automatically sets the
		/// bgp_common_header#length field in the message
		/// @param[in] nlri New NLRI data to set in the message
		/// @return True if all NLRI data was set successfully or false otherwise. In case of an error an appropriate
		/// message will be printed to log
		bool setNetworkLayerReachabilityInfo(const std::vector<prefix_and_ip>& nlri);

		/// Clear all NLRI data currently in the message. This is equivalent to calling
		/// setNetworkLayerReachabilityInfo() with an empty vector as a parameter
		/// @return True if all NLRI were successfully cleared or false otherwise. In case of an error an appropriate
		/// message will be printed to log
		bool clearNetworkLayerReachabilityInfo();

		// implement abstract methods

		BgpMessageType getBgpMessageType() const override
		{
			return BgpLayer::Update;
		}

	private:
		void parsePrefixAndIPData(uint8_t* dataPtr, size_t dataLen, std::vector<prefix_and_ip>& result);

		size_t prefixAndIPDataToByteArray(const std::vector<prefix_and_ip>& prefixAndIpData, uint8_t* resultByteArr,
		                                  size_t maxByteArrSize);

		size_t pathAttributesToByteArray(const std::vector<path_attribute>& pathAttributes, uint8_t* resultByteArr,
		                                 size_t maxByteArrSize);
	};

	/// @class BgpNotificationMessageLayer
	/// Represents a BGP v4 NOTIFICATION message
	class BgpNotificationMessageLayer : public BgpLayer
	{
	public:
#pragma pack(push, 1)
		/// @struct bgp_notification_message
		/// BGP NOTIFICATION message structure
		typedef struct bgp_notification_message : bgp_common_header
		{
			/// BGP notification error code
			uint8_t errorCode;
			/// BGP notification error sub-code
			uint8_t errorSubCode;
		} bgp_notification_message;
#pragma pack(pop)

		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		BgpNotificationMessageLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : BgpLayer(data, dataLen, prevLayer, packet)
		{}

		/// A c'tor that creates a new BGP NOTIFICATION message
		/// @param[in] errorCode BGP notification error code
		/// @param[in] errorSubCode BGP notification error sub code
		BgpNotificationMessageLayer(uint8_t errorCode, uint8_t errorSubCode);

		/// A c'tor that creates a new BGP Notification message
		/// @param[in] errorCode BGP notification error code
		/// @param[in] errorSubCode BGP notification error sub code
		/// @param[in] notificationData A byte array that contains the notification data
		/// @param[in] notificationDataLen The size of the byte array that contains the notification data
		BgpNotificationMessageLayer(uint8_t errorCode, uint8_t errorSubCode, const uint8_t* notificationData,
		                            size_t notificationDataLen);

		/// A c'tor that creates a new BGP Notification message
		/// @param[in] errorCode BGP notification error code
		/// @param[in] errorSubCode BGP notification error sub code
		/// @param[in] notificationData A hex string that contains the notification data. This string will be converted
		/// to a byte array that will be added to the message. If the input isn't a valid hex string notification data
		/// will remain empty and an error will be printed to log
		BgpNotificationMessageLayer(uint8_t errorCode, uint8_t errorSubCode, const std::string& notificationData);

		/// Get a pointer to the notification message data. Notice this points directly to the data, so any change will
		/// modify the actual packet data
		/// @return A pointer to a bgp_notification_message structure containing the data
		bgp_notification_message* getNotificationMsgHeader() const
		{
			return reinterpret_cast<bgp_notification_message*>(m_Data);
		}

		/// @return The size in [bytes] of the notification data. Notification data is a variable-length field used to
		/// diagnose the reason for the BGP NOTIFICATION
		size_t getNotificationDataLen() const;

		/// @return A pointer to the notification data. Notification data is a variable-length field used to diagnose
		/// the reason for the BGP NOTIFICATION
		uint8_t* getNotificationData() const;

		/// @return A hex string which represents the notification data. Notification data is a variable-length field
		/// used to diagnose the reason for the BGP NOTIFICATION
		std::string getNotificationDataAsHexString() const;

		/// Set the notification data. This method will extend or shorten the existing layer to include the new
		/// notification data. If newNotificationData is nullptr or newNotificationDataLen is zero then notification
		/// data will be set to none.
		/// @param[in] newNotificationData A byte array containing the new notification data
		/// @param[in] newNotificationDataLen The size of the byte array
		/// @return True if notification data was set successfully or false if any error occurred. In case of an error
		/// an appropriate error message will be printed to log
		bool setNotificationData(const uint8_t* newNotificationData, size_t newNotificationDataLen);

		/// Set the notification data. This method will extend or shorten the existing layer to include the new
		/// notification data. If newNotificationDataAsHexString is an empty string then notification data will be set
		/// to none.
		/// @param[in] newNotificationDataAsHexString A hex string representing the new notification data. If the string
		/// is not a valid hex string no data will be changed and an error will be returned
		/// @return True if notification data was set successfully or false if any error occurred or if the string is
		/// not a valid hex string. In case of an error an appropriate error message will be printed to log
		bool setNotificationData(const std::string& newNotificationDataAsHexString);

		// implement abstract methods

		BgpMessageType getBgpMessageType() const override
		{
			return BgpLayer::Notification;
		}

	private:
		void initMessageData(uint8_t errorCode, uint8_t errorSubCode, const uint8_t* notificationData,
		                     size_t notificationDataLen);
	};

	/// @class BgpKeepaliveMessageLayer
	/// Represents a BGP v4 KEEPALIVE message
	class BgpKeepaliveMessageLayer : public BgpLayer
	{
	public:
		/// @typedef bgp_keepalive_message
		/// BGP KEEPALIVE message structure
		typedef bgp_common_header bgp_keepalive_message;

		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		BgpKeepaliveMessageLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : BgpLayer(data, dataLen, prevLayer, packet)
		{}

		/// A c'tor that creates a new BGP KEEPALIVE message
		BgpKeepaliveMessageLayer();

		/// Get a pointer to the KeepAlive message data. Notice this points directly to the data, so any change will
		/// modify the actual packet data
		/// @return A pointer to a bgp_keepalive_message structure containing the data
		bgp_keepalive_message* getKeepaliveHeader() const
		{
			return reinterpret_cast<bgp_keepalive_message*>(getBasicHeader());
		}

		// implement abstract methods

		BgpMessageType getBgpMessageType() const override
		{
			return BgpLayer::Keepalive;
		}
	};

	/// @class BgpRouteRefreshMessageLayer
	/// Represents a BGP v4 ROUTE-REFRESH message
	class BgpRouteRefreshMessageLayer : public BgpLayer
	{
	public:
#pragma pack(push, 1)
		/// @struct bgp_route_refresh_message
		/// BGP ROUTE-REFRESH message structure
		typedef struct bgp_route_refresh_message : bgp_common_header
		{
			/// Address Family Identifier
			uint16_t afi;
			/// Reserved field
			uint8_t reserved;
			/// Subsequent Address Family Identifier
			uint8_t safi;
		} bgp_route_refresh_message;
#pragma pack(pop)

		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		BgpRouteRefreshMessageLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : BgpLayer(data, dataLen, prevLayer, packet)
		{}

		/// A c'tor that creates a new BGP ROUTE-REFRESH message
		/// @param[in] afi The Address Family Identifier (AFI) value to set in the message
		/// @param[in] safi The Subsequent Address Family Identifier (SAFI) value to set in the message
		BgpRouteRefreshMessageLayer(uint16_t afi, uint8_t safi);

		/// Get a pointer to the ROUTE-REFRESH message data. Notice this points directly to the data, so any change will
		/// modify the actual packet data
		/// @return A pointer to a bgp_route_refresh_message structure containing the data
		bgp_route_refresh_message* getRouteRefreshHeader() const
		{
			return reinterpret_cast<bgp_route_refresh_message*>(getBasicHeader());
		}

		// implement abstract methods

		BgpMessageType getBgpMessageType() const override
		{
			return BgpLayer::RouteRefresh;
		}
	};

}  // namespace pcpp
