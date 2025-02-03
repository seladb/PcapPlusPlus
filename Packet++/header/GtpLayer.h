#pragma once

#include "Layer.h"
#include "TLVData.h"
#include <vector>
#include <bitset>

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{

#pragma pack(push, 1)
	/// @struct gtpv1_header
	/// GTP v1 common message header
	struct gtpv1_header
	{
#if (BYTE_ORDER == LITTLE_ENDIAN)
		/// A 1-bit value that states whether there is a N-PDU number optional field
		uint8_t npduNumberFlag : 1,
		    /// A 1-bit value that states whether there is a Sequence Number optional field
		    sequenceNumberFlag : 1,
		    /// A 1-bit value that states whether there is an extension header optional field
		    extensionHeaderFlag : 1,
		    /// Reserved bit
		    reserved : 1,
		    /// A 1-bit value that differentiates GTP (value 1) from GTP' (value 0)
		    protocolType : 1,
		    /// GTP version
		    version : 3;
#else
		/// GTP version
		uint8_t version : 3,
		    /// A 1-bit value that differentiates GTP (value 1) from GTP' (value 0)
		    protocolType : 1,
		    /// Reserved bit
		    reserved : 1,
		    /// A 1-bit value that states whether there is an extension header optional field
		    extensionHeaderFlag : 1,
		    /// A 1-bit value that states whether there is a Sequence Number optional field
		    sequenceNumberFlag : 1,
		    /// A 1-bit value that states whether there is a N-PDU number optional field
		    npduNumberFlag : 1;
#endif
		/// An 8-bit field that indicates the type of GTP message
		uint8_t messageType;

		/// A 16-bit field that indicates the length of the payload in bytes (rest of the packet following the mandatory
		/// 8-byte GTP header). Includes the optional fields
		uint16_t messageLength;

		/// Tunnel endpoint identifier - A 32-bit(4-octet) field used to multiplex different connections in the same GTP
		/// tunnel
		uint32_t teid;
	};
#pragma pack(pop)
	static_assert(sizeof(gtpv1_header) == 8, "gtpv1_header size is not 8 bytes");

	/// An enum representing the possible GTP v1 message types.
	/// All of the message types except for #GtpV1_GPDU are considered GTP-C messages. #GtpV1_GPDU is considered a GTP-U
	/// message
	enum GtpV1MessageType
	{
		/// GTPv1 Message Type Unknown
		GtpV1_MessageTypeUnknown = 0,
		/// Echo Request
		GtpV1_EchoRequest = 1,
		/// Echo Response
		GtpV1_EchoResponse = 2,
		/// Version Not Supported
		GtpV1_VersionNotSupported = 3,
		/// Node Alive Request
		GtpV1_NodeAliveRequest = 4,
		/// Node Alive Response
		GtpV1_NodeAliveResponse = 5,
		/// Redirection Request
		GtpV1_RedirectionRequest = 6,
		/// Create PDP Context Request
		GtpV1_CreatePDPContextRequest = 7,
		/// Create PDP Context Response
		GtpV1_CreatePDPContextResponse = 16,
		/// Update PDP Context Request
		GtpV1_UpdatePDPContextRequest = 17,
		/// Update PDP Context Response
		GtpV1_UpdatePDPContextResponse = 18,
		/// Delete PDP Context Request
		GtpV1_DeletePDPContextRequest = 19,
		/// Delete PDP Context Response
		GtpV1_DeletePDPContextResponse = 20,
		/// Initiate PDP Context Activation Request
		GtpV1_InitiatePDPContextActivationRequest = 22,
		/// Initiate PDP Context Activation Response
		GtpV1_InitiatePDPContextActivationResponse = 23,
		/// Error Indication
		GtpV1_ErrorIndication = 26,
		/// PDU Notification Request
		GtpV1_PDUNotificationRequest = 27,
		/// PDU Notification Response
		GtpV1_PDUNotificationResponse = 28,
		/// PDU Notification Reject Request
		GtpV1_PDUNotificationRejectRequest = 29,
		/// PDU Notification Reject Response
		GtpV1_PDUNotificationRejectResponse = 30,
		/// Supported Extensions Header Notification
		GtpV1_SupportedExtensionsHeaderNotification = 31,
		/// Send Routing for GPRS Request
		GtpV1_SendRoutingforGPRSRequest = 32,
		/// Send Routing for GPRS Response
		GtpV1_SendRoutingforGPRSResponse = 33,
		/// Failure Report Request
		GtpV1_FailureReportRequest = 34,
		/// Failure Report Response
		GtpV1_FailureReportResponse = 35,
		/// Note MS Present Request
		GtpV1_NoteMSPresentRequest = 36,
		/// Note MS Present Response
		GtpV1_NoteMSPresentResponse = 37,
		/// Identification Request
		GtpV1_IdentificationRequest = 38,
		/// Identification Response
		GtpV1_IdentificationResponse = 39,
		/// SGSN Context Request
		GtpV1_SGSNContextRequest = 50,
		/// SGSN Context Response
		GtpV1_SGSNContextResponse = 51,
		/// SGSN Context Acknowledge
		GtpV1_SGSNContextAcknowledge = 52,
		/// Forward Relocation Request
		GtpV1_ForwardRelocationRequest = 53,
		/// Forward Relocation Response
		GtpV1_ForwardRelocationResponse = 54,
		/// Forward Relocation Complete
		GtpV1_ForwardRelocationComplete = 55,
		/// Relocation Cancel Request
		GtpV1_RelocationCancelRequest = 56,
		/// Relocation Cancel Response
		GtpV1_RelocationCancelResponse = 57,
		/// Forward SRNS Context
		GtpV1_ForwardSRNSContext = 58,
		/// Forward Relocation Complete Acknowledge
		GtpV1_ForwardRelocationCompleteAcknowledge = 59,
		/// Forward SRNS Context Acknowledge
		GtpV1_ForwardSRNSContextAcknowledge = 60,
		/// UE Registration Request
		GtpV1_UERegistrationRequest = 61,
		/// UE Registration Response
		GtpV1_UERegistrationResponse = 62,
		/// RAN Information Relay
		GtpV1_RANInformationRelay = 70,
		/// MBMS Notification Request
		GtpV1_MBMSNotificationRequest = 96,
		/// MBMS Notification Response
		GtpV1_MBMSNotificationResponse = 97,
		/// MBMS Notification Reject Request
		GtpV1_MBMSNotificationRejectRequest = 98,
		/// MBMS Notification Reject Response
		GtpV1_MBMSNotificationRejectResponse = 99,
		/// Create MBMS Notification Request
		GtpV1_CreateMBMSNotificationRequest = 100,
		/// Create MBMS Notification Response
		GtpV1_CreateMBMSNotificationResponse = 101,
		/// Update MBMS Notification Request
		GtpV1_UpdateMBMSNotificationRequest = 102,
		/// Update MBMS Notification Response
		GtpV1_UpdateMBMSNotificationResponse = 103,
		/// Delete MBMS Notification Request
		GtpV1_DeleteMBMSNotificationRequest = 104,
		/// Delete MBMS Notification Response
		GtpV1_DeleteMBMSNotificationResponse = 105,
		/// MBMS Registration Request
		GtpV1_MBMSRegistrationRequest = 112,
		/// MBMS Registration Response
		GtpV1_MBMSRegistrationResponse = 113,
		/// MBMS De-Registration Request
		GtpV1_MBMSDeRegistrationRequest = 114,
		/// MBMS De-Registration Response
		GtpV1_MBMSDeRegistrationResponse = 115,
		/// MBMS Session Start Request
		GtpV1_MBMSSessionStartRequest = 116,
		/// MBMS Session Start Response
		GtpV1_MBMSSessionStartResponse = 117,
		/// MBMS Session Stop Request
		GtpV1_MBMSSessionStopRequest = 118,
		/// MBMS Session Stop Response
		GtpV1_MBMSSessionStopResponse = 119,
		/// MBMS Session Update Request
		GtpV1_MBMSSessionUpdateRequest = 120,
		/// MBMS Session Update Response
		GtpV1_MBMSSessionUpdateResponse = 121,
		/// MS Info Change Request
		GtpV1_MSInfoChangeRequest = 128,
		/// MS Info Change Response
		GtpV1_MSInfoChangeResponse = 129,
		/// Data Record Transfer Request
		GtpV1_DataRecordTransferRequest = 240,
		/// Data Record Transfer Response
		GtpV1_DataRecordTransferResponse = 241,
		/// End Marker
		GtpV1_EndMarker = 254,
		/// G-PDU
		GtpV1_GPDU = 255
	};

	/// @class GtpV1Layer
	/// A class representing the [GTP v1](https://en.wikipedia.org/wiki/GPRS_Tunnelling_Protocol) protocol.
	class GtpV1Layer : public Layer
	{
	private:
		struct gtpv1_header_extra
		{
			uint16_t sequenceNumber;
			uint8_t npduNumber;
			uint8_t nextExtensionHeader;
		};

		gtpv1_header_extra* getHeaderExtra() const;

		void init(GtpV1MessageType messageType, uint32_t teid, bool setSeqNum, uint16_t seqNum, bool setNpduNum,
		          uint8_t npduNum);

	public:
		/// @class GtpExtension
		/// A class that represents [GTP header extensions](https://en.wikipedia.org/wiki/GPRS_Tunnelling_Protocol)
		class GtpExtension
		{
			friend class GtpV1Layer;

		private:
			uint8_t* m_Data;
			size_t m_DataLen;
			uint8_t m_ExtType;

			GtpExtension(uint8_t* data, size_t dataLen, uint8_t type);

			void setNextHeaderType(uint8_t nextHeaderType);

			static GtpExtension createGtpExtension(uint8_t* data, size_t dataLen, uint8_t extType, uint16_t content);

		public:
			/// An empty c'tor that creates an empty object, meaning one that isNull() returns "true")
			GtpExtension();

			/// A copy c'tor for this class
			/// @param[in] other The GTP extension to copy from
			GtpExtension(const GtpExtension& other);

			/// An assignment operator for this class
			/// @param[in] other The extension to assign from
			/// @return A reference to the assignee
			GtpExtension& operator=(const GtpExtension& other);

			/// @return Instances of this class may be initialized as empty, meaning they don't contain any data. In
			/// these cases this method returns true
			bool isNull() const;

			/// @return The extension type. If the object is empty a value of zero is returned
			uint8_t getExtensionType() const;

			/// @return The total length of the extension including the length and next extension type fields.
			/// If the object is empty a value of zero is returned
			size_t getTotalLength() const;

			/// @return The length of the extension's content, excluding the extension length and next extension type
			/// fields. If the object is empty a value of zero is returned
			size_t getContentLength() const;

			/// @return A byte array that includes the extension's content. The length of this array can be determined
			/// by getContentLength(). If the object is empty a null value is returned
			uint8_t* getContent() const;

			/// @return The extension type of the next header. If there are no more header extensions or if this object
			/// is empty a value of zero is returned
			uint8_t getNextExtensionHeaderType() const;

			/// @return An instance of this class representing the next extension header, if exists in the message. If
			/// there are no more header extensions or if this object is empty an empty instance of GtpExtension is
			/// returned, meaning one that GtpExtension#isNull() returns "true"
			GtpExtension getNextExtension() const;
		};  // GtpExtension

		~GtpV1Layer() override = default;

		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		GtpV1Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, GTPv1)
		{}

		/// A constructor that creates a new GTPv1 layer and sets the message type and the TEID value
		/// @param[in] messageType The GTPv1 message type to be set in the newly created layer
		/// @param[in] teid The TEID value to be set in the newly created layer
		GtpV1Layer(GtpV1MessageType messageType, uint32_t teid);

		/// A constructor that creates a new GTPv1 layer and sets various parameters
		/// @param[in] messageType The GTPv1 message type to be set in the newly created layer
		/// @param[in] teid The TEID value to be set in the newly created layer
		/// @param[in] setSeqNum A flag indicating whether to set a sequence number. If set to "false" then the
		/// parameter "seqNum" will be ignored
		/// @param[in] seqNum The sequence number to be set in the newly created later. If "setSeqNum" is set to false
		/// this parameter will be ignored
		/// @param[in] setNpduNum A flag indicating whether to set the N-PDU number. If set to "false" then the
		/// parameter "npduNum" will be ignored
		/// @param[in] npduNum The N-PDU number to be set in the newly created later. If "setNpduNum" is set to false
		/// this parameter will be ignored
		GtpV1Layer(GtpV1MessageType messageType, uint32_t teid, bool setSeqNum, uint16_t seqNum, bool setNpduNum,
		           uint8_t npduNum);

		/// A static method that takes a byte array and detects whether it is a GTP v1 message
		/// @param[in] data A byte array
		/// @param[in] dataSize The byte array size (in bytes)
		/// @return True if the data is identified as GTP v1 message (GTP-C or GTP-U)
		static bool isGTPv1(const uint8_t* data, size_t dataSize);

		/// @return The GTP v1 common header structure. Notice this points directly to the data, so every change will
		/// change the actual packet data
		gtpv1_header* getHeader() const
		{
			return reinterpret_cast<gtpv1_header*>(m_Data);
		}

		/// Get the sequence number if exists on the message (sequence number is an optional field in GTP messages)
		/// @param[out] seqNumber Set with the sequence number value if exists in the layer. Otherwise remains unchanged
		/// @return True if the sequence number field exists in layer, in which case seqNumber is set with the value.
		/// Or false otherwise
		bool getSequenceNumber(uint16_t& seqNumber) const;

		/// Set a sequence number
		/// @param[in] seqNumber The sequence number to set
		/// @return True if the value was set successfully, false otherwise. In case of failure a corresponding error
		/// message will be written to log
		bool setSequenceNumber(uint16_t seqNumber);

		/// Get the N-PDU number if exists on the message (N-PDU number is an optional field in GTP messages)
		/// @param[out] npduNum Set with the N-PDU number value if exists in the layer. Otherwise remains unchanged
		/// @return True if the N-PDU number field exists in layer, in which case npduNum is set with the value.
		/// Or false otherwise
		bool getNpduNumber(uint8_t& npduNum) const;

		/// Set an N-PDU number
		/// @param[in] npduNum The N-PDU number to set
		/// @return True if the value was set successfully, false otherwise. In case of failure a corresponding error
		/// message will be written to log
		bool setNpduNumber(uint8_t npduNum);

		/// Get the type of the next header extension if exists on the message (extensions are optional in GTP messages)
		/// @param[out] nextExtType Set with the next header extension type if exists in layer. Otherwise remains
		/// unchanged
		/// @return True if the message contains header extensions, in which case nextExtType is set to the next
		/// header extension type. If there are no header extensions false is returned and nextExtType remains unchanged
		bool getNextExtensionHeaderType(uint8_t& nextExtType) const;

		/// @return An object that represents the next extension header, if exists in the message. If there are no
		/// extensions an empty object is returned, meaning an object which GtpExtension#isNull() returns "true"
		GtpExtension getNextExtension() const;

		/// Add a GTPv1 header extension. It is assumed that the extension is 4 bytes in length and its content is 2
		/// bytes in length. If you need a different content size please reach out to me. This method takes care of
		/// extending the layer to make room for the new extension and also sets the relevant flags and fields
		/// @param[in] extensionType The type of the new extension
		/// @param[in] extensionContent A 2-byte long content
		/// @return An object representing the newly added extension. If there was an error adding the extension a null
		/// object will be returned (meaning GtpExtension#isNull() will return "true") and a corresponding error message
		/// will be written to log
		GtpExtension addExtension(uint8_t extensionType, uint16_t extensionContent);

		/// @return The message type of this GTP packet
		GtpV1MessageType getMessageType() const;

		/// @return A string representation of the packet's message type
		std::string getMessageTypeAsString() const;

		/// @return True if this is a GTP-U message, false otherwise
		bool isGTPUMessage() const;

		/// @return True if this is a GTP-C message, false otherwise
		bool isGTPCMessage() const;

		/// A static method that checks whether the port is considered as GTPv1
		/// @param[in] port The port number to be checked
		/// @return True if the port matches those associated with the GTPv1 protocol
		static bool isGTPv1Port(uint16_t port)
		{
			return port == 2152 /* GTP-U */ || port == 2123 /* GTP-C */;
		}

		// implement abstract methods

		/// Identifies the following next layers for GTP-U packets: IPv4Layer, IPv6Layer. Otherwise sets PayloadLayer
		void parseNextLayer() override;

		/// @return The size of the GTP header. For GTP-C packets the size is determined by the value of
		/// gtpv1_header#messageLength and for GTP-U the size only includes the GTP header itself (meaning
		/// the size of gtpv1_header plus the size of the optional fields such as sequence number, N-PDU
		/// or extensions if exist)
		size_t getHeaderLen() const override;

		/// Calculate the following fields:
		/// - gtpv1_header#messageLength
		void computeCalculateFields() override;

		std::string toString() const override;

		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelTransportLayer;
		}
	};

	/// @class GtpV2MessageType
	/// The enum wrapper class of GTPv2 message type
	class GtpV2MessageType
	{
	public:
		/// Define enum types and the corresponding int values
		enum Value : uint8_t
		{
			/// Unknown message
			Unknown = 0,
			/// Echo Request message
			EchoRequest = 1,
			/// Echo Response message
			EchoResponse = 2,
			/// Version Not Supported message
			VersionNotSupported = 3,
			/// Create Session Request message
			CreateSessionRequest = 32,
			/// Create Session Response message
			CreateSessionResponse = 33,
			/// Modify Bearer Request message
			ModifyBearerRequest = 34,
			/// Modify Bearer Response message
			ModifyBearerResponse = 35,
			/// Delete Session Request message
			DeleteSessionRequest = 36,
			/// Delete Session Response message
			DeleteSessionResponse = 37,
			/// Change Notification Request message
			ChangeNotificationRequest = 38,
			/// Change Notification Response message
			ChangeNotificationResponse = 39,
			/// Remote UE Report Notifications message
			RemoteUEReportNotifications = 40,
			/// Remote UE Report Acknowledge message
			RemoteUEReportAcknowledge = 41,
			/// Modify Bearer Command message
			ModifyBearerCommand = 64,
			/// Modify Bearer Failure message
			ModifyBearerFailure = 65,
			/// Delete Bearer Command message
			DeleteBearerCommand = 66,
			/// Delete Bearer Failure message
			DeleteBearerFailure = 67,
			/// Bearer Resource Command message
			BearerResourceCommand = 68,
			/// Bearer Resource Failure message
			BearerResourceFailure = 69,
			/// Downlink Data Notification Failure message
			DownlinkDataNotificationFailure = 70,
			/// Trace Session Activation message
			TraceSessionActivation = 71,
			/// Trace Session Deactivation message
			TraceSessionDeactivation = 72,
			/// Stop Paging Indication message
			StopPagingIndication = 73,
			/// Create Bearer Request message
			CreateBearerRequest = 95,
			/// Create Bearer Response message
			CreateBearerResponse = 96,
			/// Update Bearer Request message
			UpdateBearerRequest = 97,
			/// Update Bearer Response message
			UpdateBearerResponse = 98,
			/// Delete Bearer Request message
			DeleteBearerRequest = 99,
			/// Delete Bearer Response message
			DeleteBearerResponse = 100,
			/// Delete PDN Request message
			DeletePDNRequest = 101,
			/// Delete PDN Response message
			DeletePDNResponse = 102,
			/// PGW Downlink Notification message
			PGWDownlinkNotification = 103,
			/// PGW Downlink Acknowledge message
			PGWDownlinkAcknowledge = 104,
			/// Identification Request message
			IdentificationRequest = 128,
			/// Identification Response message
			IdentificationResponse = 129,
			/// Context Request message
			ContextRequest = 130,
			/// Context Response message
			ContextResponse = 131,
			/// Context Acknowledge message
			ContextAcknowledge = 132,
			/// Forward Relocation Request message
			ForwardRelocationRequest = 133,
			/// Forward Relocation Response message
			ForwardRelocationResponse = 134,
			/// Forward Relocation Notification message
			ForwardRelocationNotification = 135,
			/// Forward Relocation Acknowledge message
			ForwardRelocationAcknowledge = 136,
			/// Forward Access Notification message
			ForwardAccessNotification = 137,
			/// Forward Access Acknowledge message
			ForwardAccessAcknowledge = 138,
			/// Relocation Cancel Request message
			RelocationCancelRequest = 139,
			/// Relocation Cancel Response message
			RelocationCancelResponse = 140,
			/// Configuration Transfer Tunnel message
			ConfigurationTransferTunnel = 141,
			/// Detach Notification message
			DetachNotification = 149,
			/// Detach Acknowledge message
			DetachAcknowledge = 150,
			/// CS Paging message
			CSPaging = 151,
			/// RAN Information Relay message
			RANInformationRelay = 152,
			/// Alert MME Notification message
			AlertMMENotification = 153,
			/// Alert MME Acknowledge message
			AlertMMEAcknowledge = 154,
			/// UE Activity Notification message
			UEActivityNotification = 155,
			/// UE Activity Acknowledge message
			UEActivityAcknowledge = 156,
			/// ISR Status message
			ISRStatus = 157,
			/// Create Forwarding Request message
			CreateForwardingRequest = 160,
			/// Create Forwarding Response message
			CreateForwardingResponse = 161,
			/// Suspend Notification message
			SuspendNotification = 162,
			/// Suspend Acknowledge message
			SuspendAcknowledge = 163,
			/// Resume Notification message
			ResumeNotification = 164,
			/// Resume Acknowledge message
			ResumeAcknowledge = 165,
			/// Create Indirect Data Tunnel Request message
			CreateIndirectDataTunnelRequest = 166,
			/// Create Indirect Data Tunnel Response message
			CreateIndirectDataTunnelResponse = 167,
			/// Delete Indirect Data Tunnel Request message
			DeleteIndirectDataTunnelRequest = 168,
			/// Delete Indirect Data Tunnel Response message
			DeleteIndirectDataTunnelResponse = 169,
			/// Release Access Bearers Request message
			ReleaseAccessBearersRequest = 170,
			/// Release Access Bearers Response message
			ReleaseAccessBearersResponse = 171,
			/// Downlink Data Notification message
			DownlinkDataNotification = 176,
			/// Downlink Data Acknowledge message
			DownlinkDataAcknowledge = 177,
			/// PGW Restart Notification message
			PGWRestartNotification = 179,
			/// PGW Restart Acknowledge message
			PGWRestartAcknowledge = 180,
			/// Update PDN Connection Request message
			UpdatePDNConnectionRequest = 200,
			/// Update PDN Connection Response message
			UpdatePDNConnectionResponse = 201,
			/// Modify Access Bearers Request message
			ModifyAccessBearersRequest = 211,
			/// Modify Access Bearers Response message
			ModifyAccessBearersResponse = 212,
			/// MMBS Session Start Request message
			MMBSSessionStartRequest = 231,
			/// MMBS Session Start Response message
			MMBSSessionStartResponse = 232,
			/// MMBS Session Update Request message
			MMBSSessionUpdateRequest = 233,
			/// MMBS Session Update Response message
			MMBSSessionUpdateResponse = 234,
			/// MMBS Session Stop Request message
			MMBSSessionStopRequest = 235,
			/// MMBS Session Stop Response message
			MMBSSessionStopResponse = 236
		};

		GtpV2MessageType() = default;

		// cppcheck-suppress noExplicitConstructor
		/// Construct GtpV2MessageType from Value enum
		/// @param[in] value the message type enum value
		constexpr GtpV2MessageType(Value value) : m_Value(value)
		{}

		/// @return A string representation of the message type
		std::string toString() const;

		/// A static method that creates GtpV2MessageType from an integer value
		/// @param[in] value The message type integer value
		/// @return The message type that corresponds to the integer value. If the integer value
		/// doesn't corresponds to any message type, GtpV2MessageType::Unknown is returned
		static GtpV2MessageType fromUintValue(uint8_t value);

		// Allow switch and comparisons.
		constexpr operator Value() const
		{
			return m_Value;
		}

		// Prevent usage: if(GtpV2MessageType)
		explicit operator bool() const = delete;

	private:
		Value m_Value = GtpV2MessageType::Unknown;
	};

	/// @class GtpV2InformationElement
	/// A wrapper class for GTPv2 information elements (IE). This class does not create or modify IEs, but rather
	/// serves as a wrapper and provides useful methods for retrieving data from them
	class GtpV2InformationElement : public TLVRecord<uint8_t, uint16_t>
	{
	public:
		/// GTPv2 Information Element (IE) types as defined in 3GPP TS 29.274
		enum class Type : uint8_t
		{
			/// Unknown or reserved value
			Unknown = 0,
			/// International Mobile Subscriber Identity
			Imsi = 1,
			/// Indicates the result of a procedure
			Cause = 2,
			/// Recovery counter for GTP path management
			Recovery = 3,
			/// Session Transfer Number for SRVCC
			StnSr = 51,
			/// Access Point Name
			Apn = 71,
			/// Aggregate Maximum Bit Rate
			Ambr = 72,
			/// EPS Bearer ID
			Ebi = 73,
			/// IPv4/IPv6 Address
			IpAddress = 74,
			/// Mobile Equipment Identity (IMEI or IMEISV)
			Mei = 75,
			/// Mobile Station International Subscriber Directory Number
			Msisdn = 76,
			/// Indication flags for various features and capabilities
			Indication = 77,
			/// Protocol Configuration Options
			Pco = 78,
			/// PDN Address Allocation
			Paa = 79,
			/// Bearer Level Quality of Service
			BearerQos = 80,
			/// Flow Level Quality of Service
			FlowQos = 81,
			/// Radio Access Technology Type
			RatType = 82,
			/// Current PLMN and MME identifier
			ServingNetwork = 83,
			/// Bearer Traffic Flow Template
			BearerTft = 84,
			/// Traffic Aggregation Description
			Tad = 85,
			/// User Location Information
			Uli = 86,
			/// Fully Qualified TEID
			FTeid = 87,
			/// Temporary Mobile Subscriber Identity
			Tmsi = 88,
			/// Global Core Network ID
			GlobalCnId = 89,
			/// S103 PDN Data Forwarding Info
			S103PdnDataForwardingInfo = 90,
			/// S1-U Data Forwarding Info
			S1UDataForwardingInfo = 91,
			/// Delay Value in integer multiples of 50 milliseconds
			DelayValue = 92,
			/// Bearer Context
			BearerContext = 93,
			/// Charging ID for this PDP context
			ChargingId = 94,
			/// Charging Characteristics
			ChargingCharacteristics = 95,
			/// Trace Information
			TraceInformation = 96,
			/// Bearer Flags
			BearerFlags = 97,
			/// PDN Type (IPv4, IPv6, IPv4v6)
			PdnType = 99,
			/// Procedure Transaction ID
			Pti = 100,
			/// MM Context (GSM Key and Triplets)
			MmContext1 = 103,
			/// MM Context (UMTS Key, Used Cipher and Quintuplets)
			MmContext2 = 104,
			/// MM Context (GSM Key, Used Cipher and Quintuplets)
			MmContext3 = 105,
			/// MM Context (UMTS Key and Quintuplets)
			MmContext4 = 106,
			/// MM Context (EPS Security Context, Quadruplets and Quintuplets)
			MmContext5 = 107,
			/// MM Context (UMTS Key, Quadruplets and Quintuplets)
			MmContext6 = 108,
			/// PDN Connection
			PdnConnection = 109,
			/// PDU Numbers
			PduNumbers = 110,
			/// Packet TMSI
			PTmsi = 111,
			/// P-TMSI Signature
			PTmsiSignature = 112,
			/// Hop Counter
			HopCounter = 113,
			/// UE Time Zone
			UeTimeZone = 114,
			/// Trace Reference
			TraceReference = 115,
			/// Complete Request Message
			CompleteRequestMessage = 116,
			/// Globally Unique Temporary Identity
			Guti = 117,
			/// F-Container
			FContainer = 118,
			/// F-Cause
			FCause = 119,
			/// PLMN Identity
			PlmnId = 120,
			/// Target Identification
			TargetIdentification = 121,
			/// Packet Flow ID
			PacketFlowId = 123,
			/// RAB Context
			RabContext = 124,
			/// Source RNC PDCP Context Info
			SourceRncPdcpContextInfo = 125,
			/// Port Number
			PortNumber = 126,
			/// APN Restriction
			ApnRestriction = 127,
			/// Selection Mode
			SelectionMode = 128,
			/// Source Identification
			SourceIdentification = 129,
			/// Change Reporting Action
			ChangeReportingAction = 131,
			/// Fully Qualified PDN Connection Set Identifier
			FqCsid = 132,
			/// Channel Needed
			ChannelNeeded = 133,
			/// eMLPP Priority
			EmlppPriority = 134,
			/// Node Type
			NodeType = 135,
			/// Fully Qualified Domain Name
			Fqdn = 136,
			/// Transaction Identifier
			Ti = 137,
			/// MBMS Session Duration
			MbmsSessionDuration = 138,
			/// MBMS Service Area
			MbmsServiceArea = 139,
			/// MBMS Session Identifier
			MbmsSessionIdentifier = 140,
			/// MBMS Flow Identifier
			MbmsFlowIdentifier = 141,
			/// MBMS IP Multicast Distribution
			MbmsIpMulticastDistribution = 142,
			/// MBMS Distribution Acknowledge
			MbmsDistributionAcknowledge = 143,
			/// RF Selection Priority Index
			RfspIndex = 144,
			/// User CSG Information
			Uci = 145,
			/// CSG Information Reporting Action
			CsgInformationReportingAction = 146,
			/// CSG ID
			CsgId = 147,
			/// CSG Membership Indication
			Cmi = 148,
			/// Service Indicator
			ServiceIndicator = 149,
			/// Detach Type
			DetachType = 150,
			/// Local Distinguished Name
			Ldn = 151,
			/// Node Features
			NodeFeatures = 152,
			/// MBMS Time To Data Transfer
			MbmsTimeToDataTransfer = 153,
			/// Throttling
			Throttling = 154,
			/// Allocation Retention Priority
			Arp = 155,
			/// EPC Timer
			EpcTimer = 156,
			/// Signalling Priority Indication
			SignallingPriorityIndication = 157,
			/// Temporary Mobile Group Identity
			Tmgi = 158,
			/// Additional MM Context For SRVCC
			AdditionalMmContextForSrvcc = 159,
			/// Additional Flags For SRVCC
			AdditionalFlagsForSrvcc = 160,
			/// MDT Configuration
			MdtConfiguration = 162,
			/// Additional Protocol Configuration Options
			Apco = 163,
			/// Absolute Time of MBMS Data Transfer
			AbsoluteTimeOfMbmsDataTransfer = 164,
			/// H(e)NB Information Reporting
			HenbInformationReporting = 165,
			/// IPv4 Configuration Parameters
			Ipv4ConfigurationParameters = 166,
			/// Change To Report Flags
			ChangeToReportFlags = 167,
			/// Action Indication
			ActionIndication = 168,
			/// TWAN Identifier
			TwanIdentifier = 169,
			/// ULI Timestamp
			UliTimestamp = 170,
			/// MBMS Flags
			MbmsFlags = 171,
			/// RAN/NAS Cause
			RanNasCause = 172,
			/// CN Operator Selection Entity
			CnOperatorSelectionEntity = 173,
			/// Trusted WLAN Mode Indication
			Twmi = 174,
			/// Node Number
			NodeNumber = 175,
			/// Node Identifier
			NodeIdentifier = 176,
			/// Presence Reporting Area Action
			PresenceReportingAreaAction = 177,
			/// Presence Reporting Area Information
			PresenceReportingAreaInformation = 178,
			/// TWAN Identifier Timestamp
			TwanIdentifierTimestamp = 179,
			/// Overload Control Information
			OverloadControlInformation = 180,
			/// Load Control Information
			LoadControlInformation = 181,
			/// Metric
			Metric = 182,
			/// Sequence Number
			SequenceNumber = 183,
			/// APN and Relative Capacity
			ApnAndRelativeCapacity = 184,
			/// WLAN Offloadability Indication
			WlanOffloadabilityIndication = 185,
			/// Paging and Service Information
			PagingAndServiceInformation = 186,
			/// Integer Number
			IntegerNumber = 187,
			/// Millisecond Time Stamp
			MillisecondTimeStamp = 188,
			/// Monitoring Event Information
			MonitoringEventInformation = 189,
			/// ECGI List
			EcgiList = 190,
			/// Remote UE Context
			RemoteUeContext = 191,
			/// Remote User ID
			RemoteUserId = 192,
			/// Remote UE IP Information
			RemoteUeIpInformation = 193,
			/// CIoT Optimizations Support Indication
			CiotOptimizationsSupportIndication = 194,
			/// SCEF PDN Connection
			ScefPdnConnection = 195,
			/// Header Compression Configuration
			HeaderCompressionConfiguration = 196,
			/// Extended Protocol Configuration Options
			ExtendedPco = 197,
			/// Serving PLMN Rate Control
			ServingPlmnRateControl = 198,
			/// Counter
			Counter = 199,
			/// Mapped UE Usage Type
			MappedUeUsageType = 200,
			/// Secondary RAT Usage Data Report
			SecondaryRatUsageDataReport = 201,
			/// UP Function Selection Indication Flags
			UpFunctionSelectionIndicationFlags = 202,
			/// Maximum Packet Loss Rate
			MaximumPacketLossRate = 203,
			/// APN Rate Control Status
			ApnRateControlStatus = 204,
			/// Extended Trace Information
			ExtendedTraceInformation = 205,
			/// Monitoring Event Extension Information
			MonitoringEventExtensionInformation = 206,
			/// Additional RRM Policy Index
			AdditionalRrmPolicyIndex = 207,
			/// V2X Context
			V2xContext = 208,
			/// PC5 QoS Parameters
			Pc5QosParameters = 209,
			/// Services Authorized
			ServicesAuthorized = 210,
			/// Bit Rate
			BitRate = 211,
			/// PC5 QoS Flow
			Pc5QosFlow = 212,
			/// SGi PtP Tunnel Address
			SgiPtpTunnelAddress = 213
		};

		/// A c'tor for this class that gets a pointer to the IE raw data (byte array)
		/// @param[in] infoElementRawData A pointer to the IE raw data
		explicit GtpV2InformationElement(uint8_t* infoElementRawData) : TLVRecord(infoElementRawData)
		{}

		~GtpV2InformationElement() override = default;

		/// @return The information element (IE) type
		GtpV2InformationElement::Type getIEType();

		/// @return The IE CR flag
		uint8_t getCRFlag();

		/// @return The IE instance value
		uint8_t getInstance();

		// implement abstract methods

		size_t getValueOffset() const override
		{
			return sizeof(uint8_t);
		}

		size_t getTotalSize() const override;

		size_t getDataSize() const override;
	};

	/// @class GtpV2InformationElementBuilder
	/// A class for building GTPv2 information elements (IE). This builder receives the IE parameters in its c'tor,
	/// builds the IE raw buffer and provides a build() method to get a GtpV2InformationElement object out of it
	class GtpV2InformationElementBuilder : public TLVRecordBuilder
	{
	public:
		/// A c'tor for building information elements (IE) which their value is a byte array. The
		/// GtpV2InformationElement object can be later retrieved by calling build().
		/// @param[in] infoElementType Information elements (IE) type
		/// @param[in] crFlag CR flag value
		/// @param[in] instance Instance value
		/// @param[in] infoElementValue A byte array of the IE value
		GtpV2InformationElementBuilder(GtpV2InformationElement::Type infoElementType, const std::bitset<4>& crFlag,
		                               const std::bitset<4>& instance, const std::vector<uint8_t>& infoElementValue);

		/// Build the GtpV2InformationElement object out of the parameters defined in the c'tor
		/// @return The GtpV2InformationElement object
		GtpV2InformationElement build() const;

	private:
		std::bitset<4> m_CRFlag;
		std::bitset<4> m_Instance;
	};

	/// @class GtpV2Layer
	/// A class representing the GTPv2 defined in 3GPP TS 29.274
	class GtpV2Layer : public Layer
	{
	public:
		~GtpV2Layer() override = default;

		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		GtpV2Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, GTPv2)
		{}

		/// A constructor that creates a new GTPv2 message
		/// @param messageType GTPv2 message type
		/// @param sequenceNumber Message sequence number
		/// @param setTeid Whether or not to set Tunnel Endpoint Identifier in this message
		/// @param teid Tunnel Endpoint Identifier value. Only used if setTeid is set to true
		/// @param setMessagePriority Whether or not to set Message Priority in this message
		/// @param messagePriority Message Priority. Only used if setMessagePriority to true
		GtpV2Layer(GtpV2MessageType messageType, uint32_t sequenceNumber, bool setTeid = false, uint32_t teid = 0,
		           bool setMessagePriority = false, std::bitset<4> messagePriority = 0);

		/// A static method that checks whether the port is considered as GTPv2
		/// @param[in] port The port number to be checked
		/// @return True if the port matches those associated with the GTPv2 protocol
		static bool isGTPv2Port(uint16_t port)
		{
			return port == 2123;
		}

		/// A static method that takes a byte array and detects whether it is a GTPv2 message
		/// @param[in] data A byte array
		/// @param[in] dataSize The byte array size (in bytes)
		/// @return True if the data is identified as GTPv2 message
		static bool isDataValid(const uint8_t* data, size_t dataSize);

		/// @return The message type
		GtpV2MessageType getMessageType() const;

		/// Set message type
		/// @param type The message type to set
		void setMessageType(const GtpV2MessageType& type);

		/// @return The message length as set in the layer. Note it is different from getHeaderLen() because the later
		/// refers to the entire layers length, and this property excludes the mandatory part of the GTP-C header
		/// (the first 4 octets)
		uint16_t getMessageLength() const;

		/// @return True if there is another GTPv2 message piggybacking on this message (will appear as another
		/// GtpV2Layer after this layer)
		bool isPiggybacking() const;

		/// Get the Tunnel Endpoint Identifier (TEID) if exists
		/// @return A pair of 2 values; the first value states whether TEID exists, and if it's true the second value
		/// contains the TEID value
		std::pair<bool, uint32_t> getTeid() const;

		/// Set Tunnel Endpoint Identifier (TEID)
		/// @param teid The TEID value to set
		void setTeid(uint32_t teid);

		/// Unset Tunnel Endpoint Identifier (TEID) if exists in the layer (otherwise does nothing)
		void unsetTeid();

		/// @return The sequence number
		uint32_t getSequenceNumber() const;

		/// Set the sequence number
		/// @param sequenceNumber The sequence number value to set
		void setSequenceNumber(uint32_t sequenceNumber);

		/// Get the Message Property if exists
		/// @return A pair of 2 values; the first value states whether Message Priority exists, and if it's true
		/// the second value contains the Message Priority value
		std::pair<bool, uint8_t> getMessagePriority() const;

		/// Set Message Priority
		/// @param messagePriority The Message Priority value to set
		void setMessagePriority(const std::bitset<4>& messagePriority);

		/// Unset Message Priority if exists in the layer (otherwise does nothing)
		void unsetMessagePriority();

		/// @return The first GTPv2 Information Element (IE). If there are no IEs the returned value will contain
		/// a logical null (GtpV2InformationElement#isNull() == true)
		GtpV2InformationElement getFirstInformationElement() const;

		/// Get the GTPv2 Information Element (IE) that comes after a given IE. If the given IE was the last one, the
		/// returned value will contain a logical null (GtpV2InformationElement#isNull() == true)
		/// @param[in] infoElement A given GTPv2 Information Element
		/// @return A GtpV2InformationElement object containing the IE that comes next, or logical null if the given
		/// IE: (1) is the last one; (2) contains a logical null or (3) doesn't belong to this packet
		GtpV2InformationElement getNextInformationElement(GtpV2InformationElement infoElement) const;

		/// Get a GTPv2 Information Element (IE) by type
		/// @param[in] infoElementType GTPv2 Information Element (IE) type
		/// @return A GtpV2InformationElement object containing the first IE that matches this type, or logical
		/// null (GtpV2InformationElement#isNull() == true) if no such IE found
		GtpV2InformationElement getInformationElement(GtpV2InformationElement::Type infoElementType) const;

		/// @return The number of GTPv2 Information Elements (IEs) in this layer
		size_t getInformationElementCount() const;

		/// Add a new Information Element (IE) at the end of the layer
		/// @param[in] infoElementBuilder A GtpV2InformationElementBuilder object that contains the requested
		/// IE data to add
		/// @return A GtpV2InformationElement object containing the newly added IE data or logical null
		/// (GtpV2InformationElement#isNull() == true) if addition failed
		GtpV2InformationElement addInformationElement(const GtpV2InformationElementBuilder& infoElementBuilder);

		/// Add a new Information Element (IE) after an existing one
		/// @param[in] infoElementBuilder A GtpV2InformationElementBuilder object that contains the requested
		/// IE data to add
		/// @param[in] infoElementType The IE type which the newly added option will come after
		/// @return A GtpV2InformationElement object containing the newly added IE data or logical null
		/// (GtpV2InformationElement#isNull() == true) if addition failed
		GtpV2InformationElement addInformationElementAfter(const GtpV2InformationElementBuilder& infoElementBuilder,
		                                                   GtpV2InformationElement::Type infoElementType);

		/// Remove an existing Information Element (IE) from the layer
		/// @param[in] infoElementType The IE type to remove
		/// @return True if the IE was successfully removed or false if type wasn't found or if removal failed
		bool removeInformationElement(GtpV2InformationElement::Type infoElementType);

		/// Remove all Information Elements (IE) in this layer
		/// @return True if all IEs were successfully removed or false if removal failed for some reason
		bool removeAllInformationElements();

		// implement abstract methods

		/// Identifies if the next layer is GTPv2 piggyback. Otherwise sets PayloadLayer
		void parseNextLayer() override;

		/// @return The size of the GTPv2 header including its Information Elements (IE)
		size_t getHeaderLen() const override;

		/// Computes the piggybacking flag by checking if the next layer is also a GTPv2 message
		void computeCalculateFields() override;

		std::string toString() const override;

		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelTransportLayer;
		}

	private:
#pragma pack(push, 1)
		struct gtpv2_basic_header
		{
#if (BYTE_ORDER == LITTLE_ENDIAN)
			uint8_t unused : 2, messagePriorityPresent : 1, teidPresent : 1, piggybacking : 1, version : 3;
#else
			uint8_t version : 3, piggybacking : 1, teidPresent : 1, messagePriorityPresent : 1, unused : 2;
#endif
			uint8_t messageType;
			uint16_t messageLength;
		};
#pragma pack(pop)

		TLVRecordReader<GtpV2InformationElement> m_IEReader;

		gtpv2_basic_header* getHeader() const
		{
			return reinterpret_cast<gtpv2_basic_header*>(m_Data);
		}

		uint8_t* getIEBasePtr() const;

		GtpV2InformationElement addInformationElementAt(const GtpV2InformationElementBuilder& infoElementBuilder,
		                                                int offset);
	};
}  // namespace pcpp
