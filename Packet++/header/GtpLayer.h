#ifndef PACKETPP_GTP_LAYER
#define PACKETPP_GTP_LAYER

#include "Layer.h"

/// @file


/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

#pragma pack(push, 1)
	/**
	 * @struct gtpv1_header
	 * GTP v1 common message header
	 */
	struct gtpv1_header
	{
#if (BYTE_ORDER == LITTLE_ENDIAN)
		/** A 1-bit value that states whether there is a N-PDU number optional field */
		uint8_t npduNumberFlag:1,
		/** A 1-bit value that states whether there is a Sequence Number optional field */
		sequenceNumberFlag:1,
		/** A 1-bit value that states whether there is an extension header optional field */
		extensionHeaderFlag:1,
		/** Reserved bit */
		reserved:1,
		/** A 1-bit value that differentiates GTP (value 1) from GTP' (value 0) */
		protocolType:1,
		/** GTP version */
		version:3;
#else
		/** GTP version */
		uint8_t version:3,
		/** A 1-bit value that differentiates GTP (value 1) from GTP' (value 0) */
		protocolType:1,
		/** Reserved bit */
		reserved:1,
		/** A 1-bit value that states whether there is an extension header optional field */
		extensionHeaderFlag:1,
		/** A 1-bit value that states whether there is a Sequence Number optional field */
		sequenceNumberFlag:1,
		/** A 1-bit value that states whether there is a N-PDU number optional field */
		npduNumberFlag:1;
#endif
		/** An 8-bit field that indicates the type of GTP message */
		uint8_t messageType;

		/** A 16-bit field that indicates the length of the payload in bytes (rest of the packet following the mandatory 8-byte GTP header). Includes the optional fields */
		uint16_t messageLength;

		/** Tunnel endpoint identifier - A 32-bit(4-octet) field used to multiplex different connections in the same GTP tunnel */
		uint32_t teid;
	};

#pragma pack(pop)

	/**
	 * An enum representing the possible GTP v1 message types.
	 * All of the message types except for #GtpV1_GPDU are considered GTP-C messages. #GtpV1_GPDU is considered a GTP-U message
	 */
	enum GtpV1MessageType
	{
		/** GTPv1 Message Type Unknown */
		GtpV1_MessageTypeUnknown = 0,
		/** Echo Request */
		GtpV1_EchoRequest = 1,
		/** Echo Response */
		GtpV1_EchoResponse = 2,
		/** Version Not Supported */
		GtpV1_VersionNotSupported = 3,
		/** Node Alive Request */
		GtpV1_NodeAliveRequest = 4,
		/** Node Alive Response */
		GtpV1_NodeAliveResponse = 5,
		/** Redirection Request */
		GtpV1_RedirectionRequest = 6,
		/** Create PDP Context Request */
		GtpV1_CreatePDPContextRequest = 7,
		/** Create PDP Context Response */
		GtpV1_CreatePDPContextResponse = 16,
		/** Update PDP Context Request */
		GtpV1_UpdatePDPContextRequest = 17,
		/** Update PDP Context Response */
		GtpV1_UpdatePDPContextResponse = 18,
		/** Delete PDP Context Request */
		GtpV1_DeletePDPContextRequest = 19,
		/** Delete PDP Context Response */
		GtpV1_DeletePDPContextResponse = 20,
		/** Initiate PDP Context Activation Request */
		GtpV1_InitiatePDPContextActivationRequest = 22,
		/** Initiate PDP Context Activation Response */
		GtpV1_InitiatePDPContextActivationResponse = 23,
		/** Error Indication */
		GtpV1_ErrorIndication = 26,
		/** PDU Notification Request */
		GtpV1_PDUNotificationRequest = 27,
		/** PDU Notification Response */
		GtpV1_PDUNotificationResponse = 28,
		/** PDU Notification Reject Request */
		GtpV1_PDUNotificationRejectRequest = 29,
		/** PDU Notification Reject Response */
		GtpV1_PDUNotificationRejectResponse = 30,
		/** Supported Extensions Header Notification */
		GtpV1_SupportedExtensionsHeaderNotification = 31,
		/** Send Routing for GPRS Request */
		GtpV1_SendRoutingforGPRSRequest = 32,
		/** Send Routing for GPRS Response */
		GtpV1_SendRoutingforGPRSResponse = 33,
		/** Failure Report Request */
		GtpV1_FailureReportRequest = 34,
		/** Failure Report Response */
		GtpV1_FailureReportResponse = 35,
		/** Note MS Present Request */
		GtpV1_NoteMSPresentRequest = 36,
		/** Note MS Present Response */
		GtpV1_NoteMSPresentResponse = 37,
		/** Identification Request */
		GtpV1_IdentificationRequest = 38,
		/** Identification Response */
		GtpV1_IdentificationResponse = 39,
		/** SGSN Context Request */
		GtpV1_SGSNContextRequest = 50,
		/** SGSN Context Response */
		GtpV1_SGSNContextResponse = 51,
		/** SGSN Context Acknowledge */
		GtpV1_SGSNContextAcknowledge = 52,
		/** Forward Relocation Request */
		GtpV1_ForwardRelocationRequest = 53,
		/** Forward Relocation Response */
		GtpV1_ForwardRelocationResponse = 54,
		/** Forward Relocation Complete */
		GtpV1_ForwardRelocationComplete = 55,
		/** Relocation Cancel Request */
		GtpV1_RelocationCancelRequest = 56,
		/** Relocation Cancel Response */
		GtpV1_RelocationCancelResponse = 57,
		/** Forward SRNS Context */
		GtpV1_ForwardSRNSContext = 58,
		/** Forward Relocation Complete Acknowledge */
		GtpV1_ForwardRelocationCompleteAcknowledge = 59,
		/** Forward SRNS Context Acknowledge */
		GtpV1_ForwardSRNSContextAcknowledge = 60,
		/** UE Registration Request */
		GtpV1_UERegistrationRequest = 61,
		/** UE Registration Response */
		GtpV1_UERegistrationResponse = 62,
		/** RAN Information Relay */
		GtpV1_RANInformationRelay = 70,
		/** MBMS Notification Request */
		GtpV1_MBMSNotificationRequest = 96,
		/** MBMS Notification Response */
		GtpV1_MBMSNotificationResponse = 97,
		/** MBMS Notification Reject Request */
		GtpV1_MBMSNotificationRejectRequest = 98,
		/** MBMS Notification Reject Response */
		GtpV1_MBMSNotificationRejectResponse = 99,
		/** Create MBMS Notification Request */
		GtpV1_CreateMBMSNotificationRequest = 100,
		/** Create MBMS Notification Response */
		GtpV1_CreateMBMSNotificationResponse = 101,
		/** Update MBMS Notification Request */
		GtpV1_UpdateMBMSNotificationRequest = 102,
		/** Update MBMS Notification Response */
		GtpV1_UpdateMBMSNotificationResponse = 103,
		/** Delete MBMS Notification Request */
		GtpV1_DeleteMBMSNotificationRequest = 104,
		/** Delete MBMS Notification Response */
		GtpV1_DeleteMBMSNotificationResponse = 105,
		/** MBMS Registration Request */
		GtpV1_MBMSRegistrationRequest = 112,
		/** MBMS Registration Response */
		GtpV1_MBMSRegistrationResponse = 113,
		/** MBMS De-Registration Request */
		GtpV1_MBMSDeRegistrationRequest = 114,
		/** MBMS De-Registration Response */
		GtpV1_MBMSDeRegistrationResponse = 115,
		/** MBMS Session Start Request */
		GtpV1_MBMSSessionStartRequest = 116,
		/** MBMS Session Start Response */
		GtpV1_MBMSSessionStartResponse = 117,
		/** MBMS Session Stop Request */
		GtpV1_MBMSSessionStopRequest = 118,
		/** MBMS Session Stop Response */
		GtpV1_MBMSSessionStopResponse = 119,
		/** MBMS Session Update Request */
		GtpV1_MBMSSessionUpdateRequest = 120,
		/** MBMS Session Update Response */
		GtpV1_MBMSSessionUpdateResponse = 121,
		/** MS Info Change Request */
		GtpV1_MSInfoChangeRequest = 128,
		/** MS Info Change Response */
		GtpV1_MSInfoChangeResponse = 129,
		/** Data Record Transfer Request */
		GtpV1_DataRecordTransferRequest = 240,
		/** Data Record Transfer Response */
		GtpV1_DataRecordTransferResponse = 241,
		/** End Marker */
		GtpV1_EndMarker = 254,
		/** G-PDU */
		GtpV1_GPDU = 255
	};


	/**
	 * @class GtpV1Layer
	 * A class representing the [GTP v1](https://en.wikipedia.org/wiki/GPRS_Tunnelling_Protocol) protocol.
	 */
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

		void init(GtpV1MessageType messageType, uint32_t teid, bool setSeqNum, uint16_t seqNum, bool setNpduNum, uint8_t npduNum);

	public:

		/**
		 * @class GtpExtension
		 * A class that represents [GTP header extensions](https://en.wikipedia.org/wiki/GPRS_Tunnelling_Protocol)
		 */
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

			/**
			 * An empty c'tor that creates an empty object, meaning one that isNull() returns "true")
			 */
			GtpExtension();

			/**
			 * A copy c'tor for this class
			 * @param[in] other The GTP extension to copy from
			 */
			GtpExtension(const GtpExtension& other);

			/**
			 * An assignment operator for this class
			 * @param[in] other The extension to assign from
			 * @return A reference to the assignee
			 */
			GtpExtension& operator=(const GtpExtension& other);

			/**
			 * @return Instances of this class may be initialized as empty, meaning they don't contain any data. In
			 * these cases this method returns true
			 */
			bool isNull() const;

			/**
			 * @return The extension type. If the object is empty a value of zero is returned
			 */
			uint8_t getExtensionType() const;

			/**
			 * @return The total length of the extension including the length and next extension type fields.
			 * If the object is empty a value of zero is returned
			 */
			size_t getTotalLength() const;

			/**
			 * @return The length of the extension's content, excluding the extension length and next extension type fields.
			 * If the object is empty a value of zero is returned
			 */
			size_t getContentLength() const;

			/**
			 * @return A byte array that includes the extension's content. The length of this array can be determined by
			 * getContentLength(). If the object is empty a null value is returned
			 */
			uint8_t* getContent() const;

			/**
			 * @return The extension type of the next header. If there are no more header extensions or if this object is empty
			 * a value of zero is returned
			 */
			uint8_t getNextExtensionHeaderType() const;

			/**
			 * @return An instance of this class representing the next extension header, if exists in the message. If there are
			 * no more header extensions or if this object is empty an empty instance of GtpExtension is returned, meaning
			 * one that GtpExtension#isNull() returns "true"
			 */
			GtpExtension getNextExtension() const;
		}; // GtpExtension

		virtual ~GtpV1Layer() {}

		 /** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		GtpV1Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet) { m_Protocol = GTPv1; }

		/**
		 * A constructor that creates a new GTPv1 layer and sets the message type and the TEID value
		 * @param[in] messageType The GTPv1 message type to be set in the newly created layer
		 * @param[in] teid The TEID value to be set in the newly created layer
		 */
		GtpV1Layer(GtpV1MessageType messageType, uint32_t teid);

		/**
		 * A constructor that creates a new GTPv1 layer and sets various parameters
		 * @param[in] messageType The GTPv1 message type to be set in the newly created layer
		 * @param[in] teid The TEID value to be set in the newly created layer
		 * @param[in] setSeqNum A flag indicating whether to set a sequence number. If set to "false" then the parameter "seqNum" will be ignored
		 * @param[in] seqNum The sequence number to be set in the newly created later. If "setSeqNum" is set to false this parameter will be ignored
		 * @param[in] setNpduNum A flag indicating whether to set the N-PDU number. If set to "false" then the parameter "npduNum" will be ignored
		 * @param[in] npduNum The N-PDU number to be set in the newly created later. If "setNpduNum" is set to false this parameter will be ignored
		 */
		GtpV1Layer(GtpV1MessageType messageType, uint32_t teid, bool setSeqNum, uint16_t seqNum, bool setNpduNum, uint8_t npduNum);

		/**
		 * A static method that takes a byte array and detects whether it is a GTP v1 message
		 * @param[in] data A byte array
		 * @param[in] dataSize The byte array size (in bytes)
		 * @return True if the data is identified as GTP v1 message (GTP-C or GTP-U)
		 */
		static bool isGTPv1(const uint8_t* data, size_t dataSize);

		/**
		 * @return The GTP v1 common header structure. Notice this points directly to the data, so every change will change the actual packet data
		 */
		gtpv1_header* getHeader() const { return (gtpv1_header*)m_Data; }

		/**
		 * Get the sequence number if exists on the message (sequence number is an optional field in GTP messages)
		 * @param[out] seqNumber Set with the sequence number value if exists in the layer. Otherwise remains unchanged
		 * @return True if the sequence number field exists in layer, in which case seqNumber is set with the value.
		 * Or false otherwise
		 */
		bool getSequenceNumber(uint16_t& seqNumber) const;

		/**
		 * Set a sequence number
		 * @param[in] seqNumber The sequence number to set
		 * @return True if the value was set successfully, false otherwise. In case of failure a corresponding error message will be written to log
		 */
		bool setSequenceNumber(const uint16_t seqNumber);

		/**
		 * Get the N-PDU number if exists on the message (N-PDU number is an optional field in GTP messages)
		 * @param[out] npduNum Set with the N-PDU number value if exists in the layer. Otherwise remains unchanged
		 * @return True if the N-PDU number field exists in layer, in which case npduNum is set with the value.
		 * Or false otherwise
		 */
		bool getNpduNumber(uint8_t& npduNum) const;

		/**
		 * Set an N-PDU number
		 * @param[in] npduNum The N-PDU number to set
		 * @return True if the value was set successfully, false otherwise. In case of failure a corresponding error message will be written to log
		 */
		bool setNpduNumber(const uint8_t npduNum);

		/**
		 * Get the type of the next header extension if exists on the message (extensions are optional in GTP messages)
		 * @param[out] nextExtType Set with the next header extension type if exists in layer. Otherwise remains unchanged
		 * @return True if the message contains header extensions, in which case nextExtType is set to the next
		 * header extension type. If there are no header extensions false is returned and nextExtType remains unchanged
		 */
		bool getNextExtensionHeaderType(uint8_t& nextExtType) const;

		/**
		 * @return An object that represents the next extension header, if exists in the message. If there are no extensions
		 * an empty object is returned, meaning an object which GtpExtension#isNull() returns "true"
		 */
		GtpExtension getNextExtension() const;

		/**
		 * Add a GTPv1 header extension. It is assumed that the extension is 4 bytes in length and its content is 2 bytes in length.
		 * If you need a different content size please reach out to me. This method takes care of extending the layer to make room for
		 * the new extension and also sets the relevant flags and fields
		 * @param[in] extensionType The type of the new extension
		 * @param[in] extensionContent A 2-byte long content
		 * @return An object representing the newly added extension. If there was an error adding the extension a null object will be
		 * returned (meaning GtpExtension#isNull() will return "true") and a corresponding error message will be written to log
		 */
		GtpExtension addExtension(uint8_t extensionType, uint16_t extensionContent);

		/**
		 * @return The message type of this GTP packet
		 */
		GtpV1MessageType getMessageType() const;

		/**
		 * @return A string representation of the packet's message type
		 */
		std::string getMessageTypeAsString() const;

		/**
		 * @return True if this is a GTP-U message, false otherwise
		 */
		bool isGTPUMessage() const;

		/**
		 * @return True if this is a GTP-C message, false otherwise
		 */
		bool isGTPCMessage() const;

		/**
		 * A static method that checks whether the port is considered as GTPv1
		 * @param[in] port The port number to be checked
		 * @return True if the port matches those associated with the BGP protocol
		 */
		static bool isGTPv1Port(uint16_t port) { return port == 2152 /* GTP-U */ || port == 2123 /* GTP-C */; }


		// implement abstract methods

		/**
		 * Identifies the following next layers for GTP-U packets: IPv4Layer, IPv6Layer. Otherwise sets PayloadLayer
		 */
		void parseNextLayer();

		/**
		 * @return The size of the GTP header. For GTP-C packets the size is determined by the value of
		 * gtpv1_header#messageLength and for GTP-U the size only includes the GTP header itself (meaning
		 * the size of gtpv1_header plus the size of the optional fields such as sequence number, N-PDU
		 * or extensions if exist)
		 */
		size_t getHeaderLen() const;

		/**
		 * Calculate the following fields:
		 * - gtpv1_header#messageLength
		 */
		void computeCalculateFields();

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const { return OsiModelTransportLayer; }
	};
}

#endif //PACKETPP_GTP_LAYER
