#ifndef PACKETPP_ICMP_LAYER
#define PACKETPP_ICMP_LAYER

#include "Layer.h"
#include "IPv4Layer.h"
#ifdef _MSC_VER
#include <Winsock2.h>
#else
#include <sys/time.h>
#endif
#include <vector>


/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * @struct icmphdr
	 * Represents ICMP basic protocol header (common for all ICMP message types)
	 */
#pragma pack(push, 1)
	typedef struct
	{
		/** message type */
		uint8_t	 type;
		/** message code */
		uint8_t	 code;
		/** message checksum */
		uint16_t checksum;
	} icmphdr;
#pragma pack(pop)

	/**
	 * An enum of all supported ICMP message types
	 */
	enum IcmpMessageType
	{
		/** ICMP echo (ping) reply message */
		ICMP_ECHO_REPLY           = 0,
		/** ICMP destination unreachable message */
		ICMP_DEST_UNREACHABLE     = 3,
		/** ICMP source quench message */
		ICMP_SOURCE_QUENCH        = 4,
		/** ICMP redirect message */
		ICMP_REDIRECT             = 5,
		/** ICMP echo (ping) request message */
		ICMP_ECHO_REQUEST         = 8,
		/** ICMP router advertisement message */
		ICMP_ROUTER_ADV           = 9,
		/** ICMP router soliciatation message */
		ICMP_ROUTER_SOL           = 10,
		/** ICMP time-to-live excceded message */
		ICMP_TIME_EXCEEDED        = 11,
		/** ICMP parameter problem message */
		ICMP_PARAM_PROBLEM        = 12,
		/** ICMP timestamp request message */
		ICMP_TIMESTAMP_REQUEST    = 13,
		/** ICMP timestamp reply message */
		ICMP_TIMESTAMP_REPLY      = 14,
		/** ICMP information request message */
		ICMP_INFO_REQUEST         = 15,
		/** ICMP information reply message */
		ICMP_INFO_REPLY           = 16,
		/** ICMP address mask request message */
		ICMP_ADDRESS_MASK_REQUEST = 17,
		/** ICMP address mask reply message */
		ICMP_ADDRESS_MASK_REPLY   = 18,
		/** ICMP message type unsupported by PcapPlusPlus */
		ICMP_UNSUPPORTED          = 255
	};

	/**
	 * An enum for all possible codes for a destination unreachable message type
	 * Documentation is taken from Wikipedia: https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
	 */
	enum IcmpDestUnreachableCodes
	{
		/** Network unreachable error */
		IcmpNetworkUnreachable = 0,
		/** Host unreachable error */
		IcmpHostUnreachable = 1,
		/** Protocol unreachable error (the designated transport protocol is not supported) */
		IcmpProtocolUnreachable = 2,
		/** Port unreachable error (the designated protocol is unable to inform the host of the incoming message) */
		IcmpPortUnreachable = 3,
		/** The datagram is too big. Packet fragmentation is required but the 'don't fragment' (DF) flag is on */
		IcmpDatagramTooBig = 4,
		/** Source route failed error */
		IcmpSourceRouteFailed = 5,
		/** Destination network unknown error */
		IcmpDestinationNetworkUnknown = 6,
		/** Destination host unknown error */
		IcmpDestinationHostUnknown = 7,
		/** Source host isolated error */
		IcmpSourceHostIsolated = 8,
		/** The destination network is administratively prohibited */
		IcmpDestinationNetworkProhibited = 9,
		/** The destination host is administratively prohibited */
		IcmpDestinationHostProhibited = 10,
		/** The network is unreachable for Type Of Service */
		IcmpNetworkUnreachableForTypeOfService = 11,
		/** The host is unreachable for Type Of Service */
		IcmpHostUnreachableForTypeOfService = 12,
		/** Communication administratively prohibited (administrative filtering prevents
		 * packet from being forwarded)
		 */
		IcmpCommunicationProhibited = 13,
		/** Host precedence violation (indicates the requested precedence is not permitted for
		 * the combination of host or network and port)
		 */
		IcmpHostPrecedenceViolation = 14,
		/** Precedence cutoff in effect (precedence of datagram is below the level set by
		 * the network administrators)
		 */
		IcmpPrecedenceCutoff = 15
	};


	/**
	 * @struct icmp_echo_hdr
	 * ICMP echo (ping) request/reply message structure
	 */
#pragma pack(push, 1)
	typedef struct : icmphdr
	{
		/** the echo (ping) request identifier */
		uint16_t id;
		/** the echo (ping) request sequence number */
		uint16_t sequence;
		/** a timestamp of when the message was sent */
		uint64_t timestamp;
	} icmp_echo_hdr;
#pragma pack(pop)


	/**
	 * @struct icmp_echo_request
	 * ICMP echo (ping) request/reply message structure
	 */
	typedef struct
	{
		/** a pointer to the header data */
		icmp_echo_hdr* header;
		/** most echo requests/replies contain some payload data. This is the data length */
		size_t dataLength;
		/** most echo requests/replies contain some payload data. This is a pointer to this data */
		uint8_t* data;
	} icmp_echo_request;


	/**
	 * @typedef icmp_echo_reply
	 * ICMP echo (ping) reply message structure, same as icmp_echo_request
	 */
	typedef icmp_echo_request icmp_echo_reply;


	/**
	 * @struct icmp_timestamp_request
	 * ICMP timestamp request message structure
	 */
#pragma pack(push, 1)
	typedef struct : icmphdr
	{
		/** the timestamp request identifier */
		uint16_t id;
		/** the timestamp request sequence number */
		uint16_t sequence;
		/** the time (in milliseconds since midnight) the sender last touched the packet */
		uint32_t originateTimestamp;
		/** relevant for timestamp reply only - the time the echoer first touched it on receipt */
		uint32_t receiveTimestamp;
		/** relevant for timestamp reply only - the time the echoer last touched the message on sending it */
		uint32_t transmitTimestamp;
	} icmp_timestamp_request;
#pragma pack(pop)


	/**
	 * @typedef icmp_timestamp_reply
	 * ICMP timestamp reply message structure, same as icmp_timestamp_request
	 */
	typedef icmp_timestamp_request icmp_timestamp_reply;


	/**
	 * @struct icmp_destination_unreachable
	 * ICMP destination unreachable message structure
	 */
#pragma pack(push, 1)
	typedef struct : icmphdr
	{
		/** unused 2 bytes */
		uint16_t unused;
		/** contains the MTU of the next-hop network if a code 4 error occurs */
		uint16_t nextHopMTU;
	} icmp_destination_unreachable;
#pragma pack(pop)


	/**
	 * @struct icmp_time_exceeded
	 * ICMP time-to-live exceeded message structure
	 */
#pragma pack(push, 1)
	typedef struct : icmphdr
	{
		/** unused 4 bytes */
		uint32_t unused;
	} icmp_time_exceeded;
#pragma pack(pop)


	/**
	 * @typedef icmp_source_quench
	 * ICMP source quence message structure, same as icmp_time_exceeded
	 */
	typedef icmp_time_exceeded icmp_source_quench;


	/**
	 * @struct icmp_param_problem
	 * ICMP parameter problem message structure
	 */
#pragma pack(push, 1)
	typedef struct : icmphdr
	{
		/** in the case of an invalid IP header (Code 0), this field indicates the byte offset of the error in the header */
		uint8_t  pointer;
		/** unused 1 byte */
		uint8_t  unused1;
		/** unused 2 bytes */
		uint16_t unused2;
	} icmp_param_problem;
#pragma pack(pop)


	/**
	 * @typedef icmp_router_solicitation
	 * ICMP router solicitation message structure, same as icmphdr
	 */
	typedef icmphdr icmp_router_solicitation;

	/**
	 * @struct icmp_redirect
	 * ICMP redirect message structure
	 */
#pragma pack(push, 1)
	typedef struct : icmphdr
	{
		/** an IPv4 address of the gateway to which the redirection should be sent */
		uint32_t gatewayAddress;
	} icmp_redirect;
#pragma pack(pop)


	/**
	 * @struct icmp_router_address_structure
	 * Router address structure, relevant for ICMP router advertisement message type (icmp_router_advertisement)
	 */
#pragma pack(push, 1)
	struct icmp_router_address_structure
	{
		/** the IPv4 address of the advertised router */
		uint32_t routerAddress;
		/** The preferability of the router address as a default router address, relative to other router addresses
		 * on the same subnet. This is a twos-complement value where higher values indicate that the route is
		 * more preferable */
		uint32_t preferenceLevel;

		/**
		 * Set router address structure from a given IPv4 address and preference level
		 * @param[in] addr IPv4 address to set
		 * @param[in] preference Preference level to set
		 */
		void setRouterAddress(IPv4Address addr, uint32_t preference);

		/**
		 * @return The IPv4 address extracted from icmp_router_address_structure#routerAddress field
		 */
		IPv4Address getAddress();
	};
#pragma pack(pop)


	/**
	 * @struct icmp_router_advertisement_hdr
	 * ICMP router advertisement message structure
	 */
#pragma pack(push, 1)
	typedef struct : icmphdr
	{
		/** the number of router advertisements in this message. Each advertisement contains one router address/preference level pair */
		uint8_t  advertisementCount;
		/** the number of 32-bit words of information for each router address entry in the list. The value is normally set to 2
		 * (router address + preference level) */
		uint8_t  addressEntrySize;
		/** the maximum number of seconds that the router addresses in this list may be considered valid */
		uint16_t lifetime;
	} icmp_router_advertisement_hdr;
#pragma pack(pop)


	/**
	 * @struct icmp_router_advertisement
	 * ICMP router advertisement message structure
	 */
	struct icmp_router_advertisement
	{
		/** a pointer to the header data on the packet */
		icmp_router_advertisement_hdr* header;

		/**
		 * Extract router advertisement at a given index
		 * @param[in] index The index of the router advertisement
		 * @return A pointer to the router advertisement on the packet or null if index is out of range (less than zero or
		 * greater than the number of router advertisement records on this message, determined by advertisementCount field)
		 */
		icmp_router_address_structure* getRouterAddress(int index);
	};


	/**
	 * @struct icmp_address_mask_request
	 * ICMP address mask request message structure
	 */
#pragma pack(push, 1)
	typedef struct : icmphdr
	{
		/** the address mask request identifier */
		uint16_t id;
		/** the address mask request sequence */
		uint16_t sequence;
		/** the subnet mask of the requesting host */
		uint32_t addressMask;
	} icmp_address_mask_request;
#pragma pack(pop)


	/**
	 * @typedef icmp_address_mask_reply
	 * ICMP address mask reply message structure, same as icmp_address_mask_request
	 */
	typedef icmp_address_mask_request icmp_address_mask_reply;


	/**
	 * @struct icmp_info_request
	 * ICMP information request message structure
	 */
#pragma pack(push, 1)
	typedef struct : icmphdr
	{
		/** the information request identifier */
		uint16_t id;
		/** the information request sequence */
		uint16_t sequence;
	} icmp_info_request;
#pragma pack(pop)


	/**
	 * @typedef icmp_info_reply
	 * ICMP information reply message structure, same as icmp_info_request
	 */
	typedef icmp_info_request icmp_info_reply;


	/**
	 * @class IcmpLayer
	 * Represents an ICMP protocol layer (for IPv4 only)
	 */
	class IcmpLayer : public Layer
	{
	private:
		icmp_echo_request m_EchoData;
		icmp_router_advertisement m_RouterAdvData;

		bool cleanIcmpLayer();

		bool setEchoData(IcmpMessageType echoType, uint16_t id, uint16_t sequence, uint64_t timestamp, const uint8_t* data, size_t dataLen);

		bool setIpAndL4Layers(IPv4Layer* ipLayer, Layer* l4Layer);

	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to @ref arphdr)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		IcmpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet) { m_Protocol = ICMP; }

		/**
		 * An empty constructor that creates a new layer with an empty ICMP header without setting the ICMP type or ICMP data.
		 * Call the set*Data() methods to set ICMP type and data
		 */
		IcmpLayer();

		virtual ~IcmpLayer() {}

		/**
		 * Get a pointer to the basic ICMP header. Notice this points directly to the data, so every change will change the actual packet data
		 * @return A pointer to the @ref icmphdr
		 */
		inline icmphdr* getIcmpHeader() { return (icmphdr*)m_Data; };

		/**
		 * @return The ICMP message type
		 */
		IcmpMessageType getMessageType();

		/**
		 * @param[in] type Type to check
		 * @return True if the layer if of the given type, false otherwise
		 */
		bool isMessageOfType(IcmpMessageType type);

		/**
		 * @return ICMP echo (ping) request data. If the layer isn't of type ICMP echo request NULL is returned
		 */
		icmp_echo_request* getEchoRequestData();

		/**
		 * Set echo (ping) request message data
		 * @param[in] id Echo (ping) request identifier
		 * @param[in] sequence Echo (ping) request sequence
		 * @param[in] timestamp Echo (ping) request timestamp
		 * @param[in] data A pointer to echo (ping) request payload to set
		 * @param[in] dataLen The length of the echo (ping) request payload
		 * @return A pointer to the echo (ping) request data that have been set or NULL if something went wrong
		 * (an appropriate error log is printed in such cases)
		 */
		icmp_echo_request* setEchoRequestData(uint16_t id, uint16_t sequence, uint64_t timestamp, const uint8_t* data, size_t dataLen);

		/**
		 * @return ICMP echo reply data. If the layer isn't of type ICMP echo reply NULL is returned
		 */
		icmp_echo_reply* getEchoReplyData();

		/**
		 * Set echo (ping) reply message data
		 * @param[in] id Echo (ping) reply identifier
		 * @param[in] sequence Echo (ping) reply sequence
		 * @param[in] timestamp Echo (ping) reply timestamp
		 * @param[in] data A pointer to echo (ping) reply payload to set
		 * @param[in] dataLen The length of the echo (ping) reply payload
		 * @return A pointer to the echo (ping) reply data that have been set or NULL if something went wrong
		 * (an appropriate error log is printed in such cases)
		 */
		icmp_echo_reply* setEchoReplyData(uint16_t id, uint16_t sequence, uint64_t timestamp, const uint8_t* data, size_t dataLen);

		/**
		 * @return ICMP timestamp request data. If the layer isn't of type ICMP timestamp request NULL is returned
		 */
		icmp_timestamp_request* getTimestampRequestData();

		/**
		 * Set timestamp request message data
		 * @param[in] id Timestamp request identifier
		 * @param[in] sequence Timestamp request sequence
		 * @param[in] originateTimestamp Time (in milliseconds since midnight) the sender last touched the packet
		 * @return A pointer to the timestamp request data that have been set or NULL if something went wrong
		 * (an appropriate error log is printed in such cases)
		 */
		icmp_timestamp_request* setTimestampRequestData(uint16_t id, uint16_t sequence, timeval originateTimestamp);

		/**
		 * @return ICMP timestamp reply data. If the layer isn't of type ICMP timestamp reply NULL is returned
		 */
		icmp_timestamp_reply* getTimestampReplyData();

		/**
		 * Set timestamp reply message data
		 * @param[in] id Timestamp reply identifier
		 * @param[in] sequence Timestamp reply sequence
		 * @param[in] originateTimestamp Time (in milliseconds since midnight) the sender last touched the packet
		 * @param[in] receiveTimestamp The time the echoer first touched it on receipt
		 * @param[in] transmitTimestamp The time the echoer last touched the message on sending it
		 * @return A pointer to the timestamp reply data that have been set or NULL if something went wrong
		 * (an appropriate error log is printed in such cases)
		 */
		icmp_timestamp_reply* setTimestampReplyData(uint16_t id, uint16_t sequence,
				timeval originateTimestamp, timeval receiveTimestamp, timeval transmitTimestamp);

		/**
		 * @return ICMP destination unreachable data. If the layer isn't of type ICMP destination unreachable NULL is returned.
		 * The IP and L4 (ICMP/TCP/UDP) headers of the destination unreachable data are parsed as separate layers and can be
		 * retrieved via this->getNextLayer()
		 */
		icmp_destination_unreachable* getDestUnreachableData();

		/**
		 * Set destination unreachable message data. This method only works if IcmpLayer is already part of a packet (not
		 * a standalone layer). The reason is the Internet and L4 headers given as parameters are added as separate layers
		 * and need a packet to be added to
		 * @param[in] code Destination unreachable code
		 * @param[in] nextHopMTU The MTU of the next-hop network if a code 4 error occurs
		 * @param[in] ipHeader The Internet header of the original data. This layer is added as a separate layer on the packet
		 * @param[in] l4Header The L4 header of the original data. This layer is added as a separate layer on the packet
		 * @return A pointer to the destination unreachable data that have been set or NULL if something went wrong
		 * (an appropriate error log is printed in such cases)
		 */
		icmp_destination_unreachable* setDestUnreachableData(IcmpDestUnreachableCodes code, uint16_t nextHopMTU, IPv4Layer* ipHeader, Layer* l4Header);

		/**
		 * @return ICMP source quench data. If the layer isn't of type ICMP source quench NULL is returned.
		 * The IP and L4 (ICMP/TCP/UDP) headers of the source quench data are parsed as separate layers and can be
		 * retrieved via this->getNextLayer()
		 */
		icmp_source_quench* getSourceQuenchdata();

		/**
		 * Set source quench message data. This method only works if IcmpLayer is already part of a packet (not
		 * a standalone layer). The reason is the Internet and L4 headers given as parameters are added as separate layers
		 * and need a packet to be added to
		 * @param[in] ipHeader The Internet header of the original data. This layer is added as a separate layer on the packet
		 * @param[in] l4Header The L4 header of the original data. This layer is added as a separate layer on the packet
		 * @return A pointer to the source quench data that have been set or NULL if something went wrong
		 * (an appropriate error log is printed in such cases)
		 */
		icmp_source_quench* setSourceQuenchdata(IPv4Layer* ipHeader, Layer* l4Header);

		/**
		 * @return ICMP redirect data. If the layer isn't of type ICMP redirect NULL is returned.
		 * The IP and L4 (ICMP/TCP/UDP) headers of the redirect data are parsed as separate layers and can be
		 * retrieved via this->getNextLayer()
		 */
		icmp_redirect* getRedirectData();

		/**
		 * Set redirect message data. This method only works if IcmpLayer is already part of a packet (not
		 * a standalone layer). The reason is the Internet and L4 headers given as parameters are added as separate layers
		 * and need a packet to be added to
		 * @param[in] code The redirect message code. Only values between 0 and 3 are legal, the rest will cause the method to fail
		 * @param[in] gatewayAddress An IPv4 address of the gateway to which the redirection should be sent
		 * @param[in] ipHeader The Internet header of the original data. This layer is added as a separate layer on the packet
		 * @param[in] l4Header The L4 header of the original data. This layer is added as a separate layer on the packet
		 * @return A pointer to the redirect data that have been set or NULL if something went wrong
		 * (an appropriate error log is printed in such cases)
		 */
		icmp_redirect* setRedirectData(uint8_t code, IPv4Address gatewayAddress, IPv4Layer* ipHeader, Layer* l4Header);

		/**
		 * @return ICMP router advertisement data. If the layer isn't of type ICMP router advertisement NULL is returned
		 */
		icmp_router_advertisement* getRouterAdvertisementData();

		/**
		 * Set router advertisement message data
		 * @param[in] code The router advertisement message code. Only codes 0 or 16 are legal, the rest will fail the method
		 * @param[in] lifetimeInSeconds The maximum number of seconds that the router addresses in this list may be considered valid
		 * @param[in] routerAddresses A vector of router advertisements to set
		 * @return A pointer to the router advertisement data that have been set or NULL if something went wrong
		 * (an appropriate error log is printed in such cases)
		 */
		icmp_router_advertisement* setRouterAdvertisementData(uint8_t code, uint16_t lifetimeInSeconds, const std::vector<icmp_router_address_structure>& routerAddresses);

		/**
		 * @return ICMP router solicitation data. If the layer isn't of type ICMP router solicitation NULL is returned
		 */
		icmp_router_solicitation* getRouterSolicitationData();

		/**
		 * Set router solicitation message data. This message accepts no parameters as there are no parameters to this
		 * type of message (code is always zero)
		 * @return A pointer to the router solicitation data that have been set or NULL if something went wrong
		 * (an appropriate error log is printed in such cases)
		 */
		icmp_router_solicitation* setRouterSolicitationData();

		/**
		 * @return ICMP time-to-live exceeded data. If the layer isn't of type ICMP time-to-live exceeded NULL is returned.
		 * The IP and L4 (ICMP/TCP/UDP) headers of the time exceeded data are parsed as separate layers and can be
		 * retrieved via this->getNextLayer()
		 */
		icmp_time_exceeded* getTimeExceededData();

		/**
		 * Set time-to-live exceeded message data. This method only works if IcmpLayer is already part of a packet (not
		 * a standalone layer). The reason is the Internet and L4 headers given as parameters are added as separate layers
		 * and need a packet to be added to
		 * @param[in] code Time-to-live exceeded message code. Only codes 0 or 1 are legal, the rest will fail the method
		 * @param[in] ipHeader The Internet header of the original data. This layer is added as a separate layer on the packet
		 * @param[in] l4Header The L4 header of the original data. This layer is added as a separate layer on the packet
		 * @return A pointer to the time-to-live exceeded data that have been set or NULL if something went wrong
		 * (an appropriate error log is printed in such cases)
		 */
		icmp_time_exceeded* setTimeExceededData(uint8_t code, IPv4Layer* ipHeader, Layer* l4Header);

		/**
		 * @return ICMP parameter problem data. If the layer isn't of type ICMP parameter problem NULL is returned
		 */
		icmp_param_problem* getParamProblemData();

		/**
		 * Set parameter problem message data. This method only works if IcmpLayer is already part of a packet (not
		 * a standalone layer). The reason is the Internet and L4 headers given as parameters are added as separate layers
		 * and need a packet to be added to
		 * @param[in] code Parameter problem message code. Only code between 0 and 2 are legal, the rest will fail the method
		 * @param[in] errorOctetPointer In the case of an invalid IP header (Code 0), indicate the byte offset of the error in the header
		 * @param[in] ipHeader The Internet header of the original data. This layer is added as a separate layer on the packet
		 * @param[in] l4Header The L4 header of the original data. This layer is added as a separate layer on the packet
		 * @return A pointer to the parameter problem data that have been set or NULL if something went wrong
		 * (an appropriate error log is printed in such cases)
		 */
		icmp_param_problem* setParamProblemData(uint8_t code, uint8_t errorOctetPointer, IPv4Layer* ipHeader, Layer* l4Header);

		/**
		 * @return ICMP address mask request data. If the layer isn't of type ICMP address mask request NULL is returned
		 */
		icmp_address_mask_request* getAddressMaskRequestData();

		/**
		 * Set address mask request message data
		 * @param[in] id Address mask request identifier
		 * @param[in] sequence Address mask request sequence
		 * @param[in] mask The subnet mask of the requesting host
		 * @return A pointer to the address mask request data that have been set or NULL if something went wrong
		 * (an appropriate error log is printed in such cases)
		 */
		icmp_address_mask_request* setAddressMaskRequestData(uint16_t id, uint16_t sequence, IPv4Address mask);

		/**
		 * @return ICMP address mask reply data. If the layer isn't of type ICMP address mask reply NULL is returned
		 */
		icmp_address_mask_reply* getAddressMaskReplyData();

		/**
		 * Set address mask reply message data
		 * @param[in] id Address mask reply identifier
		 * @param[in] sequence Address mask reply sequence
		 * @param[in] mask The subnet mask of the requesting host
		 * @return A pointer to the address mask reply data that have been set or NULL if something went wrong
		 * (an appropriate error log is printed in such cases)
		 */
		icmp_address_mask_reply* setAddressMaskReplyData(uint16_t id, uint16_t sequence, IPv4Address mask);

		/**
		 * @return ICMP address information request data. If the layer isn't of type ICMP information request NULL is returned
		 */
		icmp_info_request* getInfoRequestData();

		/**
		 * Set information request message data
		 * @param[in] id Information request identifier
		 * @param[in] sequence Information request sequence
		 * @return A pointer to the information request data that have been set or NULL if something went wrong
		 * (an appropriate error log is printed in such cases)
		 */
		icmp_info_request* setInfoRequestData(uint16_t id, uint16_t sequence);

		/**
		 * @return ICMP address information reply data. If the layer isn't of type ICMP information reply NULL is returned
		 */
		icmp_info_reply* getInfoReplyData();

		/**
		 * Set information reply message data
		 * @param[in] id Information reply identifier
		 * @param[in] sequence Information reply sequence
		 * @return A pointer to the information reply data that have been set or NULL if something went wrong
		 * (an appropriate error log is printed in such cases)
		 */
		icmp_info_reply* setInfoReplyData(uint16_t id, uint16_t sequence);


		// implement abstract methods

		/**
		 * ICMP messages of types: ICMP_DEST_UNREACHABLE, ICMP_SOURCE_QUENCH, ICMP_TIME_EXCEEDED, ICMP_REDIRECT, ICMP_PARAM_PROBLEM
		 * have data that contains IPv4 header and some L4 header (TCP/UDP/ICMP). This method parses these headers as separate
		 * layers on top of the ICMP layer
		 */
		void parseNextLayer();

		/**
		 * @return The ICMP header length. This length varies according to the ICMP message type. This length doesn't include
		 * IPv4 and L4 headers in case ICMP message type are: ICMP_DEST_UNREACHABLE, ICMP_SOURCE_QUENCH, ICMP_TIME_EXCEEDED,
		 * ICMP_REDIRECT, ICMP_PARAM_PROBLEM
		 */
		size_t getHeaderLen();

		/**
		 * Calculate ICMP checksum field
		 */
		void computeCalculateFields();

		std::string toString();

		OsiModelLayer getOsiModelLayer() { return OsiModelNetworkLayer; }
	};

} // namespace pcpp

#endif /* PACKETPP_ICMP_LAYER */
