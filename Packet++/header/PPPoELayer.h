#pragma once

#include "Layer.h"
#include "TLVData.h"
#include <vector>
#include <string.h>

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	/// @struct pppoe_header
	/// Represents an PPPoE protocol header
#pragma pack(push, 1)
	struct pppoe_header
	{
#if (BYTE_ORDER == LITTLE_ENDIAN)
		/// PPPoE version
		uint8_t version : 4;
		/// PPPoE type
		uint8_t type : 4;
		/// PPPoE code
		uint8_t code;
#else
		/// PPPoE version
		uint16_t version : 4;
		/// PPPoE type
		uint16_t type : 4;
		/// PPPoE code
		uint16_t code : 8;
#endif
		/// PPPoE session ID (relevant for PPPoE session packets only)
		uint16_t sessionId;
		/// Length (in bytes) of payload, not including the PPPoE header
		uint16_t payloadLength;
	};
#pragma pack(pop)
	static_assert(sizeof(pppoe_header) == 6, "pppoe_header size is not 6 bytes");

	/// @class PPPoELayer
	/// An abstract class that describes the PPPoE protocol. Contains common data and logic of the two types of PPPoE
	/// packets: PPPoE session and PPPoE discovery
	class PPPoELayer : public Layer
	{
	public:
		/// PPPoE possible codes
		enum PPPoECode
		{
			/// PPPoE session code
			PPPOE_CODE_SESSION = 0x00,
			/// PPPoE discovery PADO
			PPPOE_CODE_PADO = 0x07,
			/// PPPoE discovery PADI
			PPPOE_CODE_PADI = 0x09,
			/// PPPoE discovery PADG
			PPPOE_CODE_PADG = 0x0a,
			/// PPPoE discovery PADC
			PPPOE_CODE_PADC = 0x0b,
			/// PPPoE discovery PADQ
			PPPOE_CODE_PADQ = 0x0c,
			/// PPPoE discovery PADR
			PPPOE_CODE_PADR = 0x19,
			/// PPPoE discovery PADS
			PPPOE_CODE_PADS = 0x65,
			/// PPPoE discovery PADT
			PPPOE_CODE_PADT = 0xa7,
			/// PPPoE discovery PADM
			PPPOE_CODE_PADM = 0xd3,
			/// PPPoE discovery PADN
			PPPOE_CODE_PADN = 0xd4
		};

		~PPPoELayer() override = default;

		/// Get a pointer to the PPPoE header. Notice this points directly to the data, so every change will change the
		/// actual packet data
		/// @return A pointer to the pppoe_header
		pppoe_header* getPPPoEHeader() const
		{
			return reinterpret_cast<pppoe_header*>(m_Data);
		}

		// abstract methods implementation

		/// Calculate @ref pppoe_header#payloadLength field
		void computeCalculateFields() override;

		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelDataLinkLayer;
		}

	protected:
		// protected c'tor as this class shouldn't be instantiated
		PPPoELayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet, ProtocolType protocol)
		    : Layer(data, dataLen, prevLayer, packet, protocol)
		{}

		// protected c'tor as this class shouldn't be instantiated
		PPPoELayer(uint8_t version, uint8_t type, PPPoELayer::PPPoECode code, uint16_t sessionId,
		           size_t additionalBytesToAllocate = 0);
	};

	/// @class PPPoESessionLayer
	/// Describes the PPPoE session protocol
	class PPPoESessionLayer : public PPPoELayer
	{
	public:
		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data (will be casted to @ref pppoe_header)
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		PPPoESessionLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : PPPoELayer(data, dataLen, prevLayer, packet, PPPoESession)
		{}

		/// A constructor that allocates a new PPPoE Session header with version, type and session ID
		/// @param[in] version PPPoE version
		/// @param[in] type PPPoE type
		/// @param[in] sessionId PPPoE session ID
		/// @param[in] pppNextProtocol The next protocol to come after the PPPoE session header. Should be one of the
		/// PPP_* macros listed below
		PPPoESessionLayer(uint8_t version, uint8_t type, uint16_t sessionId, uint16_t pppNextProtocol)
		    : PPPoELayer(version, type, PPPoELayer::PPPOE_CODE_SESSION, sessionId, sizeof(uint16_t))
		{
			setPPPNextProtocol(pppNextProtocol);
		}

		~PPPoESessionLayer() override = default;

		/// @return The protocol after the PPPoE session header. The return value is one of the PPP_* macros listed
		/// below. This method is also used when parsing a packet (this way we know which layer comes after the PPPoE
		/// session)
		uint16_t getPPPNextProtocol() const;

		/// Set the field that describes which header comes after the PPPoE session header
		/// @param[in] nextProtocol The protocol value. Should be one of the PPP_* macros listed below
		void setPPPNextProtocol(uint16_t nextProtocol);

		/// A static method that validates the input data
		/// @param[in] data The pointer to the beginning of byte stream of a packet
		/// @param[in] dataLen The length of the byte stream
		/// @return True if the data is valid and can represent a PPPoES packet
		static inline bool isDataValid(const uint8_t* data, size_t dataLen);

		// abstract methods implementation

		/// Currently identifies the following next layers: IPv4Layer, IPv6Layer. Otherwise sets PayloadLayer
		void parseNextLayer() override;

		/// @return Size of @ref pppoe_header
		size_t getHeaderLen() const override
		{
			return sizeof(pppoe_header) + sizeof(uint16_t);
		}

		std::string toString() const override;
	};

	/// @class PPPoEDiscoveryLayer
	/// Describes the PPPoE discovery protocol
	class PPPoEDiscoveryLayer : public PPPoELayer
	{
	public:
		/// PPPoE tag types
		enum PPPoETagTypes
		{
			/// End-Of-List tag type
			PPPOE_TAG_EOL = 0x0000,
			/// Service-Name tag type
			PPPOE_TAG_SVC_NAME = 0x0101,
			/// AC-Name tag type
			PPPOE_TAG_AC_NAME = 0x0102,
			/// Host-Uniq tag type
			PPPOE_TAG_HOST_UNIQ = 0x0103,
			/// AC-Cookie tag type
			PPPOE_TAG_AC_COOKIE = 0x0104,
			/// Vendor-Specific tag type
			PPPOE_TAG_VENDOR = 0x0105,
			/// Credits tag type
			PPPOE_TAG_CREDITS = 0x0106,
			/// Metrics tag type
			PPPOE_TAG_METRICS = 0x0107,
			/// Sequence Number tag type
			PPPOE_TAG_SEQ_NUM = 0x0108,
			/// Credit Scale Factor tag type
			PPPOE_TAG_CRED_SCALE = 0x0109,
			/// Relay-Session-Id tag type
			PPPOE_TAG_RELAY_ID = 0x0110,
			/// HURL tag type
			PPPOE_TAG_HURL = 0x0111,
			/// MOTM tag type
			PPPOE_TAG_MOTM = 0x0112,
			/// PPP-Max-Payload tag type
			PPPOE_TAG_MAX_PAYLD = 0x0120,
			/// IP_Route_Add tag type
			PPPOE_TAG_IP_RT_ADD = 0x0121,
			/// Service-Name-Error tag type
			PPPOE_TAG_SVC_ERR = 0x0201,
			/// AC-System-Error tag type
			PPPOE_TAG_AC_ERR = 0x0202,
			/// Generic-Error tag type
			PPPOE_TAG_GENERIC_ERR = 0x0203
		};

		/// @class PPPoETag
		/// Represents a PPPoE tag and its data
		class PPPoETag : public TLVRecord<uint16_t, uint16_t>
		{
		public:
			/// A c'tor that gets a pointer to the tag raw data (byte array)
			/// @param[in] tagRawData A pointer to the tag raw data
			explicit PPPoETag(uint8_t* tagRawData) : TLVRecord(tagRawData)
			{}

			/// A d'tor for this class, currently does nothing
			~PPPoETag() override = default;

			/// @return The tag type converted to PPPoEDiscoveryLayer#PPPoETagTypes enum
			PPPoEDiscoveryLayer::PPPoETagTypes getType() const;

			/// Retrieve the tag data as string. Relevant only if the tag value is indeed a string
			/// @return The tag data as string
			std::string getValueAsString() const
			{
				size_t dataSize = getDataSize();
				if (dataSize < 1)
					return "";

				return std::string(reinterpret_cast<const char*>(m_Data->recordValue), dataSize);
			}

			// implement abstract methods

			size_t getTotalSize() const override;

			size_t getDataSize() const override;
		};

		/// @class PPPoETagBuilder
		/// A class for building PPPoE Tags. This builder receives the tag parameters in its c'tor,
		/// builds the PPPoE Tag raw buffer and provides a build() method to get a PPPoETag object out of it
		class PPPoETagBuilder : public TLVRecordBuilder
		{
		public:
			/// A c'tor for building a PPPoE Tag which has no value (tag len is zero). The PPPoETag object can later
			/// be retrieved by calling build()
			/// @param[in] tagType Tag type
			explicit PPPoETagBuilder(PPPoETagTypes tagType)
			    : TLVRecordBuilder(static_cast<uint16_t>(tagType), nullptr, 0)
			{}

			/// A c'tor for building a PPPoE Tag which has a 4-byte value. The PPPoETag object can later
			/// be retrieved by calling build()
			/// @param[in] tagType Tag type
			/// @param[in] tagValue The tag's 4-byte value
			PPPoETagBuilder(PPPoETagTypes tagType, uint32_t tagValue)
			    : TLVRecordBuilder(static_cast<uint16_t>(tagType), tagValue)
			{}

			/// A c'tor for building a PPPoE Tag which has some arbitrary value. The PPPoETag object can later
			/// be retrieved by calling build()
			/// @param[in] tagType Tag type
			/// @param[in] tagValue A byte array that contains the tag data
			/// @param[in] tagValueLen The length of the value byte array
			PPPoETagBuilder(PPPoETagTypes tagType, uint8_t* tagValue, uint8_t tagValueLen)
			    : TLVRecordBuilder(static_cast<uint16_t>(tagType), tagValue, tagValueLen)
			{}

			/// Build the PPPoETag object out of the parameters defined in the c'tor
			/// @return The PPPoETag object
			PPPoETag build() const;
		};

		/// A constructor that creates the layer from an existing packet raw data
		/// @param[in] data A pointer to the raw data (will be casted to @ref pppoe_header)
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		PPPoEDiscoveryLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : PPPoELayer(data, dataLen, prevLayer, packet, PPPoEDiscovery)
		{
			m_DataLen = getHeaderLen();
		}

		/// A constructor that allocates a new PPPoE Discovery header with version, type, PPPoE code and session ID
		/// @param[in] version PPPoE version
		/// @param[in] type PPPoE type
		/// @param[in] code PPPoE code enum
		/// @param[in] sessionId PPPoE session ID
		PPPoEDiscoveryLayer(uint8_t version, uint8_t type, PPPoELayer::PPPoECode code, uint16_t sessionId)
		    : PPPoELayer(version, type, code, sessionId)
		{
			m_Protocol = PPPoEDiscovery;
		}

		/// Get a PPPoE Tag by tag type.
		/// @param[in] tagType The type of the tag to search
		/// @return A PPPoETag object that contains the first tag that matches this type, or logical null
		/// (PPPoETag#isNull() == true) if no such tag found
		PPPoETag getTag(PPPoEDiscoveryLayer::PPPoETagTypes tagType) const;

		/// @return The first tag in the PPPoE discovery layer. If the current layer contains no tags the returned value
		/// will contain a logical null (PPPoETag#isNull() == true)
		PPPoETag getFirstTag() const;

		/// Get the tag that comes right after the "tag" parameter. If the given tag is the last one, the returned value
		/// will contain a logical null (PPPoETag#isNull() == true)
		/// @param[in] tag A given tag
		/// @return A PPPoETag object containing the tag that comes next, or logical null if the given
		/// tag: (1) was the last one; (2) contains a logical null or (3) doesn't belong to this packet
		PPPoETag getNextTag(const PPPoETag& tag) const;

		/// @return The number of tags in this layer
		int getTagCount() const;

		/// Add a new PPPoE Tag at the end of the layer
		/// @param[in] tagBuilder A PPPoETagBuilder object that contains the requested tag data to add
		/// @return A PPPoETag object containing the newly added PPPoE Tag data or logical null
		/// (PPPoETag#isNull() == true) if addition failed
		PPPoETag addTag(const PPPoETagBuilder& tagBuilder);

		/// Add a new PPPoE Tag after an existing one
		/// @param[in] tagBuilder A PPPoETagBuilder object that contains the requested tag data to add
		/// @param[in] prevTagType The PPPoE Tag which the newly added tag will come after
		/// @return A PPPoETag object containing the newly added PPPoE Tag data or logical null
		/// (PPPoETag#isNull() == true) if addition failed
		PPPoETag addTagAfter(const PPPoETagBuilder& tagBuilder, PPPoETagTypes prevTagType);

		/// Remove an existing tag. Tag will be found by the tag type
		/// @param[in] tagType The tag type to remove
		/// @return True if tag was removed or false if tag wasn't found or if tag removal failed (in each case a proper
		/// error will be written to log)
		bool removeTag(PPPoEDiscoveryLayer::PPPoETagTypes tagType);

		/// Remove all tags in this layer
		/// @return True if all tags were successfully or false if removal failed for some reason (a proper error will
		/// be written to log)
		bool removeAllTags();

		/// A static method that validates the input data
		/// @param[in] data The pointer to the beginning of byte stream of a packet
		/// @param[in] dataLen The length of the byte stream
		/// @return True if the data is valid and can represent a PPPoED packet
		static inline bool isDataValid(const uint8_t* data, size_t dataLen);

		// abstract methods implementation

		/// Does nothing for this layer (PPPoE discovery is always the last layer)
		void parseNextLayer() override
		{}

		/// @return The header length which is size of strcut pppoe_header plus the total size of tags
		size_t getHeaderLen() const override;

		std::string toString() const override
		{
			return "PPP-over-Ethernet Discovery (" + codeToString((PPPoELayer::PPPoECode)getPPPoEHeader()->code) + ")";
		}

	private:
		TLVRecordReader<PPPoETag> m_TagReader;

		PPPoETag addTagAt(const PPPoETagBuilder& tagBuilder, int offset);

		uint8_t* getTagBasePtr() const
		{
			return m_Data + sizeof(pppoe_header);
		}

		std::string codeToString(PPPoECode code) const;
	};

	// implementation of inline methods

	bool PPPoESessionLayer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		return data && dataLen >= sizeof(pppoe_header) + sizeof(uint16_t);
	}

	bool PPPoEDiscoveryLayer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		return data && dataLen >= sizeof(pppoe_header);
	}

	// Copied from Wireshark: ppptypes.h

	/// Padding Protocol
#define PCPP_PPP_PADDING 0x1
	/// ROHC small-CID
#define PCPP_PPP_ROHC_SCID 0x3
	/// ROHC large-CID
#define PCPP_PPP_ROHC_LCID 0x5
	/// Internet Protocol version 4
#define PCPP_PPP_IP 0x21
	/// OSI Network Layer
#define PCPP_PPP_OSI 0x23
	/// Xerox NS IDP
#define PCPP_PPP_XNSIDP 0x25
	/// DECnet Phase IV
#define PCPP_PPP_DEC4 0x27
	/// AppleTalk
#define PCPP_PPP_AT 0x29
	/// Novell IPX
#define PCPP_PPP_IPX 0x2b
	/// Van Jacobson Compressed TCP/IP
#define PCPP_PPP_VJC_COMP 0x2d
	/// Van Jacobson Uncompressed TCP/IP
#define PCPP_PPP_VJC_UNCOMP 0x2f
	/// Bridging PDU
#define PCPP_PPP_BCP 0x31
	/// Stream Protocol (ST-II)
#define PCPP_PPP_ST 0x33
	/// Banyan Vines
#define PCPP_PPP_VINES 0x35
	/// AppleTalk EDDP
#define PCPP_PPP_AT_EDDP 0x39
	/// AppleTalk SmartBuffered
#define PCPP_PPP_AT_SB 0x3b
	/// Multi-Link
#define PCPP_PPP_MP 0x3d
	/// NETBIOS Framing
#define PCPP_PPP_NB 0x3f
	/// Cisco Systems
#define PCPP_PPP_CISCO 0x41
	/// Ascom Timeplex
#define PCPP_PPP_ASCOM 0x43
	/// Fujitsu Link Backup and Load Balancing
#define PCPP_PPP_LBLB 0x45
	/// DCA Remote Lan
#define PCPP_PPP_RL 0x47
	/// Serial Data Transport Protocol
#define PCPP_PPP_SDTP 0x49
	/// SNA over 802.2
#define PCPP_PPP_LLC 0x4b
	/// SNA
#define PCPP_PPP_SNA 0x4d
	/// IPv6 Header Compression
#define PCPP_PPP_IPV6HC 0x4f
	/// KNX Bridging Data
#define PCPP_PPP_KNX 0x51
	/// Encryption
#define PCPP_PPP_ENCRYPT 0x53
	/// Individual Link Encryption
#define PCPP_PPP_ILE 0x55
	/// Internet Protocol version 6
#define PCPP_PPP_IPV6 0x57
	/// PPP Muxing
#define PCPP_PPP_MUX 0x59
	/// Vendor-Specific Network Protocol (VSNP)
#define PCPP_PPP_VSNP 0x5b
	/// TRILL Network Protocol (TNP)
#define PCPP_PPP_TNP 0x5d
	/// RTP IPHC Full Header
#define PCPP_PPP_RTP_FH 0x61
	/// RTP IPHC Compressed TCP
#define PCPP_PPP_RTP_CTCP 0x63
	/// RTP IPHC Compressed Non TCP
#define PCPP_PPP_RTP_CNTCP 0x65
	/// RTP IPHC Compressed UDP 8
#define PCPP_PPP_RTP_CUDP8 0x67
	/// RTP IPHC Compressed RTP 8
#define PCPP_PPP_RTP_CRTP8 0x69
	/// Stampede Bridging
#define PCPP_PPP_STAMPEDE 0x6f
	/// MP+ Protocol
#define PCPP_PPP_MPPLUS 0x73
	/// NTCITS IPI
#define PCPP_PPP_NTCITS_IPI 0xc1
	/// Single link compression in multilink
#define PCPP_PPP_ML_SLCOMP 0xfb
	/// Compressed datagram
#define PCPP_PPP_COMP 0xfd
	/// 802.1d Hello Packets
#define PCPP_PPP_STP_HELLO 0x0201
	/// IBM Source Routing BPDU
#define PCPP_PPP_IBM_SR 0x0203
	/// DEC LANBridge100 Spanning Tree
#define PCPP_PPP_DEC_LB 0x0205
	/// Cisco Discovery Protocol
#define PCPP_PPP_CDP 0x0207
	/// Netcs Twin Routing
#define PCPP_PPP_NETCS 0x0209
	/// STP - Scheduled Transfer Protocol
#define PCPP_PPP_STP 0x020b
	/// EDP - Extreme Discovery Protocol
#define PCPP_PPP_EDP 0x020d
	/// Optical Supervisory Channel Protocol
#define PCPP_PPP_OSCP 0x0211
	/// Optical Supervisory Channel Protocol
#define PCPP_PPP_OSCP2 0x0213
	/// Luxcom
#define PCPP_PPP_LUXCOM 0x0231
	/// Sigma Network Systems
#define PCPP_PPP_SIGMA 0x0233
	/// Apple Client Server Protocol
#define PCPP_PPP_ACSP 0x0235
	/// MPLS Unicast
#define PCPP_PPP_MPLS_UNI 0x0281
	/// MPLS Multicast
#define PCPP_PPP_MPLS_MULTI 0x0283
	/// IEEE p1284.4 standard - data packets
#define PCPP_PPP_P12844 0x0285
	/// ETSI TETRA Network Protocol Type 1
#define PCPP_PPP_TETRA 0x0287
	/// Multichannel Flow Treatment Protocol
#define PCPP_PPP_MFTP 0x0289
	/// RTP IPHC Compressed TCP No Delta
#define PCPP_PPP_RTP_CTCPND 0x2063
	/// RTP IPHC Context State
#define PCPP_PPP_RTP_CS 0x2065
	/// RTP IPHC Compressed UDP 16
#define PCPP_PPP_RTP_CUDP16 0x2067
	/// RTP IPHC Compressed RTP 16
#define PCPP_PPP_RTP_CRDP16 0x2069
	/// Cray Communications Control Protocol
#define PCPP_PPP_CCCP 0x4001
	/// CDPD Mobile Network Registration Protocol
#define PCPP_PPP_CDPD_MNRP 0x4003
	/// Expand accelerator protocol
#define PCPP_PPP_EXPANDAP 0x4005
	/// ODSICP NCP
#define PCPP_PPP_ODSICP 0x4007
	/// DOCSIS DLL
#define PCPP_PPP_DOCSIS 0x4009
	/// Cetacean Network Detection Protocol
#define PCPP_PPP_CETACEANNDP 0x400b
	/// Stacker LZS
#define PCPP_PPP_LZS 0x4021
	/// RefTek Protocol
#define PCPP_PPP_REFTEK 0x4023
	/// Fibre Channel
#define PCPP_PPP_FC 0x4025
	/// EMIT Protocols
#define PCPP_PPP_EMIT 0x4027
	/// Vendor-Specific Protocol (VSP)
#define PCPP_PPP_VSP 0x405b
	/// TRILL Link State Protocol (TLSP)
#define PCPP_PPP_TLSP 0x405d
	/// Internet Protocol Control Protocol
#define PCPP_PPP_IPCP 0x8021
	/// OSI Network Layer Control Protocol
#define PCPP_PPP_OSINLCP 0x8023
	/// Xerox NS IDP Control Protocol
#define PCPP_PPP_XNSIDPCP 0x8025
	/// DECnet Phase IV Control Protocol
#define PCPP_PPP_DECNETCP 0x8027
	/// AppleTalk Control Protocol
#define PCPP_PPP_ATCP 0x8029
	/// Novell IPX Control Protocol
#define PCPP_PPP_IPXCP 0x802b
	/// Bridging NCP
#define PCPP_PPP_BRIDGENCP 0x8031
	/// Stream Protocol Control Protocol
#define PCPP_PPP_SPCP 0x8033
	/// Banyan Vines Control Protocol
#define PCPP_PPP_BVCP 0x8035
	/// Multi-Link Control Protocol
#define PCPP_PPP_MLCP 0x803d
	/// NETBIOS Framing Control Protocol
#define PCPP_PPP_NBCP 0x803f
	/// Cisco Systems Control Protocol
#define PCPP_PPP_CISCOCP 0x8041
	/// Ascom Timeplex Control Protocol (?)
#define PCPP_PPP_ASCOMCP 0x8043
	/// Fujitsu LBLB Control Protocol
#define PCPP_PPP_LBLBCP 0x8045
	/// DCA Remote Lan Network Control Protocol
#define PCPP_PPP_RLNCP 0x8047
	/// Serial Data Control Protocol
#define PCPP_PPP_SDCP 0x8049
	/// SNA over 802.2 Control Protocol
#define PCPP_PPP_LLCCP 0x804b
	/// SNA Control Protocol
#define PCPP_PPP_SNACP 0x804d
	/// IP6 Header Compression Control Protocol
#define PCPP_PPP_IP6HCCP 0x804f
	/// KNX Bridging Control Protocol
#define PCPP_PPP_KNXCP 0x8051
	/// Encryption Control Protocol
#define PCPP_PPP_ECP 0x8053
	/// Individual Link Encryption Control Protocol
#define PCPP_PPP_ILECP 0x8055
	/// IPv6 Control Protocol
#define PCPP_PPP_IPV6CP 0x8057
	/// PPP Muxing Control Protocol
#define PCPP_PPP_MUXCP 0x8059
	/// Vendor-Specific Network Control Protocol (VSNCP)   [RFC3772]
#define PCPP_PPP_VSNCP 0x805b
	/// TRILL Network Control Protocol (TNCP)
#define PCPP_PPP_TNCP 0x805d
	/// Stampede Bridging Control Protocol
#define PCPP_PPP_STAMPEDECP 0x806f
	/// MP+ Contorol Protocol
#define PCPP_PPP_MPPCP 0x8073
	/// NTCITS IPI Control Protocol
#define PCPP_PPP_IPICP 0x80c1
	/// Single link compression in multilink control
#define PCPP_PPP_SLCC 0x80fb
	/// Compression Control Protocol
#define PCPP_PPP_CCP 0x80fd
	/// Cisco Discovery Protocol Control Protocol
#define PCPP_PPP_CDPCP 0x8207
	/// Netcs Twin Routing
#define PCPP_PPP_NETCSCP 0x8209
	/// STP - Control Protocol
#define PCPP_PPP_STPCP 0x820b
	/// EDPCP - Extreme Discovery Protocol Control Protocol
#define PCPP_PPP_EDPCP 0x820d
	/// Apple Client Server Protocol Control
#define PCPP_PPP_ACSPC 0x8235
	/// MPLS Control Protocol
#define PCPP_PPP_MPLSCP 0x8281
	/// IEEE p1284.4 standard - Protocol Control
#define PCPP_PPP_P12844CP 0x8285
	/// ETSI TETRA TNP1 Control Protocol
#define PCPP_PPP_TETRACP 0x8287
	/// Multichannel Flow Treatment Protocol
#define PCPP_PPP_MFTPCP 0x8289
	/// Link Control Protocol
#define PCPP_PPP_LCP 0xc021
	/// Password Authentication Protocol
#define PCPP_PPP_PAP 0xc023
	/// Link Quality Report
#define PCPP_PPP_LQR 0xc025
	/// Shiva Password Authentication Protocol
#define PCPP_PPP_SPAP 0xc027
	/// CallBack Control Protocol (CBCP)
#define PCPP_PPP_CBCP 0xc029
	/// BACP Bandwidth Allocation Control Protocol
#define PCPP_PPP_BACP 0xc02b
	/// BAP Bandwidth Allocation Protocol
#define PCPP_PPP_BAP 0xc02d
	/// Vendor-Specific Authentication Protocol (VSAP)
#define PCPP_PPP_VSAP 0xc05b
	/// Container Control Protocol
#define PCPP_PPP_CONTCP 0xc081
	/// Challenge Handshake Authentication Protocol
#define PCPP_PPP_CHAP 0xc223
	/// RSA Authentication Protocol
#define PCPP_PPP_RSAAP 0xc225
	/// Extensible Authentication Protocol
#define PCPP_PPP_EAP 0xc227
	/// Mitsubishi Security Information Exchange Protocol (SIEP)
#define PCPP_PPP_SIEP 0xc229
	/// Stampede Bridging Authorization Protocol
#define PCPP_PPP_SBAP 0xc26f
	/// Proprietary Authentication Protocol
#define PCPP_PPP_PRPAP 0xc281
	/// Proprietary Authentication Protocol
#define PCPP_PPP_PRPAP2 0xc283
	/// Proprietary Node ID Authentication Protocol
#define PCPP_PPP_PRPNIAP 0xc481

}  // namespace pcpp
