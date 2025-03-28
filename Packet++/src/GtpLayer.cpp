#define LOG_MODULE PacketLogModuleGtpLayer

#include <unordered_map>
#include <sstream>
#include "Logger.h"
#include "GtpLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "PayloadLayer.h"
#include "EndianPortable.h"

namespace pcpp
{

#define PCPP_GTP_V1_GPDU_MESSAGE_TYPE 0xff

	/// ==================
	/// GtpExtension class
	/// ==================

	GtpV1Layer::GtpExtension::GtpExtension()
	{
		m_Data = nullptr;
		m_DataLen = 0;
		m_ExtType = 0;
	}

	GtpV1Layer::GtpExtension::GtpExtension(uint8_t* data, size_t dataLen, uint8_t type)
	{
		m_Data = data;
		m_DataLen = dataLen;
		m_ExtType = type;
	}

	GtpV1Layer::GtpExtension::GtpExtension(const GtpExtension& other)
	{
		m_Data = other.m_Data;
		m_DataLen = other.m_DataLen;
		m_ExtType = other.m_ExtType;
	}

	GtpV1Layer::GtpExtension& GtpV1Layer::GtpExtension::operator=(const GtpV1Layer::GtpExtension& other)
	{
		m_Data = other.m_Data;
		m_DataLen = other.m_DataLen;
		m_ExtType = other.m_ExtType;
		return *this;
	}

	bool GtpV1Layer::GtpExtension::isNull() const
	{
		return m_Data == nullptr;
	}

	uint8_t GtpV1Layer::GtpExtension::getExtensionType() const
	{
		return m_ExtType;
	}

	size_t GtpV1Layer::GtpExtension::getTotalLength() const
	{
		if (m_Data == nullptr)
		{
			return 0;
		}

		size_t len = (size_t)(m_Data[0] * 4);
		if (len <= m_DataLen)
		{
			return len;
		}

		return m_DataLen;
	}

	size_t GtpV1Layer::GtpExtension::getContentLength() const
	{
		size_t res = getTotalLength();

		if (res >= 2 * sizeof(uint8_t))
		{
			return (size_t)(res - 2 * sizeof(uint8_t));
		}

		return 0;
	}

	uint8_t* GtpV1Layer::GtpExtension::getContent() const
	{
		if (m_Data == nullptr || getContentLength() == 0)
		{
			return nullptr;
		}

		return m_Data + sizeof(uint8_t);
	}

	uint8_t GtpV1Layer::GtpExtension::getNextExtensionHeaderType() const
	{
		if (m_Data == nullptr || getTotalLength() < 4)
		{
			return 0;
		}

		uint8_t res = *(uint8_t*)(m_Data + sizeof(uint8_t) + getContentLength());

		return res;
	}

	GtpV1Layer::GtpExtension GtpV1Layer::GtpExtension::getNextExtension() const
	{
		size_t totalLength = getTotalLength();
		uint8_t nextExtType = getNextExtensionHeaderType();
		if (nextExtType > 0 && m_DataLen > totalLength + sizeof(uint8_t))
		{
			return { m_Data + totalLength, m_DataLen - totalLength, nextExtType };
		}
		else
		{
			return {};
		}
	}

	void GtpV1Layer::GtpExtension::setNextHeaderType(uint8_t nextHeaderType)
	{
		if (m_Data != nullptr && m_DataLen > 1)
		{
			m_Data[getTotalLength() - 1] = nextHeaderType;
		}
	}

	GtpV1Layer::GtpExtension GtpV1Layer::GtpExtension::createGtpExtension(uint8_t* data, size_t dataLen,
	                                                                      uint8_t extType, uint16_t content)
	{
		if (dataLen < 4 * sizeof(uint8_t))
		{
			return {};
		}

		data[0] = 1;
		data[1] = (content >> 8);
		data[2] = content & 0xff;
		data[3] = 0;

		return { data, dataLen, extType };
	}

	/// ================
	/// GtpV1Layer class
	/// ================

	GtpV1Layer::GtpV1Layer(GtpV1MessageType messageType, uint32_t teid)
	{
		init(messageType, teid, false, 0, false, 0);
	}

	GtpV1Layer::GtpV1Layer(GtpV1MessageType messageType, uint32_t teid, bool setSeqNum, uint16_t seqNum,
	                       bool setNpduNum, uint8_t npduNum)
	{
		init(messageType, teid, setSeqNum, seqNum, setNpduNum, npduNum);
	}

	void GtpV1Layer::init(GtpV1MessageType messageType, uint32_t teid, bool setSeqNum, uint16_t seqNum, bool setNpduNum,
	                      uint8_t npduNum)
	{
		size_t dataLen = sizeof(gtpv1_header);
		if (setSeqNum || setNpduNum)
		{
			dataLen += sizeof(gtpv1_header_extra);
		}

		m_DataLen = dataLen;
		m_Data = new uint8_t[dataLen];
		memset(m_Data, 0, dataLen);
		m_Protocol = GTPv1;

		gtpv1_header* hdr = getHeader();
		hdr->version = 1;
		hdr->protocolType = 1;
		hdr->messageType = (uint8_t)messageType;
		hdr->teid = htobe32(teid);

		if (setSeqNum || setNpduNum)
		{
			hdr->messageLength = htobe16(sizeof(gtpv1_header_extra));
			gtpv1_header_extra* extraHdr = getHeaderExtra();
			if (setSeqNum)
			{
				hdr->sequenceNumberFlag = 1;
				extraHdr->sequenceNumber = htobe16(seqNum);
			}

			if (setNpduNum)
			{
				hdr->npduNumberFlag = 1;
				extraHdr->npduNumber = npduNum;
			}
		}
	}

	bool GtpV1Layer::isGTPv1(const uint8_t* data, size_t dataSize)
	{
		if (data != nullptr && dataSize >= sizeof(gtpv1_header) && (data[0] & 0xE0) == 0x20)
		{
			return true;
		}

		return false;
	}

	GtpV1Layer::gtpv1_header_extra* GtpV1Layer::getHeaderExtra() const
	{
		if (m_Data != nullptr && m_DataLen >= sizeof(gtpv1_header) + sizeof(gtpv1_header_extra))
		{
			return (gtpv1_header_extra*)(m_Data + sizeof(gtpv1_header));
		}

		return nullptr;
	}

	bool GtpV1Layer::getSequenceNumber(uint16_t& seqNumber) const
	{
		gtpv1_header* header = getHeader();
		gtpv1_header_extra* headerExtra = getHeaderExtra();
		if (header != nullptr && headerExtra != nullptr && header->sequenceNumberFlag == 1)
		{
			seqNumber = be16toh(headerExtra->sequenceNumber);
			return true;
		}

		return false;
	}

	bool GtpV1Layer::setSequenceNumber(const uint16_t seqNumber)
	{
		// get GTP header
		gtpv1_header* header = getHeader();
		if (header == nullptr)
		{
			PCPP_LOG_ERROR("Set sequence failed: GTP header is nullptr");
			return false;
		}

		// if all flags are unset then create the GTP extra header
		if (header->npduNumberFlag == 0 && header->sequenceNumberFlag == 0 && header->extensionHeaderFlag == 0)
		{
			if (!extendLayer(sizeof(gtpv1_header), sizeof(gtpv1_header_extra)))
			{
				PCPP_LOG_ERROR("Set sequence failed: cannot extend layer");
				return false;
			}
			header = getHeader();
		}

		// get the extra header
		gtpv1_header_extra* headerExtra = getHeaderExtra();
		if (headerExtra == nullptr)
		{
			PCPP_LOG_ERROR("Set sequence failed: extra header is nullptr");
			return false;
		}

		// set seq number
		header->sequenceNumberFlag = 1;
		headerExtra->sequenceNumber = htobe16(seqNumber);

		// extend GTP length
		header->messageLength = htobe16(be16toh(header->messageLength) + sizeof(gtpv1_header_extra));

		return true;
	}

	bool GtpV1Layer::getNpduNumber(uint8_t& npduNum) const
	{
		gtpv1_header* header = getHeader();
		gtpv1_header_extra* headerExtra = getHeaderExtra();
		if (header != nullptr && headerExtra != nullptr && header->npduNumberFlag == 1)
		{
			npduNum = headerExtra->npduNumber;
			return true;
		}

		return false;
	}

	bool GtpV1Layer::setNpduNumber(const uint8_t npduNum)
	{
		// get GTP header
		gtpv1_header* header = getHeader();
		if (header == nullptr)
		{
			PCPP_LOG_ERROR("Set N-PDU failed: GTP header is nullptr");
			return false;
		}

		// if all flags are unset then create the GTP extra header
		if (header->npduNumberFlag == 0 && header->sequenceNumberFlag == 0 && header->extensionHeaderFlag == 0)
		{
			if (!extendLayer(sizeof(gtpv1_header), sizeof(gtpv1_header_extra)))
			{
				PCPP_LOG_ERROR("Set N-PDU failed: cannot extend layer");
				return false;
			}
			header = getHeader();
		}

		// get the extra header
		gtpv1_header_extra* headerExtra = getHeaderExtra();
		if (headerExtra == nullptr)
		{
			PCPP_LOG_ERROR("Set N-PDU failed: extra header is nullptr");
			return false;
		}

		// set N-PDU value
		header->npduNumberFlag = 1;
		headerExtra->npduNumber = npduNum;

		// extend GTP length
		header->messageLength = htobe16(be16toh(header->messageLength) + sizeof(gtpv1_header_extra));

		return true;
	}

	bool GtpV1Layer::getNextExtensionHeaderType(uint8_t& nextExtType) const
	{
		gtpv1_header* header = getHeader();
		gtpv1_header_extra* headerExtra = getHeaderExtra();
		if (header != nullptr && headerExtra != nullptr && header->extensionHeaderFlag == 1)
		{
			nextExtType = headerExtra->nextExtensionHeader;
			return true;
		}

		return false;
	}

	GtpV1Layer::GtpExtension GtpV1Layer::getNextExtension() const
	{
		uint8_t nextExtType = 0;
		bool nextExtExists = getNextExtensionHeaderType(nextExtType);
		if (!nextExtExists || nextExtType == 0 || m_DataLen <= sizeof(gtpv1_header) + sizeof(gtpv1_header_extra))
		{
			return {};
		}

		return { m_Data + sizeof(gtpv1_header) + sizeof(gtpv1_header_extra),
			     m_DataLen - sizeof(gtpv1_header) - sizeof(gtpv1_header_extra), nextExtType };
	}

	GtpV1Layer::GtpExtension GtpV1Layer::addExtension(uint8_t extensionType, uint16_t extensionContent)
	{
		// get GTP header
		gtpv1_header* header = getHeader();
		if (header == nullptr)
		{
			PCPP_LOG_ERROR("Add extension failed: GTP header is nullptr");
			return {};
		}

		size_t offsetForNewExtension = sizeof(gtpv1_header);

		// if all flags are unset then create the GTP extra header
		if (header->npduNumberFlag == 0 && header->sequenceNumberFlag == 0 && header->extensionHeaderFlag == 0)
		{
			if (!extendLayer(offsetForNewExtension, sizeof(gtpv1_header_extra)))
			{
				PCPP_LOG_ERROR("Add extension failed: cannot extend layer");
				return {};
			}
		}

		// get the extra header
		gtpv1_header_extra* headerExtra = getHeaderExtra();
		if (headerExtra == nullptr)
		{
			PCPP_LOG_ERROR("Add extension failed: extra header is nullptr");
			return {};
		}

		offsetForNewExtension += sizeof(gtpv1_header_extra);

		// find the last GTP header extension
		GtpV1Layer::GtpExtension lastExt = getNextExtension();

		// go over the GTP header extensions
		while (!lastExt.getNextExtension().isNull())
		{
			// add ext total length to offset
			offsetForNewExtension += lastExt.getTotalLength();
			lastExt = lastExt.getNextExtension();
		}

		// lastExt != null means layer contains 1 or more extensions
		if (!lastExt.isNull())
		{
			// add ext total length to offset
			offsetForNewExtension += lastExt.getTotalLength();
		}

		// allocate extension space in layer (assuming extension length can only be 4 bytes)
		if (!extendLayer(offsetForNewExtension, 4 * sizeof(uint8_t)))
		{
			PCPP_LOG_ERROR("Add extension failed: cannot extend layer");
			return {};
		}

		// lastExt != null means layer contains 1 or more extensions
		if (!lastExt.isNull())
		{
			// set the next header type in the last extension
			lastExt.setNextHeaderType(extensionType);
		}
		else
		{
			// mark extension flags in the layer
			header = getHeader();
			headerExtra = getHeaderExtra();

			header->extensionHeaderFlag = 1;
			headerExtra->nextExtensionHeader = extensionType;
		}

		// create the extension data and return the extension object to the user
		return GtpV1Layer::GtpExtension::createGtpExtension(
		    m_Data + offsetForNewExtension, m_DataLen - offsetForNewExtension, extensionType, extensionContent);
	}

	GtpV1MessageType GtpV1Layer::getMessageType() const
	{
		gtpv1_header* header = getHeader();

		if (header == nullptr)
		{
			return GtpV1_MessageTypeUnknown;
		}

		return (GtpV1MessageType)header->messageType;
	}

	std::unordered_map<uint8_t, std::string> createGtpV1MessageTypeToStringMap()
	{
		std::unordered_map<uint8_t, std::string> tempMap;

		tempMap[0] = "GTPv1 Message Type Unknown";
		tempMap[1] = "Echo Request";
		tempMap[2] = "Echo Response";
		tempMap[3] = "Version Not Supported";
		tempMap[4] = "Node Alive Request";
		tempMap[5] = "Node Alive Response";
		tempMap[6] = "Redirection Request";
		tempMap[7] = "Create PDP Context Request";
		tempMap[16] = "Create PDP Context Response";
		tempMap[17] = "Update PDP Context Request";
		tempMap[18] = "Update PDP Context Response";
		tempMap[19] = "Delete PDP Context Request";
		tempMap[20] = "Delete PDP Context Response";
		tempMap[22] = "Initiate PDP Context Activation Request";
		tempMap[23] = "Initiate PDP Context Activation Response";
		tempMap[26] = "Error Indication";
		tempMap[27] = "PDU Notification Request";
		tempMap[28] = "PDU Notification Response";
		tempMap[29] = "PDU Notification Reject Request";
		tempMap[30] = "PDU Notification Reject Response";
		tempMap[31] = "Supported Extensions Header Notification";
		tempMap[32] = "Send Routing for GPRS Request";
		tempMap[33] = "Send Routing for GPRS Response";
		tempMap[34] = "Failure Report Request";
		tempMap[35] = "Failure Report Response";
		tempMap[36] = "Note MS Present Request";
		tempMap[37] = "Note MS Present Response";
		tempMap[38] = "Identification Request";
		tempMap[39] = "Identification Response";
		tempMap[50] = "SGSN Context Request";
		tempMap[51] = "SGSN Context Response";
		tempMap[52] = "SGSN Context Acknowledge";
		tempMap[53] = "Forward Relocation Request";
		tempMap[54] = "Forward Relocation Response";
		tempMap[55] = "Forward Relocation Complete";
		tempMap[56] = "Relocation Cancel Request";
		tempMap[57] = "Relocation Cancel Response";
		tempMap[58] = "Forward SRNS Context";
		tempMap[59] = "Forward Relocation Complete Acknowledge";
		tempMap[60] = "Forward SRNS Context Acknowledge";
		tempMap[61] = "UE Registration Request";
		tempMap[62] = "UE Registration Response";
		tempMap[70] = "RAN Information Relay";
		tempMap[96] = "MBMS Notification Request";
		tempMap[97] = "MBMS Notification Response";
		tempMap[98] = "MBMS Notification Reject Request";
		tempMap[99] = "MBMS Notification Reject Response";
		tempMap[100] = "Create MBMS Notification Request";
		tempMap[101] = "Create MBMS Notification Response";
		tempMap[102] = "Update MBMS Notification Request";
		tempMap[103] = "Update MBMS Notification Response";
		tempMap[104] = "Delete MBMS Notification Request";
		tempMap[105] = "Delete MBMS Notification Response";
		tempMap[112] = "MBMS Registration Request";
		tempMap[113] = "MBMS Registration Response";
		tempMap[114] = "MBMS De-Registration Request";
		tempMap[115] = "MBMS De-Registration Response";
		tempMap[116] = "MBMS Session Start Request";
		tempMap[117] = "MBMS Session Start Response";
		tempMap[118] = "MBMS Session Stop Request";
		tempMap[119] = "MBMS Session Stop Response";
		tempMap[120] = "MBMS Session Update Request";
		tempMap[121] = "MBMS Session Update Response";
		tempMap[128] = "MS Info Change Request";
		tempMap[129] = "MS Info Change Response";
		tempMap[240] = "Data Record Transfer Request";
		tempMap[241] = "Data Record Transfer Response";
		tempMap[254] = "End Marker";
		tempMap[255] = "G-PDU";

		return tempMap;
	}

	const std::unordered_map<uint8_t, std::string> GTPv1MsgTypeToStringMap = createGtpV1MessageTypeToStringMap();

	std::string GtpV1Layer::getMessageTypeAsString() const
	{
		gtpv1_header* header = getHeader();

		if (header == nullptr)
		{
			return GTPv1MsgTypeToStringMap.find(0)->second;
		}

		auto iter = GTPv1MsgTypeToStringMap.find(header->messageType);
		if (iter != GTPv1MsgTypeToStringMap.end())
		{
			return iter->second;
		}
		else
		{
			return GTPv1MsgTypeToStringMap.find(0)->second;
		}
	}

	bool GtpV1Layer::isGTPUMessage() const
	{
		gtpv1_header* header = getHeader();
		if (header == nullptr)
		{
			return false;
		}

		return header->messageType == PCPP_GTP_V1_GPDU_MESSAGE_TYPE;
	}

	bool GtpV1Layer::isGTPCMessage() const
	{
		gtpv1_header* header = getHeader();
		if (header == nullptr)
		{
			return false;
		}

		return header->messageType != PCPP_GTP_V1_GPDU_MESSAGE_TYPE;
	}

	void GtpV1Layer::parseNextLayer()
	{
		size_t headerLen = getHeaderLen();
		if (headerLen < sizeof(gtpv1_header))
		{
			// do nothing
			return;
		}

		gtpv1_header* header = getHeader();
		if (header->messageType != PCPP_GTP_V1_GPDU_MESSAGE_TYPE)
		{
			// this is a GTP-C message, hence it is the last layer
			return;
		}

		if (m_DataLen <= headerLen)
		{
			// no data beyond headerLen, nothing to parse further
			return;
		}

		// GTP-U message, try to parse the next layer

		auto* payload = static_cast<uint8_t*>(m_Data + headerLen);
		size_t payloadLen = m_DataLen - headerLen;

		uint8_t subProto = *payload;
		if (subProto >= 0x45 && subProto <= 0x4e)
		{
			m_NextLayer = IPv4Layer::isDataValid(payload, payloadLen)
			                  ? static_cast<Layer*>(new IPv4Layer(payload, payloadLen, this, m_Packet))
			                  : static_cast<Layer*>(new PayloadLayer(payload, payloadLen, this, m_Packet));
		}
		else if ((subProto & 0xf0) == 0x60)
		{
			m_NextLayer = IPv6Layer::isDataValid(payload, payloadLen)
			                  ? static_cast<Layer*>(new IPv6Layer(payload, payloadLen, this, m_Packet))
			                  : static_cast<Layer*>(new PayloadLayer(payload, payloadLen, this, m_Packet));
		}
		else
		{
			m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
		}
	}

	size_t GtpV1Layer::getHeaderLen() const
	{
		gtpv1_header* header = getHeader();
		if (header == nullptr)
		{
			return 0;
		}

		size_t res = sizeof(gtpv1_header);

		if (header->messageType != PCPP_GTP_V1_GPDU_MESSAGE_TYPE)
		{
			size_t msgLen = be16toh(header->messageLength);
			res += (msgLen > m_DataLen - sizeof(gtpv1_header) ? m_DataLen - sizeof(gtpv1_header) : msgLen);
		}
		else
		{
			gtpv1_header_extra* headerExtra = getHeaderExtra();
			if (headerExtra != nullptr &&
			    (header->extensionHeaderFlag == 1 || header->sequenceNumberFlag == 1 || header->npduNumberFlag == 1))
			{
				res += sizeof(gtpv1_header_extra);
				GtpExtension nextExt = getNextExtension();
				while (!nextExt.isNull())
				{
					res += nextExt.getTotalLength();
					nextExt = nextExt.getNextExtension();
				}
			}
		}

		return res;
	}

	std::string GtpV1Layer::toString() const
	{
		std::string res = "GTP v1 Layer";

		gtpv1_header* header = getHeader();
		if (header != nullptr)
		{
			std::stringstream teidStream;
			teidStream << be32toh(header->teid);

			std::string gtpu_gtpc;
			if (header->messageType == PCPP_GTP_V1_GPDU_MESSAGE_TYPE)
			{
				gtpu_gtpc = "GTP-U message";
			}
			else
			{
				gtpu_gtpc = "GTP-C message: " + getMessageTypeAsString();
			}

			res += ", " + gtpu_gtpc + ", TEID: " + teidStream.str();
		}

		return res;
	}

	void GtpV1Layer::computeCalculateFields()
	{
		gtpv1_header* hdr = getHeader();
		if (hdr == nullptr)
		{
			return;
		}

		hdr->messageLength = htobe16(m_DataLen - sizeof(gtpv1_header));
	}

	/// ================
	/// GtpV2MessageType
	/// ================

	struct GtpV2MessageTypeHash
	{
		size_t operator()(const GtpV2MessageType& messageType) const
		{
			return static_cast<uint8_t>(messageType);
		}
	};

	static const std::unordered_map<GtpV2MessageType, std::string, GtpV2MessageTypeHash> messageTypeMap = {
		{ GtpV2MessageType::EchoRequest,                      "Echo Request"                         },
		{ GtpV2MessageType::EchoResponse,                     "Echo Response"                        },
		{ GtpV2MessageType::VersionNotSupported,              "Version Not Supported"                },
		{ GtpV2MessageType::CreateSessionRequest,             "Create Session Request"               },
		{ GtpV2MessageType::CreateSessionResponse,            "Create Session Response"              },
		{ GtpV2MessageType::ModifyBearerRequest,              "Modify Bearer Request"                },
		{ GtpV2MessageType::ModifyBearerResponse,             "Modify Bearer Response"               },
		{ GtpV2MessageType::DeleteSessionRequest,             "Delete Session Request"               },
		{ GtpV2MessageType::DeleteSessionResponse,            "Delete Session Response"              },
		{ GtpV2MessageType::ChangeNotificationRequest,        "Change Notification Request"          },
		{ GtpV2MessageType::ChangeNotificationResponse,       "Change Notification Response"         },
		{ GtpV2MessageType::RemoteUEReportNotifications,      "Remote UE Report Notifications"       },
		{ GtpV2MessageType::RemoteUEReportAcknowledge,        "Remote UE Report Acknowledge"         },
		{ GtpV2MessageType::ModifyBearerCommand,              "Modify Bearer Command"                },
		{ GtpV2MessageType::ModifyBearerFailure,              "Modify Bearer Failure"                },
		{ GtpV2MessageType::DeleteBearerCommand,              "Delete Bearer Command"                },
		{ GtpV2MessageType::DeleteBearerFailure,              "Delete Bearer Failure"                },
		{ GtpV2MessageType::BearerResourceCommand,            "Bearer Resource Command"              },
		{ GtpV2MessageType::BearerResourceFailure,            "Bearer Resource Failure"              },
		{ GtpV2MessageType::DownlinkDataNotificationFailure,  "Downlink Data Notification Failure"   },
		{ GtpV2MessageType::TraceSessionActivation,           "Trace Session Activation"             },
		{ GtpV2MessageType::TraceSessionDeactivation,         "Trace Session Deactivation"           },
		{ GtpV2MessageType::StopPagingIndication,             "Stop Paging Indication"               },
		{ GtpV2MessageType::CreateBearerRequest,              "Create Bearer Request"                },
		{ GtpV2MessageType::CreateBearerResponse,             "Create Bearer Response"               },
		{ GtpV2MessageType::UpdateBearerRequest,              "Update Bearer Request"                },
		{ GtpV2MessageType::UpdateBearerResponse,             "Update Bearer Response"               },
		{ GtpV2MessageType::DeleteBearerRequest,              "Delete Bearer Request"                },
		{ GtpV2MessageType::DeleteBearerResponse,             "Delete Bearer Response"               },
		{ GtpV2MessageType::DeletePDNRequest,                 "Delete PDN Request"                   },
		{ GtpV2MessageType::DeletePDNResponse,                "Delete PDN Response"                  },
		{ GtpV2MessageType::PGWDownlinkNotification,          "PGW Downlink Notification"            },
		{ GtpV2MessageType::PGWDownlinkAcknowledge,           "PGW Downlink Acknowledge"             },
		{ GtpV2MessageType::IdentificationRequest,            "Identification Request"               },
		{ GtpV2MessageType::IdentificationResponse,           "Identification Response"              },
		{ GtpV2MessageType::ContextRequest,                   "Context Request"                      },
		{ GtpV2MessageType::ContextResponse,                  "Context Response"                     },
		{ GtpV2MessageType::ContextAcknowledge,               "Context Acknowledge"                  },
		{ GtpV2MessageType::ForwardRelocationRequest,         "Forward Relocation Request"           },
		{ GtpV2MessageType::ForwardRelocationResponse,        "Forward Relocation Response"          },
		{ GtpV2MessageType::ForwardRelocationNotification,    "Forward Relocation Notification"      },
		{ GtpV2MessageType::ForwardRelocationAcknowledge,     "Forward Relocation Acknowledge"       },
		{ GtpV2MessageType::ForwardAccessNotification,        "Forward Access Notification"          },
		{ GtpV2MessageType::ForwardAccessAcknowledge,         "Forward Access Acknowledge"           },
		{ GtpV2MessageType::RelocationCancelRequest,          "Relocation Cancel Request"            },
		{ GtpV2MessageType::RelocationCancelResponse,         "Relocation Cancel Response"           },
		{ GtpV2MessageType::ConfigurationTransferTunnel,      "Configuration Transfer Tunnel"        },
		{ GtpV2MessageType::DetachNotification,               "Detach Notification"                  },
		{ GtpV2MessageType::DetachAcknowledge,                "Detach Acknowledge"                   },
		{ GtpV2MessageType::CSPaging,                         "CS Paging"                            },
		{ GtpV2MessageType::RANInformationRelay,              "RAN Information Relay"                },
		{ GtpV2MessageType::AlertMMENotification,             "Alert MME Notification"               },
		{ GtpV2MessageType::AlertMMEAcknowledge,              "Alert MME Acknowledge"                },
		{ GtpV2MessageType::UEActivityNotification,           "UE Activity Notification"             },
		{ GtpV2MessageType::UEActivityAcknowledge,            "UE Activity Acknowledge"              },
		{ GtpV2MessageType::ISRStatus,                        "ISR Status"                           },
		{ GtpV2MessageType::CreateForwardingRequest,          "Create Forwarding Request"            },
		{ GtpV2MessageType::CreateForwardingResponse,         "Create Forwarding Response"           },
		{ GtpV2MessageType::SuspendNotification,              "Suspend Notification"                 },
		{ GtpV2MessageType::SuspendAcknowledge,               "Suspend Acknowledge"                  },
		{ GtpV2MessageType::ResumeNotification,               "Resume Notification"                  },
		{ GtpV2MessageType::ResumeAcknowledge,                "Resume Acknowledge"                   },
		{ GtpV2MessageType::CreateIndirectDataTunnelRequest,  "Create Indirect Data Tunnel Request"  },
		{ GtpV2MessageType::CreateIndirectDataTunnelResponse, "Create Indirect Data Tunnel Response" },
		{ GtpV2MessageType::DeleteIndirectDataTunnelRequest,  "Delete Indirect Data Tunnel Request"  },
		{ GtpV2MessageType::DeleteIndirectDataTunnelResponse, "Delete Indirect Data Tunnel Response" },
		{ GtpV2MessageType::ReleaseAccessBearersRequest,      "Release Access Bearers Request"       },
		{ GtpV2MessageType::ReleaseAccessBearersResponse,     "Release Access Bearers Response"      },
		{ GtpV2MessageType::DownlinkDataNotification,         "Downlink Data Notification"           },
		{ GtpV2MessageType::DownlinkDataAcknowledge,          "Downlink Data Acknowledge"            },
		{ GtpV2MessageType::PGWRestartNotification,           "PGW Restart Notification"             },
		{ GtpV2MessageType::PGWRestartAcknowledge,            "PGW Restart Acknowledge"              },
		{ GtpV2MessageType::UpdatePDNConnectionRequest,       "Update PDN Connection Request"        },
		{ GtpV2MessageType::UpdatePDNConnectionResponse,      "Update PDN Connection Response"       },
		{ GtpV2MessageType::ModifyAccessBearersRequest,       "Modify Access Bearers Request"        },
		{ GtpV2MessageType::ModifyAccessBearersResponse,      "Modify Access Bearers Response"       },
		{ GtpV2MessageType::MMBSSessionStartRequest,          "MMBS Session Start Request"           },
		{ GtpV2MessageType::MMBSSessionStartResponse,         "MMBS Session Start Response"          },
		{ GtpV2MessageType::MMBSSessionUpdateRequest,         "MMBS Session Update Request"          },
		{ GtpV2MessageType::MMBSSessionUpdateResponse,        "MMBS Session Update Response"         },
		{ GtpV2MessageType::MMBSSessionStopRequest,           "MMBS Session Stop Request"            },
		{ GtpV2MessageType::MMBSSessionStopResponse,          "MMBS Session Stop Response"           }
	};

	std::string GtpV2MessageType::toString() const
	{
		auto iter = messageTypeMap.find(m_Value);
		if (iter != messageTypeMap.end())
		{
			return iter->second;
		}

		return "Unknown GTPv2 Message Type";
	}

	// clang-format off
	static const std::unordered_map<uint8_t, GtpV2MessageType> uintToValueMap = {
		{ static_cast<uint8_t>(GtpV2MessageType::EchoRequest),                      GtpV2MessageType::EchoRequest                      },
		{ static_cast<uint8_t>(GtpV2MessageType::EchoResponse),                     GtpV2MessageType::EchoResponse                     },
		{ static_cast<uint8_t>(GtpV2MessageType::VersionNotSupported),              GtpV2MessageType::VersionNotSupported              },
		{ static_cast<uint8_t>(GtpV2MessageType::CreateSessionRequest),             GtpV2MessageType::CreateSessionRequest             },
		{ static_cast<uint8_t>(GtpV2MessageType::CreateSessionResponse),            GtpV2MessageType::CreateSessionResponse            },
		{ static_cast<uint8_t>(GtpV2MessageType::ModifyBearerRequest),              GtpV2MessageType::ModifyBearerRequest              },
		{ static_cast<uint8_t>(GtpV2MessageType::ModifyBearerResponse),             GtpV2MessageType::ModifyBearerResponse             },
		{ static_cast<uint8_t>(GtpV2MessageType::DeleteSessionRequest),             GtpV2MessageType::DeleteSessionRequest             },
		{ static_cast<uint8_t>(GtpV2MessageType::DeleteSessionResponse),            GtpV2MessageType::DeleteSessionResponse            },
		{ static_cast<uint8_t>(GtpV2MessageType::ChangeNotificationRequest),        GtpV2MessageType::ChangeNotificationRequest        },
		{ static_cast<uint8_t>(GtpV2MessageType::ChangeNotificationResponse),       GtpV2MessageType::ChangeNotificationResponse       },
		{ static_cast<uint8_t>(GtpV2MessageType::RemoteUEReportNotifications),      GtpV2MessageType::RemoteUEReportNotifications      },
		{ static_cast<uint8_t>(GtpV2MessageType::RemoteUEReportAcknowledge),        GtpV2MessageType::RemoteUEReportAcknowledge        },
		{ static_cast<uint8_t>(GtpV2MessageType::ModifyBearerCommand),              GtpV2MessageType::ModifyBearerCommand              },
		{ static_cast<uint8_t>(GtpV2MessageType::ModifyBearerFailure),              GtpV2MessageType::ModifyBearerFailure              },
		{ static_cast<uint8_t>(GtpV2MessageType::DeleteBearerCommand),              GtpV2MessageType::DeleteBearerCommand              },
		{ static_cast<uint8_t>(GtpV2MessageType::DeleteBearerFailure),              GtpV2MessageType::DeleteBearerFailure              },
		{ static_cast<uint8_t>(GtpV2MessageType::BearerResourceCommand),            GtpV2MessageType::BearerResourceCommand            },
		{ static_cast<uint8_t>(GtpV2MessageType::BearerResourceFailure),            GtpV2MessageType::BearerResourceFailure            },
		{ static_cast<uint8_t>(GtpV2MessageType::DownlinkDataNotificationFailure),  GtpV2MessageType::DownlinkDataNotificationFailure  },
		{ static_cast<uint8_t>(GtpV2MessageType::TraceSessionActivation),           GtpV2MessageType::TraceSessionActivation           },
		{ static_cast<uint8_t>(GtpV2MessageType::TraceSessionDeactivation),         GtpV2MessageType::TraceSessionDeactivation         },
		{ static_cast<uint8_t>(GtpV2MessageType::StopPagingIndication),             GtpV2MessageType::StopPagingIndication             },
		{ static_cast<uint8_t>(GtpV2MessageType::CreateBearerRequest),              GtpV2MessageType::CreateBearerRequest              },
		{ static_cast<uint8_t>(GtpV2MessageType::CreateBearerResponse),             GtpV2MessageType::CreateBearerResponse             },
		{ static_cast<uint8_t>(GtpV2MessageType::UpdateBearerRequest),              GtpV2MessageType::UpdateBearerRequest              },
		{ static_cast<uint8_t>(GtpV2MessageType::UpdateBearerResponse),             GtpV2MessageType::UpdateBearerResponse             },
		{ static_cast<uint8_t>(GtpV2MessageType::DeleteBearerRequest),              GtpV2MessageType::DeleteBearerRequest              },
		{ static_cast<uint8_t>(GtpV2MessageType::DeleteBearerResponse),             GtpV2MessageType::DeleteBearerResponse             },
		{ static_cast<uint8_t>(GtpV2MessageType::DeletePDNRequest),                 GtpV2MessageType::DeletePDNRequest                 },
		{ static_cast<uint8_t>(GtpV2MessageType::DeletePDNResponse),                GtpV2MessageType::DeletePDNResponse                },
		{ static_cast<uint8_t>(GtpV2MessageType::PGWDownlinkNotification),          GtpV2MessageType::PGWDownlinkNotification          },
		{ static_cast<uint8_t>(GtpV2MessageType::PGWDownlinkAcknowledge),           GtpV2MessageType::PGWDownlinkAcknowledge           },
		{ static_cast<uint8_t>(GtpV2MessageType::IdentificationRequest),            GtpV2MessageType::IdentificationRequest            },
		{ static_cast<uint8_t>(GtpV2MessageType::IdentificationResponse),           GtpV2MessageType::IdentificationResponse           },
		{ static_cast<uint8_t>(GtpV2MessageType::ContextRequest),                   GtpV2MessageType::ContextRequest                   },
		{ static_cast<uint8_t>(GtpV2MessageType::ContextResponse),                  GtpV2MessageType::ContextResponse                  },
		{ static_cast<uint8_t>(GtpV2MessageType::ContextAcknowledge),               GtpV2MessageType::ContextAcknowledge               },
		{ static_cast<uint8_t>(GtpV2MessageType::ForwardRelocationRequest),         GtpV2MessageType::ForwardRelocationRequest         },
		{ static_cast<uint8_t>(GtpV2MessageType::ForwardRelocationResponse),        GtpV2MessageType::ForwardRelocationResponse        },
		{ static_cast<uint8_t>(GtpV2MessageType::ForwardRelocationNotification),    GtpV2MessageType::ForwardRelocationNotification    },
		{ static_cast<uint8_t>(GtpV2MessageType::ForwardRelocationAcknowledge),     GtpV2MessageType::ForwardRelocationAcknowledge     },
		{ static_cast<uint8_t>(GtpV2MessageType::ForwardAccessNotification),        GtpV2MessageType::ForwardAccessNotification        },
		{ static_cast<uint8_t>(GtpV2MessageType::ForwardAccessAcknowledge),         GtpV2MessageType::ForwardAccessAcknowledge         },
		{ static_cast<uint8_t>(GtpV2MessageType::RelocationCancelRequest),          GtpV2MessageType::RelocationCancelRequest          },
		{ static_cast<uint8_t>(GtpV2MessageType::RelocationCancelResponse),         GtpV2MessageType::RelocationCancelResponse         },
		{ static_cast<uint8_t>(GtpV2MessageType::ConfigurationTransferTunnel),      GtpV2MessageType::ConfigurationTransferTunnel      },
		{ static_cast<uint8_t>(GtpV2MessageType::DetachNotification),               GtpV2MessageType::DetachNotification               },
		{ static_cast<uint8_t>(GtpV2MessageType::DetachAcknowledge),                GtpV2MessageType::DetachAcknowledge                },
		{ static_cast<uint8_t>(GtpV2MessageType::CSPaging),                         GtpV2MessageType::CSPaging                         },
		{ static_cast<uint8_t>(GtpV2MessageType::RANInformationRelay),              GtpV2MessageType::RANInformationRelay              },
		{ static_cast<uint8_t>(GtpV2MessageType::AlertMMENotification),             GtpV2MessageType::AlertMMENotification             },
		{ static_cast<uint8_t>(GtpV2MessageType::AlertMMEAcknowledge),              GtpV2MessageType::AlertMMEAcknowledge              },
		{ static_cast<uint8_t>(GtpV2MessageType::UEActivityNotification),           GtpV2MessageType::UEActivityNotification           },
		{ static_cast<uint8_t>(GtpV2MessageType::UEActivityAcknowledge),            GtpV2MessageType::UEActivityAcknowledge            },
		{ static_cast<uint8_t>(GtpV2MessageType::ISRStatus),                        GtpV2MessageType::ISRStatus                        },
		{ static_cast<uint8_t>(GtpV2MessageType::CreateForwardingRequest),          GtpV2MessageType::CreateForwardingRequest          },
		{ static_cast<uint8_t>(GtpV2MessageType::CreateForwardingResponse),         GtpV2MessageType::CreateForwardingResponse         },
		{ static_cast<uint8_t>(GtpV2MessageType::SuspendNotification),              GtpV2MessageType::SuspendNotification              },
		{ static_cast<uint8_t>(GtpV2MessageType::SuspendAcknowledge),               GtpV2MessageType::SuspendAcknowledge               },
		{ static_cast<uint8_t>(GtpV2MessageType::ResumeNotification),               GtpV2MessageType::ResumeNotification               },
		{ static_cast<uint8_t>(GtpV2MessageType::ResumeAcknowledge),                GtpV2MessageType::ResumeAcknowledge                },
		{ static_cast<uint8_t>(GtpV2MessageType::CreateIndirectDataTunnelRequest),  GtpV2MessageType::CreateIndirectDataTunnelRequest  },
		{ static_cast<uint8_t>(GtpV2MessageType::CreateIndirectDataTunnelResponse), GtpV2MessageType::CreateIndirectDataTunnelResponse },
		{ static_cast<uint8_t>(GtpV2MessageType::DeleteIndirectDataTunnelRequest),  GtpV2MessageType::DeleteIndirectDataTunnelRequest  },
		{ static_cast<uint8_t>(GtpV2MessageType::DeleteIndirectDataTunnelResponse), GtpV2MessageType::DeleteIndirectDataTunnelResponse },
		{ static_cast<uint8_t>(GtpV2MessageType::ReleaseAccessBearersRequest),      GtpV2MessageType::ReleaseAccessBearersRequest      },
		{ static_cast<uint8_t>(GtpV2MessageType::ReleaseAccessBearersResponse),     GtpV2MessageType::ReleaseAccessBearersResponse     },
		{ static_cast<uint8_t>(GtpV2MessageType::DownlinkDataNotification),         GtpV2MessageType::DownlinkDataNotification         },
		{ static_cast<uint8_t>(GtpV2MessageType::DownlinkDataAcknowledge),          GtpV2MessageType::DownlinkDataAcknowledge          },
		{ static_cast<uint8_t>(GtpV2MessageType::PGWRestartNotification),           GtpV2MessageType::PGWRestartNotification           },
		{ static_cast<uint8_t>(GtpV2MessageType::PGWRestartAcknowledge),            GtpV2MessageType::PGWRestartAcknowledge            },
		{ static_cast<uint8_t>(GtpV2MessageType::UpdatePDNConnectionRequest),       GtpV2MessageType::UpdatePDNConnectionRequest       },
		{ static_cast<uint8_t>(GtpV2MessageType::UpdatePDNConnectionResponse),      GtpV2MessageType::UpdatePDNConnectionResponse      },
		{ static_cast<uint8_t>(GtpV2MessageType::ModifyAccessBearersRequest),       GtpV2MessageType::ModifyAccessBearersRequest       },
		{ static_cast<uint8_t>(GtpV2MessageType::ModifyAccessBearersResponse),      GtpV2MessageType::ModifyAccessBearersResponse      },
		{ static_cast<uint8_t>(GtpV2MessageType::MMBSSessionStartRequest),          GtpV2MessageType::MMBSSessionStartRequest          },
		{ static_cast<uint8_t>(GtpV2MessageType::MMBSSessionStartResponse),         GtpV2MessageType::MMBSSessionStartResponse         },
		{ static_cast<uint8_t>(GtpV2MessageType::MMBSSessionUpdateRequest),         GtpV2MessageType::MMBSSessionUpdateRequest         },
		{ static_cast<uint8_t>(GtpV2MessageType::MMBSSessionUpdateResponse),        GtpV2MessageType::MMBSSessionUpdateResponse        },
		{ static_cast<uint8_t>(GtpV2MessageType::MMBSSessionStopRequest),           GtpV2MessageType::MMBSSessionStopRequest           },
		{ static_cast<uint8_t>(GtpV2MessageType::MMBSSessionStopResponse),          GtpV2MessageType::MMBSSessionStopResponse          }
	};
	// clang-format on

	GtpV2MessageType GtpV2MessageType::fromUintValue(uint8_t value)
	{
		auto iter = uintToValueMap.find(value);
		if (iter != uintToValueMap.end())
		{
			return iter->second;
		}

		return Unknown;
	}

	/// =======================
	/// GtpV2InformationElement
	/// =======================

	GtpV2InformationElement::Type GtpV2InformationElement::getIEType()
	{
		if (m_Data == nullptr)
		{
			return GtpV2InformationElement::Type::Unknown;
		}

		auto ieType = m_Data->recordType;
		if ((ieType >= 4 && ieType <= 50) || (ieType >= 52 && ieType <= 70) || ieType == 98 || ieType == 101 ||
		    ieType == 102 || ieType == 122 || ieType == 130 || ieType == 161 || ieType > 213)
		{
			return GtpV2InformationElement::Type::Unknown;
		}

		return static_cast<GtpV2InformationElement::Type>(ieType);
	}

	uint8_t GtpV2InformationElement::getCRFlag()
	{
		if (m_Data == nullptr)
		{
			return 0;
		}

		return m_Data->recordValue[0] >> 4;
	}

	uint8_t GtpV2InformationElement::getInstance()
	{
		if (m_Data == nullptr)
		{
			return 0;
		}

		return m_Data->recordValue[0] & 0xf;
	}

	size_t GtpV2InformationElement::getTotalSize() const
	{
		if (m_Data == nullptr)
		{
			return 0;
		}

		return getDataSize() + 2 * sizeof(uint8_t) + sizeof(uint16_t);
	}

	size_t GtpV2InformationElement::getDataSize() const
	{
		if (m_Data == nullptr)
		{
			return 0;
		}

		return static_cast<size_t>(be16toh(m_Data->recordLen));
	}

	/// ==============================
	/// GtpV2InformationElementBuilder
	/// ==============================

	GtpV2InformationElementBuilder::GtpV2InformationElementBuilder(GtpV2InformationElement::Type infoElementType,
	                                                               const std::bitset<4>& crFlag,
	                                                               const std::bitset<4>& instance,
	                                                               const std::vector<uint8_t>& infoElementValue)
	    : TLVRecordBuilder(static_cast<uint32_t>(infoElementType), infoElementValue.data(),
	                       static_cast<uint8_t>(infoElementValue.size())),
	      m_CRFlag(crFlag), m_Instance(instance)
	{}

	GtpV2InformationElement GtpV2InformationElementBuilder::build() const
	{
		if (m_RecType == 0)
		{
			GtpV2InformationElement(nullptr);
		}

		size_t infoElementBaseSize = sizeof(uint8_t) + sizeof(uint16_t);
		size_t infoElementTotalSize = infoElementBaseSize + sizeof(uint8_t) + m_RecValueLen;
		auto* recordBuffer = new uint8_t[infoElementTotalSize];
		recordBuffer[0] = static_cast<uint8_t>(m_RecType);
		auto infoElementLength = htobe16(m_RecValueLen);
		memcpy(recordBuffer + sizeof(uint8_t), &infoElementLength, sizeof(uint16_t));
		auto crFlag = static_cast<uint8_t>(m_CRFlag.to_ulong());
		auto instance = static_cast<uint8_t>(m_Instance.to_ulong());
		recordBuffer[infoElementBaseSize] = ((crFlag << 4) & 0xf0) | (instance & 0x0f);
		if (m_RecValueLen > 0 && m_RecValue != nullptr)
		{
			memcpy(recordBuffer + infoElementBaseSize + sizeof(uint8_t), m_RecValue, m_RecValueLen);
		}

		return GtpV2InformationElement(recordBuffer);
	}

	/// ==========
	/// GtpV2Layer
	/// ==========

	GtpV2Layer::GtpV2Layer(GtpV2MessageType messageType, uint32_t sequenceNumber, bool setTeid, uint32_t teid,
	                       bool setMessagePriority, std::bitset<4> messagePriority)
	{
		size_t messageLength = sizeof(uint32_t) + (setTeid ? sizeof(uint32_t) : 0);
		size_t headerLen = sizeof(gtpv2_basic_header) + messageLength;
		m_DataLen = headerLen;
		m_Data = new uint8_t[headerLen];
		memset(m_Data, 0, headerLen);

		auto* hdr = getHeader();
		hdr->version = 2;
		hdr->teidPresent = setTeid;
		hdr->messagePriorityPresent = setMessagePriority;
		hdr->messageType = static_cast<uint8_t>(messageType);
		hdr->messageLength = htobe16(messageLength);

		auto* dataPtr = m_Data + sizeof(gtpv2_basic_header);
		if (setTeid)
		{
			teid = htobe32(teid);
			memcpy(dataPtr, &teid, sizeof(uint32_t));
			dataPtr += sizeof(uint32_t);
		}

		sequenceNumber = htobe32(sequenceNumber) >> 8;
		memcpy(dataPtr, &sequenceNumber, sizeof(uint32_t));
		dataPtr += sizeof(uint32_t) - 1;

		if (setMessagePriority)
		{
			auto messagePriorityNum = static_cast<uint8_t>(messagePriority.to_ulong());
			dataPtr[0] = messagePriorityNum << 4;
		}

		m_Protocol = GTPv2;
	}

	bool GtpV2Layer::isDataValid(const uint8_t* data, size_t dataSize)
	{
		if (!data || dataSize < sizeof(gtpv2_basic_header) + sizeof(uint32_t))
		{
			return false;
		}

		auto* header = reinterpret_cast<const gtpv2_basic_header*>(data);

		if (header->version != 2)
		{
			return false;
		}

		return true;
	}

	GtpV2MessageType GtpV2Layer::getMessageType() const
	{
		return GtpV2MessageType::fromUintValue(getHeader()->messageType);
	}

	void GtpV2Layer::setMessageType(const GtpV2MessageType& type)
	{
		getHeader()->messageType = type;
	}

	uint16_t GtpV2Layer::getMessageLength() const
	{
		return be16toh(getHeader()->messageLength);
	}

	bool GtpV2Layer::isPiggybacking() const
	{
		return getHeader()->piggybacking;
	}

	std::pair<bool, uint32_t> GtpV2Layer::getTeid() const
	{
		if (!getHeader()->teidPresent)
		{
			return { false, 0 };
		}

		return { true, be32toh(*reinterpret_cast<uint32_t*>(m_Data + sizeof(gtpv2_basic_header))) };
	}

	void GtpV2Layer::setTeid(uint32_t teid)
	{
		auto* header = getHeader();

		auto teidOffset = sizeof(gtpv2_basic_header);
		if (!header->teidPresent)
		{
			if (!extendLayer(static_cast<int>(teidOffset), sizeof(uint32_t)))
			{
				PCPP_LOG_ERROR("Unable to set TEID: failed to extend the layer");
				return;
			}
			header = getHeader();
			header->messageLength = htobe16(be16toh(header->messageLength) + sizeof(uint32_t));
		}

		reinterpret_cast<uint32_t*>(m_Data + teidOffset)[0] = htobe32(teid);

		header->teidPresent = 1;
	}

	void GtpV2Layer::unsetTeid()
	{
		auto* header = getHeader();

		if (!header->teidPresent)
		{
			return;
		}

		auto teidOffset = sizeof(gtpv2_basic_header);
		if (!shortenLayer(static_cast<int>(teidOffset), sizeof(uint32_t)))
		{
			PCPP_LOG_ERROR("Unable to unset TEID: failed to shorten the layer");
			return;
		}

		header = getHeader();
		header->messageLength = htobe16(be16toh(header->messageLength) - sizeof(uint32_t));
		header->teidPresent = 0;
	}

	uint32_t GtpV2Layer::getSequenceNumber() const
	{
		auto* sequencePos = m_Data + sizeof(gtpv2_basic_header);
		if (getHeader()->teidPresent)
		{
			sequencePos += sizeof(uint32_t);
		}

		return be32toh(*reinterpret_cast<uint32_t*>(sequencePos)) >> 8;
	}

	void GtpV2Layer::setSequenceNumber(uint32_t sequenceNumber)
	{
		auto* sequencePos = m_Data + sizeof(gtpv2_basic_header);
		if (getHeader()->teidPresent)
		{
			sequencePos += sizeof(uint32_t);
		}

		sequenceNumber = htobe32(sequenceNumber) >> 8;
		memcpy(sequencePos, &sequenceNumber, sizeof(uint32_t) - 1);
	}

	std::pair<bool, uint8_t> GtpV2Layer::getMessagePriority() const
	{
		auto* header = getHeader();

		if (!header->messagePriorityPresent)
		{
			return { false, 0 };
		}

		auto* mpPos = m_Data + sizeof(gtpv2_basic_header) + sizeof(uint32_t) - 1;
		if (header->teidPresent)
		{
			mpPos += sizeof(uint32_t);
		}

		return { true, mpPos[0] >> 4 };
	}

	void GtpV2Layer::setMessagePriority(const std::bitset<4>& messagePriority)
	{
		auto* header = getHeader();

		header->messagePriorityPresent = 1;

		auto* mpPos = m_Data + sizeof(gtpv2_basic_header) + sizeof(uint32_t) - 1;
		if (header->teidPresent)
		{
			mpPos += sizeof(uint32_t);
		}

		auto messagePriorityNum = static_cast<uint8_t>(messagePriority.to_ulong());
		mpPos[0] = messagePriorityNum << 4;
	}

	void GtpV2Layer::unsetMessagePriority()
	{
		auto* header = getHeader();

		header->messagePriorityPresent = 0;

		auto* mpPos = m_Data + sizeof(gtpv2_basic_header) + sizeof(uint32_t) - 1;
		if (header->teidPresent)
		{
			mpPos += sizeof(uint32_t);
		}

		mpPos[0] = 0;
	}

	GtpV2InformationElement GtpV2Layer::getFirstInformationElement() const
	{
		auto* basePtr = getIEBasePtr();
		return m_IEReader.getFirstTLVRecord(basePtr, m_Data + getHeaderLen() - basePtr);
	}

	GtpV2InformationElement GtpV2Layer::getNextInformationElement(GtpV2InformationElement infoElement) const
	{
		auto* basePtr = getIEBasePtr();
		return m_IEReader.getNextTLVRecord(infoElement, basePtr, m_Data + getHeaderLen() - basePtr);
	}

	GtpV2InformationElement GtpV2Layer::getInformationElement(GtpV2InformationElement::Type infoElementType) const
	{
		auto* basePtr = getIEBasePtr();
		return m_IEReader.getTLVRecord(static_cast<uint32_t>(infoElementType), basePtr,
		                               m_Data + getHeaderLen() - basePtr);
	}

	size_t GtpV2Layer::getInformationElementCount() const
	{
		auto* basePtr = getIEBasePtr();
		return m_IEReader.getTLVRecordCount(basePtr, m_Data + getHeaderLen() - basePtr);
	}

	GtpV2InformationElement GtpV2Layer::addInformationElement(const GtpV2InformationElementBuilder& infoElementBuilder)
	{
		return addInformationElementAt(infoElementBuilder, static_cast<int>(getHeaderLen()));
	}

	GtpV2InformationElement GtpV2Layer::addInformationElementAfter(
	    const GtpV2InformationElementBuilder& infoElementBuilder, GtpV2InformationElement::Type infoElementType)
	{
		auto prevInfoElement = getInformationElement(infoElementType);

		if (prevInfoElement.isNull())
		{
			PCPP_LOG_ERROR("Information element type " << static_cast<int>(infoElementType)
			                                           << " doesn't exist in layer");
			return GtpV2InformationElement(nullptr);
		}
		auto offset = prevInfoElement.getRecordBasePtr() + prevInfoElement.getTotalSize() - m_Data;
		return addInformationElementAt(infoElementBuilder, offset);
	}

	bool GtpV2Layer::removeInformationElement(GtpV2InformationElement::Type infoElementType)
	{
		auto infoElementToRemove = getInformationElement(infoElementType);
		if (infoElementToRemove.isNull())
		{
			return false;
		}

		int offset = infoElementToRemove.getRecordBasePtr() - m_Data;

		auto infoElementSize = infoElementToRemove.getTotalSize();
		if (!shortenLayer(offset, infoElementSize))
		{
			return false;
		}

		getHeader()->messageLength = htobe16(be16toh(getHeader()->messageLength) - infoElementSize);
		m_IEReader.changeTLVRecordCount(-1);
		return true;
	}

	bool GtpV2Layer::removeAllInformationElements()
	{
		auto firstInfoElement = getFirstInformationElement();
		if (firstInfoElement.isNull())
		{
			return true;
		}

		auto offset = firstInfoElement.getRecordBasePtr() - m_Data;

		if (!shortenLayer(offset, getHeaderLen() - offset))
		{
			return false;
		}

		m_IEReader.changeTLVRecordCount(static_cast<int>(0 - getInformationElementCount()));
		return true;
	}

	GtpV2InformationElement GtpV2Layer::addInformationElementAt(
	    const GtpV2InformationElementBuilder& infoElementBuilder, int offset)
	{
		auto newInfoElement = infoElementBuilder.build();

		if (newInfoElement.isNull())
		{
			PCPP_LOG_ERROR("Cannot build new information element");
			return newInfoElement;
		}

		auto sizeToExtend = newInfoElement.getTotalSize();

		if (!extendLayer(offset, sizeToExtend))
		{
			PCPP_LOG_ERROR("Could not extend GtpV2Layer in [" << sizeToExtend << "] bytes");
			newInfoElement.purgeRecordData();
			return GtpV2InformationElement(nullptr);
		}

		memcpy(m_Data + offset, newInfoElement.getRecordBasePtr(), newInfoElement.getTotalSize());

		auto newMessageLength = getMessageLength() + newInfoElement.getTotalSize();

		newInfoElement.purgeRecordData();

		m_IEReader.changeTLVRecordCount(1);

		getHeader()->messageLength = htobe16(newMessageLength);

		uint8_t* newInfoElementPtr = m_Data + offset;

		return GtpV2InformationElement(newInfoElementPtr);
	}

	void GtpV2Layer::parseNextLayer()
	{
		auto headerLen = getHeaderLen();
		if (m_DataLen <= headerLen)
		{
			return;
		}

		auto* nextLayerData = m_Data + headerLen;
		auto nextLayerDataLen = m_DataLen - headerLen;

		if (getHeader()->piggybacking && GtpV2Layer::isDataValid(nextLayerData, nextLayerDataLen))
		{
			m_NextLayer = new GtpV2Layer(nextLayerData, nextLayerDataLen, this, m_Packet);
		}
		else
		{
			m_NextLayer = new PayloadLayer(nextLayerData, nextLayerDataLen, this, m_Packet);
		}
	}

	size_t GtpV2Layer::getHeaderLen() const
	{
		auto messageLength = be16toh(getHeader()->messageLength) + sizeof(gtpv2_basic_header);
		if (messageLength > m_DataLen)
		{
			return m_DataLen;
		}

		return messageLength;
	}

	void GtpV2Layer::computeCalculateFields()
	{
		if (m_NextLayer == nullptr)
		{
			return;
		}

		if (m_NextLayer->getProtocol() == GTPv2)
		{
			getHeader()->piggybacking = 1;
		}
		else
		{
			getHeader()->piggybacking = 0;
		}
	}

	std::string GtpV2Layer::toString() const
	{
		return "GTPv2 Layer, " + getMessageType().toString() + " message";
	}

	uint8_t* GtpV2Layer::getIEBasePtr() const
	{
		auto* basePtr = m_Data + sizeof(gtpv2_basic_header) + sizeof(uint32_t);
		if (getHeader()->teidPresent)
		{
			basePtr += sizeof(uint32_t);
		}

		return basePtr;
	}

}  // namespace pcpp
