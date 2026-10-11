#define LOG_MODULE PacketLogModuleGreLayer

#include "GreLayer.h"
#include "EthLayer.h"
#include "EthDot3Layer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "PPPoELayer.h"
#include "VlanLayer.h"
#include "MplsLayer.h"
#include "PayloadLayer.h"
#include "PacketUtils.h"
#include "Logger.h"
#include "EndianPortable.h"

// ==============
// GreLayer class
// ==============

namespace pcpp
{

	ProtocolType GreLayer::getGREVersion(uint8_t* greData, size_t greDataLen)
	{
		if (greDataLen < sizeof(gre_basic_header))
			return UnknownProtocol;

		uint8_t version = *(greData + 1);
		version &= 0x07;
		if (version == 0)
			return GREv0;
		else if (version == 1)
			return GREv1;
		else
			return UnknownProtocol;
	}

	uint8_t* GreLayer::getFieldValue(GreField field, bool returnOffsetEvenIfFieldMissing) const
	{
		uint8_t* ptr = m_Data + sizeof(gre_basic_header);

		auto* header = reinterpret_cast<gre_basic_header*>(m_Data);

		constexpr int numGreField = 4;
		for (int curFieldAsInt = static_cast<int>(GreChecksumOrRouting); curFieldAsInt < numGreField; ++curFieldAsInt)
		{
			const GreField curField = static_cast<GreField>(curFieldAsInt);
			bool curFieldExists = false;

			uint8_t* origPtr = ptr;

			switch (curField)
			{
			case GreChecksumOrRouting:
				if (header->checksumBit == 1 || header->routingBit == 1)
				{
					curFieldExists = true;
					ptr += sizeof(uint32_t);
				}
				break;
			case GreKey:
				if (header->keyBit == 1)
				{
					curFieldExists = true;
					ptr += sizeof(uint32_t);
				}
				break;
			case GreSeq:
				if (header->sequenceNumBit == 1)
				{
					curFieldExists = true;
					ptr += sizeof(uint32_t);
				}
				break;
			case GreAck:
				if (header->ackSequenceNumBit == 1)
				{
					curFieldExists = true;
					ptr += sizeof(uint32_t);
				}
				break;
			default:  // shouldn't get there
				return nullptr;
			}

			if (field == curField)
			{
				// If the packet is truncated/malformed it might be overflow packet length
				if ((curFieldExists && static_cast<size_t>(std::abs(ptr - m_Data)) <= m_DataLen) ||
				    returnOffsetEvenIfFieldMissing)
					return origPtr;

				return nullptr;
			}
		}  // for

		return nullptr;
	}

	void GreLayer::computeCalculateFieldsInner()
	{
		gre_basic_header* header = (gre_basic_header*)m_Data;
		if (m_NextLayer != nullptr)
		{
			switch (m_NextLayer->getProtocol())
			{
			case IPv4:
				header->protocol = htobe16(PCPP_ETHERTYPE_IP);
				break;
			case IPv6:
				header->protocol = htobe16(PCPP_ETHERTYPE_IPV6);
				break;
			case VLAN:
				header->protocol = htobe16(PCPP_ETHERTYPE_VLAN);
				break;
			case MPLS:
				header->protocol = htobe16(PCPP_ETHERTYPE_MPLS);
				break;
			case PPP_PPTP:
				header->protocol = htobe16(PCPP_ETHERTYPE_PPP);
				break;
			case Ethernet:
				header->protocol = htobe16(PCPP_ETHERTYPE_ETHBRIDGE);
				break;
			default:
				break;
			}
		}
	}

	bool GreLayer::getSequenceNumber(uint32_t& seqNumber) const
	{
		gre_basic_header* header = (gre_basic_header*)m_Data;

		if (header->sequenceNumBit == 0)
			return false;

		uint32_t* val = (uint32_t*)getFieldValue(GreSeq, false);
		if (val == nullptr)
			return false;

		seqNumber = be32toh(*val);
		return true;
	}

	bool GreLayer::setSequenceNumber(uint32_t seqNumber)
	{
		gre_basic_header* header = (gre_basic_header*)m_Data;

		bool needToExtendLayer = false;

		if (header->sequenceNumBit == 0)
			needToExtendLayer = true;

		uint8_t* offsetPtr = getFieldValue(GreSeq, true);

		int offset = offsetPtr - m_Data;
		if (needToExtendLayer && !extendLayer(offset, sizeof(uint32_t)))
		{
			header->sequenceNumBit = 0;
			PCPP_LOG_ERROR("Couldn't extend layer to set sequence number");
			return false;
		}

		header = (gre_basic_header*)m_Data;
		header->sequenceNumBit = 1;
		uint32_t* seqPtr = (uint32_t*)(m_Data + offset);
		*seqPtr = htobe32(seqNumber);

		return true;
	}

	bool GreLayer::unsetSequenceNumber()
	{
		gre_basic_header* header = (gre_basic_header*)m_Data;

		if (header->sequenceNumBit == 0)
		{
			PCPP_LOG_ERROR("Couldn't unset sequence number as it's already unset");
			return false;
		}

		uint8_t* offsetPtr = getFieldValue(GreSeq, true);

		int offset = offsetPtr - m_Data;
		if (!shortenLayer(offset, sizeof(uint32_t)))
		{
			PCPP_LOG_ERROR("Couldn't shorted layer to unset sequence number");
			return false;
		}

		header = (gre_basic_header*)m_Data;
		header->sequenceNumBit = 0;
		return true;
	}

	void GreLayer::parseNextLayer()
	{
		size_t headerLen = getHeaderLen();
		if (m_DataLen <= headerLen)
			return;

		gre_basic_header* header = (gre_basic_header*)m_Data;
		uint8_t* payload = m_Data + headerLen;
		size_t payloadLen = m_DataLen - headerLen;

		switch (be16toh(header->protocol))
		{
		case PCPP_ETHERTYPE_IP:
			tryConstructNextLayerWithFallback<IPv4Layer, PayloadLayer>(payload, payloadLen);
			break;
		case PCPP_ETHERTYPE_IPV6:
			tryConstructNextLayerWithFallback<IPv6Layer, PayloadLayer>(payload, payloadLen);
			break;
		case PCPP_ETHERTYPE_VLAN:
			constructNextLayer<VlanLayer>(payload, payloadLen);
			break;
		case PCPP_ETHERTYPE_MPLS:
			tryConstructNextLayerWithFallback<MplsLayer, PayloadLayer>(payload, payloadLen);
			break;
		case PCPP_ETHERTYPE_PPP:
			tryConstructNextLayerWithFallback<PPP_PPTPLayer, PayloadLayer>(payload, payloadLen);
			break;
		case PCPP_ETHERTYPE_ETHBRIDGE:
		{
			if (tryConstructNextLayer<EthLayer>(payload, payloadLen) != nullptr)
			{
				break;
			}

			tryConstructNextLayerWithFallback<EthDot3Layer, PayloadLayer>(payload, payloadLen);
			break;
		}
		default:
			constructNextLayer<PayloadLayer>(payload, payloadLen);
		}
	}

	size_t GreLayer::getHeaderLen() const
	{
		size_t result = sizeof(gre_basic_header);

		gre_basic_header const* header = reinterpret_cast<gre_basic_header const*>(m_Data);

		if (header->checksumBit == 1 || header->routingBit == 1)
			result += 4;
		if (header->keyBit == 1)
			result += 4;
		if (header->sequenceNumBit == 1)
			result += 4;
		if (header->ackSequenceNumBit == 1)
			result += 4;

		return result;
	}

	const FieldDescriptor GreLayer::SerializedFields::StrictSourceRouteBit{ Layer::SerializedFields::MaxID + 1,
		                                                                    "strictSourceRouteBit" };
	const FieldDescriptor GreLayer::SerializedFields::SequenceNumBit{ Layer::SerializedFields::MaxID + 2,
		                                                              "sequenceNumBit" };
	const FieldDescriptor GreLayer::SerializedFields::KeyBit{ Layer::SerializedFields::MaxID + 3, "keyBit" };
	const FieldDescriptor GreLayer::SerializedFields::RoutingBit{ Layer::SerializedFields::MaxID + 4, "routingBit" };
	const FieldDescriptor GreLayer::SerializedFields::ChecksumBit{ Layer::SerializedFields::MaxID + 5, "checksumBit" };
	const FieldDescriptor GreLayer::SerializedFields::RecursionControl{ Layer::SerializedFields::MaxID + 6,
		                                                                "recursionControl" };
	const FieldDescriptor GreLayer::SerializedFields::Flags{ Layer::SerializedFields::MaxID + 7, "flags" };
	const FieldDescriptor GreLayer::SerializedFields::Version{ Layer::SerializedFields::MaxID + 8, "version" };
	const FieldDescriptor GreLayer::SerializedFields::Protocol{ Layer::SerializedFields::MaxID + 9, "protocol" };
	const FieldDescriptor GreLayer::SerializedFields::SequenceNumber{ Layer::SerializedFields::MaxID + 10,
		                                                              "sequenceNumber" };

	void GreLayer::serializeLayer(ObjectScope& serializer) const
	{
		auto* header = reinterpret_cast<const gre_basic_header*>(m_Data);
		serializer.writeField(SerializedFields::ChecksumBit, header->checksumBit != 0);
		serializer.writeField(SerializedFields::RoutingBit, header->routingBit != 0);
		serializer.writeField(SerializedFields::KeyBit, header->keyBit != 0);
		serializer.writeField(SerializedFields::SequenceNumBit, header->sequenceNumBit != 0);
		serializer.writeField(SerializedFields::StrictSourceRouteBit, header->strictSourceRouteBit != 0);
		serializer.writeField(SerializedFields::RecursionControl, static_cast<uint8_t>(header->recursionControl));
		serializer.writeField(SerializedFields::Flags, static_cast<uint8_t>(header->flags));
		serializer.writeField(SerializedFields::Version, static_cast<uint8_t>(header->version));
		serializer.writeField(SerializedFields::Protocol, be16toh(header->protocol));

		uint32_t seqNumber = 0;
		if (getSequenceNumber(seqNumber))
		{
			serializer.writeField(SerializedFields::SequenceNumber, seqNumber);
		}
	}

	// ================
	// GREv0Layer class
	// ================

	GREv0Layer::GREv0Layer()
	{
		allocData(sizeof(gre_basic_header));
		m_Protocol = GREv0;
	}

	bool GREv0Layer::getChecksum(uint16_t& checksum) const
	{
		if (getGreHeader()->checksumBit == 0)
			return false;

		uint16_t* val = (uint16_t*)getFieldValue(GreChecksumOrRouting, false);
		if (val == nullptr)
			return false;

		checksum = be16toh(*val);
		return true;
	}

	bool GREv0Layer::setChecksum(uint16_t checksum)
	{
		gre_basic_header* header = getGreHeader();

		bool needToExtendLayer = false;

		if (header->routingBit == 0 && header->checksumBit == 0)
			needToExtendLayer = true;

		uint8_t* offsetPtr = getFieldValue(GreChecksumOrRouting, true);
		int offset = offsetPtr - m_Data;
		// extend layer in 4 bytes to keep 4-byte alignment
		if (needToExtendLayer && !extendLayer(offset, sizeof(uint32_t)))
		{
			PCPP_LOG_ERROR("Couldn't extend layer to set checksum");
			return false;
		}

		uint16_t* checksumPtr = (uint16_t*)(m_Data + offset);
		*checksumPtr = htobe16(checksum);

		// if layer was extended in 4 bytes, make sure the offset field stays 0
		if (needToExtendLayer)
		{
			checksumPtr++;
			*checksumPtr = 0;
		}

		header = getGreHeader();
		header->checksumBit = 1;

		return true;
	}

	bool GREv0Layer::unsetChecksum()
	{
		gre_basic_header* header = getGreHeader();

		if (header->checksumBit == 0)
		{
			PCPP_LOG_ERROR("Couldn't unset checksum as it's already unset");
			return false;
		}

		// if both routing and checksum are unset we need to shorted the layer
		bool needToShortenLayer = (header->routingBit == 0);

		uint8_t* offsetPtr = getFieldValue(GreChecksumOrRouting, true);
		int offset = offsetPtr - m_Data;
		if (needToShortenLayer && !shortenLayer(offset, sizeof(uint32_t)))
		{
			PCPP_LOG_ERROR("Couldn't extend layer to unset checksum");
			return false;
		}

		if (!needToShortenLayer)  // meaning routing bit is set - only zero the checksum field
		{
			uint16_t* checksumPtr = (uint16_t*)(m_Data + offset);
			*checksumPtr = 0;
		}

		header = getGreHeader();
		header->checksumBit = 0;

		return true;
	}

	bool GREv0Layer::getOffset(uint16_t& offset) const
	{
		if (getGreHeader()->routingBit == 0)
			return false;

		uint8_t* val = (uint8_t*)getFieldValue(GreChecksumOrRouting, false);
		if (val == nullptr)
			return false;

		offset = be16toh(*(val + 2));
		return true;
	}

	bool GREv0Layer::getKey(uint32_t& key) const
	{
		if (getGreHeader()->keyBit == 0)
			return false;

		uint32_t* val = (uint32_t*)getFieldValue(GreKey, false);
		if (val == nullptr)
			return false;

		key = be32toh(*val);
		return true;
	}

	bool GREv0Layer::setKey(uint32_t key)
	{
		gre_basic_header* header = getGreHeader();

		bool needToExtendLayer = false;

		if (header->keyBit == 0)
			needToExtendLayer = true;

		uint8_t* offsetPtr = getFieldValue(GreKey, true);

		int offset = offsetPtr - m_Data;
		if (needToExtendLayer && !extendLayer(offset, sizeof(uint32_t)))
		{
			header->keyBit = 0;
			PCPP_LOG_ERROR("Couldn't extend layer to set key");
			return false;
		}

		header = getGreHeader();
		header->keyBit = 1;
		uint32_t* keyPtr = (uint32_t*)(m_Data + offset);
		*keyPtr = htobe32(key);

		return true;
	}

	bool GREv0Layer::unsetKey()
	{
		gre_basic_header* header = getGreHeader();

		if (header->keyBit == 0)
		{
			PCPP_LOG_ERROR("Couldn't unset key as it's already unset");
			return false;
		}

		uint8_t* offsetPtr = getFieldValue(GreKey, true);

		int offset = offsetPtr - m_Data;
		if (!shortenLayer(offset, sizeof(uint32_t)))
		{
			PCPP_LOG_ERROR("Couldn't shorted layer to unset key");
			return false;
		}

		header = (gre_basic_header*)m_Data;
		header->keyBit = 0;
		return true;
	}

	void GREv0Layer::computeCalculateFields()
	{
		computeCalculateFieldsInner();

		if (getGreHeader()->checksumBit == 0)
			return;

		// calculate checksum
		setChecksum(0);

		ScalarBuffer<uint16_t> buffer;
		buffer.buffer = (uint16_t*)m_Data;
		buffer.len = m_DataLen;
		size_t checksum = computeChecksum(&buffer, 1);

		setChecksum(checksum);
	}

	std::string GREv0Layer::toString() const
	{
		return "GRE Layer, version 0";
	}

	const FieldDescriptor GREv0Layer::SerializedFields::Checksum{ GreLayer::SerializedFields::MaxID + 1, "checksum" };
	const FieldDescriptor GREv0Layer::SerializedFields::Offset{ GreLayer::SerializedFields::MaxID + 2, "offset" };
	const FieldDescriptor GREv0Layer::SerializedFields::Key{ GreLayer::SerializedFields::MaxID + 3, "key" };

	void GREv0Layer::serializeLayer(ObjectScope& serializer) const
	{
		GreLayer::serializeLayer(serializer);

		uint16_t checksum = 0;
		if (getChecksum(checksum))
		{
			serializer.writeHexField(SerializedFields::Checksum, checksum);
		}

		uint16_t offset = 0;
		if (getOffset(offset))
		{
			serializer.writeField(SerializedFields::Offset, offset);
		}

		uint32_t key = 0;
		if (getKey(key))
		{
			serializer.writeField(SerializedFields::Key, key);
		}
	}

	// ================
	// GREv1Layer class
	// ================

	GREv1Layer::GREv1Layer(uint16_t callID)
	{
		allocData(sizeof(gre1_header));
		m_Protocol = GREv1;

		gre1_header* header = getGreHeader();
		header->keyBit = 1;
		header->version = 1;
		header->callID = htobe16(callID);
	}

	bool GREv1Layer::getAcknowledgmentNum(uint32_t& ackNum) const
	{
		if (getGreHeader()->ackSequenceNumBit == 0)
			return false;

		uint32_t* val = (uint32_t*)getFieldValue(GreAck, false);
		if (val == nullptr)
			return false;

		ackNum = be32toh(*val);
		return true;
	}

	bool GREv1Layer::setAcknowledgmentNum(uint32_t ackNum)
	{
		bool needToExtendLayer = false;

		gre1_header* header = getGreHeader();

		if (header->ackSequenceNumBit == 0)
			needToExtendLayer = true;

		uint8_t* offsetPtr = getFieldValue(GreAck, true);
		int offset = offsetPtr - m_Data;
		if (needToExtendLayer && !extendLayer(offset, sizeof(uint32_t)))
		{
			PCPP_LOG_ERROR("Couldn't extend layer to set ack number");
			return false;
		}

		header = getGreHeader();
		header->ackSequenceNumBit = 1;
		uint32_t* ackPtr = (uint32_t*)(m_Data + offset);
		*ackPtr = htobe32(ackNum);
		return true;
	}

	bool GREv1Layer::unsetAcknowledgmentNum()
	{
		gre1_header* header = getGreHeader();

		if (header->ackSequenceNumBit == 0)
		{
			PCPP_LOG_ERROR("Couldn't unset ack number as it's already unset");
			return false;
		}

		uint8_t* offsetPtr = getFieldValue(GreAck, true);

		int offset = offsetPtr - m_Data;
		if (!shortenLayer(offset, sizeof(uint32_t)))
		{
			PCPP_LOG_ERROR("Couldn't shorted layer to unset ack number");
			return false;
		}

		header = getGreHeader();
		header->ackSequenceNumBit = 0;
		return true;
	}

	void GREv1Layer::computeCalculateFields()
	{
		computeCalculateFieldsInner();

		getGreHeader()->payloadLength = htobe16(m_DataLen - getHeaderLen());
	}

	std::string GREv1Layer::toString() const
	{
		return "GRE Layer, version 1";
	}

	const FieldDescriptor GREv1Layer::SerializedFields::AckSequenceNumBit{ GreLayer::SerializedFields::MaxID + 1,
		                                                                   "ackSequenceNumBit" };
	const FieldDescriptor GREv1Layer::SerializedFields::PayloadLength{ GreLayer::SerializedFields::MaxID + 2,
		                                                               "payloadLength" };
	const FieldDescriptor GREv1Layer::SerializedFields::CallID{ GreLayer::SerializedFields::MaxID + 3, "callID" };
	const FieldDescriptor GREv1Layer::SerializedFields::AcknowledgmentNumber{ GreLayer::SerializedFields::MaxID + 4,
		                                                                      "acknowledgmentNumber" };

	void GREv1Layer::serializeLayer(ObjectScope& serializer) const
	{
		GreLayer::serializeLayer(serializer);

		auto* header = getGreHeader();
		serializer.writeField(SerializedFields::AckSequenceNumBit, header->ackSequenceNumBit != 0);
		serializer.writeField(SerializedFields::PayloadLength, be16toh(header->payloadLength));
		serializer.writeField(SerializedFields::CallID, be16toh(header->callID));

		uint32_t ackNum = 0;
		if (getAcknowledgmentNum(ackNum))
		{
			serializer.writeField(SerializedFields::AcknowledgmentNumber, ackNum);
		}
	}

	// ===================
	// PPP_PPTPLayer class
	// ===================

	PPP_PPTPLayer::PPP_PPTPLayer(uint8_t address, uint8_t control)
	{
		allocData(sizeof(ppp_pptp_header));
		m_Protocol = PPP_PPTP;

		ppp_pptp_header* header = getPPP_PPTPHeader();
		header->address = address;
		header->control = control;
	}

	void PPP_PPTPLayer::parseNextLayer()
	{
		size_t headerLen = getHeaderLen();
		if (m_DataLen <= headerLen)
			return;

		uint8_t* payload = m_Data + headerLen;
		size_t payloadLen = m_DataLen - headerLen;

		switch (be16toh(getPPP_PPTPHeader()->protocol))
		{
		case PCPP_PPP_IP:
			tryConstructNextLayerWithFallback<IPv4Layer, PayloadLayer>(payload, payloadLen);
			break;
		case PCPP_PPP_IPV6:
			tryConstructNextLayerWithFallback<IPv6Layer, PayloadLayer>(payload, payloadLen);
			break;
		default:
			constructNextLayer<PayloadLayer>(payload, payloadLen);
			break;
		}
	}

	void PPP_PPTPLayer::computeCalculateFields()
	{
		ppp_pptp_header* header = getPPP_PPTPHeader();
		if (m_NextLayer != nullptr)
		{
			switch (m_NextLayer->getProtocol())
			{
			case IPv4:
				header->protocol = htobe16(PCPP_PPP_IP);
				break;
			case IPv6:
				header->protocol = htobe16(PCPP_PPP_IPV6);
				break;
			default:
				break;
			}
		}
		else
			header->protocol = 0;
	}

	const FieldDescriptor PPP_PPTPLayer::SerializedFields::Address{ Layer::SerializedFields::MaxID + 1, "address" };
	const FieldDescriptor PPP_PPTPLayer::SerializedFields::Control{ Layer::SerializedFields::MaxID + 2, "control" };
	const FieldDescriptor PPP_PPTPLayer::SerializedFields::Protocol{ Layer::SerializedFields::MaxID + 3, "protocol" };

	void PPP_PPTPLayer::serializeLayer(ObjectScope& serializer) const
	{
		auto* header = getPPP_PPTPHeader();
		serializer.writeField(SerializedFields::Address, header->address);
		serializer.writeField(SerializedFields::Control, header->control);
		serializer.writeField(SerializedFields::Protocol, be16toh(header->protocol));
	}

}  // namespace pcpp
