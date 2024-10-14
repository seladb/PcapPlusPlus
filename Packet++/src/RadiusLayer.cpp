#define LOG_MODULE PacketLogModuleRadiusLayer
#include "RadiusLayer.h"
#include "Logger.h"
#include "GeneralUtils.h"
#include <sstream>
#include "EndianPortable.h"

namespace pcpp
{

	RadiusAttribute RadiusAttributeBuilder::build() const
	{
		size_t recSize = m_RecValueLen + 2;
		uint8_t* recordBuffer = new uint8_t[recSize];
		memset(recordBuffer, 0, recSize);
		recordBuffer[0] = static_cast<uint8_t>(m_RecType);
		recordBuffer[1] = static_cast<uint8_t>(recSize);
		if (m_RecValueLen > 0)
			memcpy(recordBuffer + 2, m_RecValue, m_RecValueLen);

		return RadiusAttribute(recordBuffer);
	}

	RadiusLayer::RadiusLayer(uint8_t code, uint8_t id, const uint8_t* authenticator, uint8_t authenticatorArrSize)
	{
		m_DataLen = sizeof(radius_header);
		m_Data = new uint8_t[m_DataLen];
		memset(m_Data, 0, m_DataLen);
		m_Protocol = Radius;

		radius_header* hdr = getRadiusHeader();
		hdr->code = code;
		hdr->id = id;
		hdr->length = htobe16(sizeof(radius_header));
		if (authenticatorArrSize == 0 || authenticator == nullptr)
			return;
		if (authenticatorArrSize > 16)
			authenticatorArrSize = 16;
		memcpy(hdr->authenticator, authenticator, authenticatorArrSize);
	}

	RadiusLayer::RadiusLayer(uint8_t code, uint8_t id, const std::string& authenticator)
	{
		m_DataLen = sizeof(radius_header);
		m_Data = new uint8_t[m_DataLen];
		memset(m_Data, 0, m_DataLen);
		m_Protocol = Radius;

		radius_header* hdr = getRadiusHeader();
		hdr->code = code;
		hdr->id = id;
		hdr->length = htobe16(sizeof(radius_header));
		setAuthenticatorValue(authenticator);
	}

	RadiusAttribute RadiusLayer::addAttrAt(const RadiusAttributeBuilder& attrBuilder, int offset)
	{
		RadiusAttribute newAttr = attrBuilder.build();
		if (newAttr.isNull())
		{
			PCPP_LOG_ERROR("Cannot build new attribute of type " << (int)newAttr.getType());
			return newAttr;
		}

		size_t sizeToExtend = newAttr.getTotalSize();
		if (!extendLayer(offset, sizeToExtend))
		{
			PCPP_LOG_ERROR("Could not extend RadiusLayer in [" << newAttr.getTotalSize() << "] bytes");
			newAttr.purgeRecordData();
			return RadiusAttribute(nullptr);
		}

		memcpy(m_Data + offset, newAttr.getRecordBasePtr(), newAttr.getTotalSize());

		uint8_t* newAttrPtr = m_Data + offset;

		m_AttributeReader.changeTLVRecordCount(1);

		newAttr.purgeRecordData();

		getRadiusHeader()->length = htobe16(m_DataLen);

		return RadiusAttribute(newAttrPtr);
	}

	std::string RadiusLayer::getAuthenticatorValue() const
	{
		return byteArrayToHexString(getRadiusHeader()->authenticator, 16);
	}

	void RadiusLayer::setAuthenticatorValue(const std::string& authValue)
	{
		hexStringToByteArray(authValue, getRadiusHeader()->authenticator, 16);
	}

	std::string RadiusLayer::getRadiusMessageString(uint8_t radiusMessageCode)
	{
		switch (radiusMessageCode)
		{
		case 1:
			return "Access-Request";
		case 2:
			return "Access-Accept";
		case 3:
			return "Access-Reject";
		case 4:
			return "Accounting-Request";
		case 5:
			return "Accounting-Response";
		case 11:
			return "Access-Challenge";
		case 12:
			return "Status-Server";
		case 13:
			return "Status-Client";
		case 40:
			return "Disconnect-Request";
		case 41:
			return "Disconnect-ACK";
		case 42:
			return "Disconnect-NAK";
		case 43:
			return "CoA-Request";
		case 44:
			return "CoA-ACK";
		case 45:
			return "CoA-NAK";
		case 255:
			return "Reserved";
		default:
			return "Unknown";
		}
	}

	size_t RadiusLayer::getHeaderLen() const
	{
		uint16_t len = be16toh(getRadiusHeader()->length);
		if (len > m_DataLen)
			return m_DataLen;

		return len;
	}

	void RadiusLayer::computeCalculateFields()
	{
		getRadiusHeader()->length = htobe16(m_DataLen);
	}

	std::string RadiusLayer::toString() const
	{
		std::ostringstream str;
		str << "RADIUS Layer, " << RadiusLayer::getRadiusMessageString(getRadiusHeader()->code) << "("
		    << (int)getRadiusHeader()->code
		    << "), "
		       "Id="
		    << (int)getRadiusHeader()->id << ", "
		    << "Length=" << be16toh(getRadiusHeader()->length);

		return str.str();
	}

	RadiusAttribute RadiusLayer::getFirstAttribute() const
	{
		return m_AttributeReader.getFirstTLVRecord(getAttributesBasePtr(), getHeaderLen() - sizeof(radius_header));
	}

	RadiusAttribute RadiusLayer::getNextAttribute(RadiusAttribute& attr) const
	{
		return m_AttributeReader.getNextTLVRecord(attr, getAttributesBasePtr(), getHeaderLen() - sizeof(radius_header));
	}

	RadiusAttribute RadiusLayer::getAttribute(uint8_t attributeType) const
	{
		return m_AttributeReader.getTLVRecord(attributeType, getAttributesBasePtr(),
		                                      getHeaderLen() - sizeof(radius_header));
	}

	size_t RadiusLayer::getAttributeCount() const
	{
		return m_AttributeReader.getTLVRecordCount(getAttributesBasePtr(), getHeaderLen() - sizeof(radius_header));
	}

	RadiusAttribute RadiusLayer::addAttribute(const RadiusAttributeBuilder& attrBuilder)
	{
		int offset = getHeaderLen();
		return addAttrAt(attrBuilder, offset);
	}

	RadiusAttribute RadiusLayer::addAttributeAfter(const RadiusAttributeBuilder& attrBuilder, uint8_t prevAttrType)
	{
		int offset = 0;

		RadiusAttribute prevAttr = getAttribute(prevAttrType);

		if (prevAttr.isNull())
		{
			offset = getHeaderLen();
		}
		else
		{
			offset = prevAttr.getRecordBasePtr() + prevAttr.getTotalSize() - m_Data;
		}

		return addAttrAt(attrBuilder, offset);
	}

	bool RadiusLayer::removeAttribute(uint8_t attrType)
	{
		RadiusAttribute attrToRemove = getAttribute(attrType);
		if (attrToRemove.isNull())
		{
			return false;
		}

		int offset = attrToRemove.getRecordBasePtr() - m_Data;

		if (!shortenLayer(offset, attrToRemove.getTotalSize()))
		{
			return false;
		}

		m_AttributeReader.changeTLVRecordCount(-1);
		getRadiusHeader()->length = htobe16(m_DataLen);

		return true;
	}

	bool RadiusLayer::removeAllAttributes()
	{
		int offset = sizeof(radius_header);

		if (!shortenLayer(offset, getHeaderLen() - offset))
			return false;

		m_AttributeReader.changeTLVRecordCount(0 - getAttributeCount());

		getRadiusHeader()->length = htobe16(m_DataLen);

		return true;
	}

	bool RadiusLayer::isDataValid(const uint8_t* udpData, size_t udpDataLen)
	{
		if (udpData != nullptr && udpDataLen >= sizeof(radius_header))
		{
			const radius_header* radHdr = reinterpret_cast<const radius_header*>(udpData);
			size_t radLen = be16toh(radHdr->length);
			return radLen >= sizeof(radius_header) && radLen <= udpDataLen;
		}
		return false;
	}

}  // namespace pcpp
