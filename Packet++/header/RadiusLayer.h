#ifndef PACKETPP_RADIUS_LAYER
#define PACKETPP_RADIUS_LAYER

#include "Layer.h"
#include "TLVData.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

/**
 * @struct radius_hedear
 */
#pragma pack(push, 1)
	struct radius_header
	{
		uint8_t code;
		uint8_t id;
		uint16_t length;
		uint8_t authenticator[16];
	};
#pragma pack(pop)

	class RadiusAttribute : public TLVRecord
	{
	public:

		RadiusAttribute(uint8_t* recordRawData) : TLVRecord(recordRawData) { }

		virtual ~RadiusAttribute() { }

		// implement abstract methods

		size_t getTotalSize() const
		{
			return (size_t)m_Data->recordLen;
		}

		size_t getDataSize()
		{
			return (size_t)m_Data->recordLen - 2*sizeof(uint8_t);
		}
	};


	class RadiusAttributeBuilder : public TLVRecordBuilder
	{
	public:

		/**
		 * A c'tor which gets the record type, record length and a buffer containing the record value and builds
		 * the record raw buffer which can later be casted to TLVRecord object using the build() method
		 * @param[in] recType Record type
		 * @param[in] recDataLen Record length in bytes
		 * @param[in] recValue A buffer containing the record data. This buffer is read-only and isn't modified in any way
		 */
		RadiusAttributeBuilder(uint8_t recType, const uint8_t* recValue, uint8_t recDataLen) :
			TLVRecordBuilder(recType, recValue, recDataLen) { }

		/**
		 * A c'tor which gets the record type, a 1-byte record value (which length is 1) and builds
		 * the record raw buffer which can later be casted to TLVRecord object using the build() method
		 * @param[in] recType Record type
		 * @param[in] recValue A 1-byte record value
		 */
		RadiusAttributeBuilder(uint8_t recType, uint8_t recValue) :
			TLVRecordBuilder(recType, recValue) { }

		/**
		 * A c'tor which gets the record type, a 2-byte record value (which length is 2) and builds
		 * the record raw buffer which can later be casted to TLVRecord object using the build() method
		 * @param[in] recType Record type
		 * @param[in] recValue A 2-byte record value
		 */
		RadiusAttributeBuilder(uint8_t recType, uint16_t recValue) :
			TLVRecordBuilder(recType, recValue) { }


		RadiusAttributeBuilder(uint8_t recType, uint32_t recValue) :
			TLVRecordBuilder(recType, recValue) { }

		RadiusAttributeBuilder(uint8_t recType, const IPv4Address& recValue) :
			TLVRecordBuilder(recType, recValue) { }

		RadiusAttributeBuilder(uint8_t recType, const std::string& recValue) :
			TLVRecordBuilder(recType, recValue) { }

		/**
		 * A copy c'tor which copies all the data from another instance of TLVRecordBuilder
		 * @param[in] other The instance to copy from
		 */
		RadiusAttributeBuilder(const RadiusAttributeBuilder& other) :
			TLVRecordBuilder(other) { }

		RadiusAttribute build() const;

	};


	/**
	 * @class RadiusLayer
	 */
	class RadiusLayer : public Layer
	{
	private:

		TLVRecordReader<RadiusAttribute> m_AttributeReader;

		inline uint8_t* getAttributesBasePtr() { return m_Data + sizeof(radius_header); }

		RadiusAttribute addAttrAt(const RadiusAttributeBuilder& attrBuilder, int offset);

	public:

		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to @ref arphdr)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		RadiusLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) :
			Layer(data, dataLen, prevLayer, packet)
			{ m_Protocol = Radius; }

		RadiusLayer(uint8_t code, uint8_t id, const uint8_t* authenticator, uint8_t authenticatorArrSize);

		RadiusLayer(uint8_t code, uint8_t id, const std::string authenticator);


		~RadiusLayer() {}

		inline radius_header* getRadiusHeader() { return (radius_header*)m_Data; };

		std::string getAuthenticatorValue();

		void setAuthenticatorValue(const std::string& authValue);

		static std::string getRadiusMessageString(uint8_t radiusMessageCode);

		/**
		 * Does nothing for this layer, RADIUS is always the last layer
		 */
		void parseNextLayer() {}

		RadiusAttribute getFirstAttribute();

		RadiusAttribute getNextAttribute(RadiusAttribute& attr);

		RadiusAttribute getAttribute(uint8_t attributeType);

		size_t getAttributeCount();

		RadiusAttribute addAttribute(const RadiusAttributeBuilder& attrBuilder);

		RadiusAttribute addAttributeAfter(const RadiusAttributeBuilder& attrBuilder, uint8_t prevAttrType);

		bool removeAttribute(uint8_t attrType);

		bool removeAllAttributes();

		size_t getHeaderLen();

		/**
		 * Calculate the layer size
		 */
		void computeCalculateFields();

		std::string toString();

		OsiModelLayer getOsiModelLayer() { return OsiModelSesionLayer; }

	};
}

#endif // PACKETPP_RADIUS_LAYER
