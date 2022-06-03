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
	 * @struct radius_header
	 * Represents a RADIUS protocol header
	 */
#pragma pack(push, 1)
	struct radius_header
	{
		/** RADIUS message code */
		uint8_t code;
		/** RADIUS message ID */
		uint8_t id;
		/** RADIUS message length */
		uint16_t length;
		/** Used to authenticate the reply from the RADIUS server and to encrypt passwords */
		uint8_t authenticator[16];
	};
#pragma pack(pop)


	/**
	 * @class RadiusAttribute
	 * A wrapper class for RADIUS attributes. This class does not create or modify RADIUS attribute records, but rather
	 * serves as a wrapper and provides useful methods for retrieving data from them
	 */
	class RadiusAttribute : public TLVRecord<uint8_t, uint8_t>
	{
	public:

		/**
		 * A c'tor for this class that gets a pointer to the attribute raw data (byte array)
		 * @param[in] attrRawData A pointer to the attribute raw data
		 */
		RadiusAttribute(uint8_t* attrRawData) : TLVRecord(attrRawData) { }

		/**
		 * A d'tor for this class, currently does nothing
		 */
		virtual ~RadiusAttribute() { }

		// implement abstract methods

		size_t getTotalSize() const
		{
			return (size_t)m_Data->recordLen;
		}

		size_t getDataSize() const
		{
			return (size_t)m_Data->recordLen - 2*sizeof(uint8_t);
		}
	};


	/**
	 * @class RadiusAttributeBuilder
	 * A class for building RADIUS attributes. This builder receives the attribute parameters in its c'tor,
	 * builds the RADIUS attribute raw buffer and provides a build() method to get a RadiusAttribute object out of it
	 */
	class RadiusAttributeBuilder : public TLVRecordBuilder
	{
	public:

		/**
		 * A c'tor for building RADIUS attributes which their value is a byte array. The RadiusAttribute object can later
		 * be retrieved by calling build()
		 * @param[in] attrType RADIUS attribute type
		 * @param[in] attrValue A buffer containing the attribute value. This buffer is read-only and isn't modified in any way
		 * @param[in] attrValueLen Attribute value length in bytes
		 */
		RadiusAttributeBuilder(uint8_t attrType, const uint8_t* attrValue, uint8_t attrValueLen) :
			TLVRecordBuilder(attrType, attrValue, attrValueLen) { }

		/**
		 * A c'tor for building RADIUS attributes which have a 1-byte value. The RadiusAttribute object can later be retrieved
		 * by calling build()
		 * @param[in] attrType RADIUS attribute type
		 * @param[in] attrValue A 1-byte attribute value
		 */
		RadiusAttributeBuilder(uint8_t attrType, uint8_t attrValue) :
			TLVRecordBuilder(attrType, attrValue) { }

		/**
		 * A c'tor for building RADIUS attributes which have a 2-byte value. The RadiusAttribute object can later be retrieved
		 * by calling build()
		 * @param[in] attrType RADIUS attribute type
		 * @param[in] attrValue A 2-byte attribute value
		 */
		RadiusAttributeBuilder(uint8_t attrType, uint16_t attrValue) :
			TLVRecordBuilder(attrType, attrValue) { }

		/**
		 * A c'tor for building RADIUS attributes which have a 4-byte value. The RadiusAttribute object can later be retrieved
		 * by calling build()
		 * @param[in] attrType RADIUS attribute type
		 * @param[in] attrValue A 4-byte attribute value
		 */
		RadiusAttributeBuilder(uint8_t attrType, uint32_t attrValue) :
			TLVRecordBuilder(attrType, attrValue) { }

		/**
		 * A c'tor for building RADIUS attributes which have an IPv4Address value. The RadiusAttribute object can later be
		 * retrieved by calling build()
		 * @param[in] attrType RADIUS attribute type
		 * @param[in] attrValue The IPv4 address attribute value
		 */
		RadiusAttributeBuilder(uint8_t attrType, const IPv4Address& attrValue) :
			TLVRecordBuilder(attrType, attrValue) { }

		/**
		 * A c'tor for building RADIUS attributes which have a string value. The RadiusAttribute object can later be retrieved
		 * by calling build()
		 * @param[in] attrType RADIUS attribute type
		 * @param[in] attrValue The string attribute value
		 */
		RadiusAttributeBuilder(uint8_t attrType, const std::string& attrValue) :
			TLVRecordBuilder(attrType, attrValue) { }

		/**
		 * A copy c'tor which copies all the data from another instance of RadiusAttributeBuilder
		 * @param[in] other The instance to copy from
		 */
		RadiusAttributeBuilder(const RadiusAttributeBuilder& other) :
			TLVRecordBuilder(other) { }

		/**
		 * Assignment operator that copies all data from another instance of RadiusAttributeBuilder
		 * @param[in] other The instance to assign from
		 */
		RadiusAttributeBuilder& operator=(const RadiusAttributeBuilder& other)
		{
			TLVRecordBuilder::operator=(other);
			return *this;
		}

		/**
		 * Build the RadiusAttribute object out of the parameters defined in the c'tor
		 * @return The RadiusAttribute object
		 */
		RadiusAttribute build() const;
	};


	/**
	 * @class RadiusLayer
	 * Represents a RADIUS (Remote Authentication Dial-In User Service) protocol layer
	 */
	class RadiusLayer : public Layer
	{
	private:

		TLVRecordReader<RadiusAttribute> m_AttributeReader;

		uint8_t* getAttributesBasePtr() const { return m_Data + sizeof(radius_header); }

		RadiusAttribute addAttrAt(const RadiusAttributeBuilder& attrBuilder, int offset);

	public:

		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		RadiusLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) :
			Layer(data, dataLen, prevLayer, packet)
			{ m_Protocol = Radius; }

		/**
		 * A constructor that creates a new layer from scratch
		 * @param[in] code The RADIUS message code
		 * @param[in] id The RADIUS message ID
		 * @param[in] authenticator A pointer to a byte array containing the authenticator value
		 * @param[in] authenticatorArrSize The authenticator byte array size. A valid size of the authenticator field is
		 * 16 bytes. If the provided size is less than that then the byte array will be copied to the packet but the missing
		 * bytes will stay zero. If the size is more than 16 bytes, only the first 16 bytes will be copied to the packet
		 */
		RadiusLayer(uint8_t code, uint8_t id, const uint8_t* authenticator, uint8_t authenticatorArrSize);

		/**
		 * A constructor that creates a new layer from scratch
		 * @param[in] code The RADIUS message code
		 * @param[in] id The RADIUS message ID
		 * @param[in] authenticator A hex string representing the authenticator value. A valid size of the authenticator
		 * field is 16 bytes. If the hex string represents an array that is smaller than this then the missing bytes in the
		 * packet's authenticator field will stay zero. If the hex string represents an array that is larger than 16 bytes,
		 * only the first 16 bytes will be copied to the packet
		 */
		RadiusLayer(uint8_t code, uint8_t id, const std::string authenticator);

		/**
		 * A d'tor for this layer, currently does nothing
		 */
		~RadiusLayer() {}

		/**
		 * Get a pointer to the RADIUS header. Notice this points directly to the data, so every change will change the actual packet data
		 * @return A pointer to the radius_header object
		 */
		radius_header* getRadiusHeader() const { return (radius_header*)m_Data; }

		/**
		 * @return A hex string representation of the radius_header#authenticator byte array value
		 */
		std::string getAuthenticatorValue() const;

		/**
		 * Setter for radius_header#authenticator
		 * @param[in] authValue A hex string representing the requested authenticator value
		 */
		void setAuthenticatorValue(const std::string& authValue);

		/**
		 * A static method that returns the RADIUS message string for a give message code. For example: the string
		 * "Access-Request" will be returned for code 1
		 * @param[in] radiusMessageCode RADIUS message code
		 * @return RADIUS message string
		 */
		static std::string getRadiusMessageString(uint8_t radiusMessageCode);

		/**
		 * @return The first RADIUS attribute in the packet. If there are no attributes the returned value will contain
		 * a logical NULL (RadiusAttribute#isNull() == true)
		 */
		RadiusAttribute getFirstAttribute() const;

		/**
		 * Get the RADIUS attribute that comes after a given attribute. If the given attribute was the last one, the
		 * returned value will contain a logical NULL (RadiusAttribute#isNull() == true)
		 * @param[in] attr A given attribute
		 * @return A RadiusAttribute object containing the attribute data that comes next, or logical NULL if the given
		 * attribute: (1) was the last one; (2) contains a logical NULL or (3) doesn't belong to this packet
		 */
		RadiusAttribute getNextAttribute(RadiusAttribute& attr) const;

		/**
		 * Get a RADIUS attribute by attribute type
		 * @param[in] attrType RADIUS attribute type
		 * @return A RadiusAttribute object containing the first attribute data that matches this type, or logical NULL
		 * (RadiusAttribute#isNull() == true) if no such attribute found
		 */
		RadiusAttribute getAttribute(uint8_t attrType) const;

		/**
		 * @return The number of RADIUS attributes in the packet
		 */
		size_t getAttributeCount() const;

		/**
		 * Add a new RADIUS attribute at the end of the layer
		 * @param[in] attrBuilder A RadiusAttributeBuilder object that contains the requested attribute data to add
		 * @return A RadiusAttribute object containing the newly added RADIUS attribute data or logical NULL
		 * (RadiusAttribute#isNull() == true) if addition failed
		 */
		RadiusAttribute addAttribute(const RadiusAttributeBuilder& attrBuilder);

		/**
		 * Add a new RADIUS attribute after an existing one
		 * @param[in] attrBuilder A RadiusAttributeBuilder object that contains the requested attribute data to add
		 * @param[in] prevAttrType The RADIUS attribute which the newly added attribute will come after
		 * @return A RadiusAttribute object containing the newly added RADIUS attribute data or logical NULL
		 * (RadiusAttribute#isNull() == true) if addition failed
		 */
		RadiusAttribute addAttributeAfter(const RadiusAttributeBuilder& attrBuilder, uint8_t prevAttrType);

		/**
		 * Remove an existing RADIUS attribute from the layer
		 * @param[in] attrType The RADIUS attribute type to remove
		 * @return True if the RADIUS attribute was successfully removed or false if type wasn't found or if removal failed
		 */
		bool removeAttribute(uint8_t attrType);

		/**
		 * Remove all RADIUS attributes in this layer
		 * @return True if all attributes were successfully removed or false if removal failed for some reason
		 */
		bool removeAllAttributes();

		/**
		 * The static method makes validation of UDP data
		 * @param[in] udpData The pointer to the UDP payload data. It points to the first byte of RADIUS header.
		 * @param[in] udpDataLen The payload data size
		 * @return True if the data is valid and can represent the RADIUS packet
		 */
		static bool isDataValid(const uint8_t* udpData, size_t udpDataLen);

		/**
		 * A static method that checks whether the port is considered as RADIUS
		 * @param[in] port The port number to be checked
		 */
		static inline bool isRadiusPort(uint16_t port);

		// implement abstract methods

		/**
		 * @return The size written in radius_header#length
		 */
		size_t getHeaderLen() const;

		/**
		 * Does nothing for this layer, RADIUS is always last
		 */
		void parseNextLayer() {}

		/**
		 * Calculate and store the value of radius_header#length according to the layer size
		 */
		void computeCalculateFields();

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const { return OsiModelApplicationLayer; }
	};


	// implementation of inline methods

	bool RadiusLayer::isRadiusPort(uint16_t port)
	{
		switch (port)
		{
		case 1812:
		case 1813:
		case 3799:
			return true;
		default:
			return false;
		}
	} // isRadiusPort

} // namespace pcpp

#endif // PACKETPP_RADIUS_LAYER
