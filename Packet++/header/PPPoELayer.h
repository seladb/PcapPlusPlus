#ifndef PACKETPP_PPPOE_LAYER
#define PACKETPP_PPPOE_LAYER

#include <Layer.h>
#include <vector>

using namespace std;

/// @file

/**
 * @struct pppoe_header
 * Represents an PPPoE protocol header
 */
#pragma pack(push, 1)
struct pppoe_header {
#if (BYTE_ORDER == LITTLE_ENDIAN)
	/** PPPoE version */
    uint8_t version:4,
    /** PPPoE type */
            type:4;
    /** PPPoE code */
    uint8_t code;
#else
    /** PPPoE version */
    uint16_t version:4,
    /** PPPoE type */
            type:4,
    /** PPPoE code */
            code:8;
#endif
    /** PPPoE session ID (relevant for PPPoE session packets only) */
    uint16_t sessionId;
    /** Length (in bytes) of payload, not including the PPPoE header */
    uint16_t payloadLength;
};
#pragma pack(pop)


/**
 * @class PPPoELayer
 * An abstract class that describes the PPPoE protocol. Contains common data and logic of the two types of PPPoE packets: PPPoE session
 * and PPPoE discovery
 */
class PPPoELayer : public Layer
{
public:
	/**
	 * PPPoE possible codes
	 */
	enum PPPoECode
	{
		/** PPPoE session code */
		PPPOE_CODE_SESSION	= 0x00,
		/** PPPoE discovery PADO */
		PPPOE_CODE_PADO		= 0x07,
		/** PPPoE discovery PADI */
		PPPOE_CODE_PADI		= 0x09,
		/** PPPoE discovery PADG */
		PPPOE_CODE_PADG		= 0x0a,
		/** PPPoE discovery PADC */
		PPPOE_CODE_PADC		= 0x0b,
		/** PPPoE discovery PADQ */
		PPPOE_CODE_PADQ		= 0x0c,
		/** PPPoE discovery PADR */
		PPPOE_CODE_PADR		= 0x19,
		/** PPPoE discovery PADS */
		PPPOE_CODE_PADS		= 0x65,
		/** PPPoE discovery PADT */
		PPPOE_CODE_PADT		= 0xa7,
		/** PPPoE discovery PADM */
		PPPOE_CODE_PADM		= 0xd3,
		/** PPPoE discovery PADN */
		PPPOE_CODE_PADN		= 0xd4
	};

	~PPPoELayer() {}

	/**
	 * Get a pointer to the PPPoE header. Notice this points directly to the data, so every change will change the actual packet data
	 * @return A pointer to the pppoe_header
	 */
	inline pppoe_header* getPPPoEHeader() { return (pppoe_header*)m_Data; };

	// abstract methods implementation

	/**
	 * Calculate @ref pppoe_header#payloadLength field
	 */
	virtual void computeCalculateFields();

protected:

	// protected c'tor as this class shouldn't be instantiated
	PPPoELayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet) { }

	// protected c'tor as this class shouldn't be instantiated
	PPPoELayer(uint8_t version, uint8_t type, PPPoELayer::PPPoECode code, uint16_t sessionId);

};


/**
 * @class PPPoESessionLayer
 * Describes the PPPoE session protocol
 */
class PPPoESessionLayer : public PPPoELayer
{
public:

	/**
	 * A constructor that creates the layer from an existing packet raw data
	 * @param[in] data A pointer to the raw data (will be casted to @ref pppoe_header)
	 * @param[in] dataLen Size of the data in bytes
	 * @param[in] prevLayer A pointer to the previous layer
	 * @param[in] packet A pointer to the Packet instance where layer will be stored in
	 */
	PPPoESessionLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : PPPoELayer(data, dataLen, prevLayer, packet) { m_Protocol = PPPoESession; }

	/**
	 * A constructor that allocates a new PPPoE Session header with version, type and session ID
	 * @param version PPPoE version
	 * @param type PPPoE type
	 * @param sessionId PPPoE session ID
	 */
	PPPoESessionLayer(uint8_t version, uint8_t type, uint16_t sessionId) : PPPoELayer(version, type, PPPoELayer::PPPOE_CODE_SESSION, sessionId) {}

	virtual ~PPPoESessionLayer() {}

	// abstract methods implementation

	/**
	 * Currently set only PayloadLayer for the rest of the data
	 */
	virtual void parseNextLayer();

	/**
	 * @return Size of @ref pppoe_header
	 */
	virtual size_t getHeaderLen() { return sizeof(pppoe_header); }

	virtual std::string toString() { return "PPP-over-Ethernet Session"; }
};



/**
 * @class PPPoEDiscoveryLayer
 * Describes the PPPoE discovery protocol
 */
class PPPoEDiscoveryLayer : public PPPoELayer
{
public:
	/**
	 * PPPoE tag types
	 */
	enum PPPoETagTypes
	{
		/** End-Of-List tag type*/
		PPPOE_TAG_EOL		 = 0x0000,
		/** Service-Name tag type*/
		PPPOE_TAG_SVC_NAME	 = 0x0101,
		/** AC-Name tag type*/
		PPPOE_TAG_AC_NAME	 = 0x0102,
		/** Host-Uniq tag type*/
		PPPOE_TAG_HOST_UNIQ	 = 0x0103,
		/** AC-Cookie tag type*/
		PPPOE_TAG_AC_COOKIE	 = 0x0104,
		/** Vendor-Specific tag type*/
		PPPOE_TAG_VENDOR	 = 0x0105,
		/** Credits tag type*/
		PPPOE_TAG_CREDITS	 = 0x0106,
		/** Metrics tag type*/
		PPPOE_TAG_METRICS	 = 0x0107,
		/** Sequence Number tag type */
		PPPOE_TAG_SEQ_NUM	 = 0x0108,
		/** Credit Scale Factor tag type */
		PPPOE_TAG_CRED_SCALE = 0x0109,
		/** Relay-Session-Id tag type */
		PPPOE_TAG_RELAY_ID	 = 0x0110,
		/** HURL tag type */
		PPPOE_TAG_HURL		 = 0x0111,
		/** MOTM tag type */
		PPPOE_TAG_MOTM		 = 0x0112,
		/** PPP-Max-Payload tag type */
		PPPOE_TAG_MAX_PAYLD	 = 0x0120,
		/** IP_Route_Add tag type */
		PPPOE_TAG_IP_RT_ADD	 = 0x0121,
		/** Service-Name-Error tag type */
		PPPOE_TAG_SVC_ERR	 = 0x0201,
		/** AC-System-Error tag type */
		PPPOE_TAG_AC_ERR	 = 0x0202,
		/** Generic-Error tag type */
		PPPOE_TAG_GENERIC_ERR= 0x0203
	};

	/**
	 * @struct PPPoETag
	 * Represents a PPPoE tag and its data
	 */
	struct PPPoETag
	{
	public:

		/** The type of the data, can be converted to PPPoEDiscoveryLayer#PPPoETagTypes enum (or use getType()) */
		uint16_t tagType;
		/** The length of the tag data */
		uint16_t tagDataLength;
		/** A pointer to the tag data. It's recommended to use getTagDataAs() to retrieve the tag data or setTagData() to set tag data */
		uint8_t	 tagData[];

		/**
		 * A templated method to retrieve the tag data as a certain type T. For example, if tag data is 4B (integer) then this method
		 * should be used as getTagDataAs<int>() and it will return the tag data as integer.<BR>
		 * Notice this return value is a copy of the data, not a pointer to the actual data
		 * @param tagDataOffset An optional parameter that specifies where to start copy the tag data. For example: if tag data is 20 bytes
		 * and you need only the 4 last bytes as integer then use this method like this: getTagDataAs<int>(16). The default is 0 - start copy
		 * from the beginning of tag data
		 * @return The tag data as type T
		 */
		template<typename T>
		T getTagDataAs(int tagDataOffset = 0)
		{
			T result;
			memcpy(&result, tagData+tagDataOffset, sizeof(T));
			return result;
		}

		/**
		 * A templated method to copy data of type T into the tag data. For example: if tag data is 4[Bytes] long use this method like
		 * this to set an integer "num" into tag data: setTagData<int>(num)
		 * @param value The value of type T to copy to tag data
		 * @param tagDataOffset An optional parameter that specifies where to start set the tag data. For example: if tag data is 20 bytes
		 * and you only need to set the 4 last bytes as integer then use this method like this: setTagDataAs<int>(num, 16).
		 * The default is 0 - start copy to the beginning of tag data
		 */
		template<typename T>
		void setTagData(T value, int tagDataOffset = 0)
		{
			memcpy(tagData+tagDataOffset, &value, sizeof(T));
		}

		/**
		 * @return The total size in bytes of this tag which includes: 2[Bytes] (tag name) + 2[Bytes] (tag length) + X[Bytes] (tag data length)
		 */
		size_t getTagTotalSize() const;

		/**
		 * @return The tag type converted to PPPoEDiscoveryLayer#PPPoETagTypes enum
		 */
		PPPoEDiscoveryLayer::PPPoETagTypes getType();
	private:
		// private c'tor which isn't implemented to make this struct impossible to construct
		PPPoETag();
	};

	/**
	 * A constructor that creates the layer from an existing packet raw data
	 * @param[in] data A pointer to the raw data (will be casted to @ref pppoe_header)
	 * @param[in] dataLen Size of the data in bytes
	 * @param[in] prevLayer A pointer to the previous layer
	 * @param[in] packet A pointer to the Packet instance where layer will be stored in
	 */
	PPPoEDiscoveryLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : PPPoELayer(data, dataLen, prevLayer, packet) { m_Protocol = PPPoEDiscovery; m_TagCount = -1; }

	/**
	 * A constructor that allocates a new PPPoE Discovery header with version, type, PPPoE code and session ID
	 * @param version PPPoE version
	 * @param type PPPoE type
	 * @param code PPPoE code enum
	 * @param sessionId PPPoE session ID
	 */
	PPPoEDiscoveryLayer(uint8_t version, uint8_t type, PPPoELayer::PPPoECode code, uint16_t sessionId) : PPPoELayer(version, type, code, sessionId) { m_Protocol = PPPoEDiscovery; m_TagCount = -1; }

	/**
	 * Retrieve a PPPoE tag by tag type. If packet consists of multiple tags of the same type, the first tag will be returned. If packet contains
	 * no tags of the tag type NULL will be returned. Notice the return value is a pointer to the real data casted to PPPoETag type (as opposed
	 * to a copy of the tag data). So changes in the return value will affect the packet data
	 * @param tagType The type of the tag to search
	 * @return A pointer to the tag data casted to PPPoETag*
	 */
	PPPoETag* getTag(PPPoEDiscoveryLayer::PPPoETagTypes tagType);

	/**
	 * @return The first tag in the PPPoE discovery layer, or NULL if no tags exist. Notice the return value is a pointer to the real data casted to PPPoETag type (as opposed
	 * to a copy of the tag data). So changes in the return value will affect the packet data
	 */
	PPPoETag* getFirstTag();

	/**
	 * Get the tag which come next to "tag" parameter. If "tag" is NULL or then NULL will be returned. If "tag" is the last tag NULL will be
	 * returned. Notice the return value is a pointer to the real data casted to PPPoETag type (as opposed to a copy of the tag data).
	 * So changes in the return value will affect the packet data
	 * @param tag The tag to start search
	 * @return The next tag or NULL if "tag" is NULL or "tag" is the last tag
	 */
	PPPoETag* getNextTag(PPPoETag* tag);

	/**
	 * @return The number of tags in this layer
	 */
	int getTagCount();

	/**
	 * Add a new tag at the end of the layer (after the last tag)
	 * @param tagType The type of the added tag
	 * @param tagLength The length of the tag data
	 * @param tagData A pointer to the tag data. This data will be copied to added tag data. Notice the length of tagData must be tagLength
	 * @return A pointer to the new added tag. Notice this is a pointer to the real data casted to PPPoETag type (as opposed to a copy of
	 * the tag data). So changes in this return value will affect the packet data
	 */
	PPPoETag* addTag(PPPoETagTypes tagType, uint16_t tagLength, const uint8_t* tagData);

	/**
	 * Add a new tag after an existing tag
	 * @param tagType The type of the added tag
	 * @param tagLength The length of the tag data
	 * @param tagData A pointer to the tag data. This data will be copied to added tag data. Notice the length of tagData must be tagLength
	 * @param prevTag The tag which the new added tag will come after
	 * @return A pointer to the new added tag. Notice this is a pointer to the real data casted to PPPoETag type (as opposed to a copy of
	 * the tag data). So changes in this return value will affect the packet data
	 */
	PPPoETag* addTagAfter(PPPoETagTypes tagType, uint16_t tagLength, const uint8_t* tagData, PPPoETag* prevTag);

	/**
	 * Remove an existing tag. Tag will be found by the tag type
	 * @param tagType The tag type to remove
	 * @return True if tag was removed or false if tag wasn't found or if tag removal failed (in each case a proper error will be written
	 * to log)
	 */
	bool removeTag(PPPoEDiscoveryLayer::PPPoETagTypes tagType);

	/**
	 * Remove all tags in this layer
	 * @return True if all tags were successfully or false if removal failed for some reason (a proper error will be written to log)
	 */
	bool removeAllTags();

	// abstract methods implementation

	/**
	 * Does nothing for this layer (PPPoE discovery is always the last layer)
	 */
	virtual void parseNextLayer() {};

	/**
	 * @return The header length which is size of strcut pppoe_header plus the total size of tags
	 */
	virtual size_t getHeaderLen();

	virtual std::string toString() { return "PPP-over-Ethernet Discovery (" + codeToString((PPPoELayer::PPPoECode)getPPPoEHeader()->code) + ")"; }

private:
	int m_TagCount;

	PPPoETag* addTagAt(PPPoETagTypes tagType, uint16_t tagLength, const uint8_t* tagData, int offset);

	PPPoETag* castPtrToPPPoETag(uint8_t* ptr);

	std::string codeToString(PPPoECode code);
};

#endif /* PACKETPP_PPPOE_LAYER */
