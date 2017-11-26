#ifndef PACKETPP_GRE_LAYER
#define PACKETPP_GRE_LAYER

#include "Layer.h"

/// @file


/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * @struct gre_basic_header
	 * Represents GRE basic protocol header (common for GREv0 and GREv1)
	 */
#pragma pack(push, 1)
	struct gre_basic_header
	{
#if (BYTE_ORDER == LITTLE_ENDIAN)
		/** Number of additional encapsulations which are permitted. 0 is the default value */
		uint8_t recursionControl:3,
		/** Strict source routing bit (GRE v0 only) */
				strictSourceRouteBit:1,
		/** Set if sequence number exists */
				sequenceNumBit:1,
		/** Set if key exists */
				keyBit:1,
		/** Set if routing exists (GRE v0 only) */
				routingBit:1,
		/** Set if checksum exists (GRE v0 only) */
				checksumBit:1;
#else
		/** Set if checksum exists (GRE v0 only) */
		uint8_t checksumBit:1,
		/** Set if routing exists (GRE v0 only) */
				routingBit:1,
		/** Set if key exists */
				keyBit:1,
		/** Set if sequence number exists */
				sequenceNumBit:1,
		/** Strict source routing bit (GRE v0 only) */
				strictSourceRouteBit:1,
		/** Number of additional encapsulations which are permitted. 0 is the default value */
				recursionControl:3;
#endif
#if (BYTE_ORDER == LITTLE_ENDIAN)
		/** GRE version - can be 0 or 1 */
		uint8_t version:3,
		/** Reserved */
				flags:4,
		/** Set if acknowledgment number is set (GRE v1 only) */
				ackSequenceNumBit:1;
#else
		/** Set if acknowledgment number is set (GRE v1 only) */
		uint8_t ackSequenceNumBit:1,
		/** Reserved */
				flags:4,
		/** GRE version - can be 0 or 1 */
				version:3;
#endif

		/** Protocol type of the next layer */
		uint16_t protocol;
	};
#pragma pack(pop)


	/**
	 * @struct gre1_header
	 * Represents GREv1 protocol header
	 */
#pragma pack(push, 1)
	struct gre1_header : gre_basic_header
	{
		/** Size of the payload not including the GRE header */
		uint16_t payloadLength;
		/** Contains the Peer's Call ID for the session to which this packet belongs */
		uint16_t callID;
	};
#pragma pack(pop)


	/**
	 * @struct ppp_pptp_header
	 * Represents PPP layer that comes after GREv1 as part of PPTP protocol
	 */
#pragma pack(push, 1)
	struct ppp_pptp_header
	{
		/** Broadcast address */
		uint8_t address;
		/** Control byte */
		uint8_t control;
		/** Protocol type of the next layer (see PPP_* macros at PPPoELayer.h) */
		uint16_t protocol;
	};
#pragma pack(pop)


	/**
	 * @class GreLayer
	 * Abstract base class for GRE layers (GREv0Layer and GREv1Layer). Cannot be instantiated and contains common logic for derived classes
	 */
	class GreLayer : public Layer
	{
	public:

		virtual ~GreLayer() {}

		/**
		 * A static method that determines the GRE version of GRE layer raw data by looking at the gre_basic_header#version
		 * field
		 * @param[in] greData GRE layer raw data
		 * @param[in] greDataLen Size of raw data
		 * @return ::GREv0 or ::GREv1 values if raw data is GREv0 or GREv1 (accordingly) or ::UnknownProtocol otherwise
		 */
		static ProtocolType getGREVersion(uint8_t* greData, size_t greDataLen);

		/**
		 * Get sequence number value if field exists in layer
		 * @param[out] seqNumber The returned sequence number value if exists in layer. Else remain unchanged
		 * @return True if sequence number field exists in layer. In this case seqNumber will be filled with the value.
		 * Or false if sequence number field doesn't exist in layer
		 */
		bool getSequenceNumber(uint32_t& seqNumber);

		/**
		 * Set sequence number value. If field already exists (gre_basic_header#sequenceNumBit is set) then only the new
		 * value is set. If field doesn't exist it will be added to the layer, gre_basic_header#sequenceNumBit will be set
		 * and the new value will be set
		 * @param[in] seqNumber The sequence number value to set
		 * @return True if managed to set the value successfully, or false otherwise (if couldn't extend the layer)
		 */
		bool setSequenceNumber(uint32_t seqNumber);

		/**
		 * Unset sequence number and remove it from the layer
		 * @return True if managed to unset successfully or false (and error log) if sequence number wasn't set in the first
		 * place or if didn't manage to remove it from the layer
		 */
		bool unsetSequenceNumber();


		// implement abstract methods

		/**
		 * Currently identifies the following next layers: IPv4Layer, IPv6Layer, VlanLayer, MplsLayer and PPP_PPTPLayer.
		 * Otherwise sets PayloadLayer
		 */
		void parseNextLayer();

		/**
		 * @return Size of GRE header (may change if optional fields are added or removed)
		 */
		size_t getHeaderLen();

		OsiModelLayer getOsiModelLayer() { return OsiModelNetworkLayer; }

	protected:
		GreLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet) { }

		GreLayer() {}

		enum GreField
		{
			GreChecksumOrRouting = 0,
			GreKey = 1,
			GreSeq = 2,
			GreAck = 3
		};

		uint8_t* getFieldValue(GreField field, bool returnOffsetEvenIfFieldMissing);

		void computeCalculateFieldsInner();
	};


	/**
	 * @class GREv0Layer
	 * Represents a GRE version 0 protocol. Limitation: currently this layer doesn't support GRE routing information parsing
	 * and editing. So if a GREv0 packet includes routing information it won't be parse correctly. I didn't add it because
	 * of lack of time, but if you need it please tell me and I'll add it
	 */
	class GREv0Layer : public GreLayer
	{
	public:

		 /** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		GREv0Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : GreLayer(data, dataLen, prevLayer, packet) { m_Protocol = GREv0; }

		/**
		 * A constructor that creates a new GREv0 header and allocates the data
		 */
		GREv0Layer();

		virtual ~GREv0Layer() {}

		/**
		 * Get a pointer to the basic GRE header containing only non-optional fields. Notice this points directly to the data,
		 * so every change will change the actual packet data. Also please notice that changing the set bits
		 * (gre_basic_header#strictSourceRouteBit, gre_basic_header#sequenceNumBit, gre_basic_header#keyBit, gre_basic_header#routingBit,
		 * gre_basic_header#checksumBit, gre_basic_header#ackSequenceNumBit) without using the proper set or unset methods (such
		 * as setChecksum(), unsetChecksum(), etc.) may result to wrong calculation of header length and really weird bugs.
		 * Please avoid doing so
		 * @return A pointer to the gre_basic_header
		 */
		inline gre_basic_header* getGreHeader() { return (gre_basic_header*)m_Data; }

		/**
		 * Get checksum value if field exists in layer
		 * @param[out] checksum The returned checksum value if exists in layer. Else remain unchanged
		 * @return True if checksum field exists in layer. In this case checksum parameter will be filled with the value.
		 * Or false if checksum field doesn't exist in layer
		 */
		bool getChecksum(uint16_t& checksum);

		/**
		 * Set checksum value. If checksum or offset fields already exist (gre_basic_header#checksumBit or gre_basic_header#routingBit are set)
		 * then only the new value is set. If both fields don't exist a new 4-byte value will be added to the layer,
		 * gre_basic_header#checksumBit will be set (gre_basic_header#routingBit will remain unset), the new checksum value
		 * will be set and offset value will be set to 0. The reason both fields are added is that GREv0 protocol states
		 * both of them or none of them should exist on packet (even if only one of the bits are set)
		 * @param[in] checksum The checksum value to set
		 * @return True if managed to set the value/s successfully, or false otherwise (if couldn't extend the layer)
		 */
		bool setChecksum(uint16_t checksum);

		/**
		 * Unset checksum and possibly remove it from the layer. It will be removed from the layer only if gre_basic_header#routingBit
		 * is not set as well. Otherwise checksum field will remain on packet with value of 0
		 * @return True if managed to unset successfully or false (and error log) if checksum wasn't set in the first
		 * place or if didn't manage to remove it from the layer
		 */
		bool unsetChecksum();

		/**
		 * Get offset value if field exists in layer. Notice there is no setOffset() method as GRE routing information isn't
		 * supported yet (see comment on class description)
		 * @param[out] offset The returned offset value if exists in layer. Else remain unchanged
		 * @return True if offset field exists in layer. In this case offset parameter will be filled with the value.
		 * Or false if offset field doesn't exist in layer
		 */
		bool getOffset(uint16_t& offset);

		/**
		 * Get key value if field exists in layer
		 * @param[out] key The returned key value if exists in layer. Else remain unchanged
		 * @return True if key field exists in layer. In this case key parameter will be filled with the value.
		 * Or false if key field doesn't exist in layer
		 */
		bool getKey(uint32_t& key);

		/**
		 * Set key value. If field already exists (gre_basic_header#keyBit is set) then only the new value is set.
		 * If field doesn't exist it will be added to the layer, gre_basic_header#keyBit will be set
		 * and the new value will be set
		 * @param[in] key The key value to set
		 * @return True if managed to set the value successfully, or false otherwise (if couldn't extend the layer)
		 */
		bool setKey(uint32_t key);

		/**
		 * Unset key and remove it from the layer
		 * @return True if managed to unset successfully or false (and error log) if key wasn't set in the first
		 * place or if didn't manage to remove it from the layer
		 */
		bool unsetKey();


		// implement abstract methods


		/**
		 * Calculate the following fields:
		 * - gre_basic_header#protocol
		 * - GRE checksum field (if exists in packet)
		 */
		void computeCalculateFields();

		std::string toString();

	};


	/**
	 * @class GREv1Layer
	 * Represents a GRE version 1 protocol
	 */
	class GREv1Layer : public GreLayer
	{
	public:

		 /** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		GREv1Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : GreLayer(data, dataLen, prevLayer, packet) { m_Protocol = GREv1; }

		/**
		 * A constructor that creates a new GREv1 header and allocates the data
		 * @param[in] callID The call ID to set
		 */
		GREv1Layer(uint16_t callID);

		virtual ~GREv1Layer() {}

		/**
		 * Get a pointer to the basic GREv1 header containing all non-optional fields. Notice this points directly to the data, so every change will change the actual
		 * packet data. Also please notice that changing the set bits (gre_basic_header#strictSourceRouteBit, gre_basic_header#sequenceNumBit, gre_basic_header#keyBit,
		 * gre_basic_header#routingBit, gre_basic_header#checksumBit, gre_basic_header#ackSequenceNumBit) without using the proper set or unset methods
		 * (such as setAcknowledgmentNum(), unsetSequenceNumber(), etc.) may result to wrong calculation of header length or illegal GREv1 packet and
		 * to some really weird bugs. Please avoid doing so
		 * @return A pointer to the gre1_header
		 */
		inline gre1_header* getGreHeader() { return (gre1_header*)m_Data; }

		/**
		 * Get acknowledgment (ack) number value if field exists in layer
		 * @param[out] ackNum The returned ack number value if exists in layer. Else remain unchanged
		 * @return True if ack number field exists in layer. In this case ackNum will be filled with the value.
		 * Or false if ack number field doesn't exist in layer
		 */
		bool getAcknowledgmentNum(uint32_t& ackNum);

		/**
		 * Set acknowledgment (ack) number value. If field already exists (gre_basic_header#ackSequenceNumBit is set)
		 * then only the new value is set. If field doesn't exist it will be added to the layer,
		 * gre_basic_header#ackSequenceNumBit will be set and the new value will be set
		 * @param[in] ackNum The ack number value to set
		 * @return True if managed to set the value successfully, or false otherwise (if couldn't extend the layer)
		 */
		bool setAcknowledgmentNum(uint32_t ackNum);

		/**
		 * Unset acknowledgment (ack) number and remove it from the layer
		 * @return True if managed to unset successfully or false (and error log) if ack number wasn't set in the first
		 * place or if didn't manage to remove it from the layer
		 */
		bool unsetAcknowledgmentNum();


		// implement abstract methods

		/**
		 * Calculate the following fields:
		 * - gre1_header#payloadLength
		 * - gre_basic_header#protocol
		 */
		void computeCalculateFields();

		std::string toString();

	};


	/**
	 * @class PPP_PPTPLayer
	 * Represent a PPP (point-to-point) protocol header that comes after GREv1 header, as part of PPTP - Point-to-Point Tunneling Protocol
	 */
	class PPP_PPTPLayer : public Layer
	{
	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to @ref ppp_pptp_header)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		PPP_PPTPLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet) { m_Protocol = PPP_PPTP; }

		/**
		 * A constructor that allocates a new PPP-PPTP header
		 * @param[in] address Address field
		 * @param[in] control Control field
		 */
		PPP_PPTPLayer(uint8_t address, uint8_t control);

		~PPP_PPTPLayer() {}

		/**
		 * Get a pointer to the PPP-PPTP header. Notice this points directly to the data, so every change will change the actual packet data
		 * @return A pointer to the @ref ppp_pptp_header
		 */
		inline ppp_pptp_header* getPPP_PPTPHeader() { return (ppp_pptp_header*)m_Data; };


		// implement abstract methods

		/**
		 * Currently identifies the following next layers: IPv4Layer, IPv6Layer. Otherwise sets PayloadLayer
		 */
		void parseNextLayer();

		/**
		 * @return The size of @ref ppp_pptp_header
		 */
		inline size_t getHeaderLen() { return sizeof(ppp_pptp_header); }

		/**
		 * Calculate the following fields:
		 * - ppp_pptp_header#protocol
		 */
		void computeCalculateFields();

		std::string toString() { return "PPP for PPTP Layer"; }

		OsiModelLayer getOsiModelLayer() { return OsiModelSesionLayer; }

	};

} // namespace pcpp

#endif /* PACKETPP_GRE_LAYER */
