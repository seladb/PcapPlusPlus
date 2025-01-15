#pragma once

#include <vector>
#include <unordered_map>
#include "Layer.h"
#include "IpAddress.h"
#include "MacAddress.h"
#include "Logger.h"
#include "GeneralUtils.h"
#include "DoIpLayerData.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
	/**
	 * @struct doiphdr
	 * Represents an DoIP protocol header
	 */
#pragma pack(push, 1)
	struct doiphdr
	{
		/** DoIP version (DOIPV) */
		uint8_t protocolVersion;
		/** DoIP invert version (DOIPIV). Inverse of protocol version */
		uint8_t invertProtocolVersion;
		/** DoIP payload type (DOIPT)*/
		uint16_t payloadType;
		/** DoIP content payload length (DOIPL)*/
		uint32_t payloadLength;
	};
#pragma pack(pop)

	/**
	 * @class DoIpLayer
	 * Represents an DoIP protocol layer. Currently only IPv4 DoIP messages are supported
	 */
	class DoIpLayer : public Layer
	{
		// class DoIpLayerData;
	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to @ref doiphdr)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		DoIpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, DOIP)
		{}

		/**
		 * A constructor that creates an generic doip layer and set header and payload fields
		 * @param[in] Fields DoIpMessageFields contains all doipMessage specification based on its payload type
		 */
		DoIpLayer(DoIpProtocolVersion version, DoIpPayloadTypes type, const IDoIpMessageData* data = nullptr);

		/**
		 * A constructor that create a doip announcement message with all
		 * zeros for vin, eid, gid and no further action required
		 */
		DoIpLayer();

		/**
		 * init doip layer with all zeros with size  of doip header
		 */
		void initLayer();

		/**
		 * A destructor for DoIpLayer class
		 */
		~DoIpLayer() override {};

		/**
		 * Get a pointer to the DoIP header. Notice this points directly to the data, so every change will change the
		 * actual packet data
		 * @return A pointer to the @ref doiphdr
		 */
		doiphdr* getDoIpHeader() const
		{
			return reinterpret_cast<doiphdr*>(m_Data);
		}
		/**
		 * Check the integrity of protocol version in doip header
		 * @return true if version has no integration errors
		 */
		bool resolveProtocolVersion() const;

		/**
		 * Check the integrity of length field in doip header
		 * @return true if length represent the exact payload arg struct size
		 */
		bool resolvePayloadLength() const;

		/**
		 * Get the version of DOIP protocol
		 * @return DoIpProtocolVersion presenting the used protocol version (DOIPV)
		 */
		DoIpProtocolVersion getProtocolVersion() const;

		/**
		 * Get the version of DOIP protocol
		 * @return string presentation the used protocol version (DOIPV)
		 */
		std::string getProtocolVersionAsStr() const;

		/**
		 * Set the version of DOIP protocol
		 * @param[in] version the version of DOIP protocol to set, restricted to existent doip version
		 */
		void setProtocolVersion(DoIpProtocolVersion version);

		/**
		 * Get the invert version of DOIP protocol
		 * @return A uint8_t presenting the used protocol invert version (DOIPV)
		 */
		uint8_t getInvertProtocolVersion() const;

		/**
		 * Set the invert protocol version of DOIP protocol
		 * @param[in] version the invert version of DOIP protocol to set
		 */
		void setInvertProtocolVersion(uint8_t iVersion);

		/**
		 * Get the doip payload type
		 * @return DoIpPayloadTypes presenting the message doip payload type
		 */
		DoIpPayloadTypes getPayloadType() const;

		/**
		 * Get the doip payload type as string
		 * @return uint16_t presenting the message doip payload type as string
		 */
		std::string getPayloadTypeAsStr() const;

		/**
		 * Set the doip payload type
		 * @param[in] payloadType the payload type to set
		 */
		void setPayloadType(DoIpPayloadTypes payloadType);

		/**
		 * Get the doip payload length
		 * @return uint32_t presenting the length of doip paylad not including the header
		 */
		uint32_t getPayloadLength() const;

		/**
		 * Set the doip payload length
		 * @param[in] length the doip payload length to set
		 */
		void setPayloadength(uint32_t length);

		/**
		 * copy data from msgFields to dest
		 * @param[in] dest pointer to where start copying
		 * @param[in] msgFields the doip Fields to copy
		 */
		void serializeData(uint8_t* dest, std::vector<uint8_t> data);

		/**
		 * A static method that checks whether a port is considered as a DOIP port
		 * @param[in] port The port number to check
		 * @return True if this is a DOIP port number, false otherwise
		 */
		static inline bool isDoIpPort(uint16_t port);

		/**
		 * A static method that validates the input data
		 * @param[in] data The pointer to the beginning of a byte stream of an DOIP layer
		 * @param[in] dataLen The length of the byte stream
		 * @return True if the data is valid and can represent an DOIP layer
		 */
		static inline bool isDataValid(const uint8_t* data, size_t dataLen);

		/**
		 * @brief Builds the DoIP layer based on the payload type and provided data.
		 *
		 * This function configures the DoIP layer with the appropriate payload type, payload length,
		 * and data, depending on the specified payload type. If the payload type does not require
		 * additional data, the payload length is set to zero. For payloads that require data, the data
		 * is serialized and added to the layer.
		 *
		 * @param type The DoIP payload type to set for this layer.
		 * @param data Pointer to the message data (of type IDoIpMessageData) to be serialized into the layer.
		 *             This parameter can be nullptr for payload types that do not require additional data.
		 *
		 * @note If the payload type requires data and the `data` parameter is `nullptr`, an error message
		 *       is logged, and the function does not build the layer.
		 */
		void buildLayer(DoIpPayloadTypes type, const IDoIpMessageData* data = nullptr);

		/**
		 * @brief Resolves and validates the DoIP layer.
		 *
		 * This function validates the protocol version and payload length of the DoIP layer.
		 * If either validation fails, an error is logged, and the function returns `false`.
		 *
		 * @return `true` if both the protocol version and payload length are valid;
		 *         otherwise, `false`.
		 *
		 * @note This function is typically used to ensure the integrity of the DoIP layer
		 *       before further processing or transmission.
		 */
		bool resolveLayer() const;

		// implement abstract methods

		/**
		 * TODO, parse UDS layer
		 */
		void parseNextLayer() override
		{}

		/**
		 * @return The size of @ref doiphdr + attached fields length
		 */
		size_t getHeaderLen() const override
		{
			return m_DataLen;
		}

		std::string toString() const override;

		void computeCalculateFields() override {};

		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelTransportLayer;
		}
	};

	// inline methods definition
	inline bool DoIpLayer::isDoIpPort(uint16_t port)
	{
		return ((DoIpPorts)port == DoIpPorts::UDP_PORT || (DoIpPorts)port == DoIpPorts::TCP_PORT ||
		        (DoIpPorts)port == DoIpPorts::TLS_PORT);
	}

	inline bool DoIpLayer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		return (data && dataLen >= sizeof(doiphdr));
	}
}  // namespace pcpp
