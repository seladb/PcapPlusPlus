#define LOG_MODULE PacketLogModuleBgpLayer

#include <numeric>

#include "Logger.h"
#include "BgpLayer.h"
#include "EndianPortable.h"
#include "GeneralUtils.h"

namespace pcpp
{
	// ~~~~~~~~
	// BgpLayer
	// ~~~~~~~~

	size_t BgpLayer::getHeaderLen() const
	{
		if (m_DataLen < sizeof(bgp_common_header))
		{
			return m_DataLen;
		}

		uint16_t messageLen = be16toh(getBasicHeader()->length);
		if (m_DataLen < messageLen)
		{
			return m_DataLen;
		}

		return (size_t)messageLen;
	}

	BgpLayer* BgpLayer::parseBgpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	{
		if (data == nullptr || dataLen < sizeof(bgp_common_header))
			return nullptr;

		bgp_common_header* bgpHeader = (bgp_common_header*)data;

		// illegal header data - length is too small
		uint16_t messageLen = be16toh(bgpHeader->length);
		if (dataLen < messageLen || messageLen < static_cast<uint16_t>(sizeof(bgp_common_header)))
			return nullptr;

		switch (bgpHeader->messageType)
		{
		case 1:  // OPEN
			return new BgpOpenMessageLayer(data, dataLen, prevLayer, packet);
		case 2:  // UPDATE
			return BgpUpdateMessageLayer::isDataValid(data, dataLen)
			           ? new BgpUpdateMessageLayer(data, dataLen, prevLayer, packet)
			           : nullptr;
		case 3:  // NOTIFICATION
			return new BgpNotificationMessageLayer(data, dataLen, prevLayer, packet);
		case 4:  // KEEPALIVE
			return new BgpKeepaliveMessageLayer(data, dataLen, prevLayer, packet);
		case 5:  // ROUTE-REFRESH
			return new BgpRouteRefreshMessageLayer(data, dataLen, prevLayer, packet);
		default:
			return nullptr;
		}
	}

	std::string BgpLayer::getMessageTypeAsString() const
	{
		switch (getBgpMessageType())
		{
		case BgpLayer::Open:
			return "OPEN";
		case BgpLayer::Update:
			return "UPDATE";
		case BgpLayer::Notification:
			return "NOTIFICATION";
		case BgpLayer::Keepalive:
			return "KEEPALIVE";
		case BgpLayer::RouteRefresh:
			return "ROUTE-REFRESH";
		default:
			return "Unknown";
		}
	}

	void BgpLayer::parseNextLayer()
	{
		size_t headerLen = getHeaderLen();
		if (m_DataLen <= headerLen || headerLen == 0)
			return;

		uint8_t* payload = m_Data + headerLen;
		size_t payloadLen = m_DataLen - headerLen;

		m_NextLayer = BgpLayer::parseBgpLayer(payload, payloadLen, this, m_Packet);
	}

	std::string BgpLayer::toString() const
	{
		return "BGP Layer, " + getMessageTypeAsString() + " message";
	}

	void BgpLayer::computeCalculateFields()
	{
		bgp_common_header* bgpHeader = getBasicHeader();
		memset(bgpHeader->marker, 0xff, 16 * sizeof(uint8_t));
		bgpHeader->messageType = (uint8_t)getBgpMessageType();
		bgpHeader->length = htobe16(getHeaderLen());
	}

	void BgpLayer::setBgpFields(size_t messageLen)
	{
		bgp_common_header* bgpHdr = getBasicHeader();
		memset(bgpHdr->marker, 0xff, 16 * sizeof(uint8_t));
		bgpHdr->messageType = (uint8_t)getBgpMessageType();
		if (messageLen != 0)
		{
			bgpHdr->length = htobe16((uint16_t)messageLen);
		}
		else
		{
			bgpHdr->length = m_DataLen;
		}
	}

	uint16_t BgpBasicHeaderConstView::getBgpLength() const
	{
		return be16toh(m_Layer.getBasicHeader()->length);
	}

	uint16_t BgpBasicHeaderView::getBgpLength() const
	{
		return be16toh(m_Layer.getBasicHeader()->length);
	}

	void BgpBasicHeaderView::setBgpLength(uint16_t length)
	{
		m_Layer.getBasicHeader()->length = htobe16(length);
	}

	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	// BgpOpenMessageView + BgpOpenMessageConstView
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	namespace
	{
		/// @brief Helper methods related to BGP OPEN messages
		namespace open
		{
			/// @brief Reads BGP Open message Optional parameters from a bytes buffer
			/// @param buffer Pointer to the buffer containing the BGP Open message optional parameters pack.
			/// @param bufferLen Length of the buffer in bytes
			/// @param outOptionalParameters Vector to store the parsed optional parameters
			/// @return True if the optional parameters were read successfully, false otherwise
			bool readOptionalParamsFromBuffer(
			    uint8_t const* buffer, size_t bufferLen,
			    std::vector<BgpOpenMessageConstView::OptionalParameter>& outOptionalParameters)
			{
				if (buffer == nullptr)
					throw std::invalid_argument("Buffer is null");

				size_t offset = 0;
				while (offset + 2 <= bufferLen)
				{
					BgpOpenMessageConstView::OptionalParameter param;
					param.type = buffer[offset];
					param.length = buffer[offset + 1];

					if (param.length > 0)
					{
						if (param.length > 32)
						{
							PCPP_LOG_ERROR("Illegal optional parameter length " << (int)param.length
							                                                    << ", must be 32 bytes or less");
							return false;
						}

						if (offset + 2 + param.length > bufferLen)
						{
							PCPP_LOG_ERROR("Illegal optional parameter length " << (int)param.length
							                                                    << ", buffer is too small");
							return false;
						}

						memcpy(param.value.data(), buffer + offset + 2, param.length);
					}

					outOptionalParameters.push_back(param);
					offset += 2 + param.length;
				}

				return true;
			}

			/// @brief Writes BGP Open message Optional parameters to a bytes buffer
			///
			/// This functions supports querying the required buffer size by passing a null pointer as the output
			/// buffer and zero length. In this case, the function will return the required size without writing any
			/// data.
			///
			/// @param opParams Vector of optional parameters to write
			/// @param outBuffer Pointer to the buffer where the optional parameters will be written
			/// @param outBufferLen Length of the output buffer in bytes
			/// @return The number of bytes written to the buffer, or the required buffer size if insufficient.
			size_t writeOptionalParamsToBuffer(std::vector<BgpOpenMessageConstView::OptionalParameter> const& opParams,
			                                   uint8_t* outBuffer, size_t outBufferLen)
			{
				auto sumLength = [](size_t sum, BgpOpenMessageConstView::OptionalParameter const& param) {
					// Check for illegal parameter length
					if (param.length > 32)
						throw std::invalid_argument("Illegal optional parameter length " +
						                            std::to_string(param.length) + ", must be 32 bytes or less");

					return sum + 2 + param.length;
				};

				const size_t requiredBytes = std::accumulate(opParams.begin(), opParams.end(), 0, sumLength);

				if (outBuffer == nullptr)
				{
					if (outBufferLen == 0)
					{
						// Query mode - calculate required buffer
						return requiredBytes;
					}

					throw std::invalid_argument("Buffer is nullptr");
				}

				if (outBufferLen < requiredBytes)
				{
					return requiredBytes;
				}

				for (auto const& param : opParams)
				{
					outBuffer[0] = param.type;
					outBuffer[1] = param.length;
					if (param.length > 0)
					{
						std::copy(param.value.begin(), param.value.begin() + param.length, outBuffer + 2);
					}
					outBuffer += 2 + param.length;
				}

				return requiredBytes;
			}
		}  // namespace open
	}  // namespace

	BgpOpenMessageConstView::BgpOpenMessageConstView(BgpLayer const& layer) : BgpBasicHeaderConstView(layer)
	{
		if (m_Layer.getBgpMessageType() != BgpLayer::BgpMessageType::Open)
			throw std::invalid_argument("Layer is not a BGP OPEN message");
		if (m_Layer.getHeaderLen() < sizeof(bgp_open_message))
			throw std::invalid_argument("Data length is smaller than BGP OPEN message header size");
		if (m_Layer.getHeaderLen() < sizeof(bgp_open_message) + getOptionalPrametersLength())
			throw std::invalid_argument(
			    "Data length is smaller than BGP OPEN message header size + optional parameter length");
	}

	size_t BgpOpenMessageConstView::getOptionalPrametersLength() const
	{
		// Optional param length is 1 byte. Endianness shouldn't matter;
		static_assert(sizeof(bgp_open_message::optionalParameterLength) == 1, "Optional param length must be 1 byte");
		return getOpenMsgHeader()->optionalParameterLength;
	}

	std::vector<BgpOpenMessageConstView::OptionalParameter> BgpOpenMessageConstView::getOptionalParameters() const
	{
		std::vector<BgpOpenMessageConstView::OptionalParameter> result;
		getOptionalParameters(result);
		return result;
	}

	void BgpOpenMessageConstView::getOptionalParameters(std::vector<OptionalParameter>& outOptionalParameters) const
	{
		size_t const optionalParamsLen = getOptionalPrametersLength();
		if (optionalParamsLen == 0)
			return;

		uint8_t const* optionalParamsData = m_Layer.getData() + sizeof(bgp_open_message);
		open::readOptionalParamsFromBuffer(optionalParamsData, optionalParamsLen, outOptionalParameters);
	}

	BgpOpenMessageView::BgpOpenMessageView(BgpLayer& layer) : BgpBasicHeaderView(layer)
	{
		if (m_Layer.getBgpMessageType() != BgpLayer::BgpMessageType::Open)
			throw std::invalid_argument("Layer is not a BGP OPEN message");
		if (m_Layer.getHeaderLen() < sizeof(bgp_open_message))
			throw std::invalid_argument("Data length is smaller than BGP OPEN message header size");
		if (m_Layer.getHeaderLen() < sizeof(bgp_open_message) + getOptionalPrametersLength())
			throw std::invalid_argument(
			    "Data length is smaller than BGP OPEN message header size + optional parameter length");
	}

	size_t BgpOpenMessageView::getOptionalPrametersLength() const
	{
		return BgpOpenMessageConstView(internal::nocheck, m_Layer).getOptionalPrametersLength();
	}

	std::vector<BgpOpenMessageView::OptionalParameter> BgpOpenMessageView::getOptionalParameters() const
	{
		return BgpOpenMessageConstView(internal::nocheck, m_Layer).getOptionalParameters();
	}

	void BgpOpenMessageView::getOptionalParameters(std::vector<OptionalParameter>& outOptionalParameters) const
	{
		return BgpOpenMessageConstView(internal::nocheck, m_Layer).getOptionalParameters(outOptionalParameters);
	}

	bool BgpOpenMessageView::setOptionalParameters(const std::vector<OptionalParameter>& optionalParameters)
	{
		size_t requiredOptionalParamsLen = open::writeOptionalParamsToBuffer(optionalParameters, nullptr, 0);

		// Numeric limits max is in () to escape MAX macro
		if (requiredOptionalParamsLen > (std::numeric_limits<uint8_t>::max)())
		{
			PCPP_LOG_ERROR("The total length of the optional parameters is too large");
			return false;
		}

		size_t currentOptionalParamsLen = getOptionalPrametersLength();

		if (requiredOptionalParamsLen > currentOptionalParamsLen)
		{
			bool res =
			    m_Layer.extendLayer(sizeof(bgp_open_message), requiredOptionalParamsLen - currentOptionalParamsLen);
			if (!res)
			{
				PCPP_LOG_ERROR("Couldn't extend BGP open layer to include the additional optional parameters");
				return res;
			}
		}
		else if (requiredOptionalParamsLen < currentOptionalParamsLen)
		{
			bool res =
			    m_Layer.shortenLayer(sizeof(bgp_open_message), currentOptionalParamsLen - requiredOptionalParamsLen);
			if (!res)
			{
				PCPP_LOG_ERROR("Couldn't shorten BGP open layer to set the right size of the optional parameters data");
				return res;
			}
		}

		if (requiredOptionalParamsLen > 0)
		{
			uint8_t* optionalParamsData = m_Layer.getData() + sizeof(bgp_open_message);
			open::writeOptionalParamsToBuffer(optionalParameters, optionalParamsData, requiredOptionalParamsLen);
		}

		// Update the length field in the BGP header
		getOpenMsgHeader()->optionalParameterLength = static_cast<uint8_t>(requiredOptionalParamsLen);
		setBgpLength(static_cast<uint16_t>(sizeof(bgp_open_message) + requiredOptionalParamsLen));

		return true;
	}

	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	// BgpUpdateMessageView + BgpUpdateMessageConstView
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	namespace
	{
		namespace update
		{
			constexpr size_t MIN_BGP_UPDATE_HEADER_SIZE =
			    sizeof(internal::bgp_common_header) + 2 * sizeof(uint16_t);  // 23 bytes
			static_assert(MIN_BGP_UPDATE_HEADER_SIZE == 23, "MIN_BGP_UPDATE_HEADER_SIZE is 23 bytes by spec");

			struct PathAttributeLengthData
			{
				size_t withdrawnRoutesLen = 0;
				size_t pathAttributesLen = 0;
			};

			struct NetworkLayerReachabilityInfoLengthData
			{
				size_t withdrawnRoutesLen = 0;
				size_t pathAttributesLen = 0;
				size_t networkLayerReachabilityInfoLen = 0;
			};

			size_t readWithdrawnRoutesLen(uint8_t const* buffer, size_t bufferLen)
			{
				if (buffer == nullptr)
					throw std::invalid_argument("Buffer is null");

				if (bufferLen < MIN_BGP_UPDATE_HEADER_SIZE)
				{
					throw std::invalid_argument("Buffer length is smaller than BGP UPDATE minimal message header size");
				}

				uint8_t const* withdrawnLenPtr = buffer + sizeof(internal::bgp_common_header);
				uint16_t withdrawnRoutesLen = be16toh((withdrawnLenPtr[0] << 8 | withdrawnLenPtr[1]));
				return withdrawnRoutesLen;
			}

			PathAttributeLengthData readPathAttributesLen(uint8_t const* buffer, size_t bufferLen)
			{
				if (buffer == nullptr)
					throw std::invalid_argument("Buffer is null");

				if (bufferLen < MIN_BGP_UPDATE_HEADER_SIZE)
				{
					throw std::invalid_argument(
					    "Buffer length is smaller than BGP UPDATE minimal message header size (23 bytes)");
				}

				size_t const withdrawnRoutesLen = readWithdrawnRoutesLen(buffer, bufferLen);

				// Checks if the buffer is large enough to read:
				// - the BGP common header
				// - the withdrawn routes length
				// - the withdrawn routes data
				// - the path attribute length
				if (bufferLen < MIN_BGP_UPDATE_HEADER_SIZE + withdrawnRoutesLen)
				{
					throw std::runtime_error("Buffer is too small to read path attribute length");
				}

				uint8_t const* pathAttrLenPtr =
				    buffer + sizeof(internal::bgp_common_header) + sizeof(uint16_t) + withdrawnRoutesLen;
				uint16_t pathAttributesLen = be16toh((pathAttrLenPtr[0] << 8 | pathAttrLenPtr[1]));

				PathAttributeLengthData result;
				result.withdrawnRoutesLen = withdrawnRoutesLen;
				result.pathAttributesLen = pathAttributesLen;
				return result;
			}

			NetworkLayerReachabilityInfoLengthData readNetworkLayerReachabilityInfoLen(uint8_t const* buffer,
			                                                                           size_t bufferLen)
			{
				if (buffer == nullptr)
					throw std::invalid_argument("Buffer is null");

				if (bufferLen < MIN_BGP_UPDATE_HEADER_SIZE)
				{
					throw std::invalid_argument(
					    "Buffer length is smaller than BGP UPDATE minimal message header size (23 bytes)");
				}

				PathAttributeLengthData const pathAttrLenData = readPathAttributesLen(buffer, bufferLen);

				size_t const withdrawnRoutesLen = pathAttrLenData.withdrawnRoutesLen;
				size_t const pathAttributesLen = pathAttrLenData.pathAttributesLen;
				if (bufferLen < withdrawnRoutesLen + pathAttributesLen + MIN_BGP_UPDATE_HEADER_SIZE)
				{
					throw std::runtime_error(
					    "Recorded withdrawn routes and path attributes length exceeds buffer length");
				}
				size_t const NlriLen =
				    bufferLen - (MIN_BGP_UPDATE_HEADER_SIZE + withdrawnRoutesLen + pathAttributesLen);

				if (bufferLen < withdrawnRoutesLen + pathAttributesLen + NlriLen + MIN_BGP_UPDATE_HEADER_SIZE)
				{
					throw std::runtime_error("Recorded NLRI length exceeds buffer length");
				}

				NetworkLayerReachabilityInfoLengthData result;
				result.withdrawnRoutesLen = withdrawnRoutesLen;
				result.pathAttributesLen = pathAttributesLen;
				result.networkLayerReachabilityInfoLen = NlriLen;
				return result;
			}

			std::pair<uint8_t const*, size_t> getWithdrawnRoutesBuffer(uint8_t const* buffer, size_t bufferLen)
			{
				if (buffer == nullptr)
					throw std::invalid_argument("Buffer is null");
				if (bufferLen < MIN_BGP_UPDATE_HEADER_SIZE)
				{
					throw std::invalid_argument(
					    "Buffer length is smaller than BGP UPDATE minimal message header size (23 bytes)");
				}

				size_t const withdrawnRoutesLen = readWithdrawnRoutesLen(buffer, bufferLen);
				constexpr size_t WITHDRAWN_ROUTES_DATA_OFFSET = sizeof(internal::bgp_common_header) + sizeof(uint16_t);
				return { buffer + WITHDRAWN_ROUTES_DATA_OFFSET, withdrawnRoutesLen };
			}

			std::pair<uint8_t const*, size_t> getPathAttributesBuffer(uint8_t const* buffer, size_t bufferLen)
			{
				if (buffer == nullptr)
					throw std::invalid_argument("Buffer is null");
				if (bufferLen < MIN_BGP_UPDATE_HEADER_SIZE)
				{
					throw std::invalid_argument(
					    "Buffer length is smaller than BGP UPDATE minimal message header size (23 bytes)");
				}

				auto const pathAttrLenData = readPathAttributesLen(buffer, bufferLen);
				size_t const withdrawnRoutesLen = pathAttrLenData.withdrawnRoutesLen;
				size_t const pathAttributesLen = pathAttrLenData.pathAttributesLen;
				return { buffer + MIN_BGP_UPDATE_HEADER_SIZE + withdrawnRoutesLen, pathAttributesLen };
			}

			std::pair<uint8_t const*, size_t> getNlriBuffer(uint8_t const* buffer, size_t bufferLen)
			{
				if (buffer == nullptr)
					throw std::invalid_argument("Buffer is null");
				if (bufferLen < MIN_BGP_UPDATE_HEADER_SIZE)
				{
					throw std::invalid_argument(
					    "Buffer length is smaller than BGP UPDATE minimal message header size (23 bytes)");
				}

				auto const nlriLenData = readNetworkLayerReachabilityInfoLen(buffer, bufferLen);
				size_t const withdrawnRoutesLen = nlriLenData.withdrawnRoutesLen;
				size_t const pathAttributesLen = nlriLenData.pathAttributesLen;
				size_t const networkLayerReachabilityInfoLen = nlriLenData.networkLayerReachabilityInfoLen;
				return { buffer + MIN_BGP_UPDATE_HEADER_SIZE + withdrawnRoutesLen + pathAttributesLen,
					     networkLayerReachabilityInfoLen };
			}

			void parsePrefixAndIPDataBuffer(uint8_t const* buffer, size_t dataLen,
			                                std::vector<BgpUpdateMessageConstView::PrefixAndIp>& result)
			{
				if (buffer == nullptr)
					throw std::invalid_argument("Buffer is null");

				size_t offset = 0;
				while (offset < dataLen)
				{
					if (offset + 1 > dataLen)
					{
						throw std::runtime_error("Buffer length is smaller than expected");
					}

					uint8_t prefixLen = buffer[offset];
					if (prefixLen > 32)
					{
						throw std::runtime_error("Illegal prefix length " + std::to_string(prefixLen));
					}

					size_t const ipDataLen = ((prefixLen + 7) / 8);

					offset += 1;
					if (offset + ipDataLen > dataLen)
					{
						throw std::runtime_error("Buffer length is smaller than expected");
					}
					uint8_t const* ipData = buffer + offset;

					// Copy the variable length IP address data to a fixed size array
					// Garbage in the trailing bits is zeroed in IPv4Address::applySubnetMask
					std::array<uint8_t, 4> ipBuffer;
					std::copy(ipData, ipData + ipDataLen, ipBuffer.begin());

					// Create an IPv4Address object and apply the subnet mask to zero trailing bits
					IPv4Address ipAddr(ipBuffer);
					ipAddr.applySubnetMask(prefixLen);

					result.emplace_back(prefixLen, ipAddr);
					offset += ipDataLen;
				}
			}

			void parsePathAttributesBuffer(uint8_t const* buffer, size_t bufferLen,
			                               std::vector<BgpUpdateMessageConstView::PathAttribute>& result)
			{
				if (buffer == nullptr)
					throw std::invalid_argument("Buffer is null");

				size_t offset = 0;
				while (offset < bufferLen)
				{
					if (offset + 3 > bufferLen)
					{
						throw std::runtime_error("Buffer length is smaller than expected");
					}

					BgpPathAttributeFlag flags = static_cast<BgpPathAttributeFlag>(buffer[offset]);
					BgpPathAttributeType type = static_cast<BgpPathAttributeType>(buffer[offset + 1]);

					bool isExtendedLength = false;
					uint16_t length = 0;
					uint8_t const* attrDataPtr;
					if ((flags & BgpPathAttributeFlag::ExtendedLength) != BgpPathAttributeFlag::None)
					{
						// Extended length
						isExtendedLength = true;

						if (offset + 4 > bufferLen)
						{
							throw std::runtime_error("Buffer length is smaller than expected");
						}

						uint16_t lengthBE = buffer[offset + 2] << 8 | buffer[offset + 3];
						length = be16toh(lengthBE);

						if (bufferLen < offset + 4 + length)
						{
							throw std::runtime_error("Buffer length is smaller than expected");
						}

						attrDataPtr = buffer + offset + 4;
					}
					else
					{
						// Standard length
						length = buffer[offset + 2];

						if (bufferLen < offset + 3 + length)
						{
							throw std::runtime_error("Buffer length is smaller than expected");
						}

						attrDataPtr = buffer + offset + 3;
					}

					// Create a PathAttribute object and assign the data
					result.emplace_back(flags, type, attrDataPtr, length);

					// Move the offset to the next attribute
					if (isExtendedLength)
					{
						offset += 4;
					}
					else
					{
						offset += 3;
					}
					offset += length;
				}
			}
		}  // namespace update
	}  // namespace

	BgpUpdateMessageConstView::PrefixAndIp::PrefixAndIp(uint8_t prefixLen, IPv4Address const& ipAddr)
	    : ipAddress(ipAddr), m_prefixLength(prefixLen)
	{
		if (prefixLen > 32)
			throw std::invalid_argument("Prefix must be between 0 and 32");
	};

	void BgpUpdateMessageConstView::PrefixAndIp::setPrefix(uint8_t prefixLen)
	{
		if (prefixLen > 32)
			throw std::invalid_argument("Prefix must be between 0 and 32");

		m_prefixLength = prefixLen;
	}

	size_t BgpUpdateMessageConstView::PrefixAndIp::writeToBuffer(uint8_t* buffer, size_t bufferLen) const
	{
		// Size is 1 byte for the prefix length and 0~32 bits for the IP address, aligned to the next 8 bits.
		size_t const requiredBytes = sizeof(uint8_t) + (1 + m_prefixLength / 8) * sizeof(uint8_t);

		if (buffer == nullptr)
		{
			if (bufferLen == 0)
			{
				// Query mode
				return requiredBytes;
			}
			// Invalid buffer
			throw std::invalid_argument("Buffer is nullptr or has length 0");
		}
		if (bufferLen < requiredBytes)
		{
			// Insufficient buffer
			return requiredBytes;
		}

		if (m_prefixLength > 0)
		{
			buffer[0] = m_prefixLength;
			auto const& ipBytes = ipAddress.toByteArray();
			for (size_t i = 0; i < (static_cast<size_t>(m_prefixLength) + 7) / 8; ++i)
			{
				buffer[i + 1] = ipBytes[i];
			}
		}
		else
		{
			buffer[0] = 0;
		}

		return requiredBytes;
	}

	BgpUpdateMessageConstView::PathAttribute::PathAttribute(BgpPathAttributeFlag flags, BgpPathAttributeType type,
	                                                        const std::string& dataAsHexString)
	    : m_Flags(flags), m_Type(type)
	{
		if (dataAsHexString.empty())
			throw std::invalid_argument("Data is empty");

		if (dataAsHexString.size() % 2 != 0)
			throw std::invalid_argument("Hex string must be even number of characters");

		// Check if the data length exceeds the maximum path attribute size
		size_t const dataLen = dataAsHexString.size() / 2;
		if (dataLen > (std::numeric_limits<uint8_t>::max)() && !isExtendedLength())
		{
			throw std::invalid_argument("Data length is too large for standard length attribute.");
		}
		else if (dataLen > (std::numeric_limits<uint16_t>::max)())
		{
			throw std::invalid_argument("Data length is too large for extended length attribute.");
		}

		// Check if the data length exceeds the maximum inline data size
		if (dataLen > MAX_INLINE_DATA_SIZE)
		{
			// Allocate memory for the data
			// TODO: Replace with std::make_unique
			m_HeapData = std::unique_ptr<uint8_t[]>(new uint8_t[dataLen]);
			m_Length = dataLen;
			if (hexStringToByteArray(dataAsHexString, m_HeapData.get(), m_Length) != dataLen)
			{
				throw std::runtime_error("Failed to convert hex string to byte array");
			};
		}
		else
		{
			m_Length = dataLen;
			if (hexStringToByteArray(dataAsHexString, m_InlineData.data(), m_Length) != dataLen)
			{
				throw std::runtime_error("Failed to convert hex string to byte array");
			}
		}
	}

	BgpUpdateMessageConstView::PathAttribute::PathAttribute(BgpPathAttributeFlag flags, BgpPathAttributeType type,
	                                                        uint8_t const* data, uint16_t dataLen)
	    : m_Flags(flags), m_Type(type)
	{
		if (dataLen > 0)
		{
			assign(data, dataLen);
		}
	}

	void BgpUpdateMessageConstView::PathAttribute::assign(uint8_t const* data, uint16_t dataLen)
	{
		if (data == nullptr)
			throw std::invalid_argument("Data is null");

		if (dataLen > (std::numeric_limits<uint8_t>::max)() && !isExtendedLength())
		{
			throw std::invalid_argument("Data length is too large for standard length attribute.");
		}

		// Check if the data length exceeds the maximum inline data size
		if (dataLen > MAX_INLINE_DATA_SIZE)
		{
			if (m_HeapData == nullptr)
			{
				// Allocate memory for the data
				// TODO: Replace with std::make_unique
				m_HeapData = std::unique_ptr<uint8_t[]>(new uint8_t[dataLen]);
			}
			else if (m_HeapData && m_Length < dataLen)
			{
				// Reallocate memory for the data
				m_HeapData.reset(new uint8_t[dataLen]);
			}

			m_Length = dataLen;
			std::memcpy(m_HeapData.get(), data, dataLen);
		}
		else
		{
			// Free the heap memory if it was previously allocated
			m_HeapData.reset();
			m_Length = dataLen;
			std::memcpy(m_InlineData.data(), data, dataLen);
		}
	}

	BgpUpdateMessageConstView::BgpUpdateMessageConstView(BgpLayer const& layer) : BgpBasicHeaderConstView(layer)
	{
		if (m_Layer.getBgpMessageType() != BgpLayer::BgpMessageType::Update)
			throw std::invalid_argument("Layer is not a BGP UPDATE message");
		if (m_Layer.getHeaderLen() < update::MIN_BGP_UPDATE_HEADER_SIZE)
		{
			// The view enforces at least the fixed BGP header size + WithdrawnRoutesLength (1 byte) +
			// PathAttributeLength (1 byte)
			throw std::invalid_argument("Data length is smaller than BGP UPDATE minimal message header size");
		}
	}

	size_t BgpUpdateMessageConstView::getWithdrawnRoutesByteLength() const
	{
		return update::readWithdrawnRoutesLen(m_Layer.getData(), m_Layer.getHeaderLen());
	}

	void BgpUpdateMessageConstView::getWithdrawnRoutes(std::vector<PrefixAndIp>& outWithdrawnRoutes) const
	{
		auto const withdrawnRoutesBufferInfo =
		    update::getWithdrawnRoutesBuffer(m_Layer.getData(), m_Layer.getHeaderLen());

		if (withdrawnRoutesBufferInfo.second == 0)
		{
			return;
		}

		update::parsePrefixAndIPDataBuffer(withdrawnRoutesBufferInfo.first, withdrawnRoutesBufferInfo.second,
		                                   outWithdrawnRoutes);
	}

	size_t BgpUpdateMessageConstView::getPathAttributesByteLength() const
	{
		return update::readPathAttributesLen(m_Layer.getData(), m_Layer.getHeaderLen()).pathAttributesLen;
	}

	void BgpUpdateMessageConstView::getPathAttributes(std::vector<PathAttribute>& outPathAttributes) const
	{
		auto const pathBufferInfo = update::getPathAttributesBuffer(m_Layer.getData(), m_Layer.getHeaderLen());

		if (pathBufferInfo.second == 0)
		{
			return;
		}

		update::parsePathAttributesBuffer(pathBufferInfo.first, pathBufferInfo.second, outPathAttributes);
	}

	size_t BgpUpdateMessageConstView::getNetworkLayerReachabilityInfoByteLength() const
	{
		return update::readNetworkLayerReachabilityInfoLen(m_Layer.getData(), m_Layer.getHeaderLen())
		    .networkLayerReachabilityInfoLen;
	}

	void BgpUpdateMessageConstView::getNetworkLayerReachabilityInfo(std::vector<PrefixAndIp>& outNLRI) const
	{
		auto const nlriBufferInfo = update::getNlriBuffer(m_Layer.getData(), m_Layer.getHeaderLen());

		if (nlriBufferInfo.second == 0)
		{
			return;
		}

		update::parsePrefixAndIPDataBuffer(nlriBufferInfo.first, nlriBufferInfo.second, outNLRI);
	}

	// ~~~~~~~~~~~~~~~~~~~~
	// BgpOpenMessageLayer
	// ~~~~~~~~~~~~~~~~~~~~

	BgpOpenMessageLayer::optional_parameter::optional_parameter(uint8_t typeVal, const std::string& valueAsHexString)
	{
		type = typeVal;
		length = hexStringToByteArray(valueAsHexString, value, 32);
	}

	BgpOpenMessageLayer::BgpOpenMessageLayer(uint16_t myAutonomousSystem, uint16_t holdTime, const IPv4Address& bgpId,
	                                         const std::vector<optional_parameter>& optionalParams)
	{
		uint8_t optionalParamsData[1500];
		size_t optionalParamsDataLen = optionalParamsToByteArray(optionalParams, optionalParamsData, 1500);

		const size_t headerLen = sizeof(bgp_open_message) + optionalParamsDataLen;
		m_DataLen = headerLen;
		m_Data = new uint8_t[headerLen];
		memset(m_Data, 0, headerLen);
		setBgpFields(headerLen);

		bgp_open_message* msgHdr = getOpenMsgHeader();
		msgHdr->version = 4;
		msgHdr->myAutonomousSystem = htobe16(myAutonomousSystem);
		msgHdr->holdTime = htobe16(holdTime);
		msgHdr->bgpId = bgpId.toInt();
		msgHdr->optionalParameterLength = optionalParamsDataLen;
		if (optionalParamsDataLen > 0)
		{
			memcpy(m_Data + sizeof(bgp_open_message), optionalParamsData, optionalParamsDataLen);
		}

		m_Protocol = BGP;
	}

	size_t BgpOpenMessageLayer::optionalParamsToByteArray(const std::vector<optional_parameter>& optionalParams,
	                                                      uint8_t* resultByteArr, size_t maxByteArrSize)
	{
		if (resultByteArr == nullptr || maxByteArrSize == 0)
		{
			return 0;
		}

		size_t dataLen = 0;

		for (const auto& param : optionalParams)
		{
			if (param.length > 32)
			{
				PCPP_LOG_ERROR("Illegal optional parameter length " << (int)param.length
				                                                    << ", must be 32 bytes or less");
				break;  // illegal value
			}

			size_t curDataSize = 2 * sizeof(uint8_t) + (size_t)param.length;

			if (dataLen + curDataSize > maxByteArrSize)
			{
				break;
			}

			resultByteArr[0] = param.type;
			resultByteArr[1] = param.length;
			if (param.length > 0)
			{
				memcpy(resultByteArr + 2 * sizeof(uint8_t), param.value, param.length);
			}

			dataLen += curDataSize;
			resultByteArr += curDataSize;
		}

		return dataLen;
	}

	void BgpOpenMessageLayer::setBgpId(const IPv4Address& newBgpId)
	{
		bgp_open_message* msgHdr = getOpenMsgHeader();
		if (msgHdr == nullptr)
		{
			return;
		}

		msgHdr->bgpId = newBgpId.toInt();
	}

	void BgpOpenMessageLayer::getOptionalParameters(std::vector<optional_parameter>& optionalParameters)
	{
		bgp_open_message* msgHdr = getOpenMsgHeader();
		if (msgHdr == nullptr || msgHdr->optionalParameterLength == 0)
		{
			return;
		}

		size_t optionalParamsLen = (size_t)be16toh(msgHdr->optionalParameterLength);

		if (optionalParamsLen > getHeaderLen() - sizeof(bgp_open_message))
		{
			optionalParamsLen = getHeaderLen() - sizeof(bgp_open_message);
		}

		uint8_t* dataPtr = m_Data + sizeof(bgp_open_message);
		size_t byteCount = 0;
		while (byteCount < optionalParamsLen)
		{
			optional_parameter op;
			op.type = dataPtr[0];
			op.length = dataPtr[1];

			if (op.length > optionalParamsLen - byteCount)
			{
				PCPP_LOG_ERROR("Optional parameter length is out of bounds: " << (int)op.length);
				break;
			}

			if (op.length > 0)
			{
				memcpy(op.value, dataPtr + 2 * sizeof(uint8_t), (op.length > 32 ? 32 : op.length));
			}

			optionalParameters.push_back(op);
			size_t totalLen = 2 + (size_t)op.length;
			byteCount += totalLen;
			dataPtr += totalLen;
		}
	}

	size_t BgpOpenMessageLayer::getOptionalParametersLength()
	{
		bgp_open_message* msgHdr = getOpenMsgHeader();
		if (msgHdr != nullptr)
		{
			return (size_t)(msgHdr->optionalParameterLength);
		}

		return 0;
	}

	bool BgpOpenMessageLayer::setOptionalParameters(const std::vector<optional_parameter>& optionalParameters)
	{
		uint8_t newOptionalParamsData[1500];
		size_t newOptionalParamsDataLen = optionalParamsToByteArray(optionalParameters, newOptionalParamsData, 1500);
		size_t curOptionalParamsDataLen = getOptionalParametersLength();

		if (newOptionalParamsDataLen > curOptionalParamsDataLen)
		{
			bool res = extendLayer(sizeof(bgp_open_message), newOptionalParamsDataLen - curOptionalParamsDataLen);
			if (!res)
			{
				PCPP_LOG_ERROR("Couldn't extend BGP open layer to include the additional optional parameters");
				return res;
			}
		}
		else if (newOptionalParamsDataLen < curOptionalParamsDataLen)
		{
			bool res = shortenLayer(sizeof(bgp_open_message), curOptionalParamsDataLen - newOptionalParamsDataLen);
			if (!res)
			{
				PCPP_LOG_ERROR("Couldn't shorten BGP open layer to set the right size of the optional parameters data");
				return res;
			}
		}

		if (newOptionalParamsDataLen > 0)
		{
			memcpy(m_Data + sizeof(bgp_open_message), newOptionalParamsData, newOptionalParamsDataLen);
		}

		getOpenMsgHeader()->optionalParameterLength = (uint8_t)newOptionalParamsDataLen;
		getOpenMsgHeader()->length = htobe16(sizeof(bgp_open_message) + newOptionalParamsDataLen);

		return true;
	}

	bool BgpOpenMessageLayer::clearOptionalParameters()
	{
		return setOptionalParameters(std::vector<optional_parameter>());
	}

	// ~~~~~~~~~~~~~~~~~~~~~
	// BgpUpdateMessageLayer
	// ~~~~~~~~~~~~~~~~~~~~~

	BgpUpdateMessageLayer::path_attribute::path_attribute(uint8_t flagsVal, uint8_t typeVal,
	                                                      const std::string& dataAsHexString)
	{
		flags = flagsVal;
		type = typeVal;
		length = hexStringToByteArray(dataAsHexString, data, 32);
	}

	BgpUpdateMessageLayer::BgpUpdateMessageLayer(const std::vector<prefix_and_ip>& withdrawnRoutes,
	                                             const std::vector<path_attribute>& pathAttributes,
	                                             const std::vector<prefix_and_ip>& nlri)
	{
		uint8_t withdrawnRoutesData[1500];
		uint8_t pathAttributesData[1500];
		uint8_t nlriData[1500];
		size_t withdrawnRoutesDataLen = prefixAndIPDataToByteArray(withdrawnRoutes, withdrawnRoutesData, 1500);
		size_t pathAttributesDataLen = pathAttributesToByteArray(pathAttributes, pathAttributesData, 1500);
		size_t nlriDataLen = prefixAndIPDataToByteArray(nlri, nlriData, 1500);

		size_t headerLen = sizeof(bgp_common_header) + 2 * sizeof(uint16_t) + withdrawnRoutesDataLen +
		                   pathAttributesDataLen + nlriDataLen;
		m_DataLen = headerLen;
		m_Data = new uint8_t[headerLen];
		memset(m_Data, 0, headerLen);
		setBgpFields(headerLen);

		uint8_t* dataPtr = m_Data + sizeof(bgp_common_header);

		// copy withdrawn routes data
		uint16_t withdrawnRoutesDataLenBE = htobe16(withdrawnRoutesDataLen);
		memcpy(dataPtr, &withdrawnRoutesDataLenBE, sizeof(uint16_t));
		dataPtr += sizeof(uint16_t);
		if (withdrawnRoutesDataLen > 0)
		{
			memcpy(dataPtr, withdrawnRoutesData, withdrawnRoutesDataLen);
			dataPtr += withdrawnRoutesDataLen;
		}

		// copy path attributes data
		uint16_t pathAttributesDataLenBE = htobe16(pathAttributesDataLen);
		memcpy(dataPtr, &pathAttributesDataLenBE, sizeof(uint16_t));
		dataPtr += sizeof(uint16_t);
		if (pathAttributesDataLen > 0)
		{
			memcpy(dataPtr, pathAttributesData, pathAttributesDataLen);
			dataPtr += pathAttributesDataLen;
		}

		// copy nlri data
		if (nlriDataLen > 0)
		{
			memcpy(dataPtr, nlriData, nlriDataLen);
		}

		m_Protocol = BGP;
	}

	void BgpUpdateMessageLayer::parsePrefixAndIPData(uint8_t* dataPtr, size_t dataLen,
	                                                 std::vector<prefix_and_ip>& result)
	{
		size_t byteCount = 0;
		while (byteCount < dataLen)
		{
			prefix_and_ip wr;
			wr.prefix = dataPtr[0];
			size_t curByteCount = 1;
			if (wr.prefix == 32)
			{
				uint8_t octets[4] = { dataPtr[1], dataPtr[2], dataPtr[3], dataPtr[4] };
				wr.ipAddr = IPv4Address(octets);
				curByteCount += 4;
			}
			else if (wr.prefix == 24)
			{
				uint8_t octets[4] = { dataPtr[1], dataPtr[2], dataPtr[3], 0 };
				wr.ipAddr = IPv4Address(octets);
				curByteCount += 3;
			}
			else if (wr.prefix == 16)
			{
				uint8_t octets[4] = { dataPtr[1], dataPtr[2], 0, 0 };
				wr.ipAddr = IPv4Address(octets);
				curByteCount += 2;
			}
			else if (wr.prefix == 8)
			{
				uint8_t octets[4] = { dataPtr[1], 0, 0, 0 };
				wr.ipAddr = IPv4Address(octets);
				curByteCount += 1;
			}
			else
			{
				PCPP_LOG_DEBUG("Illegal prefix value " << (int)wr.prefix);
				break;  // illegal value
			}

			result.push_back(wr);
			dataPtr += curByteCount;
			byteCount += curByteCount;
		}
	}

	size_t BgpUpdateMessageLayer::prefixAndIPDataToByteArray(const std::vector<prefix_and_ip>& prefixAndIpData,
	                                                         uint8_t* resultByteArr, size_t maxByteArrSize)
	{
		if (resultByteArr == nullptr || maxByteArrSize == 0)
		{
			return 0;
		}

		size_t dataLen = 0;

		for (const auto& prefixAndIp : prefixAndIpData)
		{
			uint8_t curData[5];
			curData[0] = prefixAndIp.prefix;
			size_t curDataSize = 1;
			const uint8_t* octets = prefixAndIp.ipAddr.toBytes();
			if (prefixAndIp.prefix == 32)
			{
				curDataSize += 4;
				curData[1] = octets[0];
				curData[2] = octets[1];
				curData[3] = octets[2];
				curData[4] = octets[3];
			}
			else if (prefixAndIp.prefix == 24)
			{
				curDataSize += 3;
				curData[1] = octets[0];
				curData[2] = octets[1];
				curData[3] = octets[2];
			}
			else if (prefixAndIp.prefix == 16)
			{
				curDataSize += 2;
				curData[1] = octets[0];
				curData[2] = octets[1];
			}
			else if (prefixAndIp.prefix == 8)
			{
				curDataSize += 1;
				curData[1] = octets[0];
			}
			else
			{
				PCPP_LOG_ERROR("Illegal prefix value " << (int)prefixAndIp.prefix);
				break;  // illegal value
			}

			if (dataLen + curDataSize > maxByteArrSize)
			{
				break;
			}

			dataLen += curDataSize;

			memcpy(resultByteArr, curData, curDataSize);
			resultByteArr += curDataSize;
		}

		return dataLen;
	}

	size_t BgpUpdateMessageLayer::pathAttributesToByteArray(const std::vector<path_attribute>& pathAttributes,
	                                                        uint8_t* resultByteArr, size_t maxByteArrSize)
	{
		if (resultByteArr == nullptr || maxByteArrSize == 0)
		{
			return 0;
		}

		size_t dataLen = 0;

		for (const auto& attribute : pathAttributes)
		{
			if (attribute.length > 32)
			{
				PCPP_LOG_ERROR("Illegal path attribute length " << (int)attribute.length);
				break;  // illegal value
			}

			size_t curDataSize = 3 * sizeof(uint8_t) + (size_t)attribute.length;

			if (dataLen + curDataSize > maxByteArrSize)
			{
				break;
			}

			resultByteArr[0] = attribute.flags;
			resultByteArr[1] = attribute.type;
			resultByteArr[2] = attribute.length;
			if (attribute.length > 0)
			{
				memcpy(resultByteArr + 3 * sizeof(uint8_t), attribute.data, attribute.length);
			}

			dataLen += curDataSize;
			resultByteArr += curDataSize;
		}

		return dataLen;
	}

	size_t BgpUpdateMessageLayer::getWithdrawnRoutesLength() const
	{
		size_t headerLen = getHeaderLen();
		size_t minLen = sizeof(bgp_common_header) + sizeof(uint16_t);
		if (headerLen >= minLen)
		{
			uint16_t res = be16toh(*(uint16_t*)(m_Data + sizeof(bgp_common_header)));
			if ((size_t)res > headerLen - minLen)
			{
				return headerLen - minLen;
			}

			return (size_t)res;
		}

		return 0;
	}

	void BgpUpdateMessageLayer::getWithdrawnRoutes(std::vector<prefix_and_ip>& withdrawnRoutes)
	{
		size_t withdrawnRouteLen = getWithdrawnRoutesLength();
		if (withdrawnRouteLen == 0)
		{
			return;
		}

		uint8_t* dataPtr = m_Data + sizeof(bgp_common_header) + sizeof(uint16_t);
		parsePrefixAndIPData(dataPtr, withdrawnRouteLen, withdrawnRoutes);
	}

	size_t BgpUpdateMessageLayer::getPathAttributesLength() const
	{
		size_t headerLen = getHeaderLen();
		size_t minLen = sizeof(bgp_common_header) + 2 * sizeof(uint16_t);
		if (headerLen >= minLen)
		{
			size_t withdrawnRouteLen = getWithdrawnRoutesLength();
			// Ensure the memory access is within bounds
			if (sizeof(bgp_common_header) + sizeof(uint16_t) + withdrawnRouteLen + sizeof(uint16_t) > headerLen)
			{
				return 0;  // Invalid access, return 0
			}
			uint16_t res =
			    be16toh(*(uint16_t*)(m_Data + sizeof(bgp_common_header) + sizeof(uint16_t) + withdrawnRouteLen));
			if ((size_t)res > headerLen - minLen - withdrawnRouteLen)
			{
				return headerLen - minLen - withdrawnRouteLen;
			}

			return (size_t)res;
		}

		return 0;
	}

	bool BgpUpdateMessageLayer::setWithdrawnRoutes(const std::vector<prefix_and_ip>& withdrawnRoutes)
	{
		uint8_t newWithdrawnRoutesData[1500];
		size_t newWithdrawnRoutesDataLen = prefixAndIPDataToByteArray(withdrawnRoutes, newWithdrawnRoutesData, 1500);
		size_t curWithdrawnRoutesDataLen = getWithdrawnRoutesLength();

		if (newWithdrawnRoutesDataLen > curWithdrawnRoutesDataLen)
		{
			bool res = extendLayer(sizeof(bgp_common_header) + sizeof(uint16_t),
			                       newWithdrawnRoutesDataLen - curWithdrawnRoutesDataLen);
			if (!res)
			{
				PCPP_LOG_ERROR("Couldn't extend BGP update layer to include the additional withdrawn routes");
				return res;
			}
		}
		else if (newWithdrawnRoutesDataLen < curWithdrawnRoutesDataLen)
		{
			bool res = shortenLayer(sizeof(bgp_common_header) + sizeof(uint16_t),
			                        curWithdrawnRoutesDataLen - newWithdrawnRoutesDataLen);
			if (!res)
			{
				PCPP_LOG_ERROR("Couldn't shorten BGP update layer to set the right size of the withdrawn routes data");
				return res;
			}
		}

		if (newWithdrawnRoutesDataLen > 0)
		{
			memcpy(m_Data + sizeof(bgp_common_header) + sizeof(uint16_t), newWithdrawnRoutesData,
			       newWithdrawnRoutesDataLen);
		}

		getBasicHeader()->length =
		    htobe16(be16toh(getBasicHeader()->length) + newWithdrawnRoutesDataLen - curWithdrawnRoutesDataLen);

		uint16_t newWithdrawnRoutesDataLenBE = htobe16(newWithdrawnRoutesDataLen);
		memcpy(m_Data + sizeof(bgp_common_header), &newWithdrawnRoutesDataLenBE, sizeof(uint16_t));

		return true;
	}

	bool BgpUpdateMessageLayer::clearWithdrawnRoutes()
	{
		return setWithdrawnRoutes(std::vector<prefix_and_ip>());
	}

	void BgpUpdateMessageLayer::getPathAttributes(std::vector<path_attribute>& pathAttributes)
	{
		size_t pathAttrLen = getPathAttributesLength();
		if (pathAttrLen == 0)
		{
			return;
		}

		uint8_t* dataPtr = m_Data + sizeof(bgp_common_header) + 2 * sizeof(uint16_t) + getWithdrawnRoutesLength();
		size_t byteCount = 0;
		while (byteCount < pathAttrLen)
		{
			path_attribute pa;
			pa.flags = dataPtr[0];
			pa.type = dataPtr[1];
			pa.length = dataPtr[2];
			size_t curByteCount = 3 + pa.length;
			if (pa.length > 0)
			{
				size_t dataLenToCopy = (pa.length <= 32 ? pa.length : 32);
				memcpy(pa.data, dataPtr + 3, dataLenToCopy);
			}

			pathAttributes.push_back(pa);
			dataPtr += curByteCount;
			byteCount += curByteCount;
		}
	}

	bool BgpUpdateMessageLayer::setPathAttributes(const std::vector<path_attribute>& pathAttributes)
	{
		uint8_t newPathAttributesData[1500];
		size_t newPathAttributesDataLen = pathAttributesToByteArray(pathAttributes, newPathAttributesData, 1500);
		size_t curPathAttributesDataLen = getPathAttributesLength();
		size_t curWithdrawnRoutesDataLen = getWithdrawnRoutesLength();

		if (newPathAttributesDataLen > curPathAttributesDataLen)
		{
			bool res = extendLayer(sizeof(bgp_common_header) + 2 * sizeof(uint16_t) + curWithdrawnRoutesDataLen,
			                       newPathAttributesDataLen - curPathAttributesDataLen);
			if (!res)
			{
				PCPP_LOG_ERROR("Couldn't extend BGP update layer to include the additional path attributes");
				return res;
			}
		}
		else if (newPathAttributesDataLen < curPathAttributesDataLen)
		{
			bool res = shortenLayer(sizeof(bgp_common_header) + 2 * sizeof(uint16_t) + curWithdrawnRoutesDataLen,
			                        curPathAttributesDataLen - newPathAttributesDataLen);
			if (!res)
			{
				PCPP_LOG_ERROR("Couldn't shorten BGP update layer to set the right size of the path attributes data");
				return res;
			}
		}

		if (newPathAttributesDataLen > 0)
		{
			memcpy(m_Data + sizeof(bgp_common_header) + 2 * sizeof(uint16_t) + curWithdrawnRoutesDataLen,
			       newPathAttributesData, newPathAttributesDataLen);
		}

		getBasicHeader()->length =
		    htobe16(be16toh(getBasicHeader()->length) + newPathAttributesDataLen - curPathAttributesDataLen);

		uint16_t newWithdrawnRoutesDataLenBE = htobe16(newPathAttributesDataLen);
		memcpy(m_Data + sizeof(bgp_common_header) + sizeof(uint16_t) + curWithdrawnRoutesDataLen,
		       &newWithdrawnRoutesDataLenBE, sizeof(uint16_t));

		return true;
	}

	bool BgpUpdateMessageLayer::clearPathAttributes()
	{
		return setPathAttributes(std::vector<path_attribute>());
	}

	size_t BgpUpdateMessageLayer::getNetworkLayerReachabilityInfoLength() const
	{
		size_t headerLen = getHeaderLen();
		size_t minLen = sizeof(bgp_common_header) + 2 * sizeof(uint16_t);
		if (headerLen >= minLen)
		{
			size_t withdrawnRouteLen = getWithdrawnRoutesLength();
			size_t pathAttrLen = getPathAttributesLength();
			int nlriSize = headerLen - minLen - withdrawnRouteLen - pathAttrLen;
			if (nlriSize >= 0)
			{
				return (size_t)nlriSize;
			}

			return 0;
		}

		return 0;
	}

	void BgpUpdateMessageLayer::getNetworkLayerReachabilityInfo(std::vector<prefix_and_ip>& nlri)
	{
		size_t nlriSize = getNetworkLayerReachabilityInfoLength();
		if (nlriSize == 0)
		{
			return;
		}

		uint8_t* dataPtr = m_Data + sizeof(bgp_common_header) + 2 * sizeof(uint16_t) + getWithdrawnRoutesLength() +
		                   getPathAttributesLength();
		parsePrefixAndIPData(dataPtr, nlriSize, nlri);
	}

	bool BgpUpdateMessageLayer::isDataValid(const uint8_t* data, size_t dataSize)
	{
		if (dataSize < sizeof(bgp_common_header) + 2 * sizeof(uint16_t))
			return false;

		uint16_t withdrLen = be16toh(*(uint16_t*)(data + sizeof(bgp_common_header)));
		if (dataSize < sizeof(bgp_common_header) + 2 * sizeof(uint16_t) + withdrLen)
			return false;

		uint16_t attrLen = be16toh(*(uint16_t*)(data + sizeof(bgp_common_header) + sizeof(uint16_t) + withdrLen));
		if (dataSize < sizeof(bgp_common_header) + 2 * sizeof(uint16_t) + withdrLen + attrLen)
			return false;

		return true;
	}

	bool BgpUpdateMessageLayer::setNetworkLayerReachabilityInfo(const std::vector<prefix_and_ip>& nlri)
	{
		uint8_t newNlriData[1500];
		size_t newNlriDataLen = prefixAndIPDataToByteArray(nlri, newNlriData, 1500);
		size_t curNlriDataLen = getNetworkLayerReachabilityInfoLength();
		size_t curPathAttributesDataLen = getPathAttributesLength();
		size_t curWithdrawnRoutesDataLen = getWithdrawnRoutesLength();

		if (newNlriDataLen > curNlriDataLen)
		{
			bool res = extendLayer(sizeof(bgp_common_header) + 2 * sizeof(uint16_t) + curWithdrawnRoutesDataLen +
			                           curPathAttributesDataLen,
			                       newNlriDataLen - curNlriDataLen);
			if (!res)
			{
				PCPP_LOG_ERROR("Couldn't extend BGP update layer to include the additional NLRI data");
				return res;
			}
		}
		else if (newNlriDataLen < curNlriDataLen)
		{
			bool res = shortenLayer(sizeof(bgp_common_header) + 2 * sizeof(uint16_t) + curWithdrawnRoutesDataLen +
			                            curPathAttributesDataLen,
			                        curNlriDataLen - newNlriDataLen);
			if (!res)
			{
				PCPP_LOG_ERROR("Couldn't shorten BGP update layer to set the right size of the NLRI data");
				return res;
			}
		}

		if (newNlriDataLen > 0)
		{
			memcpy(m_Data + sizeof(bgp_common_header) + 2 * sizeof(uint16_t) + curWithdrawnRoutesDataLen +
			           curPathAttributesDataLen,
			       newNlriData, newNlriDataLen);
		}

		getBasicHeader()->length = htobe16(be16toh(getBasicHeader()->length) + newNlriDataLen - curNlriDataLen);

		return true;
	}

	bool BgpUpdateMessageLayer::clearNetworkLayerReachabilityInfo()
	{
		return setNetworkLayerReachabilityInfo(std::vector<prefix_and_ip>());
	}

	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~
	// BgpNotificationMessageLayer
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~

	BgpNotificationMessageLayer::BgpNotificationMessageLayer(uint8_t errorCode, uint8_t errorSubCode)
	{
		initMessageData(errorCode, errorSubCode, nullptr, 0);
	}

	BgpNotificationMessageLayer::BgpNotificationMessageLayer(uint8_t errorCode, uint8_t errorSubCode,
	                                                         const uint8_t* notificationData,
	                                                         size_t notificationDataLen)
	{
		initMessageData(errorCode, errorSubCode, notificationData, notificationDataLen);
	}

	BgpNotificationMessageLayer::BgpNotificationMessageLayer(uint8_t errorCode, uint8_t errorSubCode,
	                                                         const std::string& notificationData)
	{
		uint8_t notificationDataByteArr[1500];
		size_t notificationDataLen = hexStringToByteArray(notificationData, notificationDataByteArr, 1500);
		initMessageData(errorCode, errorSubCode, notificationDataByteArr, notificationDataLen);
	}

	void BgpNotificationMessageLayer::initMessageData(uint8_t errorCode, uint8_t errorSubCode,
	                                                  const uint8_t* notificationData, size_t notificationDataLen)
	{
		size_t headerLen = sizeof(bgp_notification_message);
		if (notificationData != nullptr && notificationDataLen > 0)
		{
			headerLen += notificationDataLen;
		}
		m_DataLen = headerLen;
		m_Data = new uint8_t[headerLen];
		memset(m_Data, 0, headerLen);
		setBgpFields(headerLen);
		bgp_notification_message* msgHdr = getNotificationMsgHeader();
		msgHdr->errorCode = errorCode;
		msgHdr->errorSubCode = errorSubCode;
		memcpy(m_Data + sizeof(bgp_notification_message), notificationData, notificationDataLen);
		m_Protocol = BGP;
	}

	size_t BgpNotificationMessageLayer::getNotificationDataLen() const
	{
		size_t headerLen = getHeaderLen();
		if (headerLen > sizeof(bgp_notification_message))
		{
			return headerLen - sizeof(bgp_notification_message);
		}

		return 0;
	}

	uint8_t* BgpNotificationMessageLayer::getNotificationData() const
	{
		if (getNotificationDataLen() > 0)
		{
			return m_Data + sizeof(bgp_notification_message);
		}

		return nullptr;
	}

	std::string BgpNotificationMessageLayer::getNotificationDataAsHexString() const
	{
		uint8_t* notificationData = getNotificationData();
		if (notificationData == nullptr)
		{
			return "";
		}

		return byteArrayToHexString(notificationData, getNotificationDataLen());
	}

	bool BgpNotificationMessageLayer::setNotificationData(const uint8_t* newNotificationData,
	                                                      size_t newNotificationDataLen)
	{
		if (newNotificationData == nullptr)
		{
			newNotificationDataLen = 0;
		}

		size_t curNotificationDataLen = getNotificationDataLen();

		if (newNotificationDataLen > curNotificationDataLen)
		{
			bool res = extendLayer(sizeof(bgp_notification_message), newNotificationDataLen - curNotificationDataLen);
			if (!res)
			{
				PCPP_LOG_ERROR("Couldn't extend BGP notification layer to include the additional notification data");
				return res;
			}
		}
		else if (newNotificationDataLen < curNotificationDataLen)
		{
			bool res = shortenLayer(sizeof(bgp_notification_message), curNotificationDataLen - newNotificationDataLen);
			if (!res)
			{
				PCPP_LOG_ERROR(
				    "Couldn't shorten BGP notification layer to set the right size of the notification data");
				return res;
			}
		}

		if (newNotificationDataLen > 0)
		{
			memcpy(m_Data + sizeof(bgp_notification_message), newNotificationData, newNotificationDataLen);
		}

		getNotificationMsgHeader()->length = htobe16(sizeof(bgp_notification_message) + newNotificationDataLen);

		return true;
	}

	bool BgpNotificationMessageLayer::setNotificationData(const std::string& newNotificationDataAsHexString)
	{
		if (newNotificationDataAsHexString.empty())
		{
			return setNotificationData(nullptr, 0);
		}

		uint8_t newNotificationData[1500];
		size_t newNotificationDataLen = hexStringToByteArray(newNotificationDataAsHexString, newNotificationData, 1500);

		if (newNotificationDataLen == 0)
		{
			PCPP_LOG_ERROR("newNotificationDataAsHexString is not a valid hex string");
			return false;
		}

		return setNotificationData(newNotificationData, newNotificationDataLen);
	}

	// ~~~~~~~~~~~~~~~~~~~~~~~~
	// BgpKeepaliveMessageLayer
	// ~~~~~~~~~~~~~~~~~~~~~~~~

	BgpKeepaliveMessageLayer::BgpKeepaliveMessageLayer() : BgpLayer()
	{
		const size_t headerLen = sizeof(bgp_common_header);
		m_DataLen = headerLen;
		m_Data = new uint8_t[headerLen];
		memset(m_Data, 0, headerLen);
		setBgpFields(headerLen);
		m_Protocol = BGP;
	}

	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~
	// BgpRouteRefreshMessageLayer
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~

	BgpRouteRefreshMessageLayer::BgpRouteRefreshMessageLayer(uint16_t afi, uint8_t safi)
	{
		const size_t headerLen = sizeof(bgp_route_refresh_message);
		m_DataLen = headerLen;
		m_Data = new uint8_t[headerLen];
		memset(m_Data, 0, headerLen);
		setBgpFields(headerLen);
		bgp_route_refresh_message* msgHdr = getRouteRefreshHeader();
		msgHdr->afi = htobe16(afi);
		msgHdr->safi = safi;
		m_Protocol = BGP;
	}

}  // namespace pcpp
