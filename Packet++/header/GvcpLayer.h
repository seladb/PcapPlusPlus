#pragma once

#include "Layer.h"

/**
 * @file GvcpLayer.h
 * @author An-Chi Liu (phy.tiger@gmail.com)
 */

/**
 * @namespace pcpp
 * @brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
	namespace detail
	{
		static constexpr size_t kGvcpMagicNumber = 0x42;
		static constexpr size_t kGvcpRequestHeaderLength = 8;
		static constexpr size_t kGvcpAckHeaderLength = 8;
		static constexpr size_t kGvcpDiscoveryLength = 256;

	} // namespace detail

	typedef uint8_t GvcpFlag; // flag bits are specified by each command

	enum class GvcpCommand : uint16_t
	{
		// Discovery Protocol Control
		DiscoveredCmd = 0x0002,
		DiscoveredAck = 0x0003,
		ForceIpCmd = 0x0004,
		ForceIpAck = 0x0005,

		// Streaming Protocol Control
		PacketResendCmd = 0x0040,
		PacketResendAck = 0x0041, // Resent packet must be on the stream channel

		// Device Memory Access
		ReadRegCmd = 0x0080,
		ReadRegAck = 0x0081,
		WriteRegCmd = 0x0082,
		WriteRegAck = 0x0083,
		ReadMemCmd = 0x0084,
		ReadMemAck = 0x0085,
		WriteMemCmd = 0x0086,
		WriteMemAck = 0x0087,
		PendingAck = 0x0089,

		// Asynchronous Events
		EventCmd = 0x00C0,
		EventAck = 0x00C1,
		EventDataCmd = 0x00C2,
		EventDataAck = 0x00C3,

		// Miscellaneous
		ActionCmd = 0x0100,
		ActionAck = 0x0101,
		Unknown = 0xFFFF
	};

	enum class GvcpResponseStatus : uint16_t
	{
		Success = 0x0000,
		PacketResend = 0x0100,
		NotImplemented = 0x8001,
		InvalidParameter = 0x8002,
		InvalidAddress = 0x8003,
		WriteProtect = 0x8004,
		BadAlignment = 0x8005,
		AccessDenied = 0x8006,
		Busy = 0x8007,
		LocalProblem = 0x8008,	  // deprecated
		MsgMismatch = 0x8009,	  // deprecated
		InvalidProtocol = 0x800A, // deprecated
		NoMsg = 0x800B,			  // deprecated
		PacketUnavailable = 0x800C,
		DataOverrun = 0x800D,
		InvalidHeader = 0x800E,
		WrongConfig = 0x800F, // deprecated
		PacketNotYetAvailable = 0x8010,
		PacketAndPrevRemovedFromMemory = 0x8011,
		PacketRemovedFromMemory = 0x8012,
		NoRefTime = 0x8013,					   // GEV 2.0
		PacketTemporarilyUnavailable = 0x8014, // GEV 2.0
		Overflow = 0x8015,					   // GEV 2.0
		ActionLate = 0x8016,				   // GEV 2.0
		LeaderTrailerOverflow = 0x8017,		   // GEV 2.1
		Error = 0x8FFF,
		Unknown = 0xFFFF
	};

#pragma pack(push, 1)
	/// @brief Gvcp request header
	/// @note refer to the spec "15.1 Request Header"
	struct GvcpRequestHeader
	{
		uint8_t magicNumber = detail::kGvcpMagicNumber; // always fixed
		GvcpFlag flag = 0;
		GvcpCommand command = GvcpCommand::Unknown;
		uint16_t dataSize = 0;
		uint16_t requestId = 0;
	};
	static_assert(sizeof(GvcpRequestHeader) == detail::kGvcpRequestHeaderLength,
				  "Gvcp request header size should be 8 bytes");

	/// @brief Gvcp acknowledge header
	/// @note refer to the spec "15.2 Acknowledge Header"
	struct GvcpAckHeader
	{
		GvcpResponseStatus status = GvcpResponseStatus::Unknown;
		GvcpCommand command = GvcpCommand::Unknown;
		uint16_t dataSize = 0;
		uint16_t ackId = 0;
	};
	static_assert(sizeof(GvcpAckHeader) == detail::kGvcpAckHeaderLength, "Gvcp ack header size should be 8 bytes");

	/// @brief Gvcp discovery acknowledge body
	/// @note refer to the spec "16.1.2 DISCOVERY_ACK"
	struct GvcpDiscovery
	{
		GvcpAckHeader header;
		uint16_t versionMajor = 0;
		uint16_t versionMinor = 0;
		uint32_t deviceMode = 0;
		uint16_t reserved = 0;
		char macAddress[6] = {0};
		uint32_t supportedIpConfigOptions = 0;
		uint32_t ipConfigCurrent = 0;
		uint8_t reserved2[12] = {0};
		uint32_t ipAddress = 0;
		uint8_t reserved3[12];
		uint32_t subnetMask = 0;
		uint8_t reserved4[12] = {0};
		uint32_t defaultGatewayIpAddress = 0;
		char manufacturerName[32] = {0};
		char modelName[32] = {0};
		char deviceVersion[32] = {0};
		char manufacturerSpecificInformation[48] = {0};
		char serialNumber[16] = {0};
		char userDefinedName[16] = {0};
	};
	static_assert(sizeof(GvcpDiscovery) == detail::kGvcpDiscoveryLength, "Gvcp ack body size should be 256 bytes");
#pragma pack(pop)

	/**
	 * @class GvcpLayer
	 * A class representing the GigE Vision protocol(Gvcp).
	 * The class is implemented according to the GigE Vision specification 2.0.
	 * @see https://en.wikipedia.org/wiki/GigE_Vision
	 * @note The class cannot be instantiated directly.
	 */
	class GvcpLayer : public Layer
	{
	  public:
		/**
		 * A static method that checks whether the port is considered as GVCP
		 * @param[in] port The port number to be checked
		 */
		static bool isGvcpPort(uint16_t port) { return port == 3956; }

		/**
		 * @brief Get the magic number
		 * @return uint8_t The magic number
		 */
		static bool verifyRequest(const uint8_t *data) { return data[0] == detail::kGvcpMagicNumber; };

	  protected:
		GvcpLayer() = default;

		/**
		 * @brief Construct a new GvcpLayer object
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		GvcpLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet);

		// implement Layer's abstract methods
		void parseNextLayer() override {}

		// implement Layer's abstract methods
		void computeCalculateFields() override {}

		// implement Layer's abstract methods
		OsiModelLayer getOsiModelLayer() const override { return OsiModelLayer::OsiModelApplicationLayer; }
	};

	class GvcpRequestLayer : public GvcpLayer
	{
	  public:
		/**
		 * @brief Construct a new GvcpLayer object
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		explicit GvcpRequestLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet);

		/**
		 * @brief Construct a new GvcpRequestLayer object
		 * @param[in] command The command
		 * @param[in] data A pointer to the data, optional
		 * @param[in] dataSize The size of the data in bytes, optional
		 * @param[in] flag The flag, optional
		 * @param[in] requestId The request ID, it should be always larger than 1, optional
		 */
		explicit GvcpRequestLayer(GvcpCommand command, const uint8_t *data = nullptr, uint16_t dataSize = 0,
								  GvcpFlag flag = 0, uint16_t requestId = 1);

		/**
		 * @brief Get the header object
		 * @return GvcpRequestHeader* A pointer to the header object
		 */
		GvcpRequestHeader *getGvcpHeader() const { return m_Header; }

		// implement Layer's abstract methods
		std::string toString() const override { return ""; };

		// implement Layer's abstract methods
		size_t getHeaderLen() const override { return sizeof(GvcpRequestHeader); }

	  private:
		GvcpRequestHeader *m_Header;
	};

	class GvcpAcknowledgeLayer : public GvcpLayer
	{
	  public:
		/**
		 * @brief Construct a new GvcpLayer object
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		explicit GvcpAcknowledgeLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet);

		/**
		 * @brief Construct a new GvcpAcknowledgeLayer object
		 * @param[in] status The response status
		 * @param[in] command The command
		 * @param[in] data A pointer to the data, optional
		 * @param[in] dataSize The size of the data in bytes, optional
		 * @param[in] ackId The acknowledge ID, optional
		 */
		explicit GvcpAcknowledgeLayer(GvcpResponseStatus status, GvcpCommand command, const uint8_t *data = nullptr,
									  uint16_t dataSize = 0, uint16_t ackId = 0);

		/**
		 * @brief Get the header object
		 * @return GvcpAckHeader* A pointer to the header object
		 */
		GvcpAckHeader *getGvcpHeader() const { return m_Header; }

		// implement Layer's abstract methods
		std::string toString() const override { return ""; };

		// implement Layer's abstract methods
		size_t getHeaderLen() const override { return sizeof(GvcpAckHeader); }

	  private:
		GvcpAckHeader *m_Header;
	};
} // namespace pcpp
