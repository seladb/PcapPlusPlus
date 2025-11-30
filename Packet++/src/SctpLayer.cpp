#define LOG_MODULE PacketLogModuleSctpLayer

#include "EndianPortable.h"
#include "SctpLayer.h"
#include "PayloadLayer.h"
#include "Logger.h"
#include <sstream>
#include <cstring>

namespace pcpp
{
	// ==================== CRC32c Implementation ====================
	// CRC32c (Castagnoli) polynomial: 0x1EDC6F41
	// This is the polynomial used by SCTP as defined in RFC 9260

	namespace
	{
		// CRC32c lookup table (Castagnoli polynomial)
		// Pre-computed for polynomial 0x1EDC6F41 (reflected)
		constexpr uint32_t crc32cTable[256] = {
			0x00000000, 0xF26B8303, 0xE13B70F7, 0x1350F3F4, 0xC79A971F, 0x35F1141C, 0x26A1E7E8, 0xD4CA64EB, 0x8AD958CF,
			0x78B2DBCC, 0x6BE22838, 0x9989AB3B, 0x4D43CFD0, 0xBF284CD3, 0xAC78BF27, 0x5E133C24, 0x105EC76F, 0xE235446C,
			0xF165B798, 0x030E349B, 0xD7C45070, 0x25AFD373, 0x36FF2087, 0xC494A384, 0x9A879FA0, 0x68EC1CA3, 0x7BBCEF57,
			0x89D76C54, 0x5D1D08BF, 0xAF768BBC, 0xBC267848, 0x4E4DFB4B, 0x20BD8EDE, 0xD2D60DDD, 0xC186FE29, 0x33ED7D2A,
			0xE72719C1, 0x154C9AC2, 0x061C6936, 0xF477EA35, 0xAA64D611, 0x580F5512, 0x4B5FA6E6, 0xB93425E5, 0x6DFE410E,
			0x9F95C20D, 0x8CC531F9, 0x7EAEB2FA, 0x30E349B1, 0xC288CAB2, 0xD1D83946, 0x23B3BA45, 0xF779DEAE, 0x05125DAD,
			0x1642AE59, 0xE4292D5A, 0xBA3A117E, 0x4851927D, 0x5B016189, 0xA96AE28A, 0x7DA08661, 0x8FCB0562, 0x9C9BF696,
			0x6EF07595, 0x417B1DBC, 0xB3109EBF, 0xA0406D4B, 0x522BEE48, 0x86E18AA3, 0x748A09A0, 0x67DAFA54, 0x95B17957,
			0xCBA24573, 0x39C9C670, 0x2A993584, 0xD8F2B687, 0x0C38D26C, 0xFE53516F, 0xED03A29B, 0x1F682198, 0x5125DAD3,
			0xA34E59D0, 0xB01EAA24, 0x42752927, 0x96BF4DCC, 0x64D4CECF, 0x77843D3B, 0x85EFBE38, 0xDBFC821C, 0x2997011F,
			0x3AC7F2EB, 0xC8AC71E8, 0x1C661503, 0xEE0D9600, 0xFD5D65F4, 0x0F36E6F7, 0x61C69362, 0x93AD1061, 0x80FDE395,
			0x72966096, 0xA65C047D, 0x5437877E, 0x4767748A, 0xB50CF789, 0xEB1FCBAD, 0x197448AE, 0x0A24BB5A, 0xF84F3859,
			0x2C855CB2, 0xDEEEDFB1, 0xCDBE2C45, 0x3FD5AF46, 0x7198540D, 0x83F3D70E, 0x90A324FA, 0x62C8A7F9, 0xB602C312,
			0x44694011, 0x5739B3E5, 0xA55230E6, 0xFB410CC2, 0x092A8FC1, 0x1A7A7C35, 0xE811FF36, 0x3CDB9BDD, 0xCEB018DE,
			0xDDE0EB2A, 0x2F8B6829, 0x82F63B78, 0x709DB87B, 0x63CD4B8F, 0x91A6C88C, 0x456CAC67, 0xB7072F64, 0xA457DC90,
			0x563C5F93, 0x082F63B7, 0xFA44E0B4, 0xE9141340, 0x1B7F9043, 0xCFB5F4A8, 0x3DDE77AB, 0x2E8E845F, 0xDCE5075C,
			0x92A8FC17, 0x60C37F14, 0x73938CE0, 0x81F80FE3, 0x55326B08, 0xA759E80B, 0xB4091BFF, 0x466298FC, 0x1871A4D8,
			0xEA1A27DB, 0xF94AD42F, 0x0B21572C, 0xDFEB33C7, 0x2D80B0C4, 0x3ED04330, 0xCCBBC033, 0xA24BB5A6, 0x502036A5,
			0x4370C551, 0xB11B4652, 0x65D122B9, 0x97BAA1BA, 0x84EA524E, 0x7681D14D, 0x2892ED69, 0xDAF96E6A, 0xC9A99D9E,
			0x3BC21E9D, 0xEF087A76, 0x1D63F975, 0x0E330A81, 0xFC588982, 0xB21572C9, 0x407EF1CA, 0x532E023E, 0xA145813D,
			0x758FE5D6, 0x87E466D5, 0x94B49521, 0x66DF1622, 0x38CC2A06, 0xCAA7A905, 0xD9F75AF1, 0x2B9CD9F2, 0xFF56BD19,
			0x0D3D3E1A, 0x1E6DCDEE, 0xEC064EED, 0xC38D26C4, 0x31E6A5C7, 0x22B65633, 0xD0DDD530, 0x0417B1DB, 0xF67C32D8,
			0xE52CC12C, 0x1747422F, 0x49547E0B, 0xBB3FFD08, 0xA86F0EFC, 0x5A048DFF, 0x8ECEE914, 0x7CA56A17, 0x6FF599E3,
			0x9D9E1AE0, 0xD3D3E1AB, 0x21B862A8, 0x32E8915C, 0xC083125F, 0x144976B4, 0xE622F5B7, 0xF5720643, 0x07198540,
			0x590AB964, 0xAB613A67, 0xB831C993, 0x4A5A4A90, 0x9E902E7B, 0x6CFBAD78, 0x7FAB5E8C, 0x8DC0DD8F, 0xE330A81A,
			0x115B2B19, 0x020BD8ED, 0xF0605BEE, 0x24AA3F05, 0xD6C1BC06, 0xC5914FF2, 0x37FACCF1, 0x69E9F0D5, 0x9B8273D6,
			0x88D28022, 0x7AB90321, 0xAE7367CA, 0x5C18E4C9, 0x4F48173D, 0xBD23943E, 0xF36E6F75, 0x0105EC76, 0x12551F82,
			0xE03E9C81, 0x34F4F86A, 0xC69F7B69, 0xD5CF889D, 0x27A40B9E, 0x79B737BA, 0x8BDCB4B9, 0x988C474D, 0x6AE7C44E,
			0xBE2DA0A5, 0x4C4623A6, 0x5F16D052, 0xAD7D5351
		};

		/// Calculate CRC32c using software lookup table
		uint32_t calculateCrc32cSoftware(const uint8_t* data, size_t length)
		{
			uint32_t crc = 0xFFFFFFFF;
			for (size_t i = 0; i < length; ++i)
			{
				crc = crc32cTable[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
			}
			return crc ^ 0xFFFFFFFF;
		}
	}  // anonymous namespace

	uint32_t calculateSctpCrc32c(const uint8_t* data, size_t length)
	{
		return calculateCrc32cSoftware(data, length);
	}

	// ==================== SctpChunk Implementation ====================

	SctpChunkType SctpChunk::getChunkType() const
	{
		if (m_Data == nullptr)
			return SctpChunkType::UNKNOWN;

		uint8_t type = m_Data->type;
		switch (type)
		{
		case 0:
			return SctpChunkType::DATA;
		case 1:
			return SctpChunkType::INIT;
		case 2:
			return SctpChunkType::INIT_ACK;
		case 3:
			return SctpChunkType::SACK;
		case 4:
			return SctpChunkType::HEARTBEAT;
		case 5:
			return SctpChunkType::HEARTBEAT_ACK;
		case 6:
			return SctpChunkType::ABORT;
		case 7:
			return SctpChunkType::SHUTDOWN;
		case 8:
			return SctpChunkType::SHUTDOWN_ACK;
		case 9:
			return SctpChunkType::SCTP_ERROR;
		case 10:
			return SctpChunkType::COOKIE_ECHO;
		case 11:
			return SctpChunkType::COOKIE_ACK;
		case 12:
			return SctpChunkType::ECNE;
		case 13:
			return SctpChunkType::CWR;
		case 14:
			return SctpChunkType::SHUTDOWN_COMPLETE;
		case 15:
			return SctpChunkType::AUTH;
		case 16:
			return SctpChunkType::NR_SACK;
		case 64:
			return SctpChunkType::I_DATA;
		case 128:
			return SctpChunkType::ASCONF_ACK;
		case 130:
			return SctpChunkType::RE_CONFIG;
		case 132:
			return SctpChunkType::PAD;
		case 192:
			return SctpChunkType::FORWARD_TSN;
		case 193:
			return SctpChunkType::ASCONF;
		case 194:
			return SctpChunkType::I_FORWARD_TSN;
		default:
			return SctpChunkType::UNKNOWN;
		}
	}

	uint8_t SctpChunk::getChunkTypeAsInt() const
	{
		if (m_Data == nullptr)
			return 255;
		return m_Data->type;
	}

	uint8_t SctpChunk::getFlags() const
	{
		if (m_Data == nullptr)
			return 0;
		return m_Data->flags;
	}

	uint16_t SctpChunk::getLength() const
	{
		if (m_Data == nullptr)
			return 0;
		return be16toh(m_Data->length);
	}

	size_t SctpChunk::getTotalSize() const
	{
		uint16_t len = getLength();
		if (len == 0)
			return 0;
		// Pad to 4-byte boundary
		return (len + 3) & ~3;
	}

	uint8_t* SctpChunk::getValue() const
	{
		if (m_Data == nullptr)
			return nullptr;
		return reinterpret_cast<uint8_t*>(m_Data) + sizeof(sctp_chunk_hdr);
	}

	size_t SctpChunk::getValueSize() const
	{
		uint16_t len = getLength();
		if (len <= sizeof(sctp_chunk_hdr))
			return 0;
		return len - sizeof(sctp_chunk_hdr);
	}

	bool SctpChunk::isFlagSet(uint8_t flagBit) const
	{
		return (getFlags() & flagBit) != 0;
	}

	std::string SctpChunk::getChunkTypeName() const
	{
		switch (getChunkType())
		{
		case SctpChunkType::DATA:
			return "DATA";
		case SctpChunkType::INIT:
			return "INIT";
		case SctpChunkType::INIT_ACK:
			return "INIT-ACK";
		case SctpChunkType::SACK:
			return "SACK";
		case SctpChunkType::HEARTBEAT:
			return "HEARTBEAT";
		case SctpChunkType::HEARTBEAT_ACK:
			return "HEARTBEAT-ACK";
		case SctpChunkType::ABORT:
			return "ABORT";
		case SctpChunkType::SHUTDOWN:
			return "SHUTDOWN";
		case SctpChunkType::SHUTDOWN_ACK:
			return "SHUTDOWN-ACK";
		case SctpChunkType::SCTP_ERROR:
			return "ERROR";
		case SctpChunkType::COOKIE_ECHO:
			return "COOKIE-ECHO";
		case SctpChunkType::COOKIE_ACK:
			return "COOKIE-ACK";
		case SctpChunkType::ECNE:
			return "ECNE";
		case SctpChunkType::CWR:
			return "CWR";
		case SctpChunkType::SHUTDOWN_COMPLETE:
			return "SHUTDOWN-COMPLETE";
		case SctpChunkType::AUTH:
			return "AUTH";
		case SctpChunkType::NR_SACK:
			return "NR-SACK";
		case SctpChunkType::I_DATA:
			return "I-DATA";
		case SctpChunkType::ASCONF_ACK:
			return "ASCONF-ACK";
		case SctpChunkType::RE_CONFIG:
			return "RE-CONFIG";
		case SctpChunkType::PAD:
			return "PAD";
		case SctpChunkType::FORWARD_TSN:
			return "FORWARD-TSN";
		case SctpChunkType::ASCONF:
			return "ASCONF";
		case SctpChunkType::I_FORWARD_TSN:
			return "I-FORWARD-TSN";
		default:
			return "UNKNOWN";
		}
	}

	// ==================== SctpDataChunkView Implementation ====================

	uint32_t SctpDataChunkView::getTsn() const
	{
		if (!isValid())
			return 0;
		auto* dataChunk = reinterpret_cast<const sctp_data_chunk*>(m_Chunk.getRecordBasePtr());
		return be32toh(dataChunk->tsn);
	}

	uint16_t SctpDataChunkView::getStreamId() const
	{
		if (!isValid())
			return 0;
		auto* dataChunk = reinterpret_cast<const sctp_data_chunk*>(m_Chunk.getRecordBasePtr());
		return be16toh(dataChunk->streamId);
	}

	uint16_t SctpDataChunkView::getSequenceNumber() const
	{
		if (!isValid())
			return 0;
		auto* dataChunk = reinterpret_cast<const sctp_data_chunk*>(m_Chunk.getRecordBasePtr());
		return be16toh(dataChunk->streamSeqNum);
	}

	uint32_t SctpDataChunkView::getPpid() const
	{
		if (!isValid())
			return 0;
		auto* dataChunk = reinterpret_cast<const sctp_data_chunk*>(m_Chunk.getRecordBasePtr());
		return be32toh(dataChunk->ppid);
	}

	uint8_t* SctpDataChunkView::getUserData() const
	{
		if (!isValid())
			return nullptr;
		return m_Chunk.getRecordBasePtr() + sizeof(sctp_data_chunk);
	}

	size_t SctpDataChunkView::getUserDataLength() const
	{
		if (!isValid())
			return 0;
		uint16_t len = m_Chunk.getLength();
		if (len <= sizeof(sctp_data_chunk))
			return 0;
		return len - sizeof(sctp_data_chunk);
	}

	bool SctpDataChunkView::isBeginFragment() const
	{
		return m_Chunk.isFlagSet(SctpDataChunkFlags::BEGIN_FRAGMENT);
	}

	bool SctpDataChunkView::isEndFragment() const
	{
		return m_Chunk.isFlagSet(SctpDataChunkFlags::END_FRAGMENT);
	}

	bool SctpDataChunkView::isUnordered() const
	{
		return m_Chunk.isFlagSet(SctpDataChunkFlags::UNORDERED);
	}

	bool SctpDataChunkView::isImmediate() const
	{
		return m_Chunk.isFlagSet(SctpDataChunkFlags::IMMEDIATE);
	}

	// ==================== SctpInitChunkView Implementation ====================

	uint32_t SctpInitChunkView::getInitiateTag() const
	{
		if (!isValid())
			return 0;
		auto* initChunk = reinterpret_cast<const sctp_init_chunk*>(m_Chunk.getRecordBasePtr());
		return be32toh(initChunk->initiateTag);
	}

	uint32_t SctpInitChunkView::getArwnd() const
	{
		if (!isValid())
			return 0;
		auto* initChunk = reinterpret_cast<const sctp_init_chunk*>(m_Chunk.getRecordBasePtr());
		return be32toh(initChunk->arwnd);
	}

	uint16_t SctpInitChunkView::getNumOutboundStreams() const
	{
		if (!isValid())
			return 0;
		auto* initChunk = reinterpret_cast<const sctp_init_chunk*>(m_Chunk.getRecordBasePtr());
		return be16toh(initChunk->numOutboundStreams);
	}

	uint16_t SctpInitChunkView::getNumInboundStreams() const
	{
		if (!isValid())
			return 0;
		auto* initChunk = reinterpret_cast<const sctp_init_chunk*>(m_Chunk.getRecordBasePtr());
		return be16toh(initChunk->numInboundStreams);
	}

	uint32_t SctpInitChunkView::getInitialTsn() const
	{
		if (!isValid())
			return 0;
		auto* initChunk = reinterpret_cast<const sctp_init_chunk*>(m_Chunk.getRecordBasePtr());
		return be32toh(initChunk->initialTsn);
	}

	uint8_t* SctpInitChunkView::getFirstParameter() const
	{
		if (!isValid())
			return nullptr;
		uint16_t len = m_Chunk.getLength();
		if (len <= sizeof(sctp_init_chunk))
			return nullptr;
		return m_Chunk.getRecordBasePtr() + sizeof(sctp_init_chunk);
	}

	size_t SctpInitChunkView::getParametersLength() const
	{
		if (!isValid())
			return 0;
		uint16_t len = m_Chunk.getLength();
		if (len <= sizeof(sctp_init_chunk))
			return 0;
		return len - sizeof(sctp_init_chunk);
	}

	// ==================== SctpInitAckChunkView Implementation ====================

	uint32_t SctpInitAckChunkView::getInitiateTag() const
	{
		if (!isValid())
			return 0;
		auto* initChunk = reinterpret_cast<const sctp_init_chunk*>(m_Chunk.getRecordBasePtr());
		return be32toh(initChunk->initiateTag);
	}

	uint32_t SctpInitAckChunkView::getArwnd() const
	{
		if (!isValid())
			return 0;
		auto* initChunk = reinterpret_cast<const sctp_init_chunk*>(m_Chunk.getRecordBasePtr());
		return be32toh(initChunk->arwnd);
	}

	uint16_t SctpInitAckChunkView::getNumOutboundStreams() const
	{
		if (!isValid())
			return 0;
		auto* initChunk = reinterpret_cast<const sctp_init_chunk*>(m_Chunk.getRecordBasePtr());
		return be16toh(initChunk->numOutboundStreams);
	}

	uint16_t SctpInitAckChunkView::getNumInboundStreams() const
	{
		if (!isValid())
			return 0;
		auto* initChunk = reinterpret_cast<const sctp_init_chunk*>(m_Chunk.getRecordBasePtr());
		return be16toh(initChunk->numInboundStreams);
	}

	uint32_t SctpInitAckChunkView::getInitialTsn() const
	{
		if (!isValid())
			return 0;
		auto* initChunk = reinterpret_cast<const sctp_init_chunk*>(m_Chunk.getRecordBasePtr());
		return be32toh(initChunk->initialTsn);
	}

	uint8_t* SctpInitAckChunkView::getFirstParameter() const
	{
		if (!isValid())
			return nullptr;
		uint16_t len = m_Chunk.getLength();
		if (len <= sizeof(sctp_init_chunk))
			return nullptr;
		return m_Chunk.getRecordBasePtr() + sizeof(sctp_init_chunk);
	}

	size_t SctpInitAckChunkView::getParametersLength() const
	{
		if (!isValid())
			return 0;
		uint16_t len = m_Chunk.getLength();
		if (len <= sizeof(sctp_init_chunk))
			return 0;
		return len - sizeof(sctp_init_chunk);
	}

	// ==================== SctpSackChunkView Implementation ====================

	uint32_t SctpSackChunkView::getCumulativeTsnAck() const
	{
		if (!isValid())
			return 0;
		auto* sackChunk = reinterpret_cast<const sctp_sack_chunk*>(m_Chunk.getRecordBasePtr());
		return be32toh(sackChunk->cumulativeTsnAck);
	}

	uint32_t SctpSackChunkView::getArwnd() const
	{
		if (!isValid())
			return 0;
		auto* sackChunk = reinterpret_cast<const sctp_sack_chunk*>(m_Chunk.getRecordBasePtr());
		return be32toh(sackChunk->arwnd);
	}

	uint16_t SctpSackChunkView::getNumGapBlocks() const
	{
		if (!isValid())
			return 0;
		auto* sackChunk = reinterpret_cast<const sctp_sack_chunk*>(m_Chunk.getRecordBasePtr());
		return be16toh(sackChunk->numGapBlocks);
	}

	uint16_t SctpSackChunkView::getNumDupTsns() const
	{
		if (!isValid())
			return 0;
		auto* sackChunk = reinterpret_cast<const sctp_sack_chunk*>(m_Chunk.getRecordBasePtr());
		return be16toh(sackChunk->numDupTsns);
	}

	std::vector<sctp_gap_ack_block> SctpSackChunkView::getGapBlocks() const
	{
		std::vector<sctp_gap_ack_block> result;
		if (!isValid())
			return result;

		auto* sackChunk = reinterpret_cast<const sctp_sack_chunk*>(m_Chunk.getRecordBasePtr());
		uint16_t numGapBlocks = be16toh(sackChunk->numGapBlocks);

		const uint8_t* gapBlocksPtr = m_Chunk.getRecordBasePtr() + sizeof(sctp_sack_chunk);
		size_t availableLen = m_Chunk.getLength() - sizeof(sctp_sack_chunk);

		for (uint16_t i = 0; i < numGapBlocks && (i + 1) * sizeof(sctp_gap_ack_block) <= availableLen; ++i)
		{
			const auto* block =
			    reinterpret_cast<const sctp_gap_ack_block*>(gapBlocksPtr + i * sizeof(sctp_gap_ack_block));
			sctp_gap_ack_block gapBlock;
			gapBlock.start = be16toh(block->start);
			gapBlock.end = be16toh(block->end);
			result.push_back(gapBlock);
		}

		return result;
	}

	std::vector<uint32_t> SctpSackChunkView::getDupTsns() const
	{
		std::vector<uint32_t> result;
		if (!isValid())
			return result;

		auto* sackChunk = reinterpret_cast<const sctp_sack_chunk*>(m_Chunk.getRecordBasePtr());
		uint16_t numGapBlocks = be16toh(sackChunk->numGapBlocks);
		uint16_t numDupTsns = be16toh(sackChunk->numDupTsns);

		size_t dupTsnsOffset = sizeof(sctp_sack_chunk) + numGapBlocks * sizeof(sctp_gap_ack_block);
		const uint8_t* dupTsnsPtr = m_Chunk.getRecordBasePtr() + dupTsnsOffset;
		size_t availableLen = m_Chunk.getLength() - dupTsnsOffset;

		for (uint16_t i = 0; i < numDupTsns && (i + 1) * sizeof(uint32_t) <= availableLen; ++i)
		{
			const auto* tsn = reinterpret_cast<const uint32_t*>(dupTsnsPtr + i * sizeof(uint32_t));
			result.push_back(be32toh(*tsn));
		}

		return result;
	}

	// ==================== SctpHeartbeatChunkView Implementation ====================

	uint8_t* SctpHeartbeatChunkView::getInfo() const
	{
		if (!isValid())
			return nullptr;
		uint16_t len = m_Chunk.getLength();
		if (len <= sizeof(sctp_chunk_hdr))
			return nullptr;
		return m_Chunk.getRecordBasePtr() + sizeof(sctp_chunk_hdr);
	}

	size_t SctpHeartbeatChunkView::getInfoLength() const
	{
		if (!isValid())
			return 0;
		uint16_t len = m_Chunk.getLength();
		if (len <= sizeof(sctp_chunk_hdr))
			return 0;
		return len - sizeof(sctp_chunk_hdr);
	}

	// ==================== SctpHeartbeatAckChunkView Implementation ====================

	uint8_t* SctpHeartbeatAckChunkView::getInfo() const
	{
		if (!isValid())
			return nullptr;
		uint16_t len = m_Chunk.getLength();
		if (len <= sizeof(sctp_chunk_hdr))
			return nullptr;
		return m_Chunk.getRecordBasePtr() + sizeof(sctp_chunk_hdr);
	}

	size_t SctpHeartbeatAckChunkView::getInfoLength() const
	{
		if (!isValid())
			return 0;
		uint16_t len = m_Chunk.getLength();
		if (len <= sizeof(sctp_chunk_hdr))
			return 0;
		return len - sizeof(sctp_chunk_hdr);
	}

	// ==================== SctpAbortChunkView Implementation ====================

	bool SctpAbortChunkView::isTBitSet() const
	{
		if (!isValid())
			return false;
		return (m_Chunk.getFlags() & 0x01) != 0;
	}

	uint8_t* SctpAbortChunkView::getFirstErrorCause() const
	{
		if (!isValid())
			return nullptr;
		uint16_t len = m_Chunk.getLength();
		if (len <= sizeof(sctp_chunk_hdr))
			return nullptr;
		return m_Chunk.getRecordBasePtr() + sizeof(sctp_chunk_hdr);
	}

	size_t SctpAbortChunkView::getErrorCausesLength() const
	{
		if (!isValid())
			return 0;
		uint16_t len = m_Chunk.getLength();
		if (len <= sizeof(sctp_chunk_hdr))
			return 0;
		return len - sizeof(sctp_chunk_hdr);
	}

	// ==================== SctpErrorChunkView Implementation ====================

	uint8_t* SctpErrorChunkView::getFirstCause() const
	{
		if (!isValid())
			return nullptr;
		uint16_t len = m_Chunk.getLength();
		if (len <= sizeof(sctp_chunk_hdr))
			return nullptr;
		return m_Chunk.getRecordBasePtr() + sizeof(sctp_chunk_hdr);
	}

	size_t SctpErrorChunkView::getCausesLength() const
	{
		if (!isValid())
			return 0;
		uint16_t len = m_Chunk.getLength();
		if (len <= sizeof(sctp_chunk_hdr))
			return 0;
		return len - sizeof(sctp_chunk_hdr);
	}

	// ==================== SctpShutdownChunkView Implementation ====================

	uint32_t SctpShutdownChunkView::getCumulativeTsnAck() const
	{
		if (!isValid())
			return 0;
		// SHUTDOWN chunk has 4-byte header + 4-byte cumulative TSN ack
		auto* shutdownData = reinterpret_cast<const uint32_t*>(m_Chunk.getRecordBasePtr() + sizeof(sctp_chunk_hdr));
		return be32toh(*shutdownData);
	}

	// ==================== SctpShutdownCompleteChunkView Implementation ====================

	bool SctpShutdownCompleteChunkView::isTBitSet() const
	{
		if (!isValid())
			return false;
		return (m_Chunk.getFlags() & 0x01) != 0;
	}

	// ==================== SctpCookieEchoChunkView Implementation ====================

	uint8_t* SctpCookieEchoChunkView::getCookie() const
	{
		if (!isValid())
			return nullptr;
		uint16_t len = m_Chunk.getLength();
		if (len <= sizeof(sctp_chunk_hdr))
			return nullptr;
		return m_Chunk.getRecordBasePtr() + sizeof(sctp_chunk_hdr);
	}

	size_t SctpCookieEchoChunkView::getCookieLength() const
	{
		if (!isValid())
			return 0;
		uint16_t len = m_Chunk.getLength();
		if (len <= sizeof(sctp_chunk_hdr))
			return 0;
		return len - sizeof(sctp_chunk_hdr);
	}

	// ==================== SctpEcneChunkView Implementation ====================

	uint32_t SctpEcneChunkView::getLowestTsn() const
	{
		if (!isValid())
			return 0;
		// ECNE chunk has 4-byte header + 4-byte lowest TSN
		auto* ecneData = reinterpret_cast<const uint32_t*>(m_Chunk.getRecordBasePtr() + sizeof(sctp_chunk_hdr));
		return be32toh(*ecneData);
	}

	// ==================== SctpCwrChunkView Implementation ====================

	uint32_t SctpCwrChunkView::getLowestTsn() const
	{
		if (!isValid())
			return 0;
		// CWR chunk has 4-byte header + 4-byte lowest TSN
		auto* cwrData = reinterpret_cast<const uint32_t*>(m_Chunk.getRecordBasePtr() + sizeof(sctp_chunk_hdr));
		return be32toh(*cwrData);
	}

	// ==================== SctpAuthChunkView Implementation ====================

	uint16_t SctpAuthChunkView::getSharedKeyId() const
	{
		if (!isValid())
			return 0;
		auto* authChunk = reinterpret_cast<const sctp_auth_chunk*>(m_Chunk.getRecordBasePtr());
		return be16toh(authChunk->sharedKeyId);
	}

	uint16_t SctpAuthChunkView::getHmacId() const
	{
		if (!isValid())
			return 0;
		auto* authChunk = reinterpret_cast<const sctp_auth_chunk*>(m_Chunk.getRecordBasePtr());
		return be16toh(authChunk->hmacId);
	}

	uint8_t* SctpAuthChunkView::getHmacData() const
	{
		if (!isValid())
			return nullptr;
		uint16_t len = m_Chunk.getLength();
		if (len <= sizeof(sctp_auth_chunk))
			return nullptr;
		return m_Chunk.getRecordBasePtr() + sizeof(sctp_auth_chunk);
	}

	size_t SctpAuthChunkView::getHmacLength() const
	{
		if (!isValid())
			return 0;
		uint16_t len = m_Chunk.getLength();
		if (len <= sizeof(sctp_auth_chunk))
			return 0;
		return len - sizeof(sctp_auth_chunk);
	}

	// ==================== SctpForwardTsnChunkView Implementation ====================

	uint32_t SctpForwardTsnChunkView::getNewCumulativeTsn() const
	{
		if (!isValid())
			return 0;
		auto* fwdChunk = reinterpret_cast<const sctp_forward_tsn_chunk*>(m_Chunk.getRecordBasePtr());
		return be32toh(fwdChunk->newCumulativeTsn);
	}

	size_t SctpForwardTsnChunkView::getStreamCount() const
	{
		if (!isValid())
			return 0;
		uint16_t len = m_Chunk.getLength();
		if (len <= sizeof(sctp_forward_tsn_chunk))
			return 0;
		return (len - sizeof(sctp_forward_tsn_chunk)) / sizeof(sctp_forward_tsn_stream);
	}

	std::vector<sctp_forward_tsn_stream> SctpForwardTsnChunkView::getStreams() const
	{
		std::vector<sctp_forward_tsn_stream> result;
		if (!isValid())
			return result;

		size_t count = getStreamCount();
		const uint8_t* streamPtr = m_Chunk.getRecordBasePtr() + sizeof(sctp_forward_tsn_chunk);

		for (size_t i = 0; i < count; ++i)
		{
			const auto* entry =
			    reinterpret_cast<const sctp_forward_tsn_stream*>(streamPtr + i * sizeof(sctp_forward_tsn_stream));
			sctp_forward_tsn_stream stream;
			stream.streamId = be16toh(entry->streamId);
			stream.streamSeq = be16toh(entry->streamSeq);
			result.push_back(stream);
		}

		return result;
	}

	// ==================== SctpIDataChunkView Implementation ====================

	uint32_t SctpIDataChunkView::getTsn() const
	{
		if (!isValid())
			return 0;
		auto* idataChunk = reinterpret_cast<const sctp_idata_chunk*>(m_Chunk.getRecordBasePtr());
		return be32toh(idataChunk->tsn);
	}

	uint16_t SctpIDataChunkView::getStreamId() const
	{
		if (!isValid())
			return 0;
		auto* idataChunk = reinterpret_cast<const sctp_idata_chunk*>(m_Chunk.getRecordBasePtr());
		return be16toh(idataChunk->streamId);
	}

	uint16_t SctpIDataChunkView::getReserved() const
	{
		if (!isValid())
			return 0;
		auto* idataChunk = reinterpret_cast<const sctp_idata_chunk*>(m_Chunk.getRecordBasePtr());
		return be16toh(idataChunk->reserved);
	}

	uint32_t SctpIDataChunkView::getMessageId() const
	{
		if (!isValid())
			return 0;
		auto* idataChunk = reinterpret_cast<const sctp_idata_chunk*>(m_Chunk.getRecordBasePtr());
		return be32toh(idataChunk->mid);
	}

	uint32_t SctpIDataChunkView::getPpidOrFsn() const
	{
		if (!isValid())
			return 0;
		auto* idataChunk = reinterpret_cast<const sctp_idata_chunk*>(m_Chunk.getRecordBasePtr());
		return be32toh(idataChunk->ppidOrFsn);
	}

	uint8_t* SctpIDataChunkView::getUserData() const
	{
		if (!isValid())
			return nullptr;
		return m_Chunk.getRecordBasePtr() + sizeof(sctp_idata_chunk);
	}

	size_t SctpIDataChunkView::getUserDataLength() const
	{
		if (!isValid())
			return 0;
		uint16_t len = m_Chunk.getLength();
		if (len <= sizeof(sctp_idata_chunk))
			return 0;
		return len - sizeof(sctp_idata_chunk);
	}

	bool SctpIDataChunkView::isBeginFragment() const
	{
		return m_Chunk.isFlagSet(SctpDataChunkFlags::BEGIN_FRAGMENT);
	}

	bool SctpIDataChunkView::isEndFragment() const
	{
		return m_Chunk.isFlagSet(SctpDataChunkFlags::END_FRAGMENT);
	}

	bool SctpIDataChunkView::isUnordered() const
	{
		return m_Chunk.isFlagSet(SctpDataChunkFlags::UNORDERED);
	}

	bool SctpIDataChunkView::isImmediate() const
	{
		return m_Chunk.isFlagSet(SctpDataChunkFlags::IMMEDIATE);
	}

	// ==================== SctpIForwardTsnChunkView Implementation ====================

	uint32_t SctpIForwardTsnChunkView::getNewCumulativeTsn() const
	{
		if (!isValid())
			return 0;
		auto* ifwdChunk = reinterpret_cast<const sctp_iforward_tsn_chunk*>(m_Chunk.getRecordBasePtr());
		return be32toh(ifwdChunk->newCumulativeTsn);
	}

	size_t SctpIForwardTsnChunkView::getStreamCount() const
	{
		if (!isValid())
			return 0;
		uint16_t len = m_Chunk.getLength();
		if (len <= sizeof(sctp_iforward_tsn_chunk))
			return 0;
		return (len - sizeof(sctp_iforward_tsn_chunk)) / sizeof(sctp_iforward_tsn_stream);
	}

	std::vector<sctp_iforward_tsn_stream> SctpIForwardTsnChunkView::getStreams() const
	{
		std::vector<sctp_iforward_tsn_stream> result;
		if (!isValid())
			return result;

		size_t count = getStreamCount();
		const uint8_t* streamPtr = m_Chunk.getRecordBasePtr() + sizeof(sctp_iforward_tsn_chunk);

		for (size_t i = 0; i < count; ++i)
		{
			const auto* entry =
			    reinterpret_cast<const sctp_iforward_tsn_stream*>(streamPtr + i * sizeof(sctp_iforward_tsn_stream));
			sctp_iforward_tsn_stream stream;
			stream.streamId = be16toh(entry->streamId);
			stream.reserved = be16toh(entry->reserved);
			stream.mid = be32toh(entry->mid);
			result.push_back(stream);
		}

		return result;
	}

	// ==================== SctpAsconfChunkView Implementation ====================

	uint32_t SctpAsconfChunkView::getSerialNumber() const
	{
		if (!isValid())
			return 0;
		auto* asconfChunk = reinterpret_cast<const sctp_asconf_chunk*>(m_Chunk.getRecordBasePtr());
		return be32toh(asconfChunk->serialNumber);
	}

	uint8_t* SctpAsconfChunkView::getFirstParameter() const
	{
		if (!isValid())
			return nullptr;
		uint16_t len = m_Chunk.getLength();
		if (len <= sizeof(sctp_asconf_chunk))
			return nullptr;
		return m_Chunk.getRecordBasePtr() + sizeof(sctp_asconf_chunk);
	}

	size_t SctpAsconfChunkView::getParametersLength() const
	{
		if (!isValid())
			return 0;
		uint16_t len = m_Chunk.getLength();
		if (len <= sizeof(sctp_asconf_chunk))
			return 0;
		return len - sizeof(sctp_asconf_chunk);
	}

	// ==================== SctpAsconfAckChunkView Implementation ====================

	uint32_t SctpAsconfAckChunkView::getSerialNumber() const
	{
		if (!isValid())
			return 0;
		auto* asconfAckChunk = reinterpret_cast<const sctp_asconf_ack_chunk*>(m_Chunk.getRecordBasePtr());
		return be32toh(asconfAckChunk->serialNumber);
	}

	uint8_t* SctpAsconfAckChunkView::getFirstParameter() const
	{
		if (!isValid())
			return nullptr;
		uint16_t len = m_Chunk.getLength();
		if (len <= sizeof(sctp_asconf_ack_chunk))
			return nullptr;
		return m_Chunk.getRecordBasePtr() + sizeof(sctp_asconf_ack_chunk);
	}

	size_t SctpAsconfAckChunkView::getParametersLength() const
	{
		if (!isValid())
			return 0;
		uint16_t len = m_Chunk.getLength();
		if (len <= sizeof(sctp_asconf_ack_chunk))
			return 0;
		return len - sizeof(sctp_asconf_ack_chunk);
	}

	// ==================== SctpReconfigChunkView Implementation ====================

	uint8_t* SctpReconfigChunkView::getFirstParameter() const
	{
		if (!isValid())
			return nullptr;
		uint16_t len = m_Chunk.getLength();
		if (len <= sizeof(sctp_reconfig_chunk))
			return nullptr;
		return m_Chunk.getRecordBasePtr() + sizeof(sctp_reconfig_chunk);
	}

	size_t SctpReconfigChunkView::getParametersLength() const
	{
		if (!isValid())
			return 0;
		uint16_t len = m_Chunk.getLength();
		if (len <= sizeof(sctp_reconfig_chunk))
			return 0;
		return len - sizeof(sctp_reconfig_chunk);
	}

	// ==================== SctpPadChunkView Implementation ====================

	uint8_t* SctpPadChunkView::getPaddingData() const
	{
		if (!isValid())
			return nullptr;
		uint16_t len = m_Chunk.getLength();
		if (len <= sizeof(sctp_pad_chunk))
			return nullptr;
		return m_Chunk.getRecordBasePtr() + sizeof(sctp_pad_chunk);
	}

	size_t SctpPadChunkView::getPaddingLength() const
	{
		if (!isValid())
			return 0;
		uint16_t len = m_Chunk.getLength();
		if (len <= sizeof(sctp_pad_chunk))
			return 0;
		return len - sizeof(sctp_pad_chunk);
	}

	// ==================== SctpNrSackChunkView Implementation ====================

	uint32_t SctpNrSackChunkView::getCumulativeTsnAck() const
	{
		if (!isValid())
			return 0;
		auto* nrsackChunk = reinterpret_cast<const sctp_nr_sack_chunk*>(m_Chunk.getRecordBasePtr());
		return be32toh(nrsackChunk->cumulativeTsnAck);
	}

	uint32_t SctpNrSackChunkView::getArwnd() const
	{
		if (!isValid())
			return 0;
		auto* nrsackChunk = reinterpret_cast<const sctp_nr_sack_chunk*>(m_Chunk.getRecordBasePtr());
		return be32toh(nrsackChunk->arwnd);
	}

	uint16_t SctpNrSackChunkView::getNumGapBlocks() const
	{
		if (!isValid())
			return 0;
		auto* nrsackChunk = reinterpret_cast<const sctp_nr_sack_chunk*>(m_Chunk.getRecordBasePtr());
		return be16toh(nrsackChunk->numGapBlocks);
	}

	uint16_t SctpNrSackChunkView::getNumNrGapBlocks() const
	{
		if (!isValid())
			return 0;
		auto* nrsackChunk = reinterpret_cast<const sctp_nr_sack_chunk*>(m_Chunk.getRecordBasePtr());
		return be16toh(nrsackChunk->numNrGapBlocks);
	}

	uint16_t SctpNrSackChunkView::getNumDupTsns() const
	{
		if (!isValid())
			return 0;
		auto* nrsackChunk = reinterpret_cast<const sctp_nr_sack_chunk*>(m_Chunk.getRecordBasePtr());
		return be16toh(nrsackChunk->numDupTsns);
	}

	bool SctpNrSackChunkView::isAllNonRenegable() const
	{
		if (!isValid())
			return false;
		return (getFlags() & SctpNrSackFlags::ALL_NON_RENEGABLE) != 0;
	}

	std::vector<sctp_gap_ack_block> SctpNrSackChunkView::getGapBlocks() const
	{
		std::vector<sctp_gap_ack_block> result;
		if (!isValid())
			return result;

		auto* nrsackChunk = reinterpret_cast<const sctp_nr_sack_chunk*>(m_Chunk.getRecordBasePtr());
		uint16_t numGapBlocks = be16toh(nrsackChunk->numGapBlocks);

		const uint8_t* gapBlocksPtr = m_Chunk.getRecordBasePtr() + sizeof(sctp_nr_sack_chunk);
		size_t availableLen = m_Chunk.getLength() - sizeof(sctp_nr_sack_chunk);

		for (uint16_t i = 0; i < numGapBlocks && (i + 1) * sizeof(sctp_gap_ack_block) <= availableLen; ++i)
		{
			const auto* block =
			    reinterpret_cast<const sctp_gap_ack_block*>(gapBlocksPtr + i * sizeof(sctp_gap_ack_block));
			sctp_gap_ack_block gapBlock;
			gapBlock.start = be16toh(block->start);
			gapBlock.end = be16toh(block->end);
			result.push_back(gapBlock);
		}

		return result;
	}

	std::vector<sctp_gap_ack_block> SctpNrSackChunkView::getNrGapBlocks() const
	{
		std::vector<sctp_gap_ack_block> result;
		if (!isValid())
			return result;

		auto* nrsackChunk = reinterpret_cast<const sctp_nr_sack_chunk*>(m_Chunk.getRecordBasePtr());
		uint16_t numGapBlocks = be16toh(nrsackChunk->numGapBlocks);
		uint16_t numNrGapBlocks = be16toh(nrsackChunk->numNrGapBlocks);

		size_t nrGapBlocksOffset = sizeof(sctp_nr_sack_chunk) + numGapBlocks * sizeof(sctp_gap_ack_block);
		const uint8_t* nrGapBlocksPtr = m_Chunk.getRecordBasePtr() + nrGapBlocksOffset;
		size_t availableLen = m_Chunk.getLength() - nrGapBlocksOffset;

		for (uint16_t i = 0; i < numNrGapBlocks && (i + 1) * sizeof(sctp_gap_ack_block) <= availableLen; ++i)
		{
			const auto* block =
			    reinterpret_cast<const sctp_gap_ack_block*>(nrGapBlocksPtr + i * sizeof(sctp_gap_ack_block));
			sctp_gap_ack_block gapBlock;
			gapBlock.start = be16toh(block->start);
			gapBlock.end = be16toh(block->end);
			result.push_back(gapBlock);
		}

		return result;
	}

	std::vector<uint32_t> SctpNrSackChunkView::getDupTsns() const
	{
		std::vector<uint32_t> result;
		if (!isValid())
			return result;

		auto* nrsackChunk = reinterpret_cast<const sctp_nr_sack_chunk*>(m_Chunk.getRecordBasePtr());
		uint16_t numGapBlocks = be16toh(nrsackChunk->numGapBlocks);
		uint16_t numNrGapBlocks = be16toh(nrsackChunk->numNrGapBlocks);
		uint16_t numDupTsns = be16toh(nrsackChunk->numDupTsns);

		size_t dupTsnsOffset = sizeof(sctp_nr_sack_chunk) + numGapBlocks * sizeof(sctp_gap_ack_block) +
		                       numNrGapBlocks * sizeof(sctp_gap_ack_block);
		const uint8_t* dupTsnsPtr = m_Chunk.getRecordBasePtr() + dupTsnsOffset;
		size_t availableLen = m_Chunk.getLength() - dupTsnsOffset;

		for (uint16_t i = 0; i < numDupTsns && (i + 1) * sizeof(uint32_t) <= availableLen; ++i)
		{
			const auto* tsn = reinterpret_cast<const uint32_t*>(dupTsnsPtr + i * sizeof(uint32_t));
			result.push_back(be32toh(*tsn));
		}

		return result;
	}

	// ==================== SctpLayer Implementation ====================

	SctpLayer::SctpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	    : Layer(data, dataLen, prevLayer, packet, SCTP)
	{}

	SctpLayer::SctpLayer(uint16_t srcPort, uint16_t dstPort, uint32_t tag)
	{
		m_DataLen = sizeof(sctphdr);
		m_Data = new uint8_t[m_DataLen];
		std::memset(m_Data, 0, m_DataLen);
		m_Protocol = SCTP;

		sctphdr* hdr = getSctpHeader();
		hdr->portSrc = htobe16(srcPort);
		hdr->portDst = htobe16(dstPort);
		hdr->verificationTag = htobe32(tag);
		hdr->checksum = 0;
	}

	void SctpLayer::initLayer()
	{
		m_DataLen = sizeof(sctphdr);
		m_Data = new uint8_t[m_DataLen];
		std::memset(m_Data, 0, m_DataLen);
		m_Protocol = SCTP;
	}

	uint16_t SctpLayer::getSrcPort() const
	{
		return be16toh(getSctpHeader()->portSrc);
	}

	uint16_t SctpLayer::getDstPort() const
	{
		return be16toh(getSctpHeader()->portDst);
	}

	uint32_t SctpLayer::getVerificationTag() const
	{
		return be32toh(getSctpHeader()->verificationTag);
	}

	void SctpLayer::setSrcPort(uint16_t port)
	{
		getSctpHeader()->portSrc = htobe16(port);
	}

	void SctpLayer::setDstPort(uint16_t port)
	{
		getSctpHeader()->portDst = htobe16(port);
	}

	void SctpLayer::setVerificationTag(uint32_t tag)
	{
		getSctpHeader()->verificationTag = htobe32(tag);
	}

	uint8_t* SctpLayer::getChunksBasePtr() const
	{
		return m_Data + sizeof(sctphdr);
	}

	size_t SctpLayer::getChunksDataLen() const
	{
		if (m_DataLen <= sizeof(sctphdr))
			return 0;
		return m_DataLen - sizeof(sctphdr);
	}

	size_t SctpLayer::getChunkCount() const
	{
		size_t count = 0;
		SctpChunk chunk = getFirstChunk();
		while (chunk.isNotNull())
		{
			++count;
			chunk = getNextChunk(chunk);
		}
		return count;
	}

	SctpChunk SctpLayer::getFirstChunk() const
	{
		size_t chunksLen = getChunksDataLen();
		if (chunksLen < sizeof(sctp_chunk_hdr))
			return SctpChunk(nullptr);

		uint8_t* chunksPtr = getChunksBasePtr();

		// Validate chunk length
		auto* chunkHdr = reinterpret_cast<sctp_chunk_hdr*>(chunksPtr);
		uint16_t chunkLen = be16toh(chunkHdr->length);
		if (chunkLen < sizeof(sctp_chunk_hdr) || chunkLen > chunksLen)
			return SctpChunk(nullptr);

		return SctpChunk(chunksPtr);
	}

	SctpChunk SctpLayer::getNextChunk(const SctpChunk& chunk) const
	{
		if (chunk.isNull())
			return SctpChunk(nullptr);

		uint8_t* chunksBase = getChunksBasePtr();
		size_t chunksLen = getChunksDataLen();

		// Calculate offset of current chunk from start of chunks area
		uint8_t* currentChunkPtr = chunk.getRecordBasePtr();
		if (currentChunkPtr < chunksBase)
			return SctpChunk(nullptr);

		size_t currentOffset = currentChunkPtr - chunksBase;
		size_t currentChunkTotalSize = chunk.getTotalSize();

		if (currentChunkTotalSize == 0)
			return SctpChunk(nullptr);

		size_t nextOffset = currentOffset + currentChunkTotalSize;

		// Check if there's room for another chunk header
		if (nextOffset + sizeof(sctp_chunk_hdr) > chunksLen)
			return SctpChunk(nullptr);

		uint8_t* nextChunkPtr = chunksBase + nextOffset;

		// Validate next chunk length
		auto* nextChunkHdr = reinterpret_cast<sctp_chunk_hdr*>(nextChunkPtr);
		uint16_t nextChunkLen = be16toh(nextChunkHdr->length);
		if (nextChunkLen < sizeof(sctp_chunk_hdr) || nextOffset + nextChunkLen > chunksLen)
			return SctpChunk(nullptr);

		return SctpChunk(nextChunkPtr);
	}

	SctpChunk SctpLayer::getChunk(SctpChunkType chunkType) const
	{
		SctpChunk chunk = getFirstChunk();
		while (chunk.isNotNull())
		{
			if (chunk.getChunkType() == chunkType)
				return chunk;
			chunk = getNextChunk(chunk);
		}
		return SctpChunk(nullptr);
	}

	uint32_t SctpLayer::calculateChecksum(bool writeResultToPacket)
	{
		sctphdr* hdr = getSctpHeader();
		uint32_t originalChecksum = hdr->checksum;

		// Set checksum field to 0 for calculation
		hdr->checksum = 0;

		// Calculate CRC32c over entire SCTP packet
		uint32_t crc = calculateSctpCrc32c(m_Data, m_DataLen);

		if (writeResultToPacket)
		{
			// Per RFC 3309/9260, the checksum is stored in network byte order (big-endian)
			hdr->checksum = htobe32(crc);
		}
		else
		{
			hdr->checksum = originalChecksum;
		}

		return crc;
	}

	bool SctpLayer::isChecksumValid() const
	{
		sctphdr* hdr = getSctpHeader();
		// Read the stored checksum and convert from network byte order
		uint32_t storedChecksum = be32toh(hdr->checksum);

		// Temporarily set checksum to 0 for calculation
		hdr->checksum = 0;
		uint32_t calculatedCrc = calculateSctpCrc32c(m_Data, m_DataLen);
		// Restore the original checksum value (in network byte order)
		hdr->checksum = htobe32(storedChecksum);

		return storedChecksum == calculatedCrc;
	}

	bool SctpLayer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		// Minimum SCTP packet is just the common header (12 bytes)
		if (data == nullptr || dataLen < sizeof(sctphdr))
			return false;

		const auto* hdr = reinterpret_cast<const sctphdr*>(data);

		// Source and destination ports must not be 0
		if (hdr->portSrc == 0 || hdr->portDst == 0)
			return false;

		// If there are chunks, validate at least the first chunk header
		if (dataLen > sizeof(sctphdr))
		{
			size_t chunksLen = dataLen - sizeof(sctphdr);
			if (chunksLen < sizeof(sctp_chunk_hdr))
				return false;

			const auto* chunkHdr = reinterpret_cast<const sctp_chunk_hdr*>(data + sizeof(sctphdr));
			uint16_t chunkLen = be16toh(chunkHdr->length);

			// Chunk length must be at least 4 (header size) and not exceed available data
			if (chunkLen < sizeof(sctp_chunk_hdr) || chunkLen > chunksLen)
				return false;
		}

		return true;
	}

	void SctpLayer::parseNextLayer()
	{
		// SCTP typically doesn't have a distinct next layer in the packet parsing sense
		// The payload is contained within DATA chunks
		// For now, we don't create a next layer - applications should use getChunk() to access data
	}

	void SctpLayer::computeCalculateFields()
	{
		calculateChecksum(true);
	}

	std::string SctpLayer::toString() const
	{
		std::ostringstream ss;
		ss << "SCTP Layer, ";
		ss << "Src port: " << getSrcPort();
		ss << ", Dst port: " << getDstPort();

		size_t chunkCount = getChunkCount();
		if (chunkCount > 0)
		{
			ss << ", Chunks: " << chunkCount;

			// List chunk types
			ss << " [";
			SctpChunk chunk = getFirstChunk();
			bool first = true;
			while (chunk.isNotNull())
			{
				if (!first)
					ss << ", ";
				ss << chunk.getChunkTypeName();
				first = false;
				chunk = getNextChunk(chunk);
			}
			ss << "]";
		}

		return ss.str();
	}

	// ==================== Chunk Creation Methods ====================

	bool SctpLayer::addChunk(const uint8_t* chunkData, size_t chunkLen)
	{
		if (chunkData == nullptr || chunkLen < sizeof(sctp_chunk_hdr))
			return false;

		// Calculate padded length (chunks must be 4-byte aligned)
		size_t paddedLen = (chunkLen + 3) & ~3;

		// Extend the layer data
		if (!extendLayer(m_DataLen, paddedLen))
			return false;

		// Copy chunk data
		std::memcpy(m_Data + m_DataLen - paddedLen, chunkData, chunkLen);

		// Zero padding bytes
		if (paddedLen > chunkLen)
		{
			std::memset(m_Data + m_DataLen - paddedLen + chunkLen, 0, paddedLen - chunkLen);
		}

		return true;
	}

	bool SctpLayer::addDataChunk(uint32_t tsn, uint16_t streamId, uint16_t streamSeq, uint32_t ppid,
	                             const uint8_t* userData, size_t userDataLen, bool beginFragment, bool endFragment,
	                             bool unordered, bool immediate)
	{
		if (userData == nullptr && userDataLen > 0)
			return false;

		size_t chunkLen = sizeof(sctp_data_chunk) + userDataLen;
		std::vector<uint8_t> chunkData(chunkLen);

		auto* dataChunk = reinterpret_cast<sctp_data_chunk*>(chunkData.data());
		dataChunk->type = static_cast<uint8_t>(SctpChunkType::DATA);
		dataChunk->flags = 0;
		if (endFragment)
			dataChunk->flags |= SctpDataChunkFlags::END_FRAGMENT;
		if (beginFragment)
			dataChunk->flags |= SctpDataChunkFlags::BEGIN_FRAGMENT;
		if (unordered)
			dataChunk->flags |= SctpDataChunkFlags::UNORDERED;
		if (immediate)
			dataChunk->flags |= SctpDataChunkFlags::IMMEDIATE;
		dataChunk->length = htobe16(static_cast<uint16_t>(chunkLen));
		dataChunk->tsn = htobe32(tsn);
		dataChunk->streamId = htobe16(streamId);
		dataChunk->streamSeqNum = htobe16(streamSeq);
		dataChunk->ppid = htobe32(ppid);

		if (userDataLen > 0)
		{
			std::memcpy(chunkData.data() + sizeof(sctp_data_chunk), userData, userDataLen);
		}

		return addChunk(chunkData.data(), chunkLen);
	}

	bool SctpLayer::addInitChunk(uint32_t initiateTag, uint32_t arwnd, uint16_t numOutboundStreams,
	                             uint16_t numInboundStreams, uint32_t initialTsn, const uint8_t* parameters,
	                             size_t parametersLen)
	{
		size_t chunkLen = sizeof(sctp_init_chunk) + parametersLen;
		std::vector<uint8_t> chunkData(chunkLen);

		auto* initChunk = reinterpret_cast<sctp_init_chunk*>(chunkData.data());
		initChunk->type = static_cast<uint8_t>(SctpChunkType::INIT);
		initChunk->flags = 0;
		initChunk->length = htobe16(static_cast<uint16_t>(chunkLen));
		initChunk->initiateTag = htobe32(initiateTag);
		initChunk->arwnd = htobe32(arwnd);
		initChunk->numOutboundStreams = htobe16(numOutboundStreams);
		initChunk->numInboundStreams = htobe16(numInboundStreams);
		initChunk->initialTsn = htobe32(initialTsn);

		if (parametersLen > 0 && parameters != nullptr)
		{
			std::memcpy(chunkData.data() + sizeof(sctp_init_chunk), parameters, parametersLen);
		}

		return addChunk(chunkData.data(), chunkLen);
	}

	bool SctpLayer::addInitAckChunk(uint32_t initiateTag, uint32_t arwnd, uint16_t numOutboundStreams,
	                                uint16_t numInboundStreams, uint32_t initialTsn, const uint8_t* parameters,
	                                size_t parametersLen)
	{
		size_t chunkLen = sizeof(sctp_init_chunk) + parametersLen;
		std::vector<uint8_t> chunkData(chunkLen);

		auto* initChunk = reinterpret_cast<sctp_init_chunk*>(chunkData.data());
		initChunk->type = static_cast<uint8_t>(SctpChunkType::INIT_ACK);
		initChunk->flags = 0;
		initChunk->length = htobe16(static_cast<uint16_t>(chunkLen));
		initChunk->initiateTag = htobe32(initiateTag);
		initChunk->arwnd = htobe32(arwnd);
		initChunk->numOutboundStreams = htobe16(numOutboundStreams);
		initChunk->numInboundStreams = htobe16(numInboundStreams);
		initChunk->initialTsn = htobe32(initialTsn);

		if (parametersLen > 0 && parameters != nullptr)
		{
			std::memcpy(chunkData.data() + sizeof(sctp_init_chunk), parameters, parametersLen);
		}

		return addChunk(chunkData.data(), chunkLen);
	}

	bool SctpLayer::addSackChunk(uint32_t cumulativeTsnAck, uint32_t arwnd,
	                             const std::vector<sctp_gap_ack_block>& gapBlocks, const std::vector<uint32_t>& dupTsns)
	{
		size_t chunkLen =
		    sizeof(sctp_sack_chunk) + gapBlocks.size() * sizeof(sctp_gap_ack_block) + dupTsns.size() * sizeof(uint32_t);
		std::vector<uint8_t> chunkData(chunkLen);

		auto* sackChunk = reinterpret_cast<sctp_sack_chunk*>(chunkData.data());
		sackChunk->type = static_cast<uint8_t>(SctpChunkType::SACK);
		sackChunk->flags = 0;
		sackChunk->length = htobe16(static_cast<uint16_t>(chunkLen));
		sackChunk->cumulativeTsnAck = htobe32(cumulativeTsnAck);
		sackChunk->arwnd = htobe32(arwnd);
		sackChunk->numGapBlocks = htobe16(static_cast<uint16_t>(gapBlocks.size()));
		sackChunk->numDupTsns = htobe16(static_cast<uint16_t>(dupTsns.size()));

		// Add gap blocks
		auto* gapBlocksPtr = reinterpret_cast<sctp_gap_ack_block*>(chunkData.data() + sizeof(sctp_sack_chunk));
		for (size_t i = 0; i < gapBlocks.size(); ++i)
		{
			gapBlocksPtr[i].start = htobe16(gapBlocks[i].start);
			gapBlocksPtr[i].end = htobe16(gapBlocks[i].end);
		}

		// Add duplicate TSNs
		auto* dupTsnsPtr = reinterpret_cast<uint32_t*>(chunkData.data() + sizeof(sctp_sack_chunk) +
		                                               gapBlocks.size() * sizeof(sctp_gap_ack_block));
		for (size_t i = 0; i < dupTsns.size(); ++i)
		{
			dupTsnsPtr[i] = htobe32(dupTsns[i]);
		}

		return addChunk(chunkData.data(), chunkLen);
	}

	bool SctpLayer::addHeartbeatChunk(const uint8_t* heartbeatInfo, size_t heartbeatInfoLen)
	{
		if (heartbeatInfo == nullptr && heartbeatInfoLen > 0)
			return false;

		size_t chunkLen = sizeof(sctp_heartbeat_chunk) + heartbeatInfoLen;
		std::vector<uint8_t> chunkData(chunkLen);

		auto* hbChunk = reinterpret_cast<sctp_heartbeat_chunk*>(chunkData.data());
		hbChunk->type = static_cast<uint8_t>(SctpChunkType::HEARTBEAT);
		hbChunk->flags = 0;
		hbChunk->length = htobe16(static_cast<uint16_t>(chunkLen));

		if (heartbeatInfoLen > 0)
		{
			std::memcpy(chunkData.data() + sizeof(sctp_heartbeat_chunk), heartbeatInfo, heartbeatInfoLen);
		}

		return addChunk(chunkData.data(), chunkLen);
	}

	bool SctpLayer::addHeartbeatAckChunk(const uint8_t* heartbeatInfo, size_t heartbeatInfoLen)
	{
		if (heartbeatInfo == nullptr && heartbeatInfoLen > 0)
			return false;

		size_t chunkLen = sizeof(sctp_heartbeat_chunk) + heartbeatInfoLen;
		std::vector<uint8_t> chunkData(chunkLen);

		auto* hbChunk = reinterpret_cast<sctp_heartbeat_chunk*>(chunkData.data());
		hbChunk->type = static_cast<uint8_t>(SctpChunkType::HEARTBEAT_ACK);
		hbChunk->flags = 0;
		hbChunk->length = htobe16(static_cast<uint16_t>(chunkLen));

		if (heartbeatInfoLen > 0)
		{
			std::memcpy(chunkData.data() + sizeof(sctp_heartbeat_chunk), heartbeatInfo, heartbeatInfoLen);
		}

		return addChunk(chunkData.data(), chunkLen);
	}

	bool SctpLayer::addShutdownChunk(uint32_t cumulativeTsnAck)
	{
		sctp_shutdown_chunk shutdownChunk;
		shutdownChunk.type = static_cast<uint8_t>(SctpChunkType::SHUTDOWN);
		shutdownChunk.flags = 0;
		shutdownChunk.length = htobe16(sizeof(sctp_shutdown_chunk));
		shutdownChunk.cumulativeTsnAck = htobe32(cumulativeTsnAck);

		return addChunk(reinterpret_cast<uint8_t*>(&shutdownChunk), sizeof(shutdownChunk));
	}

	bool SctpLayer::addShutdownAckChunk()
	{
		sctp_shutdown_ack_chunk shutdownAckChunk;
		shutdownAckChunk.type = static_cast<uint8_t>(SctpChunkType::SHUTDOWN_ACK);
		shutdownAckChunk.flags = 0;
		shutdownAckChunk.length = htobe16(sizeof(sctp_shutdown_ack_chunk));

		return addChunk(reinterpret_cast<uint8_t*>(&shutdownAckChunk), sizeof(shutdownAckChunk));
	}

	bool SctpLayer::addShutdownCompleteChunk(bool tBit)
	{
		sctp_shutdown_complete_chunk shutdownCompleteChunk;
		shutdownCompleteChunk.type = static_cast<uint8_t>(SctpChunkType::SHUTDOWN_COMPLETE);
		shutdownCompleteChunk.flags = tBit ? SctpAbortFlags::T_BIT : 0;
		shutdownCompleteChunk.length = htobe16(sizeof(sctp_shutdown_complete_chunk));

		return addChunk(reinterpret_cast<uint8_t*>(&shutdownCompleteChunk), sizeof(shutdownCompleteChunk));
	}

	bool SctpLayer::addAbortChunk(bool tBit, const uint8_t* errorCauses, size_t errorCausesLen)
	{
		size_t chunkLen = sizeof(sctp_abort_chunk) + errorCausesLen;
		std::vector<uint8_t> chunkData(chunkLen);

		auto* abortChunk = reinterpret_cast<sctp_abort_chunk*>(chunkData.data());
		abortChunk->type = static_cast<uint8_t>(SctpChunkType::ABORT);
		abortChunk->flags = tBit ? SctpAbortFlags::T_BIT : 0;
		abortChunk->length = htobe16(static_cast<uint16_t>(chunkLen));

		if (errorCausesLen > 0 && errorCauses != nullptr)
		{
			std::memcpy(chunkData.data() + sizeof(sctp_abort_chunk), errorCauses, errorCausesLen);
		}

		return addChunk(chunkData.data(), chunkLen);
	}

	bool SctpLayer::addCookieEchoChunk(const uint8_t* cookie, size_t cookieLen)
	{
		if (cookie == nullptr || cookieLen == 0)
			return false;

		size_t chunkLen = sizeof(sctp_cookie_echo_chunk) + cookieLen;
		std::vector<uint8_t> chunkData(chunkLen);

		auto* cookieChunk = reinterpret_cast<sctp_cookie_echo_chunk*>(chunkData.data());
		cookieChunk->type = static_cast<uint8_t>(SctpChunkType::COOKIE_ECHO);
		cookieChunk->flags = 0;
		cookieChunk->length = htobe16(static_cast<uint16_t>(chunkLen));

		std::memcpy(chunkData.data() + sizeof(sctp_cookie_echo_chunk), cookie, cookieLen);

		return addChunk(chunkData.data(), chunkLen);
	}

	bool SctpLayer::addCookieAckChunk()
	{
		sctp_cookie_ack_chunk cookieAckChunk;
		cookieAckChunk.type = static_cast<uint8_t>(SctpChunkType::COOKIE_ACK);
		cookieAckChunk.flags = 0;
		cookieAckChunk.length = htobe16(sizeof(sctp_cookie_ack_chunk));

		return addChunk(reinterpret_cast<uint8_t*>(&cookieAckChunk), sizeof(cookieAckChunk));
	}

	bool SctpLayer::addErrorChunk(const uint8_t* errorCauses, size_t errorCausesLen)
	{
		if (errorCauses == nullptr || errorCausesLen == 0)
			return false;

		size_t chunkLen = sizeof(sctp_error_chunk) + errorCausesLen;
		std::vector<uint8_t> chunkData(chunkLen);

		auto* errorChunk = reinterpret_cast<sctp_error_chunk*>(chunkData.data());
		errorChunk->type = static_cast<uint8_t>(SctpChunkType::SCTP_ERROR);
		errorChunk->flags = 0;
		errorChunk->length = htobe16(static_cast<uint16_t>(chunkLen));

		std::memcpy(chunkData.data() + sizeof(sctp_error_chunk), errorCauses, errorCausesLen);

		return addChunk(chunkData.data(), chunkLen);
	}

	// ==================== SctpInitParameter Implementation ====================

	SctpParameterType SctpInitParameter::getType() const
	{
		if (m_Data == nullptr)
			return static_cast<SctpParameterType>(0);

		uint16_t type = be16toh(m_Data->type);
		return static_cast<SctpParameterType>(type);
	}

	uint16_t SctpInitParameter::getTypeAsInt() const
	{
		if (m_Data == nullptr)
			return 0;
		return be16toh(m_Data->type);
	}

	uint16_t SctpInitParameter::getLength() const
	{
		if (m_Data == nullptr)
			return 0;
		if (m_MaxLen < sizeof(sctp_param_hdr))
			return 0;
		return be16toh(m_Data->length);
	}

	size_t SctpInitParameter::getTotalSize() const
	{
		uint16_t len = getLength();
		if (len == 0)
			return 0;
		// Pad to 4-byte boundary
		size_t totalSize = (len + 3) & ~3;
		// Validate against available buffer
		if (totalSize > m_MaxLen)
			return 0;
		return totalSize;
	}

	uint8_t* SctpInitParameter::getValue() const
	{
		if (m_Data == nullptr)
			return nullptr;
		if (m_MaxLen < sizeof(sctp_param_hdr))
			return nullptr;
		return reinterpret_cast<uint8_t*>(m_Data) + sizeof(sctp_param_hdr);
	}

	size_t SctpInitParameter::getValueSize() const
	{
		uint16_t len = getLength();
		if (len <= sizeof(sctp_param_hdr))
			return 0;
		size_t valueSize = len - sizeof(sctp_param_hdr);
		// Validate against available buffer
		if (sizeof(sctp_param_hdr) + valueSize > m_MaxLen)
			return 0;
		return valueSize;
	}

	IPv4Address SctpInitParameter::getIPv4Address() const
	{
		if (m_Data == nullptr || getType() != SctpParameterType::IPV4_ADDRESS)
			return IPv4Address::Zero;

		if (getValueSize() < 4)
			return IPv4Address::Zero;

		return IPv4Address(getValue());
	}

	IPv6Address SctpInitParameter::getIPv6Address() const
	{
		if (m_Data == nullptr || getType() != SctpParameterType::IPV6_ADDRESS)
			return IPv6Address::Zero;

		if (getValueSize() < 16)
			return IPv6Address::Zero;

		return IPv6Address(getValue());
	}

	std::vector<uint16_t> SctpInitParameter::getSupportedAddressTypes() const
	{
		std::vector<uint16_t> result;
		if (m_Data == nullptr || getType() != SctpParameterType::SUPPORTED_ADDRESS_TYPES)
			return result;

		size_t valueSize = getValueSize();
		const uint8_t* valuePtr = getValue();

		for (size_t i = 0; i + 1 < valueSize; i += 2)
		{
			uint16_t addrType = be16toh(*reinterpret_cast<const uint16_t*>(valuePtr + i));
			result.push_back(addrType);
		}

		return result;
	}

	uint8_t* SctpInitParameter::getStateCookie() const
	{
		if (m_Data == nullptr || getType() != SctpParameterType::STATE_COOKIE)
			return nullptr;
		return getValue();
	}

	size_t SctpInitParameter::getStateCookieLength() const
	{
		if (m_Data == nullptr || getType() != SctpParameterType::STATE_COOKIE)
			return 0;
		return getValueSize();
	}

	uint32_t SctpInitParameter::getCookiePreservativeIncrement() const
	{
		if (m_Data == nullptr || getType() != SctpParameterType::COOKIE_PRESERVATIVE)
			return 0;
		if (getValueSize() < 4)
			return 0;
		return be32toh(*reinterpret_cast<const uint32_t*>(getValue()));
	}

	uint8_t* SctpInitParameter::getRandomData() const
	{
		if (m_Data == nullptr || getType() != SctpParameterType::RANDOM)
			return nullptr;
		return getValue();
	}

	size_t SctpInitParameter::getRandomDataLength() const
	{
		if (m_Data == nullptr || getType() != SctpParameterType::RANDOM)
			return 0;
		return getValueSize();
	}

	std::vector<uint8_t> SctpInitParameter::getChunkList() const
	{
		std::vector<uint8_t> result;
		if (m_Data == nullptr || getType() != SctpParameterType::CHUNK_LIST)
			return result;

		size_t valueSize = getValueSize();
		const uint8_t* valuePtr = getValue();

		for (size_t i = 0; i < valueSize; ++i)
		{
			result.push_back(valuePtr[i]);
		}

		return result;
	}

	std::vector<uint16_t> SctpInitParameter::getRequestedHmacAlgorithms() const
	{
		std::vector<uint16_t> result;
		if (m_Data == nullptr || getType() != SctpParameterType::REQUESTED_HMAC_ALGO)
			return result;

		size_t valueSize = getValueSize();
		const uint8_t* valuePtr = getValue();

		for (size_t i = 0; i + 1 < valueSize; i += 2)
		{
			uint16_t hmacId = be16toh(*reinterpret_cast<const uint16_t*>(valuePtr + i));
			result.push_back(hmacId);
		}

		return result;
	}

	std::vector<uint8_t> SctpInitParameter::getSupportedExtensions() const
	{
		std::vector<uint8_t> result;
		if (m_Data == nullptr || getType() != SctpParameterType::SUPPORTED_EXTENSIONS)
			return result;

		size_t valueSize = getValueSize();
		const uint8_t* valuePtr = getValue();

		for (size_t i = 0; i < valueSize; ++i)
		{
			result.push_back(valuePtr[i]);
		}

		return result;
	}

	bool SctpInitParameter::isHostNameAddress() const
	{
		return m_Data != nullptr && getType() == SctpParameterType::HOST_NAME_ADDRESS;
	}

	std::string SctpInitParameter::getTypeName() const
	{
		switch (getType())
		{
		case SctpParameterType::HEARTBEAT_INFO:
			return "Heartbeat Info";
		case SctpParameterType::IPV4_ADDRESS:
			return "IPv4 Address";
		case SctpParameterType::IPV6_ADDRESS:
			return "IPv6 Address";
		case SctpParameterType::STATE_COOKIE:
			return "State Cookie";
		case SctpParameterType::UNRECOGNIZED_PARAM:
			return "Unrecognized Parameter";
		case SctpParameterType::COOKIE_PRESERVATIVE:
			return "Cookie Preservative";
		case SctpParameterType::HOST_NAME_ADDRESS:
			return "Host Name Address (DEPRECATED)";
		case SctpParameterType::SUPPORTED_ADDRESS_TYPES:
			return "Supported Address Types";
		case SctpParameterType::ECN_CAPABLE:
			return "ECN Capable";
		case SctpParameterType::ZERO_CHECKSUM_ACCEPTABLE:
			return "Zero Checksum Acceptable";
		case SctpParameterType::RANDOM:
			return "Random";
		case SctpParameterType::CHUNK_LIST:
			return "Chunk List";
		case SctpParameterType::REQUESTED_HMAC_ALGO:
			return "Requested HMAC Algorithm";
		case SctpParameterType::PADDING:
			return "Padding";
		case SctpParameterType::SUPPORTED_EXTENSIONS:
			return "Supported Extensions";
		case SctpParameterType::FORWARD_TSN_SUPPORTED:
			return "Forward TSN Supported";
		case SctpParameterType::ADD_IP_ADDRESS:
			return "Add IP Address";
		case SctpParameterType::DELETE_IP_ADDRESS:
			return "Delete IP Address";
		case SctpParameterType::ERROR_CAUSE_INDICATION:
			return "Error Cause Indication";
		case SctpParameterType::SET_PRIMARY_ADDRESS:
			return "Set Primary Address";
		case SctpParameterType::SUCCESS_INDICATION:
			return "Success Indication";
		case SctpParameterType::ADAPTATION_LAYER_INDICATION:
			return "Adaptation Layer Indication";
		default:
			return "Unknown";
		}
	}

	// ==================== SctpInitParameterIterator Implementation ====================

	SctpInitParameterIterator::SctpInitParameterIterator(const SctpChunk& chunk)
	    : m_ParamsBase(nullptr), m_ParamsLen(0), m_CurrentOffset(0)
	{
		if (chunk.isNull())
			return;

		SctpChunkType type = chunk.getChunkType();
		if (type != SctpChunkType::INIT && type != SctpChunkType::INIT_ACK)
			return;

		// Get parameters from INIT/INIT-ACK chunk
		// Parameters start after the fixed 20-byte INIT header
		uint16_t chunkLen = chunk.getLength();
		if (chunkLen <= sizeof(sctp_init_chunk))
			return;

		m_ParamsBase = chunk.getRecordBasePtr() + sizeof(sctp_init_chunk);
		m_ParamsLen = chunkLen - sizeof(sctp_init_chunk);
	}

	SctpInitParameter SctpInitParameterIterator::getParameter() const
	{
		if (!isValid())
			return SctpInitParameter(nullptr, 0);

		return SctpInitParameter(m_ParamsBase + m_CurrentOffset, m_ParamsLen - m_CurrentOffset);
	}

	SctpInitParameterIterator& SctpInitParameterIterator::next()
	{
		if (!isValid())
			return *this;

		SctpInitParameter param = getParameter();
		size_t paramTotalSize = param.getTotalSize();

		if (paramTotalSize == 0)
		{
			// Invalid parameter, mark as end
			m_CurrentOffset = m_ParamsLen;
		}
		else
		{
			m_CurrentOffset += paramTotalSize;
		}

		return *this;
	}

	bool SctpInitParameterIterator::isValid() const
	{
		if (m_ParamsBase == nullptr || m_ParamsLen == 0)
			return false;

		if (m_CurrentOffset + sizeof(sctp_param_hdr) > m_ParamsLen)
			return false;

		// Validate parameter length
		auto* paramHdr = reinterpret_cast<const sctp_param_hdr*>(m_ParamsBase + m_CurrentOffset);
		uint16_t paramLen = be16toh(paramHdr->length);

		if (paramLen < sizeof(sctp_param_hdr) || m_CurrentOffset + paramLen > m_ParamsLen)
			return false;

		return true;
	}

	void SctpInitParameterIterator::reset()
	{
		m_CurrentOffset = 0;
	}

	// ==================== SctpErrorCause Implementation ====================

	SctpErrorCauseCode SctpErrorCause::getCode() const
	{
		if (m_Data == nullptr)
			return static_cast<SctpErrorCauseCode>(0);
		return static_cast<SctpErrorCauseCode>(be16toh(m_Data->code));
	}

	uint16_t SctpErrorCause::getCodeAsInt() const
	{
		if (m_Data == nullptr)
			return 0;
		return be16toh(m_Data->code);
	}

	uint16_t SctpErrorCause::getLength() const
	{
		if (m_Data == nullptr)
			return 0;
		if (m_MaxLen < sizeof(sctp_error_cause))
			return 0;
		return be16toh(m_Data->length);
	}

	size_t SctpErrorCause::getTotalSize() const
	{
		uint16_t len = getLength();
		if (len == 0)
			return 0;
		// Pad to 4-byte boundary
		size_t totalSize = (len + 3) & ~3;
		// Validate against available buffer
		if (totalSize > m_MaxLen)
			return 0;
		return totalSize;
	}

	uint8_t* SctpErrorCause::getData() const
	{
		if (m_Data == nullptr)
			return nullptr;
		if (m_MaxLen < sizeof(sctp_error_cause))
			return nullptr;
		return reinterpret_cast<uint8_t*>(m_Data) + sizeof(sctp_error_cause);
	}

	size_t SctpErrorCause::getDataSize() const
	{
		uint16_t len = getLength();
		if (len <= sizeof(sctp_error_cause))
			return 0;
		size_t dataSize = len - sizeof(sctp_error_cause);
		// Validate against available buffer
		if (sizeof(sctp_error_cause) + dataSize > m_MaxLen)
			return 0;
		return dataSize;
	}

	std::string SctpErrorCause::getCodeName() const
	{
		switch (getCode())
		{
		case SctpErrorCauseCode::INVALID_STREAM_ID:
			return "Invalid Stream Identifier";
		case SctpErrorCauseCode::MISSING_MANDATORY_PARAM:
			return "Missing Mandatory Parameter";
		case SctpErrorCauseCode::STALE_COOKIE:
			return "Stale Cookie";
		case SctpErrorCauseCode::OUT_OF_RESOURCE:
			return "Out of Resource";
		case SctpErrorCauseCode::UNRESOLVABLE_ADDRESS:
			return "Unresolvable Address";
		case SctpErrorCauseCode::UNRECOGNIZED_CHUNK_TYPE:
			return "Unrecognized Chunk Type";
		case SctpErrorCauseCode::INVALID_MANDATORY_PARAM:
			return "Invalid Mandatory Parameter";
		case SctpErrorCauseCode::UNRECOGNIZED_PARAMS:
			return "Unrecognized Parameters";
		case SctpErrorCauseCode::NO_USER_DATA:
			return "No User Data";
		case SctpErrorCauseCode::COOKIE_RECEIVED_WHILE_SHUTTING_DOWN:
			return "Cookie Received While Shutting Down";
		case SctpErrorCauseCode::RESTART_WITH_NEW_ADDRESSES:
			return "Restart with New Addresses";
		case SctpErrorCauseCode::USER_INITIATED_ABORT:
			return "User Initiated Abort";
		case SctpErrorCauseCode::PROTOCOL_VIOLATION:
			return "Protocol Violation";
		case SctpErrorCauseCode::DELETE_LAST_IP:
			return "Request to Delete Last Remaining IP";
		case SctpErrorCauseCode::OPERATION_REFUSED:
			return "Operation Refused";
		case SctpErrorCauseCode::DELETE_SOURCE_IP:
			return "Request to Delete Source IP";
		case SctpErrorCauseCode::ASSOCIATION_ABORTED:
			return "Association Aborted";
		case SctpErrorCauseCode::REQUEST_REFUSED:
			return "Request Refused";
		case SctpErrorCauseCode::UNSUPPORTED_HMAC_ID:
			return "Unsupported HMAC Identifier";
		default:
			return "Unknown";
		}
	}

	uint16_t SctpErrorCause::getInvalidStreamId() const
	{
		if (m_Data == nullptr || getCode() != SctpErrorCauseCode::INVALID_STREAM_ID)
			return 0;
		if (getDataSize() < 2)
			return 0;
		return be16toh(*reinterpret_cast<const uint16_t*>(getData()));
	}

	uint32_t SctpErrorCause::getStaleCookieStaleness() const
	{
		if (m_Data == nullptr || getCode() != SctpErrorCauseCode::STALE_COOKIE)
			return 0;
		if (getDataSize() < 4)
			return 0;
		return be32toh(*reinterpret_cast<const uint32_t*>(getData()));
	}

	uint32_t SctpErrorCause::getNoUserDataTsn() const
	{
		if (m_Data == nullptr || getCode() != SctpErrorCauseCode::NO_USER_DATA)
			return 0;
		if (getDataSize() < 4)
			return 0;
		return be32toh(*reinterpret_cast<const uint32_t*>(getData()));
	}

	// ==================== SctpErrorCauseIterator Implementation ====================

	SctpErrorCauseIterator::SctpErrorCauseIterator(const SctpChunk& chunk)
	    : m_CausesBase(nullptr), m_CausesLen(0), m_CurrentOffset(0)
	{
		if (chunk.isNull())
			return;

		SctpChunkType type = chunk.getChunkType();
		if (type != SctpChunkType::ABORT && type != SctpChunkType::SCTP_ERROR)
			return;

		uint16_t chunkLen = chunk.getLength();
		if (chunkLen <= sizeof(sctp_chunk_hdr))
			return;

		m_CausesBase = chunk.getValue();
		m_CausesLen = chunkLen - sizeof(sctp_chunk_hdr);
	}

	SctpErrorCause SctpErrorCauseIterator::getErrorCause() const
	{
		if (!isValid())
			return SctpErrorCause(nullptr, 0);

		return SctpErrorCause(m_CausesBase + m_CurrentOffset, m_CausesLen - m_CurrentOffset);
	}

	SctpErrorCauseIterator& SctpErrorCauseIterator::next()
	{
		if (!isValid())
			return *this;

		SctpErrorCause cause = getErrorCause();
		size_t causeTotalSize = cause.getTotalSize();

		if (causeTotalSize == 0)
		{
			m_CurrentOffset = m_CausesLen;
		}
		else
		{
			m_CurrentOffset += causeTotalSize;
		}

		return *this;
	}

	bool SctpErrorCauseIterator::isValid() const
	{
		if (m_CausesBase == nullptr || m_CausesLen == 0)
			return false;

		if (m_CurrentOffset + sizeof(sctp_error_cause) > m_CausesLen)
			return false;

		auto* causeHdr = reinterpret_cast<const sctp_error_cause*>(m_CausesBase + m_CurrentOffset);
		uint16_t causeLen = be16toh(causeHdr->length);

		if (causeLen < sizeof(sctp_error_cause) || m_CurrentOffset + causeLen > m_CausesLen)
			return false;

		return true;
	}

	void SctpErrorCauseIterator::reset()
	{
		m_CurrentOffset = 0;
	}

	// ==================== Additional Chunk Creation Methods ====================

	bool SctpLayer::addEcneChunk(uint32_t lowestTsn)
	{
		sctp_ecne_chunk ecneChunk;
		ecneChunk.type = static_cast<uint8_t>(SctpChunkType::ECNE);
		ecneChunk.flags = 0;
		ecneChunk.length = htobe16(sizeof(sctp_ecne_chunk));
		ecneChunk.lowestTsn = htobe32(lowestTsn);

		return addChunk(reinterpret_cast<uint8_t*>(&ecneChunk), sizeof(ecneChunk));
	}

	bool SctpLayer::addCwrChunk(uint32_t lowestTsn)
	{
		sctp_cwr_chunk cwrChunk;
		cwrChunk.type = static_cast<uint8_t>(SctpChunkType::CWR);
		cwrChunk.flags = 0;
		cwrChunk.length = htobe16(sizeof(sctp_cwr_chunk));
		cwrChunk.lowestTsn = htobe32(lowestTsn);

		return addChunk(reinterpret_cast<uint8_t*>(&cwrChunk), sizeof(cwrChunk));
	}

	bool SctpLayer::addForwardTsnChunk(uint32_t newCumulativeTsn, const std::vector<sctp_forward_tsn_stream>& streams)
	{
		size_t chunkLen = sizeof(sctp_forward_tsn_chunk) + streams.size() * sizeof(sctp_forward_tsn_stream);
		std::vector<uint8_t> chunkData(chunkLen);

		auto* fwdTsnChunk = reinterpret_cast<sctp_forward_tsn_chunk*>(chunkData.data());
		fwdTsnChunk->type = static_cast<uint8_t>(SctpChunkType::FORWARD_TSN);
		fwdTsnChunk->flags = 0;
		fwdTsnChunk->length = htobe16(static_cast<uint16_t>(chunkLen));
		fwdTsnChunk->newCumulativeTsn = htobe32(newCumulativeTsn);

		auto* streamsPtr =
		    reinterpret_cast<sctp_forward_tsn_stream*>(chunkData.data() + sizeof(sctp_forward_tsn_chunk));
		for (size_t i = 0; i < streams.size(); ++i)
		{
			streamsPtr[i].streamId = htobe16(streams[i].streamId);
			streamsPtr[i].streamSeq = htobe16(streams[i].streamSeq);
		}

		return addChunk(chunkData.data(), chunkLen);
	}

	bool SctpLayer::addIDataChunk(uint32_t tsn, uint16_t streamId, uint32_t mid, uint32_t ppidOrFsn,
	                              const uint8_t* userData, size_t userDataLen, bool beginFragment, bool endFragment,
	                              bool unordered, bool immediate)
	{
		if (userData == nullptr && userDataLen > 0)
			return false;

		size_t chunkLen = sizeof(sctp_idata_chunk) + userDataLen;
		std::vector<uint8_t> chunkData(chunkLen);

		auto* idataChunk = reinterpret_cast<sctp_idata_chunk*>(chunkData.data());
		idataChunk->type = static_cast<uint8_t>(SctpChunkType::I_DATA);
		idataChunk->flags = 0;
		if (endFragment)
			idataChunk->flags |= SctpDataChunkFlags::END_FRAGMENT;
		if (beginFragment)
			idataChunk->flags |= SctpDataChunkFlags::BEGIN_FRAGMENT;
		if (unordered)
			idataChunk->flags |= SctpDataChunkFlags::UNORDERED;
		if (immediate)
			idataChunk->flags |= SctpDataChunkFlags::IMMEDIATE;
		idataChunk->length = htobe16(static_cast<uint16_t>(chunkLen));
		idataChunk->tsn = htobe32(tsn);
		idataChunk->streamId = htobe16(streamId);
		idataChunk->reserved = 0;
		idataChunk->mid = htobe32(mid);
		idataChunk->ppidOrFsn = htobe32(ppidOrFsn);

		if (userDataLen > 0)
		{
			std::memcpy(chunkData.data() + sizeof(sctp_idata_chunk), userData, userDataLen);
		}

		return addChunk(chunkData.data(), chunkLen);
	}

	bool SctpLayer::addIForwardTsnChunk(uint32_t newCumulativeTsn, const std::vector<sctp_iforward_tsn_stream>& streams)
	{
		size_t chunkLen = sizeof(sctp_iforward_tsn_chunk) + streams.size() * sizeof(sctp_iforward_tsn_stream);
		std::vector<uint8_t> chunkData(chunkLen);

		auto* ifwdTsnChunk = reinterpret_cast<sctp_iforward_tsn_chunk*>(chunkData.data());
		ifwdTsnChunk->type = static_cast<uint8_t>(SctpChunkType::I_FORWARD_TSN);
		ifwdTsnChunk->flags = 0;
		ifwdTsnChunk->length = htobe16(static_cast<uint16_t>(chunkLen));
		ifwdTsnChunk->newCumulativeTsn = htobe32(newCumulativeTsn);

		auto* streamsPtr =
		    reinterpret_cast<sctp_iforward_tsn_stream*>(chunkData.data() + sizeof(sctp_iforward_tsn_chunk));
		for (size_t i = 0; i < streams.size(); ++i)
		{
			streamsPtr[i].streamId = htobe16(streams[i].streamId);
			streamsPtr[i].reserved = htobe16(streams[i].reserved);
			streamsPtr[i].mid = htobe32(streams[i].mid);
		}

		return addChunk(chunkData.data(), chunkLen);
	}

	bool SctpLayer::addPadChunk(size_t paddingLen)
	{
		size_t chunkLen = sizeof(sctp_pad_chunk) + paddingLen;
		std::vector<uint8_t> chunkData(chunkLen, 0);

		auto* padChunk = reinterpret_cast<sctp_pad_chunk*>(chunkData.data());
		padChunk->type = static_cast<uint8_t>(SctpChunkType::PAD);
		padChunk->flags = 0;
		padChunk->length = htobe16(static_cast<uint16_t>(chunkLen));

		return addChunk(chunkData.data(), chunkLen);
	}

	// ==================== Validation Methods ====================

	SctpBundlingStatus SctpLayer::validateBundling() const
	{
		size_t chunkCount = getChunkCount();
		if (chunkCount == 0)
			return SctpBundlingStatus::VALID;

		bool hasInit = false;
		bool hasInitAck = false;
		bool hasShutdownComplete = false;

		SctpChunk chunk = getFirstChunk();
		while (chunk.isNotNull())
		{
			SctpChunkType type = chunk.getChunkType();
			if (type == SctpChunkType::INIT)
				hasInit = true;
			else if (type == SctpChunkType::INIT_ACK)
				hasInitAck = true;
			else if (type == SctpChunkType::SHUTDOWN_COMPLETE)
				hasShutdownComplete = true;

			chunk = getNextChunk(chunk);
		}

		// Per RFC 9260: INIT, INIT-ACK, and SHUTDOWN-COMPLETE MUST NOT be bundled
		if (hasInit && chunkCount > 1)
			return SctpBundlingStatus::INIT_BUNDLED;

		if (hasInitAck && chunkCount > 1)
			return SctpBundlingStatus::INIT_ACK_BUNDLED;

		if (hasShutdownComplete && chunkCount > 1)
			return SctpBundlingStatus::SHUTDOWN_COMPLETE_BUNDLED;

		// Per RFC 9260: INIT chunk packets MUST have verification tag = 0
		if (hasInit && getVerificationTag() != 0)
			return SctpBundlingStatus::INIT_NONZERO_TAG;

		return SctpBundlingStatus::VALID;
	}

	bool SctpLayer::canAddChunk(SctpChunkType chunkType) const
	{
		size_t chunkCount = getChunkCount();

		// If packet is empty, any chunk can be added
		if (chunkCount == 0)
			return true;

		// Check what's already in the packet
		SctpChunk chunk = getFirstChunk();
		while (chunk.isNotNull())
		{
			SctpChunkType existingType = chunk.getChunkType();

			// Cannot add anything to a packet with INIT, INIT-ACK, or SHUTDOWN-COMPLETE
			if (existingType == SctpChunkType::INIT || existingType == SctpChunkType::INIT_ACK ||
			    existingType == SctpChunkType::SHUTDOWN_COMPLETE)
			{
				return false;
			}

			chunk = getNextChunk(chunk);
		}

		// Cannot add INIT, INIT-ACK, or SHUTDOWN-COMPLETE to a packet with existing chunks
		if (chunkType == SctpChunkType::INIT || chunkType == SctpChunkType::INIT_ACK ||
		    chunkType == SctpChunkType::SHUTDOWN_COMPLETE)
		{
			return false;
		}

		return true;
	}

	bool SctpLayer::containsHostNameAddress() const
	{
		SctpChunk chunk = getFirstChunk();
		while (chunk.isNotNull())
		{
			SctpChunkType type = chunk.getChunkType();
			if (type == SctpChunkType::INIT || type == SctpChunkType::INIT_ACK)
			{
				SctpInitParameterIterator iter(chunk);
				while (iter.isValid())
				{
					SctpInitParameter param = iter.getParameter();
					if (param.isHostNameAddress())
						return true;
					iter.next();
				}
			}
			chunk = getNextChunk(chunk);
		}
		return false;
	}

	// ==================== New Chunk Creation Methods (RFC 4895, 5061, 6525) ====================

	bool SctpLayer::addAuthChunk(uint16_t sharedKeyId, uint16_t hmacId, const uint8_t* hmac, size_t hmacLen)
	{
		if (hmac == nullptr && hmacLen > 0)
			return false;

		size_t chunkLen = sizeof(sctp_auth_chunk) + hmacLen;
		std::vector<uint8_t> chunkData(chunkLen);

		auto* authChunk = reinterpret_cast<sctp_auth_chunk*>(chunkData.data());
		authChunk->type = static_cast<uint8_t>(SctpChunkType::AUTH);
		authChunk->flags = 0;
		authChunk->length = htobe16(static_cast<uint16_t>(chunkLen));
		authChunk->sharedKeyId = htobe16(sharedKeyId);
		authChunk->hmacId = htobe16(hmacId);

		if (hmacLen > 0)
		{
			std::memcpy(chunkData.data() + sizeof(sctp_auth_chunk), hmac, hmacLen);
		}

		return addChunk(chunkData.data(), chunkLen);
	}

	bool SctpLayer::addAsconfChunk(uint32_t serialNumber, const uint8_t* addressParam, size_t addressParamLen,
	                               const uint8_t* asconfParams, size_t asconfParamsLen)
	{
		if (addressParam == nullptr || addressParamLen < sizeof(sctp_param_hdr))
			return false;

		size_t chunkLen = sizeof(sctp_asconf_chunk) + addressParamLen + asconfParamsLen;
		std::vector<uint8_t> chunkData(chunkLen);

		auto* asconfChunk = reinterpret_cast<sctp_asconf_chunk*>(chunkData.data());
		asconfChunk->type = static_cast<uint8_t>(SctpChunkType::ASCONF);
		asconfChunk->flags = 0;
		asconfChunk->length = htobe16(static_cast<uint16_t>(chunkLen));
		asconfChunk->serialNumber = htobe32(serialNumber);

		// Copy address parameter (mandatory)
		std::memcpy(chunkData.data() + sizeof(sctp_asconf_chunk), addressParam, addressParamLen);

		// Copy ASCONF parameters if provided
		if (asconfParamsLen > 0 && asconfParams != nullptr)
		{
			std::memcpy(chunkData.data() + sizeof(sctp_asconf_chunk) + addressParamLen, asconfParams, asconfParamsLen);
		}

		return addChunk(chunkData.data(), chunkLen);
	}

	bool SctpLayer::addAsconfAckChunk(uint32_t serialNumber, const uint8_t* responseParams, size_t responseParamsLen)
	{
		size_t chunkLen = sizeof(sctp_asconf_ack_chunk) + responseParamsLen;
		std::vector<uint8_t> chunkData(chunkLen);

		auto* asconfAckChunk = reinterpret_cast<sctp_asconf_ack_chunk*>(chunkData.data());
		asconfAckChunk->type = static_cast<uint8_t>(SctpChunkType::ASCONF_ACK);
		asconfAckChunk->flags = 0;
		asconfAckChunk->length = htobe16(static_cast<uint16_t>(chunkLen));
		asconfAckChunk->serialNumber = htobe32(serialNumber);

		if (responseParamsLen > 0 && responseParams != nullptr)
		{
			std::memcpy(chunkData.data() + sizeof(sctp_asconf_ack_chunk), responseParams, responseParamsLen);
		}

		return addChunk(chunkData.data(), chunkLen);
	}

	bool SctpLayer::addReconfigChunk(const uint8_t* parameters, size_t parametersLen)
	{
		if (parameters == nullptr || parametersLen < sizeof(sctp_param_hdr))
			return false;

		size_t chunkLen = sizeof(sctp_reconfig_chunk) + parametersLen;
		std::vector<uint8_t> chunkData(chunkLen);

		auto* reconfigChunk = reinterpret_cast<sctp_reconfig_chunk*>(chunkData.data());
		reconfigChunk->type = static_cast<uint8_t>(SctpChunkType::RE_CONFIG);
		reconfigChunk->flags = 0;
		reconfigChunk->length = htobe16(static_cast<uint16_t>(chunkLen));

		std::memcpy(chunkData.data() + sizeof(sctp_reconfig_chunk), parameters, parametersLen);

		return addChunk(chunkData.data(), chunkLen);
	}

	// ==================== Additional SctpInitParameter Accessors ====================

	uint32_t SctpInitParameter::getZeroChecksumEdmid() const
	{
		if (m_Data == nullptr || getType() != SctpParameterType::ZERO_CHECKSUM_ACCEPTABLE)
			return 0;
		if (getValueSize() < 4)
			return 0;
		return be32toh(*reinterpret_cast<const uint32_t*>(getValue()));
	}

	uint8_t* SctpInitParameter::getUnrecognizedParameter() const
	{
		if (m_Data == nullptr || getType() != SctpParameterType::UNRECOGNIZED_PARAM)
			return nullptr;
		return getValue();
	}

	size_t SctpInitParameter::getUnrecognizedParameterLength() const
	{
		if (m_Data == nullptr || getType() != SctpParameterType::UNRECOGNIZED_PARAM)
			return 0;
		return getValueSize();
	}

	uint32_t SctpInitParameter::getAdaptationLayerIndication() const
	{
		if (m_Data == nullptr || getType() != SctpParameterType::ADAPTATION_LAYER_INDICATION)
			return 0;
		if (getValueSize() < 4)
			return 0;
		return be32toh(*reinterpret_cast<const uint32_t*>(getValue()));
	}

	// ==================== Additional SctpErrorCause Accessors ====================

	std::vector<uint16_t> SctpErrorCause::getMissingMandatoryParams() const
	{
		std::vector<uint16_t> result;
		if (m_Data == nullptr || getCode() != SctpErrorCauseCode::MISSING_MANDATORY_PARAM)
			return result;

		size_t dataSize = getDataSize();
		if (dataSize < 4)  // Need at least number of params field
			return result;

		uint8_t* data = getData();
		uint32_t numParams = be32toh(*reinterpret_cast<const uint32_t*>(data));
		data += 4;
		dataSize -= 4;

		for (uint32_t i = 0; i < numParams && dataSize >= 2; ++i)
		{
			result.push_back(be16toh(*reinterpret_cast<const uint16_t*>(data)));
			data += 2;
			dataSize -= 2;
		}

		return result;
	}

	uint8_t* SctpErrorCause::getUnrecognizedChunk() const
	{
		if (m_Data == nullptr || getCode() != SctpErrorCauseCode::UNRECOGNIZED_CHUNK_TYPE)
			return nullptr;
		return getData();
	}

	size_t SctpErrorCause::getUnrecognizedChunkLength() const
	{
		if (m_Data == nullptr || getCode() != SctpErrorCauseCode::UNRECOGNIZED_CHUNK_TYPE)
			return 0;
		return getDataSize();
	}

	uint8_t* SctpErrorCause::getUnrecognizedParameters() const
	{
		if (m_Data == nullptr || getCode() != SctpErrorCauseCode::UNRECOGNIZED_PARAMS)
			return nullptr;
		return getData();
	}

	size_t SctpErrorCause::getUnrecognizedParametersLength() const
	{
		if (m_Data == nullptr || getCode() != SctpErrorCauseCode::UNRECOGNIZED_PARAMS)
			return 0;
		return getDataSize();
	}

	uint8_t* SctpErrorCause::getUnresolvableAddress() const
	{
		if (m_Data == nullptr || getCode() != SctpErrorCauseCode::UNRESOLVABLE_ADDRESS)
			return nullptr;
		return getData();
	}

	size_t SctpErrorCause::getUnresolvableAddressLength() const
	{
		if (m_Data == nullptr || getCode() != SctpErrorCauseCode::UNRESOLVABLE_ADDRESS)
			return 0;
		return getDataSize();
	}

	uint8_t* SctpErrorCause::getRestartNewAddresses() const
	{
		if (m_Data == nullptr || getCode() != SctpErrorCauseCode::RESTART_WITH_NEW_ADDRESSES)
			return nullptr;
		return getData();
	}

	size_t SctpErrorCause::getRestartNewAddressesLength() const
	{
		if (m_Data == nullptr || getCode() != SctpErrorCauseCode::RESTART_WITH_NEW_ADDRESSES)
			return 0;
		return getDataSize();
	}

	// ==================== SctpReconfigParameter Implementation ====================

	SctpParameterType SctpReconfigParameter::getType() const
	{
		if (m_Data == nullptr)
			return static_cast<SctpParameterType>(0);
		return static_cast<SctpParameterType>(be16toh(m_Data->type));
	}

	uint16_t SctpReconfigParameter::getTypeAsInt() const
	{
		if (m_Data == nullptr)
			return 0;
		return be16toh(m_Data->type);
	}

	uint16_t SctpReconfigParameter::getLength() const
	{
		if (m_Data == nullptr)
			return 0;
		if (m_MaxLen < sizeof(sctp_param_hdr))
			return 0;
		return be16toh(m_Data->length);
	}

	size_t SctpReconfigParameter::getTotalSize() const
	{
		uint16_t len = getLength();
		if (len == 0)
			return 0;
		// Pad to 4-byte boundary
		size_t totalSize = (len + 3) & ~3;
		// Validate against available buffer
		if (totalSize > m_MaxLen)
			return 0;
		return totalSize;
	}

	uint32_t SctpReconfigParameter::getOutgoingReqSeqNum() const
	{
		if (m_Data == nullptr || getType() != SctpParameterType::OUTGOING_SSN_RESET_REQ)
			return 0;
		if (getLength() < sizeof(sctp_outgoing_ssn_reset_req))
			return 0;
		auto* req = reinterpret_cast<const sctp_outgoing_ssn_reset_req*>(m_Data);
		return be32toh(req->reqSeqNum);
	}

	uint32_t SctpReconfigParameter::getOutgoingRespSeqNum() const
	{
		if (m_Data == nullptr || getType() != SctpParameterType::OUTGOING_SSN_RESET_REQ)
			return 0;
		if (getLength() < sizeof(sctp_outgoing_ssn_reset_req))
			return 0;
		auto* req = reinterpret_cast<const sctp_outgoing_ssn_reset_req*>(m_Data);
		return be32toh(req->respSeqNum);
	}

	uint32_t SctpReconfigParameter::getOutgoingLastTsn() const
	{
		if (m_Data == nullptr || getType() != SctpParameterType::OUTGOING_SSN_RESET_REQ)
			return 0;
		if (getLength() < sizeof(sctp_outgoing_ssn_reset_req))
			return 0;
		auto* req = reinterpret_cast<const sctp_outgoing_ssn_reset_req*>(m_Data);
		return be32toh(req->lastTsn);
	}

	std::vector<uint16_t> SctpReconfigParameter::getResetStreamNumbers() const
	{
		std::vector<uint16_t> result;
		if (m_Data == nullptr)
			return result;

		SctpParameterType type = getType();
		uint16_t len = getLength();
		size_t headerSize = 0;

		if (type == SctpParameterType::OUTGOING_SSN_RESET_REQ)
		{
			headerSize = sizeof(sctp_outgoing_ssn_reset_req);
		}
		else if (type == SctpParameterType::INCOMING_SSN_RESET_REQ)
		{
			headerSize = sizeof(sctp_incoming_ssn_reset_req);
		}
		else
		{
			return result;
		}

		if (len <= headerSize)
			return result;

		size_t streamBytesLen = len - headerSize;
		size_t numStreams = streamBytesLen / 2;
		auto* streamPtr = reinterpret_cast<const uint16_t*>(reinterpret_cast<const uint8_t*>(m_Data) + headerSize);

		for (size_t i = 0; i < numStreams; ++i)
		{
			result.push_back(be16toh(streamPtr[i]));
		}

		return result;
	}

	uint32_t SctpReconfigParameter::getIncomingReqSeqNum() const
	{
		if (m_Data == nullptr || getType() != SctpParameterType::INCOMING_SSN_RESET_REQ)
			return 0;
		if (getLength() < sizeof(sctp_incoming_ssn_reset_req))
			return 0;
		auto* req = reinterpret_cast<const sctp_incoming_ssn_reset_req*>(m_Data);
		return be32toh(req->reqSeqNum);
	}

	uint32_t SctpReconfigParameter::getSsnTsnResetReqSeqNum() const
	{
		if (m_Data == nullptr || getType() != SctpParameterType::SSN_TSN_RESET_REQ)
			return 0;
		if (getLength() < sizeof(sctp_ssn_tsn_reset_req))
			return 0;
		auto* req = reinterpret_cast<const sctp_ssn_tsn_reset_req*>(m_Data);
		return be32toh(req->reqSeqNum);
	}

	uint32_t SctpReconfigParameter::getReconfigRespSeqNum() const
	{
		if (m_Data == nullptr || getType() != SctpParameterType::RECONFIG_RESPONSE)
			return 0;
		if (getLength() < sizeof(sctp_reconfig_response))
			return 0;
		auto* resp = reinterpret_cast<const sctp_reconfig_response*>(m_Data);
		return be32toh(resp->respSeqNum);
	}

	SctpReconfigResult SctpReconfigParameter::getReconfigResult() const
	{
		if (m_Data == nullptr || getType() != SctpParameterType::RECONFIG_RESPONSE)
			return static_cast<SctpReconfigResult>(0);
		if (getLength() < sizeof(sctp_reconfig_response))
			return static_cast<SctpReconfigResult>(0);
		auto* resp = reinterpret_cast<const sctp_reconfig_response*>(m_Data);
		return static_cast<SctpReconfigResult>(be32toh(resp->result));
	}

	bool SctpReconfigParameter::hasReconfigOptionalTsn() const
	{
		if (m_Data == nullptr || getType() != SctpParameterType::RECONFIG_RESPONSE)
			return false;
		// Optional fields present if length is 20 (12 base + 4 sender TSN + 4 receiver TSN)
		return getLength() >= 20;
	}

	uint32_t SctpReconfigParameter::getReconfigSenderNextTsn() const
	{
		if (!hasReconfigOptionalTsn())
			return 0;
		auto* resp = reinterpret_cast<const sctp_reconfig_response*>(m_Data);
		// Sender's Next TSN is right after the base structure
		auto* senderTsn =
		    reinterpret_cast<const uint32_t*>(reinterpret_cast<const uint8_t*>(resp) + sizeof(sctp_reconfig_response));
		return be32toh(*senderTsn);
	}

	uint32_t SctpReconfigParameter::getReconfigReceiverNextTsn() const
	{
		if (!hasReconfigOptionalTsn())
			return 0;
		auto* resp = reinterpret_cast<const sctp_reconfig_response*>(m_Data);
		// Receiver's Next TSN is after sender's TSN
		auto* receiverTsn = reinterpret_cast<const uint32_t*>(reinterpret_cast<const uint8_t*>(resp) +
		                                                      sizeof(sctp_reconfig_response) + 4);
		return be32toh(*receiverTsn);
	}

	uint32_t SctpReconfigParameter::getAddStreamsReqSeqNum() const
	{
		SctpParameterType type = getType();
		if (m_Data == nullptr || (type != SctpParameterType::ADD_OUTGOING_STREAMS_REQ &&
		                          type != SctpParameterType::ADD_INCOMING_STREAMS_REQ))
			return 0;
		if (getLength() < sizeof(sctp_add_streams_req))
			return 0;
		auto* req = reinterpret_cast<const sctp_add_streams_req*>(m_Data);
		return be32toh(req->reqSeqNum);
	}

	uint16_t SctpReconfigParameter::getAddStreamsCount() const
	{
		SctpParameterType type = getType();
		if (m_Data == nullptr || (type != SctpParameterType::ADD_OUTGOING_STREAMS_REQ &&
		                          type != SctpParameterType::ADD_INCOMING_STREAMS_REQ))
			return 0;
		if (getLength() < sizeof(sctp_add_streams_req))
			return 0;
		auto* req = reinterpret_cast<const sctp_add_streams_req*>(m_Data);
		return be16toh(req->numNewStreams);
	}

	std::string SctpReconfigParameter::getTypeName() const
	{
		switch (getType())
		{
		case SctpParameterType::OUTGOING_SSN_RESET_REQ:
			return "Outgoing SSN Reset Request";
		case SctpParameterType::INCOMING_SSN_RESET_REQ:
			return "Incoming SSN Reset Request";
		case SctpParameterType::SSN_TSN_RESET_REQ:
			return "SSN/TSN Reset Request";
		case SctpParameterType::RECONFIG_RESPONSE:
			return "Re-configuration Response";
		case SctpParameterType::ADD_OUTGOING_STREAMS_REQ:
			return "Add Outgoing Streams Request";
		case SctpParameterType::ADD_INCOMING_STREAMS_REQ:
			return "Add Incoming Streams Request";
		default:
			return "Unknown";
		}
	}

	// ==================== SctpReconfigParameterIterator Implementation ====================

	SctpReconfigParameterIterator::SctpReconfigParameterIterator(const SctpChunk& chunk)
	    : m_ParamsBase(nullptr), m_ParamsLen(0), m_CurrentOffset(0)
	{
		if (chunk.isNull())
			return;

		if (chunk.getChunkType() != SctpChunkType::RE_CONFIG)
			return;

		uint16_t chunkLen = chunk.getLength();
		if (chunkLen <= sizeof(sctp_reconfig_chunk))
			return;

		m_ParamsBase = chunk.getValue();
		m_ParamsLen = chunkLen - sizeof(sctp_chunk_hdr);
	}

	SctpReconfigParameter SctpReconfigParameterIterator::getParameter() const
	{
		if (!isValid())
			return SctpReconfigParameter(nullptr, 0);

		return SctpReconfigParameter(m_ParamsBase + m_CurrentOffset, m_ParamsLen - m_CurrentOffset);
	}

	SctpReconfigParameterIterator& SctpReconfigParameterIterator::next()
	{
		if (!isValid())
			return *this;

		SctpReconfigParameter param = getParameter();
		size_t paramTotalSize = param.getTotalSize();

		if (paramTotalSize == 0)
		{
			m_CurrentOffset = m_ParamsLen;
		}
		else
		{
			m_CurrentOffset += paramTotalSize;
		}

		return *this;
	}

	bool SctpReconfigParameterIterator::isValid() const
	{
		if (m_ParamsBase == nullptr || m_ParamsLen == 0)
			return false;

		if (m_CurrentOffset + sizeof(sctp_param_hdr) > m_ParamsLen)
			return false;

		auto* paramHdr = reinterpret_cast<const sctp_param_hdr*>(m_ParamsBase + m_CurrentOffset);
		uint16_t paramLen = be16toh(paramHdr->length);

		if (paramLen < sizeof(sctp_param_hdr) || m_CurrentOffset + paramLen > m_ParamsLen)
			return false;

		return true;
	}

	void SctpReconfigParameterIterator::reset()
	{
		m_CurrentOffset = 0;
	}

	// ==================== SctpAsconfParameter Implementation ====================

	SctpParameterType SctpAsconfParameter::getType() const
	{
		if (m_Data == nullptr)
			return static_cast<SctpParameterType>(0);
		return static_cast<SctpParameterType>(be16toh(m_Data->type));
	}

	uint16_t SctpAsconfParameter::getTypeAsInt() const
	{
		if (m_Data == nullptr)
			return 0;
		return be16toh(m_Data->type);
	}

	uint16_t SctpAsconfParameter::getLength() const
	{
		if (m_Data == nullptr)
			return 0;
		if (m_MaxLen < sizeof(sctp_param_hdr))
			return 0;
		return be16toh(m_Data->length);
	}

	size_t SctpAsconfParameter::getTotalSize() const
	{
		uint16_t len = getLength();
		if (len == 0)
			return 0;
		// Pad to 4-byte boundary
		size_t totalSize = (len + 3) & ~3;
		// Validate against available buffer
		if (totalSize > m_MaxLen)
			return 0;
		return totalSize;
	}

	uint32_t SctpAsconfParameter::getCorrelationId() const
	{
		SctpParameterType type = getType();
		if (m_Data == nullptr ||
		    (type != SctpParameterType::ADD_IP_ADDRESS && type != SctpParameterType::DELETE_IP_ADDRESS &&
		     type != SctpParameterType::SET_PRIMARY_ADDRESS))
			return 0;
		if (getLength() < sizeof(sctp_asconf_param))
			return 0;
		auto* param = reinterpret_cast<const sctp_asconf_param*>(m_Data);
		return be32toh(param->correlationId);
	}

	uint8_t* SctpAsconfParameter::getAddressParameter() const
	{
		SctpParameterType type = getType();
		if (m_Data == nullptr ||
		    (type != SctpParameterType::ADD_IP_ADDRESS && type != SctpParameterType::DELETE_IP_ADDRESS &&
		     type != SctpParameterType::SET_PRIMARY_ADDRESS))
			return nullptr;
		if (getLength() <= sizeof(sctp_asconf_param))
			return nullptr;
		return reinterpret_cast<uint8_t*>(m_Data) + sizeof(sctp_asconf_param);
	}

	size_t SctpAsconfParameter::getAddressParameterLength() const
	{
		SctpParameterType type = getType();
		if (m_Data == nullptr ||
		    (type != SctpParameterType::ADD_IP_ADDRESS && type != SctpParameterType::DELETE_IP_ADDRESS &&
		     type != SctpParameterType::SET_PRIMARY_ADDRESS))
			return 0;
		uint16_t len = getLength();
		if (len <= sizeof(sctp_asconf_param))
			return 0;
		return len - sizeof(sctp_asconf_param);
	}

	IPv4Address SctpAsconfParameter::getIPv4Address() const
	{
		uint8_t* addrParam = getAddressParameter();
		if (addrParam == nullptr)
			return IPv4Address::Zero;

		auto* paramHdr = reinterpret_cast<const sctp_param_hdr*>(addrParam);
		if (be16toh(paramHdr->type) != static_cast<uint16_t>(SctpParameterType::IPV4_ADDRESS))
			return IPv4Address::Zero;

		uint16_t paramLen = be16toh(paramHdr->length);
		if (paramLen < 8)  // 4 byte header + 4 byte address
			return IPv4Address::Zero;

		return IPv4Address(addrParam + sizeof(sctp_param_hdr));
	}

	IPv6Address SctpAsconfParameter::getIPv6Address() const
	{
		uint8_t* addrParam = getAddressParameter();
		if (addrParam == nullptr)
			return IPv6Address::Zero;

		auto* paramHdr = reinterpret_cast<const sctp_param_hdr*>(addrParam);
		if (be16toh(paramHdr->type) != static_cast<uint16_t>(SctpParameterType::IPV6_ADDRESS))
			return IPv6Address::Zero;

		uint16_t paramLen = be16toh(paramHdr->length);
		if (paramLen < 20)  // 4 byte header + 16 byte address
			return IPv6Address::Zero;

		return IPv6Address(addrParam + sizeof(sctp_param_hdr));
	}

	uint32_t SctpAsconfParameter::getResponseCorrelationId() const
	{
		SctpParameterType type = getType();
		if (m_Data == nullptr ||
		    (type != SctpParameterType::ERROR_CAUSE_INDICATION && type != SctpParameterType::SUCCESS_INDICATION))
			return 0;
		if (getLength() < sizeof(sctp_asconf_response))
			return 0;
		auto* resp = reinterpret_cast<const sctp_asconf_response*>(m_Data);
		return be32toh(resp->correlationId);
	}

	uint8_t* SctpAsconfParameter::getErrorCauses() const
	{
		if (m_Data == nullptr || getType() != SctpParameterType::ERROR_CAUSE_INDICATION)
			return nullptr;
		if (getLength() <= sizeof(sctp_asconf_response))
			return nullptr;
		return reinterpret_cast<uint8_t*>(m_Data) + sizeof(sctp_asconf_response);
	}

	size_t SctpAsconfParameter::getErrorCausesLength() const
	{
		if (m_Data == nullptr || getType() != SctpParameterType::ERROR_CAUSE_INDICATION)
			return 0;
		uint16_t len = getLength();
		if (len <= sizeof(sctp_asconf_response))
			return 0;
		return len - sizeof(sctp_asconf_response);
	}

	std::string SctpAsconfParameter::getTypeName() const
	{
		switch (getType())
		{
		case SctpParameterType::ADD_IP_ADDRESS:
			return "Add IP Address";
		case SctpParameterType::DELETE_IP_ADDRESS:
			return "Delete IP Address";
		case SctpParameterType::SET_PRIMARY_ADDRESS:
			return "Set Primary Address";
		case SctpParameterType::ERROR_CAUSE_INDICATION:
			return "Error Cause Indication";
		case SctpParameterType::SUCCESS_INDICATION:
			return "Success Indication";
		default:
			return "Unknown";
		}
	}

	// ==================== SctpAsconfParameterIterator Implementation ====================

	SctpAsconfParameterIterator::SctpAsconfParameterIterator(const SctpChunk& chunk, bool skipAddressParam)
	    : m_ParamsBase(nullptr), m_ParamsLen(0), m_CurrentOffset(0), m_InitialOffset(0)
	{
		if (chunk.isNull())
			return;

		SctpChunkType type = chunk.getChunkType();
		if (type != SctpChunkType::ASCONF && type != SctpChunkType::ASCONF_ACK)
			return;

		uint16_t chunkLen = chunk.getLength();
		size_t headerSize = (type == SctpChunkType::ASCONF) ? sizeof(sctp_asconf_chunk) : sizeof(sctp_asconf_ack_chunk);

		if (chunkLen <= headerSize)
			return;

		m_ParamsBase = chunk.getRecordBasePtr() + headerSize;
		m_ParamsLen = chunkLen - headerSize;

		// For ASCONF chunks, optionally skip the mandatory Address Parameter
		if (type == SctpChunkType::ASCONF && skipAddressParam && m_ParamsLen >= sizeof(sctp_param_hdr))
		{
			auto* addrParamHdr = reinterpret_cast<const sctp_param_hdr*>(m_ParamsBase);
			uint16_t addrParamLen = be16toh(addrParamHdr->length);
			size_t paddedLen = (addrParamLen + 3) & ~3;
			if (paddedLen <= m_ParamsLen)
			{
				m_InitialOffset = paddedLen;
				m_CurrentOffset = paddedLen;
			}
		}
	}

	SctpAsconfParameter SctpAsconfParameterIterator::getParameter() const
	{
		if (!isValid())
			return SctpAsconfParameter(nullptr, 0);

		return SctpAsconfParameter(m_ParamsBase + m_CurrentOffset, m_ParamsLen - m_CurrentOffset);
	}

	SctpAsconfParameterIterator& SctpAsconfParameterIterator::next()
	{
		if (!isValid())
			return *this;

		SctpAsconfParameter param = getParameter();
		size_t paramTotalSize = param.getTotalSize();

		if (paramTotalSize == 0)
		{
			m_CurrentOffset = m_ParamsLen;
		}
		else
		{
			m_CurrentOffset += paramTotalSize;
		}

		return *this;
	}

	bool SctpAsconfParameterIterator::isValid() const
	{
		if (m_ParamsBase == nullptr || m_ParamsLen == 0)
			return false;

		if (m_CurrentOffset + sizeof(sctp_param_hdr) > m_ParamsLen)
			return false;

		auto* paramHdr = reinterpret_cast<const sctp_param_hdr*>(m_ParamsBase + m_CurrentOffset);
		uint16_t paramLen = be16toh(paramHdr->length);

		if (paramLen < sizeof(sctp_param_hdr) || m_CurrentOffset + paramLen > m_ParamsLen)
			return false;

		return true;
	}

	void SctpAsconfParameterIterator::reset()
	{
		m_CurrentOffset = m_InitialOffset;
	}

	// ==================== NR-SACK Chunk Creation ====================

	bool SctpLayer::addNrSackChunk(uint32_t cumulativeTsnAck, uint32_t arwnd,
	                               const std::vector<sctp_gap_ack_block>& gapBlocks,
	                               const std::vector<sctp_gap_ack_block>& nrGapBlocks,
	                               const std::vector<uint32_t>& dupTsns, bool allNonRenegable)
	{
		size_t chunkLen = sizeof(sctp_nr_sack_chunk) + (gapBlocks.size() * sizeof(sctp_gap_ack_block)) +
		                  (nrGapBlocks.size() * sizeof(sctp_gap_ack_block)) + (dupTsns.size() * sizeof(uint32_t));

		std::vector<uint8_t> chunkData(chunkLen);

		auto* nrSackChunk = reinterpret_cast<sctp_nr_sack_chunk*>(chunkData.data());
		nrSackChunk->type = static_cast<uint8_t>(SctpChunkType::NR_SACK);
		nrSackChunk->flags = allNonRenegable ? SctpNrSackFlags::ALL_NON_RENEGABLE : 0;
		nrSackChunk->length = htobe16(static_cast<uint16_t>(chunkLen));
		nrSackChunk->cumulativeTsnAck = htobe32(cumulativeTsnAck);
		nrSackChunk->arwnd = htobe32(arwnd);
		nrSackChunk->numGapBlocks = htobe16(static_cast<uint16_t>(gapBlocks.size()));
		nrSackChunk->numNrGapBlocks = htobe16(static_cast<uint16_t>(nrGapBlocks.size()));
		nrSackChunk->numDupTsns = htobe16(static_cast<uint16_t>(dupTsns.size()));
		nrSackChunk->reserved = 0;

		size_t offset = sizeof(sctp_nr_sack_chunk);

		// Write Gap Ack Blocks
		for (const auto& block : gapBlocks)
		{
			auto* blockPtr = reinterpret_cast<sctp_gap_ack_block*>(chunkData.data() + offset);
			blockPtr->start = htobe16(block.start);
			blockPtr->end = htobe16(block.end);
			offset += sizeof(sctp_gap_ack_block);
		}

		// Write NR Gap Ack Blocks
		for (const auto& block : nrGapBlocks)
		{
			auto* blockPtr = reinterpret_cast<sctp_gap_ack_block*>(chunkData.data() + offset);
			blockPtr->start = htobe16(block.start);
			blockPtr->end = htobe16(block.end);
			offset += sizeof(sctp_gap_ack_block);
		}

		// Write Duplicate TSNs
		for (uint32_t tsn : dupTsns)
		{
			*reinterpret_cast<uint32_t*>(chunkData.data() + offset) = htobe32(tsn);
			offset += sizeof(uint32_t);
		}

		return addChunk(chunkData.data(), chunkLen);
	}

	// ==================== HMAC Functions (RFC 4895) ====================

	// SHA-1 implementation constants
	namespace
	{
		// SHA-1 context structure
		struct SHA1Context
		{
			uint32_t state[5];
			uint32_t count[2];
			uint8_t buffer[64];
		};

		constexpr uint32_t SHA1_K0 = 0x5A827999;
		constexpr uint32_t SHA1_K1 = 0x6ED9EBA1;
		constexpr uint32_t SHA1_K2 = 0x8F1BBCDC;
		constexpr uint32_t SHA1_K3 = 0xCA62C1D6;

		inline uint32_t rotl32(uint32_t x, int n)
		{
			return (x << n) | (x >> (32 - n));
		}

		void sha1Transform(uint32_t state[5], const uint8_t buffer[64])
		{
			uint32_t a, b, c, d, e, w[80];

			for (int i = 0; i < 16; ++i)
			{
				w[i] = (static_cast<uint32_t>(buffer[i * 4]) << 24) | (static_cast<uint32_t>(buffer[i * 4 + 1]) << 16) |
				       (static_cast<uint32_t>(buffer[i * 4 + 2]) << 8) | static_cast<uint32_t>(buffer[i * 4 + 3]);
			}

			for (int i = 16; i < 80; ++i)
			{
				w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
			}

			a = state[0];
			b = state[1];
			c = state[2];
			d = state[3];
			e = state[4];

			for (int i = 0; i < 20; ++i)
			{
				uint32_t temp = rotl32(a, 5) + ((b & c) | (~b & d)) + e + w[i] + SHA1_K0;
				e = d;
				d = c;
				c = rotl32(b, 30);
				b = a;
				a = temp;
			}

			for (int i = 20; i < 40; ++i)
			{
				uint32_t temp = rotl32(a, 5) + (b ^ c ^ d) + e + w[i] + SHA1_K1;
				e = d;
				d = c;
				c = rotl32(b, 30);
				b = a;
				a = temp;
			}

			for (int i = 40; i < 60; ++i)
			{
				uint32_t temp = rotl32(a, 5) + ((b & c) | (b & d) | (c & d)) + e + w[i] + SHA1_K2;
				e = d;
				d = c;
				c = rotl32(b, 30);
				b = a;
				a = temp;
			}

			for (int i = 60; i < 80; ++i)
			{
				uint32_t temp = rotl32(a, 5) + (b ^ c ^ d) + e + w[i] + SHA1_K3;
				e = d;
				d = c;
				c = rotl32(b, 30);
				b = a;
				a = temp;
			}

			state[0] += a;
			state[1] += b;
			state[2] += c;
			state[3] += d;
			state[4] += e;
		}

		void sha1Init(SHA1Context* ctx)
		{
			ctx->state[0] = 0x67452301;
			ctx->state[1] = 0xEFCDAB89;
			ctx->state[2] = 0x98BADCFE;
			ctx->state[3] = 0x10325476;
			ctx->state[4] = 0xC3D2E1F0;
			ctx->count[0] = ctx->count[1] = 0;
		}

		void sha1Update(SHA1Context* ctx, const uint8_t* data, size_t len)
		{
			size_t i, j;
			j = (ctx->count[0] >> 3) & 63;
			if ((ctx->count[0] += static_cast<uint32_t>(len << 3)) < (len << 3))
				ctx->count[1]++;
			ctx->count[1] += static_cast<uint32_t>(len >> 29);
			if ((j + len) > 63)
			{
				std::memcpy(&ctx->buffer[j], data, (i = 64 - j));
				sha1Transform(ctx->state, ctx->buffer);
				for (; i + 63 < len; i += 64)
					sha1Transform(ctx->state, &data[i]);
				j = 0;
			}
			else
			{
				i = 0;
			}
			std::memcpy(&ctx->buffer[j], &data[i], len - i);
		}

		void sha1Final(SHA1Context* ctx, uint8_t digest[20])
		{
			uint8_t finalcount[8];
			for (int i = 0; i < 8; ++i)
				finalcount[i] = static_cast<uint8_t>((ctx->count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 255);
			sha1Update(ctx, reinterpret_cast<const uint8_t*>("\200"), 1);
			while ((ctx->count[0] & 504) != 448)
				sha1Update(ctx, reinterpret_cast<const uint8_t*>("\0"), 1);
			sha1Update(ctx, finalcount, 8);
			for (int i = 0; i < 20; ++i)
				digest[i] = static_cast<uint8_t>((ctx->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
		}

		// SHA-256 implementation
		struct SHA256Context
		{
			uint32_t state[8];
			uint64_t count;
			uint8_t buffer[64];
		};

		constexpr uint32_t SHA256_K[64] = {
			0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
			0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
			0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
			0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
			0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
			0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
			0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
			0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
		};

		inline uint32_t rotr32(uint32_t x, int n)
		{
			return (x >> n) | (x << (32 - n));
		}

		inline uint32_t sha256Ch(uint32_t x, uint32_t y, uint32_t z)
		{
			return (x & y) ^ (~x & z);
		}
		inline uint32_t sha256Maj(uint32_t x, uint32_t y, uint32_t z)
		{
			return (x & y) ^ (x & z) ^ (y & z);
		}
		inline uint32_t sha256Sig0(uint32_t x)
		{
			return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22);
		}
		inline uint32_t sha256Sig1(uint32_t x)
		{
			return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25);
		}
		inline uint32_t sha256sig0(uint32_t x)
		{
			return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3);
		}
		inline uint32_t sha256sig1(uint32_t x)
		{
			return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10);
		}

		void sha256Transform(uint32_t state[8], const uint8_t buffer[64])
		{
			uint32_t a, b, c, d, e, f, g, h, w[64];

			for (int i = 0; i < 16; ++i)
			{
				w[i] = (static_cast<uint32_t>(buffer[i * 4]) << 24) | (static_cast<uint32_t>(buffer[i * 4 + 1]) << 16) |
				       (static_cast<uint32_t>(buffer[i * 4 + 2]) << 8) | static_cast<uint32_t>(buffer[i * 4 + 3]);
			}

			for (int i = 16; i < 64; ++i)
			{
				w[i] = sha256sig1(w[i - 2]) + w[i - 7] + sha256sig0(w[i - 15]) + w[i - 16];
			}

			a = state[0];
			b = state[1];
			c = state[2];
			d = state[3];
			e = state[4];
			f = state[5];
			g = state[6];
			h = state[7];

			for (int i = 0; i < 64; ++i)
			{
				uint32_t t1 = h + sha256Sig1(e) + sha256Ch(e, f, g) + SHA256_K[i] + w[i];
				uint32_t t2 = sha256Sig0(a) + sha256Maj(a, b, c);
				h = g;
				g = f;
				f = e;
				e = d + t1;
				d = c;
				c = b;
				b = a;
				a = t1 + t2;
			}

			state[0] += a;
			state[1] += b;
			state[2] += c;
			state[3] += d;
			state[4] += e;
			state[5] += f;
			state[6] += g;
			state[7] += h;
		}

		void sha256Init(SHA256Context* ctx)
		{
			ctx->state[0] = 0x6a09e667;
			ctx->state[1] = 0xbb67ae85;
			ctx->state[2] = 0x3c6ef372;
			ctx->state[3] = 0xa54ff53a;
			ctx->state[4] = 0x510e527f;
			ctx->state[5] = 0x9b05688c;
			ctx->state[6] = 0x1f83d9ab;
			ctx->state[7] = 0x5be0cd19;
			ctx->count = 0;
		}

		void sha256Update(SHA256Context* ctx, const uint8_t* data, size_t len)
		{
			size_t bufferPos = static_cast<size_t>(ctx->count & 63);
			ctx->count += len;

			while (len > 0)
			{
				size_t toCopy = (std::min)(len, static_cast<size_t>(64 - bufferPos));
				std::memcpy(&ctx->buffer[bufferPos], data, toCopy);
				bufferPos += toCopy;
				data += toCopy;
				len -= toCopy;

				if (bufferPos == 64)
				{
					sha256Transform(ctx->state, ctx->buffer);
					bufferPos = 0;
				}
			}
		}

		void sha256Final(SHA256Context* ctx, uint8_t digest[32])
		{
			size_t bufferPos = static_cast<size_t>(ctx->count & 63);
			ctx->buffer[bufferPos++] = 0x80;

			if (bufferPos > 56)
			{
				std::memset(&ctx->buffer[bufferPos], 0, 64 - bufferPos);
				sha256Transform(ctx->state, ctx->buffer);
				bufferPos = 0;
			}

			std::memset(&ctx->buffer[bufferPos], 0, 56 - bufferPos);

			uint64_t bitLen = ctx->count * 8;
			for (int i = 0; i < 8; ++i)
				ctx->buffer[56 + i] = static_cast<uint8_t>(bitLen >> (56 - i * 8));

			sha256Transform(ctx->state, ctx->buffer);

			for (int i = 0; i < 32; ++i)
				digest[i] = static_cast<uint8_t>(ctx->state[i >> 2] >> ((3 - (i & 3)) * 8));
		}
	}  // anonymous namespace

	bool calculateSctpHmacSha1(const uint8_t* key, size_t keyLen, const uint8_t* data, size_t dataLen, uint8_t* hmacOut)
	{
		if (key == nullptr || data == nullptr || hmacOut == nullptr)
			return false;

		constexpr size_t BLOCK_SIZE = 64;
		constexpr size_t HASH_SIZE = 20;

		uint8_t keyBlock[BLOCK_SIZE];
		std::memset(keyBlock, 0, BLOCK_SIZE);

		// If key is longer than block size, hash it
		if (keyLen > BLOCK_SIZE)
		{
			SHA1Context ctx;
			sha1Init(&ctx);
			sha1Update(&ctx, key, keyLen);
			sha1Final(&ctx, keyBlock);
		}
		else
		{
			std::memcpy(keyBlock, key, keyLen);
		}

		// Create inner and outer padded keys
		uint8_t innerPad[BLOCK_SIZE];
		uint8_t outerPad[BLOCK_SIZE];
		for (size_t i = 0; i < BLOCK_SIZE; ++i)
		{
			innerPad[i] = keyBlock[i] ^ 0x36;
			outerPad[i] = keyBlock[i] ^ 0x5C;
		}

		// Inner hash: H(K XOR ipad || message)
		SHA1Context innerCtx;
		sha1Init(&innerCtx);
		sha1Update(&innerCtx, innerPad, BLOCK_SIZE);
		sha1Update(&innerCtx, data, dataLen);
		uint8_t innerHash[HASH_SIZE];
		sha1Final(&innerCtx, innerHash);

		// Outer hash: H(K XOR opad || inner_hash)
		SHA1Context outerCtx;
		sha1Init(&outerCtx);
		sha1Update(&outerCtx, outerPad, BLOCK_SIZE);
		sha1Update(&outerCtx, innerHash, HASH_SIZE);
		sha1Final(&outerCtx, hmacOut);

		return true;
	}

	bool calculateSctpHmacSha256(const uint8_t* key, size_t keyLen, const uint8_t* data, size_t dataLen,
	                             uint8_t* hmacOut)
	{
		if (key == nullptr || data == nullptr || hmacOut == nullptr)
			return false;

		constexpr size_t BLOCK_SIZE = 64;
		constexpr size_t HASH_SIZE = 32;

		uint8_t keyBlock[BLOCK_SIZE];
		std::memset(keyBlock, 0, BLOCK_SIZE);

		// If key is longer than block size, hash it
		if (keyLen > BLOCK_SIZE)
		{
			SHA256Context ctx;
			sha256Init(&ctx);
			sha256Update(&ctx, key, keyLen);
			sha256Final(&ctx, keyBlock);
		}
		else
		{
			std::memcpy(keyBlock, key, keyLen);
		}

		// Create inner and outer padded keys
		uint8_t innerPad[BLOCK_SIZE];
		uint8_t outerPad[BLOCK_SIZE];
		for (size_t i = 0; i < BLOCK_SIZE; ++i)
		{
			innerPad[i] = keyBlock[i] ^ 0x36;
			outerPad[i] = keyBlock[i] ^ 0x5C;
		}

		// Inner hash: H(K XOR ipad || message)
		SHA256Context innerCtx;
		sha256Init(&innerCtx);
		sha256Update(&innerCtx, innerPad, BLOCK_SIZE);
		sha256Update(&innerCtx, data, dataLen);
		uint8_t innerHash[HASH_SIZE];
		sha256Final(&innerCtx, innerHash);

		// Outer hash: H(K XOR opad || inner_hash)
		SHA256Context outerCtx;
		sha256Init(&outerCtx);
		sha256Update(&outerCtx, outerPad, BLOCK_SIZE);
		sha256Update(&outerCtx, innerHash, HASH_SIZE);
		sha256Final(&outerCtx, hmacOut);

		return true;
	}

	bool verifySctpHmac(uint16_t hmacId, const uint8_t* key, size_t keyLen, const uint8_t* data, size_t dataLen,
	                    const uint8_t* expectedHmac, size_t expectedHmacLen)
	{
		if (key == nullptr || data == nullptr || expectedHmac == nullptr)
			return false;

		uint8_t computedHmac[SctpHmacSize::SHA256] = { 0 };  // Use largest size, zero-initialized
		size_t hmacSize = 0;

		switch (hmacId)
		{
		case static_cast<uint16_t>(SctpHmacIdentifier::SHA1):
			if (expectedHmacLen != SctpHmacSize::SHA1)
				return false;
			if (!calculateSctpHmacSha1(key, keyLen, data, dataLen, computedHmac))
				return false;
			hmacSize = SctpHmacSize::SHA1;
			break;

		case static_cast<uint16_t>(SctpHmacIdentifier::SHA256):
			if (expectedHmacLen != SctpHmacSize::SHA256)
				return false;
			if (!calculateSctpHmacSha256(key, keyLen, data, dataLen, computedHmac))
				return false;
			hmacSize = SctpHmacSize::SHA256;
			break;

		default:
			return false;  // Unsupported HMAC algorithm
		}

		// Constant-time comparison to prevent timing attacks
		uint8_t diff = 0;
		for (size_t i = 0; i < hmacSize; ++i)
		{
			diff |= computedHmac[i] ^ expectedHmac[i];
		}

		return diff == 0;
	}

	bool computeSctpAuthHmac(const SctpLayer& sctpLayer, const uint8_t* key, size_t keyLen, uint8_t* hmacOut,
	                         size_t* hmacOutLen)
	{
		if (key == nullptr || hmacOut == nullptr || hmacOutLen == nullptr)
			return false;

		// Find AUTH chunk
		SctpChunk authChunk = const_cast<SctpLayer&>(sctpLayer).getChunk(SctpChunkType::AUTH);
		if (authChunk.isNull())
			return false;

		// Use Auth view to access chunk details
		auto authView = SctpAuthChunkView::fromChunk(authChunk);
		if (!authView.isValid())
			return false;

		// Get AUTH chunk details
		uint16_t hmacId = authView.getHmacId();
		size_t authHmacLen = authView.getHmacLength();
		uint16_t authChunkLen = authChunk.getLength();

		// Determine expected HMAC size based on algorithm
		size_t expectedHmacSize;
		switch (hmacId)
		{
		case static_cast<uint16_t>(SctpHmacIdentifier::SHA1):
			expectedHmacSize = SctpHmacSize::SHA1;
			break;
		case static_cast<uint16_t>(SctpHmacIdentifier::SHA256):
			expectedHmacSize = SctpHmacSize::SHA256;
			break;
		default:
			return false;  // Unsupported HMAC algorithm
		}

		// Get pointers to build the data to authenticate
		uint8_t* authChunkPtr = authChunk.getRecordBasePtr();
		uint8_t* layerData = const_cast<SctpLayer&>(sctpLayer).getData();
		size_t layerLen = sctpLayer.getHeaderLen();

		// Calculate offset of AUTH chunk from layer start
		size_t authOffset = authChunkPtr - layerData;

		// AUTH chunk header is 8 bytes (type, flags, length, sharedKeyId, hmacId)
		// HMAC field starts at offset 8 within AUTH chunk
		constexpr size_t AUTH_HEADER_SIZE = 8;

		// Calculate total size of data to authenticate:
		// AUTH chunk (with zeroed HMAC) + all chunks after AUTH
		size_t authChunkTotalSize = authChunk.getTotalSize();
		size_t dataAfterAuth = layerLen - authOffset - authChunkTotalSize;
		size_t totalDataLen = authChunkTotalSize + dataAfterAuth;

		// Allocate buffer for data with zeroed HMAC
		std::vector<uint8_t> dataToAuth(totalDataLen);

		// Copy AUTH chunk header (8 bytes)
		std::memcpy(dataToAuth.data(), authChunkPtr, AUTH_HEADER_SIZE);

		// Zero out the HMAC field (comes after the 8-byte header)
		std::memset(dataToAuth.data() + AUTH_HEADER_SIZE, 0, authHmacLen);

		// Copy any padding after HMAC in AUTH chunk
		size_t postHmacOffset = AUTH_HEADER_SIZE + authHmacLen;
		size_t paddingLen = authChunkTotalSize - authChunkLen;
		if (paddingLen > 0 && postHmacOffset < authChunkTotalSize)
		{
			// There are padding bytes after HMAC
			size_t authChunkRemainder = authChunkTotalSize - postHmacOffset;
			std::memcpy(dataToAuth.data() + postHmacOffset, authChunkPtr + postHmacOffset, authChunkRemainder);
		}

		// Copy all chunks after AUTH chunk
		if (dataAfterAuth > 0)
		{
			std::memcpy(dataToAuth.data() + authChunkTotalSize, authChunkPtr + authChunkTotalSize, dataAfterAuth);
		}

		// Compute HMAC
		bool success = false;
		switch (hmacId)
		{
		case static_cast<uint16_t>(SctpHmacIdentifier::SHA1):
			success = calculateSctpHmacSha1(key, keyLen, dataToAuth.data(), totalDataLen, hmacOut);
			break;
		case static_cast<uint16_t>(SctpHmacIdentifier::SHA256):
			success = calculateSctpHmacSha256(key, keyLen, dataToAuth.data(), totalDataLen, hmacOut);
			break;
		}

		if (success)
			*hmacOutLen = expectedHmacSize;

		return success;
	}

	bool verifySctpAuthChunk(const SctpLayer& sctpLayer, const uint8_t* key, size_t keyLen)
	{
		if (key == nullptr)
			return false;

		// Find AUTH chunk
		SctpChunk authChunk = const_cast<SctpLayer&>(sctpLayer).getChunk(SctpChunkType::AUTH);
		if (authChunk.isNull())
			return false;

		// Use Auth view to access chunk details
		auto authView = SctpAuthChunkView::fromChunk(authChunk);
		if (!authView.isValid())
			return false;

		// Get the HMAC from the AUTH chunk
		const uint8_t* storedHmac = authView.getHmacData();
		size_t storedHmacLen = authView.getHmacLength();

		if (storedHmac == nullptr || storedHmacLen == 0)
			return false;

		// Compute expected HMAC
		uint8_t computedHmac[SctpHmacSize::SHA256];  // Large enough for both SHA-1 and SHA-256
		size_t computedHmacLen = 0;

		if (!computeSctpAuthHmac(sctpLayer, key, keyLen, computedHmac, &computedHmacLen))
			return false;

		// Verify lengths match
		if (computedHmacLen != storedHmacLen)
			return false;

		// Constant-time comparison
		uint8_t diff = 0;
		for (size_t i = 0; i < computedHmacLen; ++i)
		{
			diff |= computedHmac[i] ^ storedHmac[i];
		}

		return diff == 0;
	}

}  // namespace pcpp
