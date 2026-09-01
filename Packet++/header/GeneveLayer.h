#pragma once

#include "Layer.h"
#include "TLVData.h"

#include <iterator>
#include <vector>

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	class GeneveLayer;
	class GeneveOptionIterator;

	/// @struct geneve_header
	/// Represents the fixed part of a GENEVE protocol header
#pragma pack(push, 1)
	struct geneve_header
	{
		static constexpr size_t OptionsLengthUnit = 4;
		static constexpr size_t MaxOptionsLength = ((1 << 6) - 1) * OptionsLengthUnit;

#if (BYTE_ORDER == LITTLE_ENDIAN)
		/// Options length in 4-byte units
		uint8_t optionsLength : 6;
		/// Protocol version
		uint8_t version : 2;
		/// Reserved bits
		uint8_t reserved1 : 6;
		/// Critical options present flag
		uint8_t criticalFlag : 1;
		/// Operations, administration, and maintenance packet flag
		uint8_t oamFlag : 1;
#else
		/// Protocol version
		uint8_t version : 2;
		/// Options length in 4-byte units
		uint8_t optionsLength : 6;
		/// Operations, administration, and maintenance packet flag
		uint8_t oamFlag : 1;
		/// Critical options present flag
		uint8_t criticalFlag : 1;
		/// Reserved bits
		uint8_t reserved1 : 6;
#endif
		/// EtherType of the encapsulated protocol
		uint16_t protocolType;
		/// Virtual network identifier
		uint8_t vni[3];
		/// Reserved byte
		uint8_t reserved2;

		/// @return Options length in bytes
		size_t getOptionsLength() const
		{
			return static_cast<size_t>(optionsLength) * OptionsLengthUnit;
		}

		/// @param[in] value Options length in bytes
		/// @pre value must be divisible by 4 and no greater than MaxOptionsLength
		void setOptionsLength(size_t value)
		{
			optionsLength = static_cast<uint8_t>(value / OptionsLengthUnit);
		}

		/// @return The 24-bit virtual network identifier
		uint32_t getVNI() const
		{
			return (static_cast<uint32_t>(vni[0]) << 16) | (static_cast<uint32_t>(vni[1]) << 8) | vni[2];
		}

		/// @param[in] value The 24-bit virtual network identifier
		void setVNI(uint32_t value)
		{
			vni[0] = static_cast<uint8_t>((value >> 16) & 0xff);
			vni[1] = static_cast<uint8_t>((value >> 8) & 0xff);
			vni[2] = static_cast<uint8_t>(value & 0xff);
		}
	};
#pragma pack(pop)
	static_assert(sizeof(geneve_header) == 8, "geneve_header size is not 8 bytes");

	/// @struct geneve_option_header
	/// Represents a GENEVE option header
#pragma pack(push, 1)
	struct geneve_option_header
	{
		static constexpr size_t DataLengthUnit = 4;
		static constexpr size_t MaxDataLength = ((1 << 5) - 1) * DataLengthUnit;
		static constexpr uint8_t TypeMask = 0x7f;
		static constexpr uint8_t CriticalBitMask = 0x80;

		/// Option namespace assigned by IANA
		uint16_t optionClass;
		/// @return Option class in host byte order
		uint16_t getOptionClass() const;

		/// @param[in] value Option class in host byte order
		void setOptionClass(uint16_t value);

		/// Option type. The most significant bit is the critical bit
		uint8_t type;
#if (BYTE_ORDER == LITTLE_ENDIAN)
		/// Option data length in 4-byte units
		uint8_t length : 5;
		/// Reserved bits
		uint8_t reserved : 3;
#else
		/// Reserved bits
		uint8_t reserved : 3;
		/// Option data length in 4-byte units
		uint8_t length : 5;
#endif

		/// @return The 7-bit option type without the critical bit
		uint8_t getType() const
		{
			return extractType(type);
		}

		/// @param[in] value A raw option type, optionally including the critical bit
		/// @return The 7-bit option type without the critical bit
		static uint8_t extractType(uint8_t value)
		{
			return static_cast<uint8_t>(value & TypeMask);
		}

		/// Round an option data length up to the next 4-byte boundary
		/// @param[in] value Unpadded option data length in bytes
		/// @return Option data length rounded up to a multiple of 4
		static size_t alignDataSize(size_t value)
		{
			constexpr size_t AlignmentMask = DataLengthUnit - 1;
			return (value + AlignmentMask) & ~AlignmentMask;
		}

		/// @return True if the critical bit is set
		bool isCritical() const
		{
			return (type & CriticalBitMask) != 0;
		}

		/// @return Option data length in bytes
		size_t getDataSize() const
		{
			return static_cast<size_t>(length) * DataLengthUnit;
		}

		/// @param[in] value Option data length in bytes
		/// @pre value must be divisible by 4 and no greater than MaxDataLength
		void setDataSize(size_t value)
		{
			length = static_cast<uint8_t>(value / DataLengthUnit);
		}

		/// @return Total option size including its 4-byte header
		size_t getTotalSize() const
		{
			return sizeof(geneve_option_header) + getDataSize();
		}

		/// @param[in] value The 7-bit option type
		/// @param[in] critical Whether to set the critical bit
		void setType(uint8_t value, bool critical)
		{
			type = static_cast<uint8_t>(extractType(value) | (critical ? CriticalBitMask : 0));
		}
	};
#pragma pack(pop)
	static_assert(sizeof(geneve_option_header) == 4, "geneve_option_header size is not 4 bytes");

	/// @class GeneveOption
	/// A non-owning view of a GENEVE option. The view is invalidated when its underlying data is destroyed or moved,
	/// including when options are added to or removed from the containing GeneveLayer
	class GeneveOption
	{
		friend class GeneveLayer;
		friend class GeneveOptionIterator;
		friend class GeneveOptionRange;

	private:
		geneve_option_header* m_Data;

		explicit GeneveOption(geneve_option_header& optionData) : m_Data(&optionData)
		{}

		static bool canAssign(const uint8_t* optionRawData, size_t optionDataLen);

	public:
		/// @return Option class in host byte order
		uint16_t getOptionClass() const;

		/// @return The 7-bit option type without the critical bit
		uint8_t getType() const;

		/// @return True if the option is critical
		bool isCritical() const;

		/// @return Option data length in bytes
		size_t getDataSize() const;

		/// @return Total option size including its 4-byte header
		size_t getTotalSize() const;

		/// @return A pointer to the option data
		uint8_t* getData() const;

		/// @return A pointer to the option header
		uint8_t* getRecordBasePtr() const
		{
			return reinterpret_cast<uint8_t*>(m_Data);
		}
	};

	/// @class GeneveOptionIterator
	/// An input iterator over structurally valid GENEVE options
	class GeneveOptionIterator
	{
		friend class GeneveOptionRange;

	private:
		uint8_t* m_Current;
		uint8_t* m_End;

		GeneveOptionIterator(uint8_t* current, uint8_t* end) : m_Current(current), m_End(end)
		{}

	public:
		using iterator_category = std::input_iterator_tag;
		using value_type = GeneveOption;
		using difference_type = std::ptrdiff_t;
		using pointer = void;
		using reference = GeneveOption;

		/// Dereference this iterator
		/// @return A valid non-owning option view
		/// @pre This iterator must not equal the end iterator
		GeneveOption operator*() const;

		/// Advance to the next structurally valid option, or to the end iterator
		/// @return This iterator
		GeneveOptionIterator& operator++();

		/// Advance to the next structurally valid option, or to the end iterator
		/// @return The iterator value before it was advanced
		GeneveOptionIterator operator++(int);

		/// Compare two option iterators
		/// @param[in] other The iterator to compare
		/// @return True if both iterators refer to the same position in the same range
		bool operator==(const GeneveOptionIterator& other) const
		{
			return m_Current == other.m_Current && m_End == other.m_End;
		}

		/// Compare two option iterators
		/// @param[in] other The iterator to compare
		/// @return True if the iterators refer to different positions or ranges
		bool operator!=(const GeneveOptionIterator& other) const
		{
			return !operator==(other);
		}
	};

	/// @class GeneveOptionRange
	/// A non-owning range of GENEVE options. The range and all iterators obtained from it are invalidated when the
	/// containing GeneveLayer is modified or destroyed
	class GeneveOptionRange
	{
		friend class GeneveLayer;

	private:
		uint8_t* m_Begin;
		uint8_t* m_End;

		GeneveOptionRange(uint8_t* begin, uint8_t* end);

	public:
		/// Construct an empty option range
		GeneveOptionRange() : m_Begin(nullptr), m_End(nullptr)
		{}

		/// @return An iterator to the first option, or end() if the range is empty
		GeneveOptionIterator begin() const
		{
			return GeneveOptionIterator(m_Begin, m_End);
		}

		/// @return The iterator marking the end of this range
		GeneveOptionIterator end() const
		{
			return GeneveOptionIterator(m_End, m_End);
		}

		/// Find the first option matching a class and type
		/// @param[in] optionClass Option class in host byte order
		/// @param[in] optionType The 7-bit option type
		/// @return An iterator to the matching option, or end() if no option matches
		GeneveOptionIterator find(uint16_t optionClass, uint8_t optionType) const;

		/// @return The number of structurally valid options in this range
		/// @note This operation has O(n) time complexity, where n is the number of options.
		size_t size() const;

		/// @return True if this range contains no options
		bool empty() const
		{
			return m_Begin == m_End;
		}
	};

	/// @class GeneveOptionBuilder
	/// Builds GENEVE options. Option data is padded with zeroes to a 4-byte boundary
	class GeneveOptionBuilder : public TLVRecordBuilder
	{
	private:
		uint16_t m_OptionClass;
		bool m_Critical;

	public:
		/// Construct a GENEVE option builder
		/// @param[in] optionClass Option namespace assigned by IANA
		/// @param[in] optionType The 7-bit option type
		/// @param[in] optionData A read-only buffer containing option data
		/// @param[in] optionDataLen Option data length in bytes. The maximum supported length is 124 bytes
		/// @param[in] critical Set the option critical bit
		GeneveOptionBuilder(uint16_t optionClass, uint8_t optionType, const uint8_t* optionData, uint8_t optionDataLen,
		                    bool critical = false)
		    : TLVRecordBuilder(optionType, optionData, optionDataLen), m_OptionClass(optionClass), m_Critical(critical)
		{}

		/// Build a GENEVE option into an owning byte buffer
		/// @return The encoded option, or an empty buffer if the data is too long
		std::vector<uint8_t> build() const;
	};

	/// @class GeneveLayer
	/// Represents a GENEVE (Generic Network Virtualization Encapsulation) protocol layer
	class GeneveLayer : public Layer
	{
	public:
		/// The IANA-assigned UDP destination port for GENEVE
		static constexpr uint16_t DefaultPort = 6081;

		/// Construct a layer from existing packet data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where the layer is stored
		/// @note This constructor does not validate the input. Use isDataValid() before constructing a standalone
		/// parsed layer.
		GeneveLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, Geneve)
		{}

		/// Construct a new GENEVE layer
		/// @param[in] vni The 24-bit virtual network identifier
		/// @param[in] protocolType EtherType of the encapsulated protocol. Defaults to Transparent Ethernet Bridging
		/// @param[in] oamFlag Set the operations, administration, and maintenance flag
		explicit GeneveLayer(uint32_t vni = 0, uint16_t protocolType = 0x6558, bool oamFlag = false);

		~GeneveLayer() override = default;

		/// Validate a GENEVE byte stream, including all declared options
		/// @param[in] data The beginning of the GENEVE header
		/// @param[in] dataLen Available bytes
		/// @return True if the data contains a supported, structurally valid GENEVE header
		static bool isDataValid(const uint8_t* data, size_t dataLen);

		/// Check whether a UDP port is the standard GENEVE destination port
		/// @param[in] port UDP port in host byte order
		/// @return True for port 6081
		static bool isGenevePort(uint16_t port)
		{
			return port == DefaultPort;
		}

		/// @return A pointer to the fixed GENEVE header
		/// @pre The layer must contain a complete fixed GENEVE header
		geneve_header* getGeneveHeader() const
		{
			return reinterpret_cast<geneve_header*>(m_Data);
		}

		/// @return The VNI in host byte order
		/// @pre The layer must contain a complete fixed GENEVE header
		uint32_t getVNI() const;

		/// Set the VNI. Only the least significant 24 bits are used
		/// @param[in] vni The VNI to set
		/// @pre The layer must contain a complete fixed GENEVE header
		void setVNI(uint32_t vni);

		/// @return Encapsulated protocol EtherType in host byte order
		/// @pre The layer must contain a complete fixed GENEVE header
		uint16_t getProtocolType() const;

		/// Set the encapsulated protocol EtherType
		/// @param[in] protocolType EtherType in host byte order
		/// @pre The layer must contain a complete fixed GENEVE header
		void setProtocolType(uint16_t protocolType);

		/// @return Total options length in bytes, or zero if the fixed GENEVE header is unavailable or truncated
		size_t getOptionsLength() const;

		/// @return Number of structurally valid options in this layer, or zero if no valid option range is available
		size_t getOptionCount() const;

		/// @return A non-owning range over the options in this layer, or an empty range if the fixed GENEVE header is
		/// unavailable or truncated
		GeneveOptionRange getOptions() const;

		/// Add an option after all existing options
		/// @param[in] optionBuilder Builder containing the option to add
		/// @return True if the option was added successfully
		bool addOption(const GeneveOptionBuilder& optionBuilder);

		/// Remove the first option matching a class and type
		/// @param[in] optionClass Option class in host byte order
		/// @param[in] optionType The 7-bit option type
		/// @return True if an option was found and removed
		bool removeOption(uint16_t optionClass, uint8_t optionType);

		/// Remove all options
		/// @return True if all options were removed
		bool removeAllOptions();

		/// Parse the encapsulated protocol according to the Protocol Type field
		void parseNextLayer() override;

		/// @return Zero if no data is available; the available data length if the fixed header is truncated; otherwise,
		/// the fixed header plus the declared options length, capped at the available data length
		size_t getHeaderLen() const override;

		/// Update the Protocol Type and Critical flag from the following layer and options
		void computeCalculateFields() override;

		std::string toString() const override;

		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelDataLinkLayer;
		}

	private:
		void updateCriticalFlag();
	};
}  // namespace pcpp
