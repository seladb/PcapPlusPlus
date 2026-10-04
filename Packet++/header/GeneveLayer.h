#pragma once

#include "Layer.h"

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	class GeneveLayer;

	/// @class GeneveOption
	/// A non-owning view of a GENEVE option. The view is invalidated when its underlying data is destroyed or moved,
	/// including when options are added to or removed from the containing GeneveLayer
	class GeneveOption
	{
		friend class GeneveLayer;

	private:
#pragma pack(push, 1)
		struct geneve_option_header
		{
			uint16_t optionClass;
			uint8_t type;
#if (BYTE_ORDER == LITTLE_ENDIAN)
			uint8_t length : 5;
			uint8_t reserved : 3;
#else
			uint8_t reserved : 3;
			uint8_t length : 5;
#endif
		};
#pragma pack(pop)
		static_assert(sizeof(geneve_option_header) == 4, "geneve_option_header size is not 4 bytes");

		static constexpr size_t HeaderLength = sizeof(geneve_option_header);
		static constexpr size_t DataLengthUnit = 4;
		static constexpr size_t MaxDataLength = ((1 << 5) - 1) * DataLengthUnit;
		static constexpr uint8_t TypeMask = 0x7f;
		static constexpr uint8_t CriticalBitMask = 0x80;

		geneve_option_header* m_Data;

		/// Construct a view over an option encoded at optionData.
		explicit GeneveOption(uint8_t* optionData) : m_Data(reinterpret_cast<geneve_option_header*>(optionData))
		{}

		static bool canAssign(const uint8_t* optionRawData, size_t optionDataLen);
		void setOptionClass(uint16_t value);
		void setType(uint8_t value, bool critical);
		void setDataSize(size_t value);

		static uint8_t extractType(uint8_t value)
		{
			return static_cast<uint8_t>(value & TypeMask);
		}

		static size_t alignDataSize(size_t value)
		{
			constexpr size_t AlignmentMask = DataLengthUnit - 1;
			return (value + AlignmentMask) & ~AlignmentMask;
		}

		uint8_t* getRecordBasePtr() const
		{
			return reinterpret_cast<uint8_t*>(m_Data);
		}

	public:
		/// Construct a null option view.
		GeneveOption() : m_Data(nullptr)
		{}

		/// @return True if this option view does not refer to a complete option
		bool isNull() const
		{
			return m_Data == nullptr;
		}

		/// @return Option class in host byte order, or zero if this option is null
		uint16_t getOptionClass() const;

		/// @return The 7-bit option type without the critical bit, or zero if this option is null
		uint8_t getType() const;

		/// @return True if the option is critical, or false if this option is null
		bool isCritical() const;

		/// @return Option data length in bytes, or zero if this option is null
		size_t getDataSize() const;

		/// @return Total option size including its 4-byte header, or zero if this option is null
		size_t getTotalSize() const;

		/// @return A pointer to the option data, or nullptr if this option is null
		uint8_t* getData() const;
	};
	/// @class GeneveLayer
	/// Represents a GENEVE (Generic Network Virtualization Encapsulation) protocol layer
	class GeneveLayer : public Layer
	{
	private:
#pragma pack(push, 1)
		struct geneve_header
		{
#if (BYTE_ORDER == LITTLE_ENDIAN)
			uint8_t optionsLength : 6;
			uint8_t version : 2;
			uint8_t reserved1 : 6;
			uint8_t criticalFlag : 1;
			uint8_t oamFlag : 1;
#else
			uint8_t version : 2;
			uint8_t optionsLength : 6;
			uint8_t oamFlag : 1;
			uint8_t criticalFlag : 1;
			uint8_t reserved1 : 6;
#endif
			uint16_t protocolType;
			uint8_t vni[3];
			uint8_t reserved2;
		};
#pragma pack(pop)
		static_assert(sizeof(geneve_header) == 8, "geneve_header size is not 8 bytes");

		static constexpr size_t HeaderLength = sizeof(geneve_header);
		static constexpr size_t OptionsLengthUnit = 4;
		static constexpr size_t MaxOptionsLength = ((1 << 6) - 1) * OptionsLengthUnit;

		geneve_header* getGeneveHeader() const
		{
			return reinterpret_cast<geneve_header*>(m_Data);
		}

		void setOptionsLength(size_t value);

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

		/// Validate the fixed GENEVE header and its declared options area.
		/// @param[in] data The beginning of the GENEVE header
		/// @param[in] dataLen Available bytes
		/// @return True if the fixed header is supported and the declared options area fits in dataLen
		/// @note This is a fast-path check and does not parse individual options. Option accessors take into account
		/// that the data might be malformed and return a null option when an option cannot be read safely.
		static bool isDataValid(const uint8_t* data, size_t dataLen);

		/// Check whether a UDP port is the standard GENEVE destination port
		/// @param[in] port UDP port in host byte order
		/// @return True for port 6081
		static bool isGenevePort(uint16_t port)
		{
			return port == DefaultPort;
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

		/// @return True if the GENEVE OAM flag is set
		/// @pre The layer must contain a complete fixed GENEVE header
		bool getOamFlag() const;

		/// Set the GENEVE OAM flag
		/// @param[in] value Whether to set the OAM flag
		/// @pre The layer must contain a complete fixed GENEVE header
		void setOamFlag(bool value);

		/// @return True if the GENEVE critical options flag is set
		/// @pre The layer must contain a complete fixed GENEVE header
		bool getCriticalFlag() const;

		/// @pre The layer must contain a complete fixed GENEVE header
		/// @return Total options length in bytes declared by the fixed header
		size_t getOptionsLength() const;

		/// @pre The layer must contain a complete fixed GENEVE header
		/// @return Number of options that can be traversed safely before malformed data, in this layer
		size_t getOptionCount() const;

		/// @pre The layer must contain a complete fixed GENEVE header
		/// @return The first option, or a null option if no complete option is available
		GeneveOption getFirstOption() const;

		/// Get the option following a previous option.
		/// @param[in] option An option previously returned by this layer
		/// @return The next option, or a null option if the input is null, malformed, doesn't belong to this layer, is
		/// the last option, or the next option is malformed
		GeneveOption getNextOption(const GeneveOption& option) const;

		/// Find the first option with the given class and type.
		/// @param[in] optionClass Option namespace assigned by IANA
		/// @param[in] optionType The 7-bit option type
		/// @return The matching option, or a null option if it is not present or traversal reaches malformed data
		GeneveOption getOption(uint16_t optionClass, uint8_t optionType) const;

		/// Add an option after all existing options. Option data is padded with zeroes to a 4-byte boundary.
		/// @param[in] optionClass Option namespace assigned by IANA
		/// @param[in] optionType The 7-bit option type
		/// @param[in] optionData A read-only buffer containing option data
		/// @param[in] optionDataLen Option data length in bytes. The maximum supported length is 124 bytes
		/// @param[in] critical Set the option critical bit
		/// @return True if the option was added successfully
		bool addOption(uint16_t optionClass, uint8_t optionType, const uint8_t* optionData, size_t optionDataLen,
		               bool critical = false);

		/// Remove the first option matching a class and type
		/// @param[in] optionClass Option class in host byte order
		/// @param[in] optionType The 7-bit option type
		/// @return True if an option was found and removed
		bool removeOption(uint16_t optionClass, uint8_t optionType);

		/// Remove all options
		/// @return True if all options were removed
		bool removeAllOptions();

		/// Parse the encapsulated protocol according to the Protocol Type field.
		/// Supported next layers are IPv4, ARP, IPv6, VLAN/QinQ, MPLS, Ethernet and EthernetDot3; unsupported or
		/// malformed payloads are represented as a generic PayloadLayer.
		void parseNextLayer() override;

		/// @pre The layer must contain a complete fixed GENEVE header
		/// @return The fixed header plus the declared options length, capped at the available data length
		size_t getHeaderLen() const override;

		/// Update the Protocol Type and Critical flag from the following layer and options
		void computeCalculateFields() override;

		std::string toString() const override;

		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelDataLinkLayer;
		}

		/// @struct SerializedFields
		/// Fields written by GeneveLayer's serializeLayer(), in addition to
		/// Layer::SerializedFields.
		struct SerializedFields : Layer::SerializedFields
		{
			/// @return All field descriptors for GeneveLayer
			static std::vector<FieldDescriptor> all()
			{
				auto result = Layer::SerializedFields::all();
				std::initializer_list<FieldDescriptor> extra{ OptionsLength, ProtocolType, VNI,
					                                          OamFlag,       CriticalFlag, Options };
				std::copy(extra.begin(), extra.end(), std::back_inserter(result));
				return result;
			}

			/// @struct OptionObject
			/// Fields describing one element of the options array.
			struct OptionObject : ObjectFieldDescriptor<OptionObject>
			{
				using ObjectFieldDescriptor::ObjectFieldDescriptor;

				/// @return All field descriptors for one GENEVE option
				static std::vector<FieldDescriptor> all()
				{
					return { OptionClass, Type, Critical, DataSize };
				}

				/// @brief Option class in host byte order
				static const FieldDescriptor OptionClass;

				/// @brief Option type without the critical bit
				static const FieldDescriptor Type;

				/// @brief True if the option critical bit is set
				static const FieldDescriptor Critical;

				/// @brief Option data length in bytes
				static const FieldDescriptor DataSize;
			};

			/// @brief Total options length in bytes declared by the GENEVE header
			static const FieldDescriptor OptionsLength;

			/// @brief Encapsulated protocol EtherType in host byte order
			static const FieldDescriptor ProtocolType;

			/// @brief The 24-bit virtual network identifier
			static const FieldDescriptor VNI;

			/// @brief True if the GENEVE OAM flag is set
			static const FieldDescriptor OamFlag;

			/// @brief True if the GENEVE critical options flag is set
			static const FieldDescriptor CriticalFlag;

			/// @brief GENEVE options
			static const FieldDescriptor Options;

			/// Descriptor for one element of the options array
			static const OptionObject Option;
		};

	protected:
		void serializeLayer(ObjectScope& serializer) const override;

	private:
		void updateCriticalFlag();
	};
}  // namespace pcpp
