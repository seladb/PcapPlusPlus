#pragma once

#include "Layer.h"
#include "Asn1Codec.h"
#include <ostream>
#include <string>

/// @file

/**
 * @namespace pcpp
 * @brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
	/**
	 * @class LdapOperationType
	 * @brief An enum wrapper class for LDAP operation types
	 */
	class LdapOperationType
	{
	public:
		/**
		 * Define enum types and the corresponding int values
		 */
		enum Value : uint8_t
		{
			/// Bind Request
			BindRequest = 0,
			/// Bind Response
			BindResponse = 1,
			/// Unbind Request
			UnbindRequest = 2,
			/// Search Request
			SearchRequest = 3,
			/// Search Result Entry
			SearchResultEntry = 4,
			/// Search Result Done
			SearchResultDone = 5,
			/// Modify Request
			ModifyRequest = 6,
			/// Modify Response
			ModifyResponse = 7,
			/// Add Request
			AddRequest = 8,
			/// Add Response
			AddResponse = 9,
			/// Delete Request
			DelRequest = 10,
			/// Delete Response
			DelResponse = 11,
			/// Modify DN (Distinguished Name) Request
			ModifyDNRequest = 12,
			/// Modify DN (Distinguished Name) Response
			ModifyDNResponse = 13,
			/// Compare Request
			CompareRequest = 14,
			/// Compare Response
			CompareResponse = 15,
			/// Abandon Request
			AbandonRequest = 16,
			/// Search Result Reference
			SearchResultReference = 19,
			/// Extended Request
			ExtendedRequest = 23,
			/// Extended Resonse
			ExtendedResponse = 24,
			/// Intermediate Response
			IntermediateResponse = 25,
			/// Unknown operation type
			Unknown = 255
		};

		LdapOperationType() = default;

		/**
 		 * Construct LdapOperationType from Value enum
 		 * @param[in] value the opetation type enum value
 		 */
		constexpr LdapOperationType(Value value) : m_Value(value) {}

		/**
		 * @return A string representation of the operation type
		 */
		std::string toString() const;

		/**
		 * A static method that creates LdapOperationType from an integer value
		 * @param[in] value The operation type integer value
		 * @return The operation type that correspondes to the integer value. If the integer value
		 * doesn't correspondes to any operation type, LdapOperationType::Unknown is returned
		 */
		static LdapOperationType fromIntValue(uint8_t value);

		// Allow switch and comparisons.
		constexpr operator Value() const { return m_Value; }

		// Prevent usage: if(LdapOperationType)
		explicit operator bool() const = delete;

	private:
		Value m_Value;
	};

	/**
	 * @struct LdapControl
	 * A struct that represents an LDAP Control
	 */
	struct LdapControl
	{
		/// LDAP control type
		std::string controlType;
		/// LDAP control value
		std::string controlValue;

		/**
		 * Equality operator overload for this struct
		 * @param[in] other The value to compare with
		 * @return True if both values are equal, false otherwise
		 */
		bool operator==(const LdapControl& other) const
		{
			return controlType == other.controlType && controlValue == other.controlValue;
		}
	};

	/**
	 * @class LdapLayer
	 * Represents an LDAP message
	 */
	class LdapLayer : public Layer
	{
	public:
		/**
		 * A constrcutor to create a new LDAP message
		 * @param[in] messageId The LDAP message ID
		 * @param[in] operationType The LDAP operation type
		 * @param[in] messageRecords A vector of ASN.1 records that comprise the LDAP message
		 * @param[in] controls A vector of LDAP controls. This is an optional parameter, if not provided the message
		 * will be created without LDAP controls
		 */
		LdapLayer(uint16_t messageId, LdapOperationType operationType,
			const std::vector<Asn1Record*>& messageRecords,
			const std::vector<LdapControl> controls = std::vector<LdapControl>());

		~LdapLayer() {}

		/**
		 * @return The root ASN.1 record of the LDAP message. All of the message data will be under this record
		 */
		Asn1SequenceRecord* getRootAsn1Record() const;

		/**
		 * @return The ASN.1 record of the specific LDAP operation in this LDAP message. Each operation has a specific
		 * structure
		 */
		Asn1ConstructedRecord* getMessageAsn1Record() const;

		/**
		 * @return The LDAP message ID
		 */
		uint16_t getMessageID() const;

		/**
		 * @return A vector of LDAP controls in this message. If the message contains no controls then an empty
		 * vector is returned
		 */
		std::vector<LdapControl> getControls() const;

		/**
		 * @return The LDAP operation of this message
		 */
		LdapOperationType getLdapOperationType() const;

		/**
		 * A static method that checks whether a source or dest port match those associated with the LDAP protocol
		 * @param[in] port The port number to check
		 * @return True if this is an LDAP port, false otherwise
		 */
		static bool isLdapPort(uint16_t port) { return port == 389; }

		/**
		 * A static message to parse an LDAP message from raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 * @return An instance of LdapLayer if this is indeed an LDAP message, nullptr otherwise
		 */
		static LdapLayer* parseLdapMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		// implement abstract methods

		/**
		 * Tries to identify more LDAP messages in this packet if exist
		 */
		void parseNextLayer() override;

		/**
		 * @return The size of the LDAP message
		 */
		size_t getHeaderLen() const override { return m_Asn1Record->getTotalLength(); }

		void computeCalculateFields() override {}

		OsiModelLayer getOsiModelLayer() const override { return OsiModelApplicationLayer; }

		std::string toString() const override;

	protected:
		std::unique_ptr<Asn1Record> m_Asn1Record;

		LdapLayer(std::unique_ptr<Asn1Record>& asn1Record, uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);
		LdapLayer() = default;
		void init(uint16_t messageId, LdapOperationType operationType, const std::vector<Asn1Record*>& messageRecords, const std::vector<LdapControl>& controls);
		virtual std::string getExtendedStringInfo() const { return ""; }

		template <typename T, typename Member, typename LdapClass>
		bool internalTryGet(LdapClass* thisPtr, Member member, T& result)
		{
			try
			{
				result = (thisPtr->*member)();
				return true;
			}
			catch (...)
			{
				return false;
			}
		}
	};

} // namespace pcpp

inline std::ostream& operator<<(std::ostream& os, const pcpp::LdapControl& control)
{
	std::string valuesStream;
	os << "{" << control.controlType << ", " << control.controlValue << "}";
	return os;
}
