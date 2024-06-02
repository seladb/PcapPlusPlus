#pragma once

#include "Layer.h"
#include "Asn1Codec.h"
#include <ostream>
#include <string>
#include <functional>

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
			/// Extended Response
			ExtendedResponse = 24,
			/// Intermediate Response
			IntermediateResponse = 25,
			/// Unknown operation type
			Unknown = 255
		};

		LdapOperationType() = default;

		// cppcheck-suppress noExplicitConstructor
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
		 * @return The operation type that corresponds to the integer value. If the integer value
		 * doesn't corresponds to any operation type, LdapOperationType::Unknown is returned
		 */
		static LdapOperationType fromUintValue(uint8_t value);

		// Allow switch and comparisons.
		constexpr operator Value() const { return m_Value; }

		// Prevent usage: if(LdapOperationType)
		explicit operator bool() const = delete;

	private:
		Value m_Value = LdapOperationType::Unknown;
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
		 * A constructor to create a new LDAP message
		 * @param[in] messageId The LDAP message ID
		 * @param[in] operationType The LDAP operation type
		 * @param[in] messageRecords A vector of ASN.1 records that comprise the LDAP message
		 * @param[in] controls A vector of LDAP controls. This is an optional parameter, if not provided the message
		 * will be created without LDAP controls
		 */
		LdapLayer(uint16_t messageId, LdapOperationType operationType,
			const std::vector<Asn1Record*>& messageRecords,
			const std::vector<LdapControl>& controls = std::vector<LdapControl>());

		~LdapLayer() {}

		/**
		 * @return The root ASN.1 record of the LDAP message. All of the message data will be under this record.
		 * If the Root ASN.1 record is malformed, an exception is thrown
		 */
		Asn1SequenceRecord* getRootAsn1Record() const;

		/**
		 * @return The ASN.1 record of the specific LDAP operation in this LDAP message. Each operation has a specific
		 * structure. If the Operation ASN.1 record is malformed, an exception is thrown
		 */
		Asn1ConstructedRecord* getLdapOperationAsn1Record() const;

		/**
		 * @return The LDAP message ID. If the ASN.1 record is malformed, an exception is thrown
		 */
		uint16_t getMessageID() const;

		/**
		 * @return A vector of LDAP controls in this message. If the message contains no controls then an empty
		 * vector is returned. If the Controls ASN.1 record is malformed, an exception is thrown
		 */
		std::vector<LdapControl> getControls() const;

		/**
		 * @return The LDAP operation of this message. If the Operation ASN.1 record is malformed, an exception is thrown
		 */
		LdapOperationType getLdapOperationType() const;

		/**
		 * Most getter methods in this class throw an exception if the corresponding ASN.1 record is invalid.
		 * This is a wrapper method that allows calling these getters without adding a `try...catch` clause.
		 * It accepts the getter method and an out variable. It tries to call the getter and if no exception
		 * is thrown, the out variable will contain the result.
		 *
		 * Here is an example:
		 * @code
		 * uint16_t messageId;
		 * ldapLayer->tryGet(&pcpp::LdapLayer::getMessageID, messageId));
		 * @endcode
		 *
		 * We call getMessageID(), if no exception is thrown the variable messageId will hold the result
		 *
		 * @tparam Method The class method type
		 * @tparam ResultType The expected result type (for example: uint8_t, std::string, etc.)
		 * @param[in] method The class method to call
		 * @param[out] result An outvariable to contain the result if no exception is thrown
		 * @return True if no exception was thrown or false otherwise
		 */
		template <typename Method, typename ResultType>
		bool tryGet(Method method, ResultType& result)
		{
			return internalTryGet(this, method, result);
		}

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

		static constexpr int messageIdIndex = 0;
		static constexpr int operationTypeIndex = 1;
		static constexpr int controlsIndex = 2;

		static constexpr int controlTypeIndex = 0;
		static constexpr int controlValueIndex = 1;

		template <typename LdapClass, typename Method, typename ResultType>
		bool internalTryGet(LdapClass* thisPtr, Method method, ResultType& result)
		{
			try
			{
				result = std::mem_fn(method)(thisPtr);
				return true;
			}
			catch (...)
			{
				return false;
			}
		}
	};

	/**
	 * @class LdapSearchRequestLayer
	 * Represents LDAP search request operation
	 */
	class LdapSearchRequestLayer : public LdapLayer
	{
	public:
		/**
		 * @class SearchRequestScope
		 * An enum wrapper class for LDAP search request scope
		 */
		class SearchRequestScope
		{
		public:
			/**
			 * Define enum types and the corresponding int values
			 */
			enum Value : uint8_t
			{
				/**
				 * The search operation should only be performed against the entry specified as the search base DN
				 */
				BaseObject = 0,
				/**
				 * The search operation should only be performed against entries that are immediate subordinates
				 * of the entry specified as the search base DN
				 */
				SingleLevel = 1,
				/**
				 * The search operation should be performed against the entry specified as the search base
				 * and all of its subordinates to any depth
				 */
				WholeSubtree = 2,
				/**
				 * The search operation should be performed against any subordinate entries (to any depth) below the
				 * entry specified by the base DN should be considered, but the base entry itself
				 * should not be considered
				 */
				subordinateSubtree = 3,
				/**
				 * Unknown or unsupported scope
				 */
				Unknown = 255
			};

			SearchRequestScope() = default;

			/**
			 * Construct SearchRequestScope from Value enum
			 * @param[in] value the scope enum value
			 */
			constexpr SearchRequestScope(Value value) : m_Value(value) {}

			/**
			 * @return A string representation of the scope value
			 */
			std::string toString() const;

			/**
			 * A static method that creates SearchRequestScope from an integer value
			 * @param[in] value The scope integer value
			 * @return The scope that corresponds to the integer value. If the integer value
			 * doesn't corresponds to any enum value, SearchRequestScope::Unknown is returned
			 */
			static SearchRequestScope fromUintValue(uint8_t value);

			// Allow switch and comparisons.
			constexpr operator Value() const { return m_Value; }

			// Prevent usage: if(LdapOperationType)
			explicit operator bool() const = delete;
		private:
			Value m_Value;
		};

		/**
		 * @class DerefAliases
		 * An enum wrapper class for LDAP search request dereferencing aliases
		 */
		class DerefAliases
		{
		public:
			/**
			 * Define enum types and the corresponding int values
			 */
			enum Value : uint8_t
			{
				/// Never dereferences aliases
				NeverDerefAliases = 0,
				/// Dereferences aliases only after name resolution
				DerefInSearching = 1,
				/// Dereferences aliases only during name resolution
				DerefFindingBaseObj = 2,
				/// Always dereference aliases
				DerefAlways = 3,
				Unknown = 255
			};

			DerefAliases() = default;

			/**
			 * Construct DerefAliases from Value enum
			 * @param[in] value the dereference alias enum value
			 */
			constexpr DerefAliases(Value value) : m_Value(value) {}

			/**
			 * @return A string representation of the dereference alias value
			 */
			std::string toString() const;

			/**
			 * A static method that creates DerefAliases from an integer value
			 * @param[in] value The dereference alias integer value
			 * @return The dereference alias that corresponds to the integer value. If the integer value
			 * doesn't corresponds to any enum value, DerefAliases::Unknown is returned
			 */
			static DerefAliases fromUintValue(uint8_t value);

			// Allow switch and comparisons.
			constexpr operator Value() const { return m_Value; }

			// Prevent usage: if(LdapOperationType)
			explicit operator bool() const = delete;
		private:
			Value m_Value;
		};

		/**
		 * A constructor to create a new LDAP search request message
		 * @param[in] messageId The LDAP message ID
		 * @param[in] baseObject The base object for the LDAP search request entry
		 * @param[in] scope The portion of the target subtree that should be considered
		 * @param[in] derefAliases The alias dereferencing behavior, which indicates how the server should treat
		 * any aliases encountered while processing the search
		 * @param[in] sizeLimit The maximum number of entries that should be returned from the search
		 * @param[in] timeLimit The time limit for the search in seconds
		 * @param[in] typesOnly If this is given a value of true, then it indicates that entries that match the
		 * search criteria should be returned containing only the attribute descriptions for the attributes
		 * contained in that entry but should not include the values for those attributes.
		 * If this is given a value of false, then it indicates that the attribute values should be included
		 * in the entries that are returned
		 * @param[in] filterRecord The filter for the search. Please note that parsing for the search filter
		 * doesn't exist yet. Therefore, the expected input value should be a plain ASN.1 record
		 * @param[in] attributes A set of attributes to request for inclusion in entries that match the search
		 * criteria and are returned to the client
		 * @param[in] controls A vector of LDAP controls. This is an optional parameter, if not provided the message
		 * will be created without LDAP controls
		 */
		LdapSearchRequestLayer(
			uint16_t messageId, const std::string& baseObject, SearchRequestScope scope, DerefAliases derefAliases,
			uint8_t sizeLimit, uint8_t timeLimit, bool typesOnly, Asn1Record* filterRecord,
			const std::vector<std::string>& attributes, const std::vector<LdapControl>& controls = std::vector<LdapControl>());

		/**
		 * @return The base object for the LDAP search request entry
		 */
		std::string getBaseObject() const;

		/**
		 * @return The portion of the target subtree that should be considered
		 */
		SearchRequestScope getScope() const;

		/**
		 * @return The alias dereferencing behavior
		 */
		DerefAliases getDerefAlias() const;

		/**
		 * @return The maximum number of entries that should be returned from the search
		 */
		uint8_t getSizeLimit() const;

		/**
		 * @return The time limit for the search in seconds
		 */
		uint8_t getTimeLimit() const;

		/**
		 * @return If this flag is true, then it indicates that entries that match the search criteria should be
		 * returned containing only the attribute descriptions for the attributes contained in that entry but
		 * should not include the values for those attributes. If this flag is false, then it indicates that the
		 * attribute values should be included in the entries that are returned
		 */
		bool getTypesOnly() const;

		/**
		 * @return The filter for the search. Please note that parsing for the search filter doesn't exist yet.
		 * Therefore, the return value is a plain ASN.1 record
		 */
		Asn1Record* getFilter() const;

		/**
		 * @return A list of search request attributes
		 */
		std::vector<std::string> getAttributes() const;

		template <typename T, typename Member>
		bool tryGet(Member member, T& result)
		{
			return internalTryGet(this, member, result);
		}

	protected:
		friend LdapLayer* LdapLayer::parseLdapMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		static constexpr int baseObjectIndex = 0;
		static constexpr int scopeIndex = 1;
		static constexpr int derefAliasIndex = 2;
		static constexpr int sizeLimitIndex = 3;
		static constexpr int timeLimitIndex = 4;
		static constexpr int typesOnlyIndex = 5;
		static constexpr int filterIndex = 6;
		static constexpr int attributesIndex = 7;

		LdapSearchRequestLayer(std::unique_ptr<Asn1Record>& asn1Record, uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
			: LdapLayer(asn1Record, data, dataLen, prevLayer, packet) {}


		std::string getExtendedStringInfo() const override;
	};


} // namespace pcpp

inline std::ostream& operator<<(std::ostream& os, const pcpp::LdapControl& control)
{
	os << "{" << control.controlType << ", " << control.controlValue << "}";
	return os;
}
