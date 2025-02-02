#pragma once

#include "Layer.h"
#include "Asn1Codec.h"
#include <ostream>
#include <string>
#include <functional>

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	/// @class LdapOperationType
	/// @brief An enum wrapper class for LDAP operation types
	class LdapOperationType
	{
	public:
		/// Define enum types and the corresponding int values
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
			DeleteRequest = 10,
			/// Delete Response
			DeleteResponse = 11,
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
		/// Construct LdapOperationType from Value enum
		/// @param[in] value the operation type enum value
		constexpr LdapOperationType(Value value) : m_Value(value)
		{}

		/// @return A string representation of the operation type
		std::string toString() const;

		/// A static method that creates LdapOperationType from an integer value
		/// @param[in] value The operation type integer value
		/// @return The operation type that corresponds to the integer value. If the integer value
		/// doesn't corresponds to any operation type, LdapOperationType::Unknown is returned
		static LdapOperationType fromUintValue(uint8_t value);

		// Allow switch and comparisons.
		constexpr operator Value() const
		{
			return m_Value;
		}

		// Prevent usage: if(LdapOperationType)
		explicit operator bool() const = delete;

	private:
		Value m_Value = LdapOperationType::Unknown;
	};

	/// @class LdapResultCode
	/// @brief An enum wrapper class for LDAP result codes
	class LdapResultCode
	{
	public:
		/// Define enum types and the corresponding int values
		enum Value : uint8_t
		{
			/// Indicates that the associated operation completed successfully
			Success = 0,
			/// Indicates that there was a problem with the client’s use of the LDAP protocol
			OperationsError = 1,
			/// Indicates that there was a problem with the client’s use of the LDAP protocol
			ProtocolError = 2,
			/// Indicates that the associated operation failed because it hadn’t completed by the time
			/// a maximum processing time limit had been reached
			TimeLimitExceeded = 3,
			/// Indicates that the associated search operation failed because the server has determined
			/// that the number of entries that would be returned in response to the search would exceed
			/// the upper bound for that operation
			SizeLimitExceeded = 4,
			/// Indicates that the associated compare request targeted an entry that exists and that contains
			/// the targeted attribute, but does not have any value that matches the provided assertion value
			CompareFalse = 5,
			/// Indicates that the associated compare request targeted an entry that exists and that contains
			/// the targeted attribute with a value that matches the provided assertion value
			CompareTrue = 6,
			/// Indicates that the associated bind operation failed because the client attempted to authenticate
			/// with a mechanism that the server does not support or that it does not allow the client to use
			AuthMethodNotSupported = 7,
			/// Indicates that the server requires the client to authenticate with a stronger form of authentication
			StrongerAuthRequired = 8,
			/// Indicates that the request cannot be processed exactly as issued, but that it might succeed
			/// if re-issued to a different server, or is updated to target a different location in the DIT
			Referral = 10,
			/// Indicates that some administrative limit within the server was exceeded while processing the request
			AdminLimitExceeded = 11,
			/// Indicates that the request includes a control with a criticality of true,
			/// but that control could not be honored for some reason
			UnavailableCriticalExtension = 12,
			/// Indicates that the server is only willing to process the requested operation if it is received
			/// over a secure connection that does not allow an eavesdropper to decipher or alter the contents
			/// of the request or response
			ConfidentialityRequired = 13,
			/// Indicates that the server has completed a portion of the processing for the provided SASL
			/// bind request, but that it needs additional information from the client to complete the authentication
			SaslBindInProgress = 14,
			/// Indicates that the request targeted an attribute that does not exist in the specified entry
			NoSuchAttribute = 16,
			/// Indicates that the request attempted to provide one or more values for an attribute type
			/// that is not defined in the server schema
			UndefinedAttributeType = 17,
			/// Indicates that the search request tried to perform some type of matching that is not
			/// supported for the target attribute type
			InappropriateMatching = 18,
			/// Indicates that the requested operation would have resulted in an entry that violates
			/// some constraint defined within the server
			ConstraintViolation = 19,
			/// Indicates that the requested operation would have resulted in an attribute in which
			/// the same value appeared more than once
			AttributeOrValueExists = 20,
			/// Indicates that the requested add or modify operation would have resulted in an entry
			/// that had at least one attribute value that does not conform to the constraints of the
			/// associated attribute syntax
			InvalidAttributeSyntax = 21,
			/// Indicates that the requested operation targeted an entry that does not exist within the DIT
			NoSuchObject = 32,
			/// Indicates that a problem occurred while attempting to dereference an alias during search processing
			AliasProblem = 33,
			/// Indicates that the request included a malformed entry DN
			InvalidDNSyntax = 34,
			/// Indicates that the server encountered an alias while processing the request and that there
			/// was some problem related to that alias
			AliasDereferencingProblem = 36,
			/// Indicates that the client attempted to bind in an inappropriate manner that is inappropriate
			/// for the target account
			InappropriateAuthentication = 48,
			/// Indicates that the client attempted to bind with a set of credentials that cannot
			/// be used to authenticate
			InvalidCredentials = 49,
			/// Indicates that the client requested an operation for which it does not have the necessary
			/// access control permissions
			InsufficientAccessRights = 50,
			/// Indicates that the requested operation cannot be processed because the server is currently too busy
			Busy = 51,
			/// Indicates that the server is currently not available to process the requested operation
			Unavailable = 52,
			/// Indicates that the server is not willing to process the requested operation for some reason
			UnwillingToPerform = 53,
			/// Indicates that the server detected some kind of circular reference in the course
			/// of processing an operation
			LoopDetect = 54,
			/// Indicates that the requested add or modify DN operation would have resulted in an entry
			/// that violates some naming constraint within the server
			NamingViolation = 64,
			/// Indicates that the requested operation would have resulted in an entry that has
			/// an inappropriate set of object classes, or whose attributes violate the constraints
			/// associated with its set of object classes
			ObjectClassViolation = 65,
			/// Indicates that the requested operation is only supported for leaf entries,
			/// but the targeted entry has one or more subordinates
			NotAllowedOnNonLeaf = 66,
			/// Indicates that the requested modify operation would have resulted in an entry that
			/// does not include all of the attributes used in its RDN
			NotAllowedOnRDN = 67,
			/// Indicates that the requested operation would have resulted in an entry with the same
			/// DN as an entry that already exists in the server
			EntryAlreadyExists = 68,
			/// Indicates that the requested modify operation would have altered the target entry’s
			/// set of object classes in a way that is not supported
			ObjectClassModsProhibited = 69,
			/// Indicates that the requested operation would have required manipulating information
			/// in multiple servers in a way that is not supported
			AffectsMultipleDSAs = 71,
			/// Used when a problem occurs for which none of the other result codes is more appropriate
			Other = 80,
			/// Unknown result code
			Unknown = 255
		};

		LdapResultCode() = default;

		// cppcheck-suppress noExplicitConstructor
		/// Construct LdapResultCode from Value enum
		/// @param[in] value the result code enum value
		constexpr LdapResultCode(Value value) : m_Value(value)
		{}

		/// @return A string representation of the result code
		std::string toString() const;

		/// A static method that creates LdapResultCode from an integer value
		/// @param[in] value The result code integer value
		/// @return The result code that corresponds to the integer value. If the integer value
		/// doesn't corresponds to any operation type, LdapResultCode::Unknown is returned
		static LdapResultCode fromUintValue(uint8_t value);

		// Allow switch and comparisons
		constexpr operator Value() const
		{
			return m_Value;
		}

		// Prevent usage: if(LdapResultCode)
		explicit operator bool() const = delete;

	private:
		Value m_Value = LdapResultCode::Unknown;
	};

	/// @struct LdapControl
	/// A struct that represents an LDAP Control
	struct LdapControl
	{
		/// LDAP control type
		std::string controlType;
		/// LDAP control value
		std::string controlValue;

		/// Equality operator overload for this struct
		/// @param[in] other The value to compare with
		/// @return True if both values are equal, false otherwise
		bool operator==(const LdapControl& other) const
		{
			return controlType == other.controlType && controlValue == other.controlValue;
		}
	};

	/// @struct LdapAttribute
	/// A struct that represents an LDAP attribute
	struct LdapAttribute
	{
		/// Attribute description
		std::string type;
		/// A list of attribute values (zero or more)
		std::vector<std::string> values;

		/// Equality operator overload for this struct
		/// @param[in] other The value to compare with
		/// @return True if both values are equal, false otherwise
		bool operator==(const LdapAttribute& other) const
		{
			return type == other.type && values == other.values;
		}
	};

	/// @class LdapLayer
	/// Represents an LDAP message
	class LdapLayer : public Layer
	{
	public:
		/// A constructor to create a new LDAP message
		/// @param[in] messageId The LDAP message ID
		/// @param[in] operationType The LDAP operation type
		/// @param[in] messageRecords A vector of ASN.1 records that comprise the LDAP message
		/// @param[in] controls A vector of LDAP controls. This is an optional parameter, if not provided the message
		/// will be created without LDAP controls
		LdapLayer(uint16_t messageId, LdapOperationType operationType, const std::vector<Asn1Record*>& messageRecords,
		          const std::vector<LdapControl>& controls = std::vector<LdapControl>());

		~LdapLayer() override = default;

		/// @return The root ASN.1 record of the LDAP message. All of the message data will be under this record.
		/// If the Root ASN.1 record is malformed, an exception is thrown
		Asn1SequenceRecord* getRootAsn1Record() const;

		/// @return The ASN.1 record of the specific LDAP operation in this LDAP message. Each operation has a specific
		/// structure. If the Operation ASN.1 record is malformed, an exception is thrown
		Asn1ConstructedRecord* getLdapOperationAsn1Record() const;

		/// @return The LDAP message ID. If the ASN.1 record is malformed, an exception is thrown
		uint16_t getMessageID() const;

		/// @return A vector of LDAP controls in this message. If the message contains no controls then an empty
		/// vector is returned. If the Controls ASN.1 record is malformed, an exception is thrown
		std::vector<LdapControl> getControls() const;

		/// @return The LDAP operation of this message. If the Operation ASN.1 record is malformed, an exception is
		/// thrown
		virtual LdapOperationType getLdapOperationType() const;

		/// Most getter methods in this class throw an exception if the corresponding ASN.1 record is invalid.
		/// This is a wrapper method that allows calling these getters without adding a `try...catch` clause.
		/// It accepts the getter method and an out variable. It tries to call the getter and if no exception
		/// is thrown, the out variable will contain the result.
		///
		/// Here is an example:
		/// @code
		/// uint16_t messageId;
		/// ldapLayer->tryGet(&pcpp::LdapLayer::getMessageID, messageId));
		/// @endcode
		///
		/// We call getMessageID(), if no exception is thrown the variable messageId will hold the result
		///
		/// @tparam Method The class method type
		/// @tparam ResultType The expected result type (for example: uint8_t, std::string, etc.)
		/// @param[in] method The class method to call
		/// @param[out] result An outvariable to contain the result if no exception is thrown
		/// @return True if no exception was thrown or false otherwise
		template <typename Method, typename ResultType> bool tryGet(Method method, ResultType& result)
		{
			return internalTryGet(this, method, result);
		}

		/// A static method that checks whether a source or dest port match those associated with the LDAP protocol
		/// @param[in] port The port number to check
		/// @return True if this is an LDAP port, false otherwise
		static bool isLdapPort(uint16_t port)
		{
			return port == 389;
		}

		/// A static message to parse an LDAP message from raw data
		/// @param[in] data A pointer to the raw data
		/// @param[in] dataLen Size of the data in bytes
		/// @param[in] prevLayer A pointer to the previous layer
		/// @param[in] packet A pointer to the Packet instance where layer will be stored in
		/// @return An instance of LdapLayer if this is indeed an LDAP message, nullptr otherwise
		static LdapLayer* parseLdapMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		// implement abstract methods

		/// Tries to identify more LDAP messages in this packet if exist
		void parseNextLayer() override;

		/// @return The size of the LDAP message
		size_t getHeaderLen() const override
		{
			return m_Asn1Record->getTotalLength();
		}

		void computeCalculateFields() override
		{}

		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelApplicationLayer;
		}

		std::string toString() const override;

	protected:
		std::unique_ptr<Asn1Record> m_Asn1Record;

		LdapLayer(std::unique_ptr<Asn1Record> asn1Record, uint8_t* data, size_t dataLen, Layer* prevLayer,
		          Packet* packet);
		LdapLayer() = default;
		void init(uint16_t messageId, LdapOperationType operationType, const std::vector<Asn1Record*>& messageRecords,
		          const std::vector<LdapControl>& controls);
		virtual std::string getExtendedInfoString() const
		{
			return "";
		}

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

	/// @class LdapResponseLayer
	/// An abstract class for representing an LDAP response message. It's the parent class
	/// for all response message layers
	class LdapResponseLayer : public LdapLayer
	{
	public:
		/// @return LDAP result code
		LdapResultCode getResultCode() const;

		/// @return An optional distinguished name (DN) that may be included in the response to a request
		/// targeting an entry that does not exist
		std::string getMatchedDN() const;

		/// @return An optional string that can provide additional information about the processing that
		/// was performed
		std::string getDiagnosticMessage() const;

		/// @return An optional list of one or more URIs that the client may use to re-try the operation
		/// somewhere else. If referral doesn't exist on the message, and empty vector is returned
		std::vector<std::string> getReferral() const;

	protected:
		static constexpr int resultCodeIndex = 0;
		static constexpr int matchedDNIndex = 1;
		static constexpr int diagnotsticsMessageIndex = 2;
		static constexpr int referralIndex = 3;

		static constexpr uint8_t referralTagType = 3;

		LdapResponseLayer() = default;
		LdapResponseLayer(std::unique_ptr<Asn1Record> asn1Record, uint8_t* data, size_t dataLen, Layer* prevLayer,
		                  Packet* packet)
		    : LdapLayer(std::move(asn1Record), data, dataLen, prevLayer, packet)
		{}

		LdapResponseLayer(uint16_t messageId, LdapOperationType operationType, LdapResultCode resultCode,
		                  const std::string& matchedDN, const std::string& diagnosticMessage,
		                  const std::vector<std::string>& referral = std::vector<std::string>(),
		                  const std::vector<LdapControl>& controls = std::vector<LdapControl>());

		void init(uint16_t messageId, LdapOperationType operationType, LdapResultCode resultCode,
		          const std::string& matchedDN, const std::string& diagnosticMessage,
		          const std::vector<std::string>& referral = std::vector<std::string>(),
		          const std::vector<Asn1Record*>& additionalRecords = std::vector<Asn1Record*>(),
		          const std::vector<LdapControl>& controls = std::vector<LdapControl>());

		std::string getExtendedInfoString() const override;
	};

	/// @class LdapBindRequestLayer
	/// Represents LDAP bind request operation
	class LdapBindRequestLayer : public LdapLayer
	{
	public:
		/// An enum to represent the bind request authentication type
		enum class AuthenticationType : uint8_t
		{
			/// Simple authentication
			Simple = 0,
			/// SASL authentication
			Sasl = 3,
			/// Unknown / not application authentication type
			NotApplicable = 255
		};

		/// @struct SaslAuthentication
		/// A struct to represent SASL authentication
		struct SaslAuthentication
		{
			/// The SASL mechanism
			std::string mechanism;
			/// Encoded SASL credentials
			std::vector<uint8_t> credentials;

			/// Equality operator overload for this struct
			/// @param[in] other The value to compare with
			/// @return True if both values are equal, false otherwise
			bool operator==(const SaslAuthentication& other) const
			{
				return mechanism == other.mechanism && credentials == other.credentials;
			}

			/// Inequality operator overload for this struct
			/// @param[in] other The value to compare with
			/// @return False if both values are equal, true otherwise
			bool operator!=(const SaslAuthentication& other) const
			{
				return !operator==(other);
			}
		};

		/// A constructor to create a new LDAP bind request message with simple authentication
		/// @param[in] messageId The LDAP message ID
		/// @param[in] version The LDAP protocol version that the client wants to use
		/// @param[in] name The DN of the user to authenticate
		/// @param[in] simpleAuthentication Simple authentication to use in this message
		/// @param[in] controls A vector of LDAP controls. This is an optional parameter, if not provided the message
		/// will be created without LDAP controls
		LdapBindRequestLayer(uint16_t messageId, uint8_t version, const std::string& name,
		                     const std::string& simpleAuthentication,
		                     const std::vector<LdapControl>& controls = std::vector<LdapControl>());

		/// A constructor to create a new LDAP bind request message with SASL authentication
		/// @param[in] messageId The LDAP message ID
		/// @param[in] version The LDAP protocol version that the client wants to use
		/// @param[in] name The DN of the user to authenticate
		/// @param[in] saslAuthentication SASL authentication to use in this message
		/// @param[in] controls A vector of LDAP controls. This is an optional parameter, if not provided the message
		/// will be created without LDAP controls
		LdapBindRequestLayer(uint16_t messageId, uint8_t version, const std::string& name,
		                     const SaslAuthentication& saslAuthentication,
		                     const std::vector<LdapControl>& controls = std::vector<LdapControl>());

		/// @return The LDAP protocol version that the client wants to use
		uint32_t getVersion() const;

		/// @return The DN of the user to authenticate
		std::string getName() const;

		/// @return The authentication type included in this message
		AuthenticationType getAuthenticationType() const;

		/// @return The simple authentication included in this message
		/// @throws std::invalid_argument if the message doesn't include simple authentication
		std::string getSimpleAuthentication() const;

		/// @return The SASL authentication included in this message
		/// @throws std::invalid_argument if the message doesn't include SASL authentication
		SaslAuthentication getSaslAuthentication() const;

		template <typename Method, typename ResultType> bool tryGet(Method method, ResultType& result)
		{
			return internalTryGet(this, method, result);
		}

	protected:
		friend LdapLayer* LdapLayer::parseLdapMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		LdapBindRequestLayer(std::unique_ptr<Asn1Record> asn1Record, uint8_t* data, size_t dataLen, Layer* prevLayer,
		                     Packet* packet)
		    : LdapLayer(std::move(asn1Record), data, dataLen, prevLayer, packet)
		{}

		std::string getExtendedInfoString() const override;

	private:
		static constexpr int versionIndex = 0;
		static constexpr int nameIndex = 1;
		static constexpr int credentialIndex = 2;

		static constexpr int saslMechanismIndex = 0;
		static constexpr int saslCredentialsIndex = 1;
	};

	/// @class LdapBindResponseLayer
	/// Represents LDAP bind response operation
	class LdapBindResponseLayer : public LdapResponseLayer
	{
	public:
		/// A constructor to create a new LDAP bind response message
		/// @param[in] messageId The LDAP message ID
		/// @param[in] resultCode The LDAP result code
		/// @param[in] matchedDN The distinguished name (DN) to set on the message. If not applicable
		/// pass an empty string
		/// @param[in] diagnosticMessage The additional information to set on the message. If not applicable
		/// pass an empty string
		/// @param[in] referral A list of URIs to re-try the operation somewhere else. This is an optional
		/// parameter. If not provided then referral won't be added to the message
		/// @param[in] serverSaslCredentials Encoded server SASL credentials for use in subsequent processing
		/// @param[in] controls A vector of LDAP controls. This is an optional parameter, if not provided the message
		/// will be created without LDAP controls
		LdapBindResponseLayer(uint16_t messageId, LdapResultCode resultCode, const std::string& matchedDN,
		                      const std::string& diagnosticMessage,
		                      const std::vector<std::string>& referral = std::vector<std::string>(),
		                      const std::vector<uint8_t>& serverSaslCredentials = std::vector<uint8_t>(),
		                      const std::vector<LdapControl>& controls = std::vector<LdapControl>());

		/// @return Encoded server SASL credentials for use in subsequent processing
		std::vector<uint8_t> getServerSaslCredentials() const;

	protected:
		friend LdapLayer* LdapLayer::parseLdapMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		static constexpr int serverSaslCredentialsTagType = 7;

		LdapBindResponseLayer(std::unique_ptr<Asn1Record> asn1Record, uint8_t* data, size_t dataLen, Layer* prevLayer,
		                      Packet* packet)
		    : LdapResponseLayer(std::move(asn1Record), data, dataLen, prevLayer, packet)
		{}
	};

	/// @class LdapUnbindRequestLayer
	/// Represents LDAP unbind operation
	class LdapUnbindRequestLayer : public LdapLayer
	{
	public:
		/// A constructor to create a new LDAP unbind message
		/// @param[in] messageId The LDAP message ID
		/// @param[in] controls A vector of LDAP controls. This is an optional parameter, if not provided the message
		/// will be created without LDAP controls
		explicit LdapUnbindRequestLayer(uint16_t messageId,
		                                const std::vector<LdapControl>& controls = std::vector<LdapControl>());

		// Unbind request has no operation record
		Asn1ConstructedRecord* getLdapOperationAsn1Record() const = delete;

		LdapOperationType getLdapOperationType() const override
		{
			return LdapOperationType::UnbindRequest;
		}

		template <typename Method, typename ResultType> bool tryGet(Method method, ResultType& result)
		{
			return internalTryGet(this, method, result);
		}

	protected:
		friend LdapLayer* LdapLayer::parseLdapMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		LdapUnbindRequestLayer(std::unique_ptr<Asn1Record> asn1Record, uint8_t* data, size_t dataLen, Layer* prevLayer,
		                       Packet* packet)
		    : LdapLayer(std::move(asn1Record), data, dataLen, prevLayer, packet)
		{}
	};

	/// @class LdapSearchRequestLayer
	/// Represents LDAP search request operation
	class LdapSearchRequestLayer : public LdapLayer
	{
	public:
		/// @class SearchRequestScope
		/// An enum wrapper class for LDAP search request scope
		class SearchRequestScope
		{
		public:
			/// Define enum types and the corresponding int values
			enum Value : uint8_t
			{
				/// The search operation should only be performed against the entry specified as the search base DN
				BaseObject = 0,
				/// The search operation should only be performed against entries that are immediate subordinates
				/// of the entry specified as the search base DN
				SingleLevel = 1,
				/// The search operation should be performed against the entry specified as the search base
				/// and all of its subordinates to any depth
				WholeSubtree = 2,
				/// The search operation should be performed against any subordinate entries (to any depth) below the
				/// entry specified by the base DN should be considered, but the base entry itself
				/// should not be considered
				subordinateSubtree = 3,
				/// Unknown or unsupported scope
				Unknown = 255
			};

			SearchRequestScope() = default;

			// cppcheck-suppress noExplicitConstructor
			/// Construct SearchRequestScope from Value enum
			/// @param[in] value the scope enum value
			constexpr SearchRequestScope(Value value) : m_Value(value)
			{}

			/// @return A string representation of the scope value
			std::string toString() const;

			/// A static method that creates SearchRequestScope from an integer value
			/// @param[in] value The scope integer value
			/// @return The scope that corresponds to the integer value. If the integer value
			/// doesn't corresponds to any enum value, SearchRequestScope::Unknown is returned
			static SearchRequestScope fromUintValue(uint8_t value);

			// Allow switch and comparisons.
			constexpr operator Value() const
			{
				return m_Value;
			}

			// Prevent usage: if(LdapOperationType)
			explicit operator bool() const = delete;

		private:
			Value m_Value = SearchRequestScope::Unknown;
		};

		/// @class DerefAliases
		/// An enum wrapper class for LDAP search request dereferencing aliases
		class DerefAliases
		{
		public:
			/// Define enum types and the corresponding int values
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
				/// Unknown value
				Unknown = 255
			};

			DerefAliases() = default;

			// cppcheck-suppress noExplicitConstructor
			/// Construct DerefAliases from Value enum
			/// @param[in] value the dereference alias enum value
			constexpr DerefAliases(Value value) : m_Value(value)
			{}

			/// @return A string representation of the dereference alias value
			std::string toString() const;

			/// A static method that creates DerefAliases from an integer value
			/// @param[in] value The dereference alias integer value
			/// @return The dereference alias that corresponds to the integer value. If the integer value
			/// doesn't corresponds to any enum value, DerefAliases::Unknown is returned
			static DerefAliases fromUintValue(uint8_t value);

			// Allow switch and comparisons.
			constexpr operator Value() const
			{
				return m_Value;
			}

			// Prevent usage: if(LdapOperationType)
			explicit operator bool() const = delete;

		private:
			Value m_Value = DerefAliases::Unknown;
		};

		/// A constructor to create a new LDAP search request message
		/// @param[in] messageId The LDAP message ID
		/// @param[in] baseObject The base object for the LDAP search request entry
		/// @param[in] scope The portion of the target subtree that should be considered
		/// @param[in] derefAliases The alias dereferencing behavior, which indicates how the server should treat
		/// any aliases encountered while processing the search
		/// @param[in] sizeLimit The maximum number of entries that should be returned from the search
		/// @param[in] timeLimit The time limit for the search in seconds
		/// @param[in] typesOnly If this is given a value of true, then it indicates that entries that match the
		/// search criteria should be returned containing only the attribute descriptions for the attributes
		/// contained in that entry but should not include the values for those attributes.
		/// If this is given a value of false, then it indicates that the attribute values should be included
		/// in the entries that are returned
		/// @param[in] filterRecord The filter for the search. Please note that parsing for the search filter
		/// doesn't exist yet. Therefore, the expected input value should be a plain ASN.1 record
		/// @param[in] attributes A set of attributes to request for inclusion in entries that match the search
		/// criteria and are returned to the client
		/// @param[in] controls A vector of LDAP controls. This is an optional parameter, if not provided the message
		/// will be created without LDAP controls
		LdapSearchRequestLayer(uint16_t messageId, const std::string& baseObject, SearchRequestScope scope,
		                       DerefAliases derefAliases, uint8_t sizeLimit, uint8_t timeLimit, bool typesOnly,
		                       Asn1Record* filterRecord, const std::vector<std::string>& attributes,
		                       const std::vector<LdapControl>& controls = std::vector<LdapControl>());

		/// @return The base object for the LDAP search request entry
		std::string getBaseObject() const;

		/// @return The portion of the target subtree that should be considered
		SearchRequestScope getScope() const;

		/// @return The alias dereferencing behavior
		DerefAliases getDerefAlias() const;

		/// @return The maximum number of entries that should be returned from the search
		uint8_t getSizeLimit() const;

		/// @return The time limit for the search in seconds
		uint8_t getTimeLimit() const;

		/// @return If this flag is true, then it indicates that entries that match the search criteria should be
		/// returned containing only the attribute descriptions for the attributes contained in that entry but
		/// should not include the values for those attributes. If this flag is false, then it indicates that the
		/// attribute values should be included in the entries that are returned
		bool getTypesOnly() const;

		/// @return The filter for the search. Please note that parsing for the search filter doesn't exist yet.
		/// Therefore, the return value is a plain ASN.1 record
		Asn1Record* getFilter() const;

		/// @return A list of search request attributes
		std::vector<std::string> getAttributes() const;

		template <typename Method, typename ResultType> bool tryGet(Method method, ResultType& result)
		{
			return internalTryGet(this, method, result);
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

		LdapSearchRequestLayer(std::unique_ptr<Asn1Record> asn1Record, uint8_t* data, size_t dataLen, Layer* prevLayer,
		                       Packet* packet)
		    : LdapLayer(std::move(asn1Record), data, dataLen, prevLayer, packet)
		{}

		std::string getExtendedInfoString() const override;
	};

	/// @class LdapSearchResultEntryLayer
	/// Represents LDAP search result entry message
	class LdapSearchResultEntryLayer : public LdapLayer
	{
	public:
		/// A constructor to create a new LDAP search result entry message
		/// @param[in] messageId The LDAP message ID
		/// @param[in] objectName The entry's DN
		/// @param[in] attributes The entry's attributes
		/// @param[in] controls A vector of LDAP controls. This is an optional parameter, if not provided the message
		/// will be created without LDAP controls
		LdapSearchResultEntryLayer(uint16_t messageId, const std::string& objectName,
		                           const std::vector<LdapAttribute>& attributes,
		                           const std::vector<LdapControl>& controls = std::vector<LdapControl>());

		/// @return The entry's DN
		std::string getObjectName() const;

		/// @return The entry's attributes
		std::vector<LdapAttribute> getAttributes() const;

		template <typename Method, typename ResultType> bool tryGet(Method method, ResultType& result)
		{
			return internalTryGet(this, method, result);
		}

	protected:
		friend LdapLayer* LdapLayer::parseLdapMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		static constexpr int objectNameIndex = 0;
		static constexpr int attributesIndex = 1;
		static constexpr int attributeTypeIndex = 0;
		static constexpr int attributeValueIndex = 1;

		LdapSearchResultEntryLayer(std::unique_ptr<Asn1Record> asn1Record, uint8_t* data, size_t dataLen,
		                           Layer* prevLayer, Packet* packet)
		    : LdapLayer(std::move(asn1Record), data, dataLen, prevLayer, packet)
		{}
	};

	/// @class LdapSearchResultDoneLayer
	/// Represents LDAP search result done message
	class LdapSearchResultDoneLayer : public LdapResponseLayer
	{
	public:
		/// A constructor to create a new LDAP search result done message
		/// @param[in] messageId The LDAP message ID
		/// @param[in] resultCode The LDAP result code
		/// @param[in] matchedDN The distinguished name (DN) to set on the message. If not applicable
		/// pass an empty string
		/// @param[in] diagnosticMessage The additional information to set on the message. If not applicable
		/// pass an empty string
		/// @param[in] referral A list of URIs to re-try the operation somewhere else. This is an optional
		/// parameter. If not provided then referral won't be added to the message
		/// @param[in] controls A vector of LDAP controls. This is an optional parameter, if not provided the message
		/// will be created without LDAP controls
		LdapSearchResultDoneLayer(uint16_t messageId, LdapResultCode resultCode, const std::string& matchedDN,
		                          const std::string& diagnosticMessage,
		                          const std::vector<std::string>& referral = std::vector<std::string>(),
		                          const std::vector<LdapControl>& controls = std::vector<LdapControl>())
		    : LdapResponseLayer(messageId, LdapOperationType::SearchResultDone, resultCode, matchedDN,
		                        diagnosticMessage, referral, controls)
		{}

	protected:
		friend LdapLayer* LdapLayer::parseLdapMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		LdapSearchResultDoneLayer(std::unique_ptr<Asn1Record> asn1Record, uint8_t* data, size_t dataLen,
		                          Layer* prevLayer, Packet* packet)
		    : LdapResponseLayer(std::move(asn1Record), data, dataLen, prevLayer, packet)
		{}
	};

	/// @class LdapModifyResponseLayer
	/// Represents LDAP modify response message
	class LdapModifyResponseLayer : public LdapResponseLayer
	{
	public:
		/// A constructor to create a new LDAP modify response message
		/// @param[in] messageId The LDAP message ID
		/// @param[in] resultCode The LDAP result code
		/// @param[in] matchedDN The distinguished name (DN) to set on the message. If not applicable
		/// pass an empty string
		/// @param[in] diagnosticMessage The additional information to set on the message. If not applicable
		/// pass an empty string
		/// @param[in] referral A list of URIs to re-try the operation somewhere else. This is an optional
		/// parameter. If not provided then referral won't be added to the message
		/// @param[in] controls A vector of LDAP controls. This is an optional parameter, if not provided the message
		/// will be created without LDAP controls
		LdapModifyResponseLayer(uint16_t messageId, LdapResultCode resultCode, const std::string& matchedDN,
		                        const std::string& diagnosticMessage,
		                        const std::vector<std::string>& referral = std::vector<std::string>(),
		                        const std::vector<LdapControl>& controls = std::vector<LdapControl>())
		    : LdapResponseLayer(messageId, LdapOperationType::ModifyResponse, resultCode, matchedDN, diagnosticMessage,
		                        referral, controls)
		{}

	protected:
		friend LdapLayer* LdapLayer::parseLdapMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		LdapModifyResponseLayer(std::unique_ptr<Asn1Record> asn1Record, uint8_t* data, size_t dataLen, Layer* prevLayer,
		                        Packet* packet)
		    : LdapResponseLayer(std::move(asn1Record), data, dataLen, prevLayer, packet)
		{}
	};

	/// @class LdapAddResponseLayer
	/// Represents LDAP add response message
	class LdapAddResponseLayer : public LdapResponseLayer
	{
	public:
		/// A constructor to create a new LDAP add response message
		/// @param[in] messageId The LDAP message ID
		/// @param[in] resultCode The LDAP result code
		/// @param[in] matchedDN The distinguished name (DN) to set on the message. If not applicable
		/// pass an empty string
		/// @param[in] diagnosticMessage The additional information to set on the message. If not applicable
		/// pass an empty string
		/// @param[in] referral A list of URIs to re-try the operation somewhere else. This is an optional
		/// parameter. If not provided then referral won't be added to the message
		/// @param[in] controls A vector of LDAP controls. This is an optional parameter, if not provided the message
		/// will be created without LDAP controls
		LdapAddResponseLayer(uint16_t messageId, LdapResultCode resultCode, const std::string& matchedDN,
		                     const std::string& diagnosticMessage,
		                     const std::vector<std::string>& referral = std::vector<std::string>(),
		                     const std::vector<LdapControl>& controls = std::vector<LdapControl>())
		    : LdapResponseLayer(messageId, LdapOperationType::AddResponse, resultCode, matchedDN, diagnosticMessage,
		                        referral, controls)
		{}

	protected:
		friend LdapLayer* LdapLayer::parseLdapMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		LdapAddResponseLayer(std::unique_ptr<Asn1Record> asn1Record, uint8_t* data, size_t dataLen, Layer* prevLayer,
		                     Packet* packet)
		    : LdapResponseLayer(std::move(asn1Record), data, dataLen, prevLayer, packet)
		{}
	};

	/// @class LdapDeleteResponseLayer
	/// Represents LDAP delete response message
	class LdapDeleteResponseLayer : public LdapResponseLayer
	{
	public:
		/// A constructor to create a new LDAP delete response message
		/// @param[in] messageId The LDAP message ID
		/// @param[in] resultCode The LDAP result code
		/// @param[in] matchedDN The distinguished name (DN) to set on the message. If not applicable
		/// pass an empty string
		/// @param[in] diagnosticMessage The additional information to set on the message. If not applicable
		/// pass an empty string
		/// @param[in] referral A list of URIs to re-try the operation somewhere else. This is an optional
		/// parameter. If not provided then referral won't be added to the message
		/// @param[in] controls A vector of LDAP controls. This is an optional parameter, if not provided the message
		/// will be created without LDAP controls
		LdapDeleteResponseLayer(uint16_t messageId, LdapResultCode resultCode, const std::string& matchedDN,
		                        const std::string& diagnosticMessage,
		                        const std::vector<std::string>& referral = std::vector<std::string>(),
		                        const std::vector<LdapControl>& controls = std::vector<LdapControl>())
		    : LdapResponseLayer(messageId, LdapOperationType::DeleteResponse, resultCode, matchedDN, diagnosticMessage,
		                        referral, controls)
		{}

	protected:
		friend LdapLayer* LdapLayer::parseLdapMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		LdapDeleteResponseLayer(std::unique_ptr<Asn1Record> asn1Record, uint8_t* data, size_t dataLen, Layer* prevLayer,
		                        Packet* packet)
		    : LdapResponseLayer(std::move(asn1Record), data, dataLen, prevLayer, packet)
		{}
	};

	/// @class LdapModifyDNResponseLayer
	/// Represents LDAP modify DN response message
	class LdapModifyDNResponseLayer : public LdapResponseLayer
	{
	public:
		/// A constructor to create a new LDAP modify DN response message
		/// @param[in] messageId The LDAP message ID
		/// @param[in] resultCode The LDAP result code
		/// @param[in] matchedDN The distinguished name (DN) to set on the message. If not applicable
		/// pass an empty string
		/// @param[in] diagnosticMessage The additional information to set on the message. If not applicable
		/// pass an empty string
		/// @param[in] referral A list of URIs to re-try the operation somewhere else. This is an optional
		/// parameter. If not provided then referral won't be added to the message
		/// @param[in] controls A vector of LDAP controls. This is an optional parameter, if not provided the message
		/// will be created without LDAP controls
		LdapModifyDNResponseLayer(uint16_t messageId, LdapResultCode resultCode, const std::string& matchedDN,
		                          const std::string& diagnosticMessage,
		                          const std::vector<std::string>& referral = std::vector<std::string>(),
		                          const std::vector<LdapControl>& controls = std::vector<LdapControl>())
		    : LdapResponseLayer(messageId, LdapOperationType::ModifyDNResponse, resultCode, matchedDN,
		                        diagnosticMessage, referral, controls)
		{}

	protected:
		friend LdapLayer* LdapLayer::parseLdapMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		LdapModifyDNResponseLayer(std::unique_ptr<Asn1Record> asn1Record, uint8_t* data, size_t dataLen,
		                          Layer* prevLayer, Packet* packet)
		    : LdapResponseLayer(std::move(asn1Record), data, dataLen, prevLayer, packet)
		{}
	};

	/// @class LdapCompareResponseLayer
	/// Represents LDAP compare response message
	class LdapCompareResponseLayer : public LdapResponseLayer
	{
	public:
		/// A constructor to create a new LDAP compare response message
		/// @param[in] messageId The LDAP message ID
		/// @param[in] resultCode The LDAP result code
		/// @param[in] matchedDN The distinguished name (DN) to set on the message. If not applicable
		/// pass an empty string
		/// @param[in] diagnosticMessage The additional information to set on the message. If not applicable
		/// pass an empty string
		/// @param[in] referral A list of URIs to re-try the operation somewhere else. This is an optional
		/// parameter. If not provided then referral won't be added to the message
		/// @param[in] controls A vector of LDAP controls. This is an optional parameter, if not provided the message
		/// will be created without LDAP controls
		LdapCompareResponseLayer(uint16_t messageId, LdapResultCode resultCode, const std::string& matchedDN,
		                         const std::string& diagnosticMessage,
		                         const std::vector<std::string>& referral = std::vector<std::string>(),
		                         const std::vector<LdapControl>& controls = std::vector<LdapControl>())
		    : LdapResponseLayer(messageId, LdapOperationType::CompareResponse, resultCode, matchedDN, diagnosticMessage,
		                        referral, controls)
		{}

	protected:
		friend LdapLayer* LdapLayer::parseLdapMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		LdapCompareResponseLayer(std::unique_ptr<Asn1Record> asn1Record, uint8_t* data, size_t dataLen,
		                         Layer* prevLayer, Packet* packet)
		    : LdapResponseLayer(std::move(asn1Record), data, dataLen, prevLayer, packet)
		{}
	};

	inline std::ostream& operator<<(std::ostream& os, const pcpp::LdapControl& control)
	{
		os << "{" << control.controlType << ", " << control.controlValue << "}";
		return os;
	}

	inline std::ostream& operator<<(std::ostream& os, const pcpp::LdapAttribute& attr)
	{
		os << "{" << attr.type << ", {";

		std::string separator;
		for (const auto& value : attr.values)
		{
			os << separator << value;
			if (separator.empty())
			{
				separator = ", ";
			}
		}

		os << "}}";
		return os;
	}

	inline std::ostream& operator<<(std::ostream& os,
	                                const pcpp::LdapBindRequestLayer::SaslAuthentication& saslAuthentication)
	{
		os << "{" << saslAuthentication.mechanism << ", {";

		std::string separator;
		for (const auto& value : saslAuthentication.credentials)
		{
			os << separator << "0x" << std::hex << static_cast<int>(value) << std::dec;
			if (separator.empty())
			{
				separator = ", ";
			}
		}

		os << "}}";
		return os;
	}
}  // namespace pcpp
