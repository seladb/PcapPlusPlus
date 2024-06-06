#include "LdapLayer.h"
#include "GeneralUtils.h"
#include <unordered_map>

namespace pcpp {

	// region LdapOperationType

	const std::unordered_map<LdapOperationType::Value, std::string, EnumClassHash<LdapOperationType::Value>> LdapOperationTypeToString{
		{LdapOperationType::BindRequest,           "BindRequest"},
		{LdapOperationType::BindResponse,          "BindResponse"},
		{LdapOperationType::UnbindRequest,         "UnbindRequest"},
		{LdapOperationType::SearchRequest,         "SearchRequest"},
		{LdapOperationType::SearchResultEntry,     "SearchResultEntry"},
		{LdapOperationType::SearchResultDone,      "SearchResultDone"},
		{LdapOperationType::ModifyRequest,         "ModifyRequest"},
		{LdapOperationType::ModifyResponse,        "ModifyResponse"},
		{LdapOperationType::AddRequest,            "AddRequest"},
		{LdapOperationType::AddResponse,           "AddResponse"},
		{LdapOperationType::DeleteRequest,         "DeleteRequest"},
		{LdapOperationType::DeleteResponse,        "DeleteResponse"},
		{LdapOperationType::ModifyDNRequest,       "ModifyDNRequest"},
		{LdapOperationType::ModifyDNResponse,      "ModifyDNResponse"},
		{LdapOperationType::CompareRequest,        "CompareRequest"},
		{LdapOperationType::CompareResponse,       "CompareResponse"},
		{LdapOperationType::AbandonRequest,        "AbandonRequest"},
		{LdapOperationType::SearchResultReference, "SearchResultReference"},
		{LdapOperationType::ExtendedRequest,       "ExtendedRequest"},
		{LdapOperationType::ExtendedResponse,      "ExtendedResponse"},
		{LdapOperationType::IntermediateResponse,  "IntermediateResponse"},
		{LdapOperationType::Unknown,               "Unknown"}
	};

	const std::unordered_map<uint8_t, LdapOperationType> UintToLdapOperationType{
		{static_cast<uint8_t>(LdapOperationType::BindRequest), LdapOperationType::BindRequest},
		{static_cast<uint8_t>(LdapOperationType::BindResponse), LdapOperationType::BindResponse},
		{static_cast<uint8_t>(LdapOperationType::UnbindRequest), LdapOperationType::UnbindRequest},
		{static_cast<uint8_t>(LdapOperationType::SearchRequest), LdapOperationType::SearchRequest},
		{static_cast<uint8_t>(LdapOperationType::SearchResultEntry), LdapOperationType::SearchResultEntry},
		{static_cast<uint8_t>(LdapOperationType::SearchResultDone), LdapOperationType::SearchResultDone},
		{static_cast<uint8_t>(LdapOperationType::ModifyResponse), LdapOperationType::ModifyResponse},
		{static_cast<uint8_t>(LdapOperationType::AddRequest), LdapOperationType::AddRequest},
		{static_cast<uint8_t>(LdapOperationType::AddResponse), LdapOperationType::AddResponse},
		{static_cast<uint8_t>(LdapOperationType::DeleteRequest), LdapOperationType::DeleteRequest},
		{static_cast<uint8_t>(LdapOperationType::DeleteResponse), LdapOperationType::DeleteResponse},
		{static_cast<uint8_t>(LdapOperationType::ModifyDNRequest), LdapOperationType::ModifyDNRequest},
		{static_cast<uint8_t>(LdapOperationType::ModifyDNResponse), LdapOperationType::ModifyDNResponse},
		{static_cast<uint8_t>(LdapOperationType::CompareRequest), LdapOperationType::CompareRequest},
		{static_cast<uint8_t>(LdapOperationType::CompareResponse), LdapOperationType::CompareResponse},
		{static_cast<uint8_t>(LdapOperationType::AbandonRequest), LdapOperationType::AbandonRequest},
		{static_cast<uint8_t>(LdapOperationType::SearchResultReference), LdapOperationType::SearchResultReference},
		{static_cast<uint8_t>(LdapOperationType::ExtendedRequest), LdapOperationType::ExtendedRequest},
		{static_cast<uint8_t>(LdapOperationType::ExtendedResponse), LdapOperationType::ExtendedResponse},
		{static_cast<uint8_t>(LdapOperationType::IntermediateResponse), LdapOperationType::IntermediateResponse}
	};

	std::string LdapOperationType::toString() const
	{
		return LdapOperationTypeToString.at(m_Value);
	}

	LdapOperationType LdapOperationType::fromUintValue(uint8_t value)
	{
		auto result = UintToLdapOperationType.find(value);
		if (result != UintToLdapOperationType.end())
		{
			return result->second;
		}

		return LdapOperationType::Unknown;
	}

	// endregion

	// region LdapResultCode

	const std::unordered_map<LdapResultCode::Value, std::string, EnumClassHash<LdapResultCode::Value>> LdapResultCodeToString{
		{LdapResultCode::Success, "Success"},
		{LdapResultCode::OperationsError, "OperationsError"},
		{LdapResultCode::ProtocolError, "ProtocolError"},
		{LdapResultCode::TimeLimitExceeded, "TimeLimitExceeded"},
		{LdapResultCode::SizeLimitExceeded, "SizeLimitExceeded"},
		{LdapResultCode::CompareFalse, "CompareFalse"},
		{LdapResultCode::CompareTrue, "CompareTrue"},
		{LdapResultCode::AuthMethodNotSupported, "AuthMethodNotSupported"},
		{LdapResultCode::StrongerAuthRequired, "StrongerAuthRequired"},
		{LdapResultCode::Referral, "Referral"},
		{LdapResultCode::AdminLimitExceeded, "AdminLimitExceeded"},
		{LdapResultCode::UnavailableCriticalExtension, "UnavailableCriticalExtension"},
		{LdapResultCode::ConfidentialityRequired, "ConfidentialityRequired"},
		{LdapResultCode::SaslBindInProgress, "SaslBindInProgress"},
		{LdapResultCode::NoSuchAttribute, "NoSuchAttribute"},
		{LdapResultCode::UndefinedAttributeType, "UndefinedAttributeType"},
		{LdapResultCode::InappropriateMatching, "InappropriateMatching"},
		{LdapResultCode::ConstraintViolation, "ConstraintViolation"},
		{LdapResultCode::AttributeOrValueExists, "AttributeOrValueExists"},
		{LdapResultCode::InvalidAttributeSyntax, "InvalidAttributeSyntax"},
		{LdapResultCode::NoSuchObject, "NoSuchObject"},
		{LdapResultCode::AliasProblem, "AliasProblem"},
		{LdapResultCode::InvalidDNSyntax, "InvalidDNSyntax"},
		{LdapResultCode::AliasDereferencingProblem, "AliasDereferencingProblem"},
		{LdapResultCode::InappropriateAuthentication, "InappropriateAuthentication"},
		{LdapResultCode::InvalidCredentials, "InvalidCredentials"},
		{LdapResultCode::InsufficientAccessRights, "InsufficientAccessRights"},
		{LdapResultCode::Busy, "Busy"},
		{LdapResultCode::Unavailable, "Unavailable"},
		{LdapResultCode::UnwillingToPerform, "UnwillingToPerform"},
		{LdapResultCode::LoopDetect, "LoopDetect"},
		{LdapResultCode::NamingViolation, "NamingViolation"},
		{LdapResultCode::ObjectClassViolation, "ObjectClassViolation"},
		{LdapResultCode::NotAllowedOnNonLeaf, "NotAllowedOnNonLeaf"},
		{LdapResultCode::NotAllowedOnRDN, "NotAllowedOnRDN"},
		{LdapResultCode::EntryAlreadyExists, "EntryAlreadyExists"},
		{LdapResultCode::ObjectClassModsProhibited, "ObjectClassModsProhibited"},
		{LdapResultCode::AffectsMultipleDSAs, "AffectsMultipleDSAs"},
		{LdapResultCode::Other, "Other"}
	};

	const std::unordered_map<uint8_t, LdapResultCode> UintToLdapResultCode{
		{static_cast<uint8_t>(LdapResultCode::Success), LdapResultCode::Success},
		{static_cast<uint8_t>(LdapResultCode::OperationsError), LdapResultCode::OperationsError},
		{static_cast<uint8_t>(LdapResultCode::ProtocolError), LdapResultCode::ProtocolError},
		{static_cast<uint8_t>(LdapResultCode::TimeLimitExceeded), LdapResultCode::TimeLimitExceeded},
		{static_cast<uint8_t>(LdapResultCode::SizeLimitExceeded), LdapResultCode::SizeLimitExceeded},
		{static_cast<uint8_t>(LdapResultCode::CompareFalse), LdapResultCode::CompareFalse},
		{static_cast<uint8_t>(LdapResultCode::CompareTrue), LdapResultCode::CompareTrue},
		{static_cast<uint8_t>(LdapResultCode::AuthMethodNotSupported), LdapResultCode::AuthMethodNotSupported},
		{static_cast<uint8_t>(LdapResultCode::StrongerAuthRequired), LdapResultCode::StrongerAuthRequired},
		{static_cast<uint8_t>(LdapResultCode::Referral), LdapResultCode::Referral},
		{static_cast<uint8_t>(LdapResultCode::AdminLimitExceeded), LdapResultCode::AdminLimitExceeded},
		{static_cast<uint8_t>(LdapResultCode::UnavailableCriticalExtension), LdapResultCode::UnavailableCriticalExtension},
		{static_cast<uint8_t>(LdapResultCode::ConfidentialityRequired), LdapResultCode::ConfidentialityRequired},
		{static_cast<uint8_t>(LdapResultCode::SaslBindInProgress), LdapResultCode::SaslBindInProgress},
		{static_cast<uint8_t>(LdapResultCode::NoSuchAttribute), LdapResultCode::NoSuchAttribute},
		{static_cast<uint8_t>(LdapResultCode::UndefinedAttributeType), LdapResultCode::UndefinedAttributeType},
		{static_cast<uint8_t>(LdapResultCode::InappropriateMatching), LdapResultCode::InappropriateMatching},
		{static_cast<uint8_t>(LdapResultCode::ConstraintViolation), LdapResultCode::ConstraintViolation},
		{static_cast<uint8_t>(LdapResultCode::AttributeOrValueExists), LdapResultCode::AttributeOrValueExists},
		{static_cast<uint8_t>(LdapResultCode::InvalidAttributeSyntax), LdapResultCode::InvalidAttributeSyntax},
		{static_cast<uint8_t>(LdapResultCode::NoSuchObject), LdapResultCode::NoSuchObject},
		{static_cast<uint8_t>(LdapResultCode::AliasProblem), LdapResultCode::AliasProblem},
		{static_cast<uint8_t>(LdapResultCode::InvalidDNSyntax), LdapResultCode::InvalidDNSyntax},
		{static_cast<uint8_t>(LdapResultCode::AliasDereferencingProblem), LdapResultCode::AliasDereferencingProblem},
		{static_cast<uint8_t>(LdapResultCode::InappropriateAuthentication), LdapResultCode::InappropriateAuthentication},
		{static_cast<uint8_t>(LdapResultCode::InvalidCredentials), LdapResultCode::InvalidCredentials},
		{static_cast<uint8_t>(LdapResultCode::InsufficientAccessRights), LdapResultCode::InsufficientAccessRights},
		{static_cast<uint8_t>(LdapResultCode::Busy), LdapResultCode::Busy},
		{static_cast<uint8_t>(LdapResultCode::Unavailable), LdapResultCode::Unavailable},
		{static_cast<uint8_t>(LdapResultCode::UnwillingToPerform), LdapResultCode::UnwillingToPerform},
		{static_cast<uint8_t>(LdapResultCode::LoopDetect), LdapResultCode::LoopDetect},
		{static_cast<uint8_t>(LdapResultCode::NamingViolation), LdapResultCode::NamingViolation},
		{static_cast<uint8_t>(LdapResultCode::ObjectClassViolation), LdapResultCode::ObjectClassViolation},
		{static_cast<uint8_t>(LdapResultCode::NotAllowedOnNonLeaf), LdapResultCode::NotAllowedOnNonLeaf},
		{static_cast<uint8_t>(LdapResultCode::NotAllowedOnRDN), LdapResultCode::NotAllowedOnRDN},
		{static_cast<uint8_t>(LdapResultCode::EntryAlreadyExists), LdapResultCode::EntryAlreadyExists},
		{static_cast<uint8_t>(LdapResultCode::ObjectClassModsProhibited), LdapResultCode::ObjectClassModsProhibited},
		{static_cast<uint8_t>(LdapResultCode::AffectsMultipleDSAs), LdapResultCode::AffectsMultipleDSAs},
		{static_cast<uint8_t>(LdapResultCode::Other), LdapResultCode::Other}
	};

	std::string LdapResultCode::toString() const
	{
		return LdapResultCodeToString.at(m_Value);
	}

	LdapResultCode LdapResultCode::fromUintValue(uint8_t value)
	{
		auto result = UintToLdapResultCode.find(value);
		if (result != UintToLdapResultCode.end())
		{
			return result->second;
		}

		return LdapResultCode::Unknown;
	}

	// endregion

	// region LdapLayer

	LdapLayer::LdapLayer(uint16_t messageId, LdapOperationType operationType,
		const std::vector<Asn1Record*>& messageRecords, const std::vector<LdapControl>& controls)
	{
		init(messageId, operationType, messageRecords, controls);
	}

	LdapLayer::LdapLayer(std::unique_ptr<Asn1Record> asn1Record, uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet)
	{
		m_Protocol = LDAP;
		m_Asn1Record = std::move(asn1Record);
	}

	void LdapLayer::init(uint16_t messageId, LdapOperationType operationType, const std::vector<Asn1Record*>& messageRecords, const std::vector<LdapControl>& controls)
	{
		Asn1IntegerRecord messageIdRecord(messageId);
		Asn1ConstructedRecord messageRootRecord(Asn1TagClass::Application, operationType, messageRecords);

		std::vector<Asn1Record*> rootSubRecords = {&messageIdRecord, &messageRootRecord};

		std::unique_ptr<Asn1ConstructedRecord> controlsRecord;
		if (!controls.empty())
		{
			PointerVector<Asn1Record> controlsSubRecords;
			for (const auto& control : controls)
			{
				Asn1OctetStringRecord controlTypeRecord(control.controlType);
				if (control.controlValue.empty())
				{
					controlsSubRecords.pushBack(new Asn1SequenceRecord({&controlTypeRecord}));
				}
				else
				{
					auto controlValueSize = static_cast<size_t>(control.controlValue.size() / 2);
					std::unique_ptr<uint8_t[]> controlValue(new uint8_t[controlValueSize]);
					controlValueSize = hexStringToByteArray(control.controlValue, controlValue.get(), controlValueSize);
					Asn1OctetStringRecord controlValueRecord(controlValue.get(), controlValueSize);
					controlsSubRecords.pushBack(new Asn1SequenceRecord({&controlTypeRecord, &controlValueRecord}));
				}
			}
			controlsRecord = std::unique_ptr<Asn1ConstructedRecord>(new Asn1ConstructedRecord(Asn1TagClass::ContextSpecific, 0, controlsSubRecords));
			rootSubRecords.push_back(controlsRecord.get());
		}

		Asn1SequenceRecord rootRecord(rootSubRecords);

		auto encodedData = rootRecord.encode();
		m_DataLen = encodedData.size();
		m_Data = new uint8_t[m_DataLen];
		std::copy(encodedData.begin(), encodedData.end(), m_Data);
		m_Protocol = LDAP;
		m_Asn1Record = Asn1Record::decode(m_Data, m_DataLen, true);
	}

	std::string LdapLayer::toString() const
	{
		auto extendedInfo = getExtendedStringInfo();
		return "LDAP Layer, " + getLdapOperationType().toString() + (extendedInfo.empty() ? "" : ", " + extendedInfo);
	}

	LdapLayer* LdapLayer::parseLdapMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	{
		try
		{
			auto asn1Record = Asn1Record::decode(data, dataLen, true);
			auto operationType = LdapOperationType::fromUintValue(asn1Record->castAs<Asn1SequenceRecord>()->getSubRecords().at(operationTypeIndex)->getTagType());
			switch (operationType)
			{
				case LdapOperationType::SearchRequest:
					return new LdapSearchRequestLayer(std::move(asn1Record), data, dataLen, prevLayer, packet);
				case LdapOperationType::SearchResultEntry:
					return new LdapSearchResultEntryLayer(std::move(asn1Record), data, dataLen, prevLayer, packet);
				case LdapOperationType::SearchResultDone:
					return new LdapSearchResultDoneLayer(std::move(asn1Record), data, dataLen, prevLayer, packet);
				case LdapOperationType::ModifyResponse:
					return new LdapModifyResponseLayer(std::move(asn1Record), data, dataLen, prevLayer, packet);
				case LdapOperationType::AddResponse:
					return new LdapAddResponseLayer(std::move(asn1Record), data, dataLen, prevLayer, packet);
				case LdapOperationType::DeleteResponse:
					return new LdapDeleteResponseLayer(std::move(asn1Record), data, dataLen, prevLayer, packet);
				case LdapOperationType::ModifyDNResponse:
					return new LdapModifyDNResponseLayer(std::move(asn1Record), data, dataLen, prevLayer, packet);
				case LdapOperationType::CompareResponse:
					return new LdapCompareResponseLayer(std::move(asn1Record), data, dataLen, prevLayer, packet);
				case LdapOperationType::Unknown:
					return nullptr;
				default:
					return new LdapLayer(std::move(asn1Record), data, dataLen, prevLayer, packet);
			}
		}
		catch (...)
		{
			return nullptr;
		}
	}

	Asn1SequenceRecord* LdapLayer::getRootAsn1Record() const
	{
		return m_Asn1Record->castAs<Asn1SequenceRecord>();
	}

	Asn1ConstructedRecord* LdapLayer::getLdapOperationAsn1Record() const
	{
		return getRootAsn1Record()->getSubRecords().at(operationTypeIndex)->castAs<Asn1ConstructedRecord>();
	}

	uint16_t LdapLayer::getMessageID() const
	{
		return getRootAsn1Record()->getSubRecords().at(messageIdIndex)->castAs<Asn1IntegerRecord>()->getValue();
	}

	std::vector<LdapControl> LdapLayer::getControls() const
	{
		std::vector<LdapControl> controls;
		if (getRootAsn1Record()->getSubRecords().size() <= controlsIndex)
		{
			return controls;
		}

		auto controlsRecord = getRootAsn1Record()->getSubRecords().at(controlsIndex)->castAs<Asn1ConstructedRecord>();
		for (auto controlRecord : controlsRecord->getSubRecords())
		{
			auto controlSequence = controlRecord->castAs<Asn1SequenceRecord>();
			auto controlType = controlSequence->getSubRecords().at(controlTypeIndex)->castAs<Asn1OctetStringRecord>()->getValue();
			std::string controlValue;
			if (controlSequence->getSubRecords().size() > controlValueIndex)
			{
				controlValue = controlSequence->getSubRecords().at(controlValueIndex)->castAs<Asn1OctetStringRecord>()->getValue();
			}
			controls.push_back({ controlType, controlValue });
		}

		return controls;
	}

	LdapOperationType LdapLayer::getLdapOperationType() const
	{
		return LdapOperationType::fromUintValue(getLdapOperationAsn1Record()->getTagType());
	}

	void LdapLayer::parseNextLayer()
	{
		size_t headerLen = getHeaderLen();
		if (m_DataLen <= headerLen || headerLen == 0)
			return;

		uint8_t* payload = m_Data + headerLen;
		size_t payloadLen = m_DataLen - headerLen;

		m_NextLayer = LdapLayer::parseLdapMessage(payload, payloadLen, this, m_Packet);
	}
	// endregion

	// region LdapResponseLayer

	LdapResponseLayer::LdapResponseLayer(uint16_t messageId, const LdapOperationType& operationType, const LdapResultCode& resultCode,
		const std::string& matchedDN, const std::string& diagnosticMessage, const std::vector<std::string>& referral,
		const std::vector<LdapControl>& controls)
	{
		Asn1EnumeratedRecord resultCodeRecord(resultCode);
		Asn1OctetStringRecord matchedDNRecord(matchedDN);
		Asn1OctetStringRecord diagnosticMessageRecord(diagnosticMessage);

		std::vector<Asn1Record*> messageRecords = {&resultCodeRecord, &matchedDNRecord, &diagnosticMessageRecord};

		std::unique_ptr<Asn1ConstructedRecord> referralRecord;
		if (!referral.empty())
		{
			PointerVector<Asn1Record> referralSubRecords;
			for (const auto& uri : referral)
			{
				referralSubRecords.pushBack(new Asn1OctetStringRecord(uri));
			}
			referralRecord = std::unique_ptr<Asn1ConstructedRecord>(new Asn1ConstructedRecord(
				Asn1TagClass::ContextSpecific, referralTagType, referralSubRecords));
			messageRecords.push_back(referralRecord.get());
		}

		LdapLayer::init(messageId, operationType, messageRecords, controls);
	}

	LdapResultCode LdapResponseLayer::getResultCode() const
	{
		return LdapResultCode::fromUintValue(getLdapOperationAsn1Record()->getSubRecords().at(resultCodeIndex)->castAs<Asn1EnumeratedRecord>()->getValue());
	}

	std::string LdapResponseLayer::getMatchedDN() const
	{
		return getLdapOperationAsn1Record()->getSubRecords().at(matchedDNIndex)->castAs<Asn1OctetStringRecord>()->getValue();
	}

	std::string LdapResponseLayer::getDiagnosticMessage() const
	{
		return getLdapOperationAsn1Record()->getSubRecords().at(diagnotsticsMessageIndex)->castAs<Asn1OctetStringRecord>()->getValue();
	}

	std::vector<std::string> LdapResponseLayer::getReferral() const
	{
		std::vector<std::string> result;
		if (getLdapOperationAsn1Record()->getSubRecords().size() <= referralIndex)
		{
			return result;
		}

		auto referralRecord = getLdapOperationAsn1Record()->getSubRecords().at(referralIndex);
		if (referralRecord->getTagClass() != Asn1TagClass::ContextSpecific || referralRecord->getTagType() != referralTagType)
		{
			return result;
		}

		for (auto uriRecord : referralRecord->castAs<Asn1ConstructedRecord>()->getSubRecords())
		{
			result.push_back(uriRecord->castAs<Asn1OctetStringRecord>()->getValue());
		}

		return result;
	}

	std::string LdapResponseLayer::getExtendedStringInfo() const
	{
		return getResultCode().toString();
	}
	// endregion

	// region LdapSearchRequestLayer

	const std::unordered_map<LdapSearchRequestLayer::SearchRequestScope::Value, std::string, EnumClassHash<LdapSearchRequestLayer::SearchRequestScope::Value>> SearchRequestScopeToString {
		{LdapSearchRequestLayer::SearchRequestScope::BaseObject,   "BaseObject"},
		{LdapSearchRequestLayer::SearchRequestScope::SingleLevel,  "SingleLevel"},
		{LdapSearchRequestLayer::SearchRequestScope::WholeSubtree, "WholeSubtree"},
		{LdapSearchRequestLayer::SearchRequestScope::Unknown,      "Unknown"}
	};

	const std::unordered_map<LdapSearchRequestLayer::DerefAliases::Value, std::string, EnumClassHash<LdapSearchRequestLayer::DerefAliases::Value>> DerefAliasesToString {
		{LdapSearchRequestLayer::DerefAliases::NeverDerefAliases,   "NeverDerefAliases"},
		{LdapSearchRequestLayer::DerefAliases::DerefInSearching,    "DerefInSearching"},
		{LdapSearchRequestLayer::DerefAliases::DerefFindingBaseObj, "DerefFindingBaseObj"},
		{LdapSearchRequestLayer::DerefAliases::DerefAlways,         "DerefAlways"},
		{LdapSearchRequestLayer::DerefAliases::Unknown,             "Unknown"}
	};

	std::string LdapSearchRequestLayer::SearchRequestScope::toString() const
	{
		return SearchRequestScopeToString.at(m_Value);
	}

	LdapSearchRequestLayer::SearchRequestScope LdapSearchRequestLayer::SearchRequestScope::fromUintValue(uint8_t value)
	{
		if (value >= 0 && value <= 2)
		{
			return static_cast<LdapSearchRequestLayer::SearchRequestScope::Value>(value);
		}

		return LdapSearchRequestLayer::SearchRequestScope::Unknown;
	}

	std::string LdapSearchRequestLayer::DerefAliases::toString() const
	{
		return DerefAliasesToString.at(m_Value);
	}

	LdapSearchRequestLayer::DerefAliases LdapSearchRequestLayer::DerefAliases::fromUintValue(uint8_t value)
	{
		if (value >= 0 && value <= 3)
		{
			return static_cast<LdapSearchRequestLayer::DerefAliases::Value>(value);
		}

		return LdapSearchRequestLayer::DerefAliases::Unknown;
	}

	LdapSearchRequestLayer::LdapSearchRequestLayer(
			uint16_t messageId, const std::string& baseObject, SearchRequestScope scope, DerefAliases derefAliases,
			uint8_t sizeLimit, uint8_t timeLimit, bool typesOnly, Asn1Record* filterRecord,
			const std::vector<std::string>& attributes, const std::vector<LdapControl>& controls)
	{
		Asn1OctetStringRecord baseObjectRecord(baseObject);
		Asn1EnumeratedRecord scopeRecord(scope);
		Asn1EnumeratedRecord derefAliasesRecord(derefAliases);
		Asn1IntegerRecord sizeLimitRecord(sizeLimit);
		Asn1IntegerRecord timeLimitRecord(timeLimit);
		Asn1BooleanRecord typeOnlyRecord(typesOnly);

		PointerVector<Asn1Record> attributeSubRecords;
		for (const auto& attribute : attributes)
		{
			attributeSubRecords.pushBack(new Asn1OctetStringRecord(attribute));
		}
		Asn1SequenceRecord attributesRecord(attributeSubRecords);

		LdapLayer::init(messageId, LdapOperationType::SearchRequest, {&baseObjectRecord, &scopeRecord, &derefAliasesRecord, &sizeLimitRecord, &timeLimitRecord, &typeOnlyRecord, filterRecord, &attributesRecord}, controls);
	}

	std::string LdapSearchRequestLayer::getBaseObject() const
	{
		return getLdapOperationAsn1Record()->getSubRecords().at(baseObjectIndex)->castAs<Asn1OctetStringRecord>()->getValue();
	}

	LdapSearchRequestLayer::SearchRequestScope LdapSearchRequestLayer::getScope() const
	{
		return LdapSearchRequestLayer::SearchRequestScope::fromUintValue(getLdapOperationAsn1Record()->getSubRecords().at(scopeIndex)->castAs<Asn1EnumeratedRecord>()->getValue());
	}

	LdapSearchRequestLayer::DerefAliases LdapSearchRequestLayer::getDerefAlias() const
	{
		return LdapSearchRequestLayer::DerefAliases::fromUintValue(getLdapOperationAsn1Record()->getSubRecords().at(derefAliasIndex)->castAs<Asn1EnumeratedRecord>()->getValue());
	}

	uint8_t LdapSearchRequestLayer::getSizeLimit() const
	{
		return static_cast<uint8_t>(getLdapOperationAsn1Record()->getSubRecords().at(sizeLimitIndex)->castAs<Asn1IntegerRecord>()->getValue());
	}

	uint8_t LdapSearchRequestLayer::getTimeLimit() const
	{
		return static_cast<uint8_t>(getLdapOperationAsn1Record()->getSubRecords().at(timeLimitIndex)->castAs<Asn1IntegerRecord>()->getValue());
	}

	bool LdapSearchRequestLayer::getTypesOnly() const
	{
		return getLdapOperationAsn1Record()->getSubRecords().at(typesOnlyIndex)->castAs<Asn1BooleanRecord>()->getValue();
	}

	Asn1Record* LdapSearchRequestLayer::getFilter() const
	{
		return getLdapOperationAsn1Record()->getSubRecords().at(filterIndex);
	}

	std::vector<std::string> LdapSearchRequestLayer::getAttributes() const
	{
		std::vector<std::string> result;
		if (getLdapOperationAsn1Record()->getSubRecords().size() <= attributesIndex)
		{
			return result;
		}

		auto attributesRecord = getLdapOperationAsn1Record()->getSubRecords().at(attributesIndex)->castAs<Asn1SequenceRecord>();
		for (auto attribute : attributesRecord->getSubRecords())
		{
			result.push_back(attribute->castAs<Asn1OctetStringRecord>()->getValue());
		}

		return result;
	}

	std::string LdapSearchRequestLayer::getExtendedStringInfo() const
	{
		auto baseObject = getBaseObject();
		if (baseObject.empty())
		{
			baseObject = "ROOT";
		}

		return "\"" + baseObject + "\", " + getScope().toString();
	}

	// endregion

	// region LdapSearchResultEntryLayer

	LdapSearchResultEntryLayer::LdapSearchResultEntryLayer(uint16_t messageId, const std::string& objectName,
		const std::vector<LdapAttribute>& attributes, const std::vector<LdapControl>& controls)
	{
		PointerVector<Asn1Record> attributesSubRecords;
		for (const auto& attribute : attributes)
		{
			PointerVector<Asn1Record> valuesSubRecords;
			for (const auto& value : attribute.values)
			{
				valuesSubRecords.pushBack(new Asn1OctetStringRecord(value));
			}

			Asn1OctetStringRecord typeRecord(attribute.type);
			Asn1SetRecord valuesRecord(valuesSubRecords);

			attributesSubRecords.pushBack(new Asn1SequenceRecord({&typeRecord, &valuesRecord}));
		}

		Asn1OctetStringRecord objectNameRecord(objectName);
		Asn1SequenceRecord attributesRecord(attributesSubRecords);

		LdapLayer::init(messageId, LdapOperationType::SearchResultEntry, {&objectNameRecord, &attributesRecord}, controls);
	}

	std::string LdapSearchResultEntryLayer::getObjectName() const
	{
		return getLdapOperationAsn1Record()->getSubRecords().at(objectNameIndex)->castAs<Asn1OctetStringRecord>()->getValue();
	}

	std::vector<LdapAttribute> LdapSearchResultEntryLayer::getAttributes() const
	{
		std::vector<LdapAttribute> result;

		auto attributes = getLdapOperationAsn1Record()->getSubRecords().at(attributesIndex)->castAs<Asn1SequenceRecord>();
		for (auto attributeRecord : attributes->getSubRecords())
		{
			auto attrAsSequence = attributeRecord->castAs<Asn1SequenceRecord>();

			auto type = attrAsSequence->getSubRecords().at(attributeTypeIndex)->castAs<Asn1OctetStringRecord>()->getValue();

			std::vector<std::string> values;
			auto valuesRecord = attrAsSequence->getSubRecords().at(attributeValueIndex)->castAs<Asn1SetRecord>();

			for (auto valueRecord : valuesRecord->getSubRecords())
			{
				values.push_back(valueRecord->castAs<Asn1OctetStringRecord>()->getValue());
			}

			LdapAttribute ldapAttribute = {type, values};
			result.push_back(ldapAttribute);
		}

		return result;
	}

	// endregion
}
