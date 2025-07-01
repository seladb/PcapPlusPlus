#include "LdapLayer.h"
#include "GeneralUtils.h"
#include <unordered_map>

namespace pcpp
{

	// region LdapOperationType

	// clang-format off
	static const std::unordered_map<LdapOperationType::Value, std::string, EnumClassHash<LdapOperationType::Value>> LdapOperationTypeToString{
		{ LdapOperationType::BindRequest,           "BindRequest"           },
		{ LdapOperationType::BindResponse,          "BindResponse"          },
		{ LdapOperationType::UnbindRequest,         "UnbindRequest"         },
		{ LdapOperationType::SearchRequest,         "SearchRequest"         },
		{ LdapOperationType::SearchResultEntry,     "SearchResultEntry"     },
		{ LdapOperationType::SearchResultDone,      "SearchResultDone"      },
		{ LdapOperationType::ModifyRequest,         "ModifyRequest"         },
		{ LdapOperationType::ModifyResponse,        "ModifyResponse"        },
		{ LdapOperationType::AddRequest,            "AddRequest"            },
		{ LdapOperationType::AddResponse,           "AddResponse"           },
		{ LdapOperationType::DeleteRequest,         "DeleteRequest"         },
		{ LdapOperationType::DeleteResponse,        "DeleteResponse"        },
		{ LdapOperationType::ModifyDNRequest,       "ModifyDNRequest"       },
		{ LdapOperationType::ModifyDNResponse,      "ModifyDNResponse"      },
		{ LdapOperationType::CompareRequest,        "CompareRequest"        },
		{ LdapOperationType::CompareResponse,       "CompareResponse"       },
		{ LdapOperationType::AbandonRequest,        "AbandonRequest"        },
		{ LdapOperationType::SearchResultReference, "SearchResultReference" },
		{ LdapOperationType::ExtendedRequest,       "ExtendedRequest"       },
		{ LdapOperationType::ExtendedResponse,      "ExtendedResponse"      },
		{ LdapOperationType::IntermediateResponse,  "IntermediateResponse"  },
		{ LdapOperationType::Unknown,               "Unknown"               }
	};
	// clang-format on

	static const std::unordered_map<uint8_t, LdapOperationType> UintToLdapOperationType{
		{ static_cast<uint8_t>(LdapOperationType::BindRequest),           LdapOperationType::BindRequest           },
		{ static_cast<uint8_t>(LdapOperationType::BindResponse),          LdapOperationType::BindResponse          },
		{ static_cast<uint8_t>(LdapOperationType::UnbindRequest),         LdapOperationType::UnbindRequest         },
		{ static_cast<uint8_t>(LdapOperationType::SearchRequest),         LdapOperationType::SearchRequest         },
		{ static_cast<uint8_t>(LdapOperationType::SearchResultEntry),     LdapOperationType::SearchResultEntry     },
		{ static_cast<uint8_t>(LdapOperationType::SearchResultDone),      LdapOperationType::SearchResultDone      },
		{ static_cast<uint8_t>(LdapOperationType::ModifyResponse),        LdapOperationType::ModifyResponse        },
		{ static_cast<uint8_t>(LdapOperationType::AddRequest),            LdapOperationType::AddRequest            },
		{ static_cast<uint8_t>(LdapOperationType::AddResponse),           LdapOperationType::AddResponse           },
		{ static_cast<uint8_t>(LdapOperationType::DeleteRequest),         LdapOperationType::DeleteRequest         },
		{ static_cast<uint8_t>(LdapOperationType::DeleteResponse),        LdapOperationType::DeleteResponse        },
		{ static_cast<uint8_t>(LdapOperationType::ModifyDNRequest),       LdapOperationType::ModifyDNRequest       },
		{ static_cast<uint8_t>(LdapOperationType::ModifyDNResponse),      LdapOperationType::ModifyDNResponse      },
		{ static_cast<uint8_t>(LdapOperationType::CompareRequest),        LdapOperationType::CompareRequest        },
		{ static_cast<uint8_t>(LdapOperationType::CompareResponse),       LdapOperationType::CompareResponse       },
		{ static_cast<uint8_t>(LdapOperationType::AbandonRequest),        LdapOperationType::AbandonRequest        },
		{ static_cast<uint8_t>(LdapOperationType::SearchResultReference), LdapOperationType::SearchResultReference },
		{ static_cast<uint8_t>(LdapOperationType::ExtendedRequest),       LdapOperationType::ExtendedRequest       },
		{ static_cast<uint8_t>(LdapOperationType::ExtendedResponse),      LdapOperationType::ExtendedResponse      },
		{ static_cast<uint8_t>(LdapOperationType::IntermediateResponse),  LdapOperationType::IntermediateResponse  }
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

	// clang-format off
	static const std::unordered_map<LdapResultCode::Value, std::string, EnumClassHash<LdapResultCode::Value>> LdapResultCodeToString{
		{ LdapResultCode::Success,                      "Success"                      },
		{ LdapResultCode::OperationsError,              "OperationsError"              },
		{ LdapResultCode::ProtocolError,                "ProtocolError"                },
		{ LdapResultCode::TimeLimitExceeded,            "TimeLimitExceeded"            },
		{ LdapResultCode::SizeLimitExceeded,            "SizeLimitExceeded"            },
		{ LdapResultCode::CompareFalse,                 "CompareFalse"                 },
		{ LdapResultCode::CompareTrue,                  "CompareTrue"                  },
		{ LdapResultCode::AuthMethodNotSupported,       "AuthMethodNotSupported"       },
		{ LdapResultCode::StrongerAuthRequired,         "StrongerAuthRequired"         },
		{ LdapResultCode::Referral,                     "Referral"                     },
		{ LdapResultCode::AdminLimitExceeded,           "AdminLimitExceeded"           },
		{ LdapResultCode::UnavailableCriticalExtension, "UnavailableCriticalExtension" },
		{ LdapResultCode::ConfidentialityRequired,      "ConfidentialityRequired"      },
		{ LdapResultCode::SaslBindInProgress,           "SaslBindInProgress"           },
		{ LdapResultCode::NoSuchAttribute,              "NoSuchAttribute"              },
		{ LdapResultCode::UndefinedAttributeType,       "UndefinedAttributeType"       },
		{ LdapResultCode::InappropriateMatching,        "InappropriateMatching"        },
		{ LdapResultCode::ConstraintViolation,          "ConstraintViolation"          },
		{ LdapResultCode::AttributeOrValueExists,       "AttributeOrValueExists"       },
		{ LdapResultCode::InvalidAttributeSyntax,       "InvalidAttributeSyntax"       },
		{ LdapResultCode::NoSuchObject,                 "NoSuchObject"                 },
		{ LdapResultCode::AliasProblem,                 "AliasProblem"                 },
		{ LdapResultCode::InvalidDNSyntax,              "InvalidDNSyntax"              },
		{ LdapResultCode::AliasDereferencingProblem,    "AliasDereferencingProblem"    },
		{ LdapResultCode::InappropriateAuthentication,  "InappropriateAuthentication"  },
		{ LdapResultCode::InvalidCredentials,           "InvalidCredentials"           },
		{ LdapResultCode::InsufficientAccessRights,     "InsufficientAccessRights"     },
		{ LdapResultCode::Busy,                         "Busy"                         },
		{ LdapResultCode::Unavailable,                  "Unavailable"                  },
		{ LdapResultCode::UnwillingToPerform,           "UnwillingToPerform"           },
		{ LdapResultCode::LoopDetect,                   "LoopDetect"                   },
		{ LdapResultCode::NamingViolation,              "NamingViolation"              },
		{ LdapResultCode::ObjectClassViolation,         "ObjectClassViolation"         },
		{ LdapResultCode::NotAllowedOnNonLeaf,          "NotAllowedOnNonLeaf"          },
		{ LdapResultCode::NotAllowedOnRDN,              "NotAllowedOnRDN"              },
		{ LdapResultCode::EntryAlreadyExists,           "EntryAlreadyExists"           },
		{ LdapResultCode::ObjectClassModsProhibited,    "ObjectClassModsProhibited"    },
		{ LdapResultCode::AffectsMultipleDSAs,          "AffectsMultipleDSAs"          },
		{ LdapResultCode::Other,                        "Other"                        }
    };
	// clang-format on

	// clang-format off
	static const std::unordered_map<uint8_t, LdapResultCode> UintToLdapResultCode{
		{ static_cast<uint8_t>(LdapResultCode::Success),                   LdapResultCode::Success                   },
		{ static_cast<uint8_t>(LdapResultCode::OperationsError),           LdapResultCode::OperationsError           },
		{ static_cast<uint8_t>(LdapResultCode::ProtocolError),             LdapResultCode::ProtocolError             },
		{ static_cast<uint8_t>(LdapResultCode::TimeLimitExceeded),         LdapResultCode::TimeLimitExceeded         },
		{ static_cast<uint8_t>(LdapResultCode::SizeLimitExceeded),         LdapResultCode::SizeLimitExceeded         },
		{ static_cast<uint8_t>(LdapResultCode::CompareFalse),              LdapResultCode::CompareFalse              },
		{ static_cast<uint8_t>(LdapResultCode::CompareTrue),               LdapResultCode::CompareTrue               },
		{ static_cast<uint8_t>(LdapResultCode::AuthMethodNotSupported),    LdapResultCode::AuthMethodNotSupported    },
		{ static_cast<uint8_t>(LdapResultCode::StrongerAuthRequired),      LdapResultCode::StrongerAuthRequired      },
		{ static_cast<uint8_t>(LdapResultCode::Referral),                  LdapResultCode::Referral                  },
		{ static_cast<uint8_t>(LdapResultCode::AdminLimitExceeded),        LdapResultCode::AdminLimitExceeded        },
		{ static_cast<uint8_t>(LdapResultCode::UnavailableCriticalExtension), LdapResultCode::UnavailableCriticalExtension },
		{ static_cast<uint8_t>(LdapResultCode::ConfidentialityRequired),   LdapResultCode::ConfidentialityRequired   },
		{ static_cast<uint8_t>(LdapResultCode::SaslBindInProgress),        LdapResultCode::SaslBindInProgress        },
		{ static_cast<uint8_t>(LdapResultCode::NoSuchAttribute),           LdapResultCode::NoSuchAttribute           },
		{ static_cast<uint8_t>(LdapResultCode::UndefinedAttributeType),    LdapResultCode::UndefinedAttributeType    },
		{ static_cast<uint8_t>(LdapResultCode::InappropriateMatching),     LdapResultCode::InappropriateMatching     },
		{ static_cast<uint8_t>(LdapResultCode::ConstraintViolation),       LdapResultCode::ConstraintViolation       },
		{ static_cast<uint8_t>(LdapResultCode::AttributeOrValueExists),    LdapResultCode::AttributeOrValueExists    },
		{ static_cast<uint8_t>(LdapResultCode::InvalidAttributeSyntax),    LdapResultCode::InvalidAttributeSyntax    },
		{ static_cast<uint8_t>(LdapResultCode::NoSuchObject),              LdapResultCode::NoSuchObject              },
		{ static_cast<uint8_t>(LdapResultCode::AliasProblem),              LdapResultCode::AliasProblem              },
		{ static_cast<uint8_t>(LdapResultCode::InvalidDNSyntax),           LdapResultCode::InvalidDNSyntax           },
		{ static_cast<uint8_t>(LdapResultCode::AliasDereferencingProblem), LdapResultCode::AliasDereferencingProblem },
		{ static_cast<uint8_t>(LdapResultCode::InappropriateAuthentication),  LdapResultCode::InappropriateAuthentication },
		{ static_cast<uint8_t>(LdapResultCode::InvalidCredentials),        LdapResultCode::InvalidCredentials        },
		{ static_cast<uint8_t>(LdapResultCode::InsufficientAccessRights),  LdapResultCode::InsufficientAccessRights  },
		{ static_cast<uint8_t>(LdapResultCode::Busy),                      LdapResultCode::Busy                      },
		{ static_cast<uint8_t>(LdapResultCode::Unavailable),               LdapResultCode::Unavailable               },
		{ static_cast<uint8_t>(LdapResultCode::UnwillingToPerform),        LdapResultCode::UnwillingToPerform        },
		{ static_cast<uint8_t>(LdapResultCode::LoopDetect),                LdapResultCode::LoopDetect                },
		{ static_cast<uint8_t>(LdapResultCode::NamingViolation),           LdapResultCode::NamingViolation           },
		{ static_cast<uint8_t>(LdapResultCode::ObjectClassViolation),      LdapResultCode::ObjectClassViolation      },
		{ static_cast<uint8_t>(LdapResultCode::NotAllowedOnNonLeaf),       LdapResultCode::NotAllowedOnNonLeaf       },
		{ static_cast<uint8_t>(LdapResultCode::NotAllowedOnRDN),           LdapResultCode::NotAllowedOnRDN           },
		{ static_cast<uint8_t>(LdapResultCode::EntryAlreadyExists),        LdapResultCode::EntryAlreadyExists        },
		{ static_cast<uint8_t>(LdapResultCode::ObjectClassModsProhibited), LdapResultCode::ObjectClassModsProhibited },
		{ static_cast<uint8_t>(LdapResultCode::AffectsMultipleDSAs),       LdapResultCode::AffectsMultipleDSAs       },
		{ static_cast<uint8_t>(LdapResultCode::Other),                     LdapResultCode::Other                     }
	};
	// clang-format on

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

	LdapLayer::LdapLayer(std::unique_ptr<Asn1Record> asn1Record, uint8_t* data, size_t dataLen, Layer* prevLayer,
	                     Packet* packet)
	    : Layer(data, dataLen, prevLayer, packet, LDAP)
	{
		m_Asn1Record = std::move(asn1Record);
	}

	void LdapLayer::init(uint16_t messageId, LdapOperationType operationType,
	                     const std::vector<Asn1Record*>& messageRecords, const std::vector<LdapControl>& controls)
	{
		Asn1IntegerRecord messageIdRecord(messageId);
		std::unique_ptr<Asn1Record> messageRootRecord;
		if (!messageRecords.empty())
		{
			messageRootRecord =
			    std::make_unique<Asn1ConstructedRecord>(Asn1TagClass::Application, operationType, messageRecords);
		}
		else
		{
			messageRootRecord =
			    std::make_unique<Asn1GenericRecord>(Asn1TagClass::Application, false, operationType, "");
		}

		std::vector<Asn1Record*> rootSubRecords = { &messageIdRecord, messageRootRecord.get() };

		std::unique_ptr<Asn1ConstructedRecord> controlsRecord;
		if (!controls.empty())
		{
			PointerVector<Asn1Record> controlsSubRecords;
			for (const auto& control : controls)
			{
				Asn1OctetStringRecord controlTypeRecord(control.controlType);
				if (control.controlValue.empty())
				{
					controlsSubRecords.pushBack(new Asn1SequenceRecord({ &controlTypeRecord }));
				}
				else
				{
					auto controlValueSize = static_cast<size_t>(control.controlValue.size() / 2);
					std::unique_ptr<uint8_t[]> controlValue = std::make_unique<uint8_t[]>(controlValueSize);
					controlValueSize = hexStringToByteArray(control.controlValue, controlValue.get(), controlValueSize);
					Asn1OctetStringRecord controlValueRecord(controlValue.get(), controlValueSize);
					controlsSubRecords.pushBack(new Asn1SequenceRecord({ &controlTypeRecord, &controlValueRecord }));
				}
			}
			controlsRecord =
			    std::make_unique<Asn1ConstructedRecord>(Asn1TagClass::ContextSpecific, 0, controlsSubRecords);
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
		auto extendedInfo = getExtendedInfoString();
		return "LDAP Layer, " + getLdapOperationType().toString() + (extendedInfo.empty() ? "" : ", " + extendedInfo);
	}

	LdapLayer* LdapLayer::parseLdapMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	{
		try
		{
			auto asn1Record = Asn1Record::decode(data, dataLen, true);
			auto operationType = LdapOperationType::fromUintValue(
			    asn1Record->castAs<Asn1SequenceRecord>()->getSubRecords().at(operationTypeIndex)->getTagType());
			switch (operationType)
			{
			case LdapOperationType::BindRequest:
				return new LdapBindRequestLayer(std::move(asn1Record), data, dataLen, prevLayer, packet);
			case LdapOperationType::BindResponse:
				return new LdapBindResponseLayer(std::move(asn1Record), data, dataLen, prevLayer, packet);
			case LdapOperationType::UnbindRequest:
				return new LdapUnbindRequestLayer(std::move(asn1Record), data, dataLen, prevLayer, packet);
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
		return getRootAsn1Record()
		    ->getSubRecords()
		    .at(messageIdIndex)
		    ->castAs<Asn1IntegerRecord>()
		    ->getIntValue<uint16_t>();
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
			auto controlType =
			    controlSequence->getSubRecords().at(controlTypeIndex)->castAs<Asn1OctetStringRecord>()->getValue();
			std::string controlValue;
			if (controlSequence->getSubRecords().size() > controlValueIndex)
			{
				controlValue =
				    controlSequence->getSubRecords().at(controlValueIndex)->castAs<Asn1OctetStringRecord>()->getValue();
			}
			controls.push_back({ controlType, controlValue });
		}

		return controls;
	}

	LdapOperationType LdapLayer::getLdapOperationType() const
	{
		uint8_t tagType;
		try
		{
			tagType = getLdapOperationAsn1Record()->getTagType();
		}
		catch (...)
		{
			tagType = LdapOperationType::Unknown;
		}

		return LdapOperationType::fromUintValue(tagType);
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

	LdapResponseLayer::LdapResponseLayer(uint16_t messageId, LdapOperationType operationType, LdapResultCode resultCode,
	                                     const std::string& matchedDN, const std::string& diagnosticMessage,
	                                     const std::vector<std::string>& referral,
	                                     const std::vector<LdapControl>& controls)
	{
		LdapResponseLayer::init(messageId, operationType, resultCode, matchedDN, diagnosticMessage, referral, {},
		                        controls);
	}

	void LdapResponseLayer::init(uint16_t messageId, LdapOperationType operationType, LdapResultCode resultCode,
	                             const std::string& matchedDN, const std::string& diagnosticMessage,
	                             const std::vector<std::string>& referral,
	                             const std::vector<Asn1Record*>& additionalRecords,
	                             const std::vector<LdapControl>& controls)
	{
		Asn1EnumeratedRecord resultCodeRecord(resultCode);
		Asn1OctetStringRecord matchedDNRecord(matchedDN);
		Asn1OctetStringRecord diagnosticMessageRecord(diagnosticMessage);

		std::vector<Asn1Record*> messageRecords = { &resultCodeRecord, &matchedDNRecord, &diagnosticMessageRecord };

		std::unique_ptr<Asn1ConstructedRecord> referralRecord;
		if (!referral.empty())
		{
			PointerVector<Asn1Record> referralSubRecords;
			for (const auto& uri : referral)
			{
				referralSubRecords.pushBack(new Asn1OctetStringRecord(uri));
			}
			referralRecord = std::make_unique<Asn1ConstructedRecord>(Asn1TagClass::ContextSpecific, referralTagType,
			                                                         referralSubRecords);
			messageRecords.push_back(referralRecord.get());
		}

		if (!additionalRecords.empty())
		{
			for (auto additionalRecord : additionalRecords)
			{
				messageRecords.push_back(additionalRecord);
			}
		}

		LdapLayer::init(messageId, operationType, messageRecords, controls);
	}

	LdapResultCode LdapResponseLayer::getResultCode() const
	{
		return LdapResultCode::fromUintValue(getLdapOperationAsn1Record()
		                                         ->getSubRecords()
		                                         .at(resultCodeIndex)
		                                         ->castAs<Asn1EnumeratedRecord>()
		                                         ->getIntValue<uint8_t>());
	}

	std::string LdapResponseLayer::getMatchedDN() const
	{
		return getLdapOperationAsn1Record()
		    ->getSubRecords()
		    .at(matchedDNIndex)
		    ->castAs<Asn1OctetStringRecord>()
		    ->getValue();
	}

	std::string LdapResponseLayer::getDiagnosticMessage() const
	{
		return getLdapOperationAsn1Record()
		    ->getSubRecords()
		    .at(diagnotsticsMessageIndex)
		    ->castAs<Asn1OctetStringRecord>()
		    ->getValue();
	}

	std::vector<std::string> LdapResponseLayer::getReferral() const
	{
		std::vector<std::string> result;
		if (getLdapOperationAsn1Record()->getSubRecords().size() <= referralIndex)
		{
			return result;
		}

		auto referralRecord = getLdapOperationAsn1Record()->getSubRecords().at(referralIndex);
		if (referralRecord->getTagClass() != Asn1TagClass::ContextSpecific ||
		    referralRecord->getTagType() != referralTagType)
		{
			return result;
		}

		for (auto uriRecord : referralRecord->castAs<Asn1ConstructedRecord>()->getSubRecords())
		{
			result.push_back(uriRecord->castAs<Asn1OctetStringRecord>()->getValue());
		}

		return result;
	}

	std::string LdapResponseLayer::getExtendedInfoString() const
	{
		return getResultCode().toString();
	}
	// endregion

	// region LdapBindRequestLayer

	LdapBindRequestLayer::LdapBindRequestLayer(uint16_t messageId, uint8_t version, const std::string& name,
	                                           const std::string& simpleAuthentication,
	                                           const std::vector<LdapControl>& controls)
	{
		Asn1IntegerRecord versionRecord(version);
		Asn1OctetStringRecord nameRecord(name);
		std::vector<Asn1Record*> messageRecords = { &versionRecord, &nameRecord };
		std::unique_ptr<Asn1GenericRecord> simpleAuthenticationRecord;
		if (!simpleAuthentication.empty())
		{
			auto data = reinterpret_cast<const uint8_t*>(simpleAuthentication.data());
			simpleAuthenticationRecord = std::make_unique<Asn1GenericRecord>(
			    Asn1TagClass::ContextSpecific, false,
			    static_cast<uint8_t>(LdapBindRequestLayer::AuthenticationType::Simple), data,
			    simpleAuthentication.size());
			messageRecords.push_back(simpleAuthenticationRecord.get());
		}

		LdapLayer::init(messageId, LdapOperationType::BindRequest, messageRecords, controls);
	}

	LdapBindRequestLayer::LdapBindRequestLayer(uint16_t messageId, uint8_t version, const std::string& name,
	                                           const SaslAuthentication& saslAuthentication,
	                                           const std::vector<LdapControl>& controls)
	{
		Asn1IntegerRecord versionRecord(version);
		Asn1OctetStringRecord nameRecord(name);
		std::vector<Asn1Record*> messageRecords = { &versionRecord, &nameRecord };
		std::unique_ptr<Asn1ConstructedRecord> saslAuthenticationRecord;
		if (!saslAuthentication.mechanism.empty())
		{
			PointerVector<Asn1Record> saslAuthenticationRecords;
			saslAuthenticationRecords.pushBack(new Asn1OctetStringRecord(saslAuthentication.mechanism));
			if (!saslAuthentication.credentials.empty())
			{
				auto credentialsRecord = new Asn1OctetStringRecord(saslAuthentication.credentials.data(),
				                                                   saslAuthentication.credentials.size());
				saslAuthenticationRecords.pushBack(credentialsRecord);
			}

			saslAuthenticationRecord = std::make_unique<Asn1ConstructedRecord>(
			    Asn1TagClass::ContextSpecific, static_cast<uint8_t>(LdapBindRequestLayer::AuthenticationType::Sasl),
			    saslAuthenticationRecords);
			messageRecords.push_back(saslAuthenticationRecord.get());
		}

		LdapLayer::init(messageId, LdapOperationType::BindRequest, messageRecords, controls);
	}

	uint32_t LdapBindRequestLayer::getVersion() const
	{
		return getLdapOperationAsn1Record()
		    ->getSubRecords()
		    .at(versionIndex)
		    ->castAs<Asn1IntegerRecord>()
		    ->getIntValue<uint32_t>();
	}

	std::string LdapBindRequestLayer::getName() const
	{
		return getLdapOperationAsn1Record()->getSubRecords().at(nameIndex)->castAs<Asn1OctetStringRecord>()->getValue();
	}

	LdapBindRequestLayer::AuthenticationType LdapBindRequestLayer::getAuthenticationType() const
	{
		if (getLdapOperationAsn1Record()->getSubRecords().size() <= credentialIndex)
		{
			return LdapBindRequestLayer::AuthenticationType::NotApplicable;
		}

		auto authType = getLdapOperationAsn1Record()->getSubRecords().at(credentialIndex)->getTagType();
		switch (authType)
		{
		case 0:
			return LdapBindRequestLayer::AuthenticationType::Simple;
		case 3:
			return LdapBindRequestLayer::AuthenticationType::Sasl;
		default:
			return LdapBindRequestLayer::AuthenticationType::NotApplicable;
		}
	}

	std::string LdapBindRequestLayer::getSimpleAuthentication() const
	{
		if (getAuthenticationType() != LdapBindRequestLayer::AuthenticationType::Simple)
		{
			throw std::invalid_argument("Authentication type is not simple");
		}

		auto authRecord =
		    getLdapOperationAsn1Record()->getSubRecords().at(credentialIndex)->castAs<Asn1GenericRecord>();
		return { reinterpret_cast<const char*>(authRecord->getValue()), authRecord->getValueLength() };
	}

	LdapBindRequestLayer::SaslAuthentication LdapBindRequestLayer::getSaslAuthentication() const
	{
		if (getAuthenticationType() != LdapBindRequestLayer::AuthenticationType::Sasl)
		{
			throw std::invalid_argument("Authentication type is not sasl");
		}

		auto authRecord =
		    getLdapOperationAsn1Record()->getSubRecords().at(credentialIndex)->castAs<Asn1ConstructedRecord>();
		std::string mechanism;
		std::vector<uint8_t> credentials;
		if (authRecord->getSubRecords().size() > saslMechanismIndex)
		{
			mechanism = authRecord->getSubRecords().at(saslMechanismIndex)->castAs<Asn1OctetStringRecord>()->getValue();
		}
		if (authRecord->getSubRecords().size() > saslCredentialsIndex)
		{
			auto credentialsAsString =
			    authRecord->getSubRecords().at(saslCredentialsIndex)->castAs<Asn1OctetStringRecord>()->getValue();
			credentials.resize(credentialsAsString.size() / 2);
			hexStringToByteArray(credentialsAsString, credentials.data(), credentials.size());
		}

		return { mechanism, credentials };
	}

	std::string LdapBindRequestLayer::getExtendedInfoString() const
	{
		switch (getAuthenticationType())
		{
		case AuthenticationType::Simple:
			return "simple";
		case AuthenticationType::Sasl:
			return "sasl";
		default:
			return "Unknown";
		}
	}

	// endregion

	// region LdapBindResponseLayer

	LdapBindResponseLayer::LdapBindResponseLayer(uint16_t messageId, LdapResultCode resultCode,
	                                             const std::string& matchedDN, const std::string& diagnosticMessage,
	                                             const std::vector<std::string>& referral,
	                                             const std::vector<uint8_t>& serverSaslCredentials,
	                                             const std::vector<LdapControl>& controls)
	{
		std::vector<Asn1Record*> additionalRecords;
		std::unique_ptr<Asn1Record> serverSaslCredentialsRecord;
		if (!serverSaslCredentials.empty())
		{
			serverSaslCredentialsRecord =
			    std::make_unique<Asn1GenericRecord>(Asn1TagClass::ContextSpecific, false, serverSaslCredentialsTagType,
			                                        serverSaslCredentials.data(), serverSaslCredentials.size());
			additionalRecords.push_back(serverSaslCredentialsRecord.get());
		}

		LdapResponseLayer::init(messageId, LdapOperationType::BindResponse, resultCode, matchedDN, diagnosticMessage,
		                        referral, additionalRecords, controls);
	}

	std::vector<uint8_t> LdapBindResponseLayer::getServerSaslCredentials() const
	{
		try
		{
			auto serverSaslCredentialsRecord =
			    getLdapOperationAsn1Record()->getSubRecords().back()->castAs<Asn1GenericRecord>();
			return { serverSaslCredentialsRecord->getValue(),
				     serverSaslCredentialsRecord->getValue() + serverSaslCredentialsRecord->getValueLength() };
		}
		catch (const std::exception&)
		{
			return {};
		}
	}

	// endregion

	// region LdapUnbindRequestLayer

	LdapUnbindRequestLayer::LdapUnbindRequestLayer(uint16_t messageId, const std::vector<LdapControl>& controls)
	{
		LdapLayer::init(messageId, LdapOperationType::UnbindRequest, {}, controls);
	}

	// endregion

	// region LdapSearchRequestLayer

	const std::unordered_map<LdapSearchRequestLayer::SearchRequestScope::Value, std::string,
	                         EnumClassHash<LdapSearchRequestLayer::SearchRequestScope::Value>>
	    SearchRequestScopeToString{
		    { LdapSearchRequestLayer::SearchRequestScope::BaseObject,   "BaseObject"   },
		    { LdapSearchRequestLayer::SearchRequestScope::SingleLevel,  "SingleLevel"  },
		    { LdapSearchRequestLayer::SearchRequestScope::WholeSubtree, "WholeSubtree" },
		    { LdapSearchRequestLayer::SearchRequestScope::Unknown,      "Unknown"      }
    };

	const std::unordered_map<LdapSearchRequestLayer::DerefAliases::Value, std::string,
	                         EnumClassHash<LdapSearchRequestLayer::DerefAliases::Value>>
	    DerefAliasesToString{
		    { LdapSearchRequestLayer::DerefAliases::NeverDerefAliases,   "NeverDerefAliases"   },
		    { LdapSearchRequestLayer::DerefAliases::DerefInSearching,    "DerefInSearching"    },
		    { LdapSearchRequestLayer::DerefAliases::DerefFindingBaseObj, "DerefFindingBaseObj" },
		    { LdapSearchRequestLayer::DerefAliases::DerefAlways,         "DerefAlways"         },
		    { LdapSearchRequestLayer::DerefAliases::Unknown,             "Unknown"             }
    };

	std::string LdapSearchRequestLayer::SearchRequestScope::toString() const
	{
		return SearchRequestScopeToString.at(m_Value);
	}

	LdapSearchRequestLayer::SearchRequestScope LdapSearchRequestLayer::SearchRequestScope::fromUintValue(uint8_t value)
	{
		if (value <= 2)
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
		if (value <= 3)
		{
			return static_cast<LdapSearchRequestLayer::DerefAliases::Value>(value);
		}

		return LdapSearchRequestLayer::DerefAliases::Unknown;
	}

	LdapSearchRequestLayer::LdapSearchRequestLayer(uint16_t messageId, const std::string& baseObject,
	                                               SearchRequestScope scope, DerefAliases derefAliases,
	                                               uint8_t sizeLimit, uint8_t timeLimit, bool typesOnly,
	                                               Asn1Record* filterRecord, const std::vector<std::string>& attributes,
	                                               const std::vector<LdapControl>& controls)
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

		LdapLayer::init(messageId, LdapOperationType::SearchRequest,
		                { &baseObjectRecord, &scopeRecord, &derefAliasesRecord, &sizeLimitRecord, &timeLimitRecord,
		                  &typeOnlyRecord, filterRecord, &attributesRecord },
		                controls);
	}

	std::string LdapSearchRequestLayer::getBaseObject() const
	{
		return getLdapOperationAsn1Record()
		    ->getSubRecords()
		    .at(baseObjectIndex)
		    ->castAs<Asn1OctetStringRecord>()
		    ->getValue();
	}

	LdapSearchRequestLayer::SearchRequestScope LdapSearchRequestLayer::getScope() const
	{
		return LdapSearchRequestLayer::SearchRequestScope::fromUintValue(getLdapOperationAsn1Record()
		                                                                     ->getSubRecords()
		                                                                     .at(scopeIndex)
		                                                                     ->castAs<Asn1EnumeratedRecord>()
		                                                                     ->getIntValue<uint8_t>());
	}

	LdapSearchRequestLayer::DerefAliases LdapSearchRequestLayer::getDerefAlias() const
	{
		return LdapSearchRequestLayer::DerefAliases::fromUintValue(getLdapOperationAsn1Record()
		                                                               ->getSubRecords()
		                                                               .at(derefAliasIndex)
		                                                               ->castAs<Asn1EnumeratedRecord>()
		                                                               ->getIntValue<uint8_t>());
	}

	uint8_t LdapSearchRequestLayer::getSizeLimit() const
	{
		return getLdapOperationAsn1Record()
		    ->getSubRecords()
		    .at(sizeLimitIndex)
		    ->castAs<Asn1IntegerRecord>()
		    ->getIntValue<uint8_t>();
	}

	uint8_t LdapSearchRequestLayer::getTimeLimit() const
	{
		return getLdapOperationAsn1Record()
		    ->getSubRecords()
		    .at(timeLimitIndex)
		    ->castAs<Asn1IntegerRecord>()
		    ->getIntValue<uint8_t>();
	}

	bool LdapSearchRequestLayer::getTypesOnly() const
	{
		return getLdapOperationAsn1Record()
		    ->getSubRecords()
		    .at(typesOnlyIndex)
		    ->castAs<Asn1BooleanRecord>()
		    ->getValue();
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

		auto attributesRecord =
		    getLdapOperationAsn1Record()->getSubRecords().at(attributesIndex)->castAs<Asn1SequenceRecord>();
		for (auto attribute : attributesRecord->getSubRecords())
		{
			result.push_back(attribute->castAs<Asn1OctetStringRecord>()->getValue());
		}

		return result;
	}

	std::string LdapSearchRequestLayer::getExtendedInfoString() const
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
	                                                       const std::vector<LdapAttribute>& attributes,
	                                                       const std::vector<LdapControl>& controls)
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

			attributesSubRecords.pushBack(new Asn1SequenceRecord({ &typeRecord, &valuesRecord }));
		}

		Asn1OctetStringRecord objectNameRecord(objectName);
		Asn1SequenceRecord attributesRecord(attributesSubRecords);

		LdapLayer::init(messageId, LdapOperationType::SearchResultEntry, { &objectNameRecord, &attributesRecord },
		                controls);
	}

	std::string LdapSearchResultEntryLayer::getObjectName() const
	{
		return getLdapOperationAsn1Record()
		    ->getSubRecords()
		    .at(objectNameIndex)
		    ->castAs<Asn1OctetStringRecord>()
		    ->getValue();
	}

	std::vector<LdapAttribute> LdapSearchResultEntryLayer::getAttributes() const
	{
		std::vector<LdapAttribute> result;

		auto attributes =
		    getLdapOperationAsn1Record()->getSubRecords().at(attributesIndex)->castAs<Asn1SequenceRecord>();
		for (auto attributeRecord : attributes->getSubRecords())
		{
			auto attrAsSequence = attributeRecord->castAs<Asn1SequenceRecord>();

			auto type =
			    attrAsSequence->getSubRecords().at(attributeTypeIndex)->castAs<Asn1OctetStringRecord>()->getValue();

			std::vector<std::string> values;
			auto valuesRecord = attrAsSequence->getSubRecords().at(attributeValueIndex)->castAs<Asn1SetRecord>();

			for (auto valueRecord : valuesRecord->getSubRecords())
			{
				values.push_back(valueRecord->castAs<Asn1OctetStringRecord>()->getValue());
			}

			LdapAttribute ldapAttribute = { type, values };
			result.push_back(ldapAttribute);
		}

		return result;
	}

	// endregion
}  // namespace pcpp
