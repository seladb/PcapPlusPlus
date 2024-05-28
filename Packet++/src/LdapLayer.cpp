#include "LdapLayer.h"
#include "GeneralUtils.h"
#include <unordered_map>

namespace pcpp {

	// region LdapOperationType

	const std::unordered_map<LdapOperationType::Value, std::string, EnumClassHash<LdapOperationType>> LdapOperationTypeToString{
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
		{LdapOperationType::DelRequest,            "DelRequest"},
		{LdapOperationType::DelResponse,           "DelResponse"},
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

	const std::unordered_map<uint8_t, LdapOperationType> IntToLdapOperationType{
		{static_cast<uint8_t>(LdapOperationType::BindRequest), LdapOperationType::BindRequest},
		{static_cast<uint8_t>(LdapOperationType::BindResponse), LdapOperationType::BindResponse},
		{static_cast<uint8_t>(LdapOperationType::UnbindRequest), LdapOperationType::UnbindRequest},
		{static_cast<uint8_t>(LdapOperationType::SearchRequest), LdapOperationType::SearchRequest},
		{static_cast<uint8_t>(LdapOperationType::SearchResultEntry), LdapOperationType::SearchResultEntry},
		{static_cast<uint8_t>(LdapOperationType::SearchResultDone), LdapOperationType::SearchResultDone},
		{static_cast<uint8_t>(LdapOperationType::ModifyResponse), LdapOperationType::ModifyResponse},
		{static_cast<uint8_t>(LdapOperationType::AddRequest), LdapOperationType::AddRequest},
		{static_cast<uint8_t>(LdapOperationType::AddResponse), LdapOperationType::AddResponse},
		{static_cast<uint8_t>(LdapOperationType::DelRequest), LdapOperationType::DelRequest},
		{static_cast<uint8_t>(LdapOperationType::DelResponse), LdapOperationType::DelResponse},
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

	LdapOperationType LdapOperationType::fromIntValue(uint8_t value)
	{
		if (IntToLdapOperationType.find(value) != IntToLdapOperationType.end())
		{
			return IntToLdapOperationType.at(value);
		}

		return LdapOperationType::Unknown;
	}

	// endregion

	// region LdapLayer

	LdapLayer::LdapLayer(uint16_t messageId, LdapOperationType operationType,
		const std::vector<Asn1Record*>& messageRecords, const std::vector<LdapControl>& controls)
	{
		init(messageId, operationType, messageRecords, controls);
	}

	LdapLayer::LdapLayer(std::unique_ptr<Asn1Record>& asn1Record, uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet)
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
			auto operationType = LdapOperationType::fromIntValue(asn1Record->castAs<Asn1SequenceRecord>()->getSubRecords().at(1)->getTagType());
			if (operationType != LdapOperationType::Unknown)
			{
				return new LdapLayer(asn1Record, data, dataLen, prevLayer, packet);
			}

			return nullptr;
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
		return getRootAsn1Record()->getSubRecords().at(1)->castAs<Asn1ConstructedRecord>();
	}

	uint16_t LdapLayer::getMessageID() const
	{
		return getRootAsn1Record()->getSubRecords().at(0)->castAs<Asn1IntegerRecord>()->getValue();
	}

	std::vector<LdapControl> LdapLayer::getControls() const
	{
		std::vector<LdapControl> controls;
		if (getRootAsn1Record()->getSubRecords().size() < 3)
		{
			return controls;
		}

		auto controlsRecord = getRootAsn1Record()->getSubRecords().at(2)->castAs<Asn1ConstructedRecord>();
		for (auto controlRecord : controlsRecord->getSubRecords())
		{
			auto controlSequence = controlRecord->castAs<Asn1SequenceRecord>();
			auto controlType = controlSequence->getSubRecords().at(0)->castAs<Asn1OctetStringRecord>()->getValue();
			std::string controlValue;
			if (controlSequence->getSubRecords().size() > 1)
			{
				controlValue = controlSequence->getSubRecords().at(1)->castAs<Asn1OctetStringRecord>()->getValue();
			}
			controls.push_back({ controlType, controlValue });
		}

		return controls;
	}

	LdapOperationType LdapLayer::getLdapOperationType() const
	{
		return LdapOperationType::fromIntValue(getLdapOperationAsn1Record()->getTagType());
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
}