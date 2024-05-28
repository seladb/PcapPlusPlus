#pragma once

#include "Layer.h"
#include "Asn1Codec.h"
#include <ostream>
#include <string>

namespace pcpp
{
	class LdapOperationType
	{
	public:
		enum Value : uint8_t
		{
			BindRequest = 0,
			BindResponse = 1,
			UnbindRequest = 2,
			SearchRequest = 3,
			SearchResultEntry = 4,
			SearchResultDone = 5,
			ModifyRequest = 6,
			ModifyResponse = 7,
			AddRequest = 8,
			AddResponse = 9,
			DelRequest = 10,
			DelResponse = 11,
			ModifyDNRequest = 12,
			ModifyDNResponse = 13,
			CompareRequest = 14,
			CompareResponse = 15,
			AbandonRequest = 16,
			SearchResultReference = 19,
			ExtendedRequest = 23,
			ExtendedResponse = 24,
			IntermediateResponse = 25,
			Unknown = 255
		};

		LdapOperationType() = default;

		constexpr LdapOperationType(Value value) : m_Value(value) {}

		constexpr operator Value() const { return m_Value; }

		// Prevent usage: if(LdapOperationType)
		explicit operator bool() const = delete;

		std::string toString() const;

		static LdapOperationType fromIntValue(uint8_t value);

	private:
		Value m_Value;
	};

	struct LdapControl
	{
		std::string controlType;
		std::string controlValue;

		bool operator==(const LdapControl& other) const
		{
			return controlType == other.controlType && controlValue == other.controlValue;
		}
	};

	/**
	 * @class LdapLayer
	 * TBD
	 */
	class LdapLayer : public Layer
	{
	public:
		LdapLayer(uint16_t messageId, LdapOperationType operationType,
			const std::vector<Asn1Record*>& messageRecords,
			const std::vector<LdapControl> controls = std::vector<LdapControl>());

		~LdapLayer() {}

		Asn1SequenceRecord* getRootAsn1Record() const;

		Asn1ConstructedRecord* getMessageAsn1Record() const;

		uint16_t getMessageID() const;

		std::vector<LdapControl> getControls() const;

		LdapOperationType getLdapOperationType() const;

		static bool isLdapPort(uint16_t port) { return port == 389; }

		static LdapLayer* parseLdapMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		// implement abstract methods

		/**
		 * Does nothing for this layer (ArpLayer is always last)
		 */
		void parseNextLayer() override {}

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
