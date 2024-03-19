#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "Asn1BerDecoder.h"
#include "RawPacket.h"
#include <deque>

struct ExpectedBerInfo
{
	pcpp::BerTagClass tagClass;
	pcpp::BerTagType berType;
	pcpp::Asn1TagType asn1Type;
	size_t totalLength;
	size_t valueLength;
	pcpp::Asn1BerRecord record;
	std::vector<ExpectedBerInfo> children;
};

PTF_TEST_CASE(Asn1BerDecodingTest)
{
	READ_FILE_INTO_BUFFER(1, "PacketExamples/ldap_asn1ber.dat");

	auto record = pcpp::Asn1BerRecord::decode(buffer1, bufferLength1);

	ExpectedBerInfo expectedBerInfo = {
		pcpp::BerTagClass::Universal,
		pcpp::BerTagType::Constructed,
		pcpp::Asn1TagType::Sequence,
		351,
		345,
		record,
		{
			{
				pcpp::BerTagClass::Universal,
				pcpp::BerTagType::Primitive,
				pcpp::Asn1TagType::Integer,
				4,
				2,
				record.getChildren().at(0),
			},
			{
				pcpp::BerTagClass::Application,
				pcpp::BerTagType::Constructed,
				pcpp::Asn1TagType::BitString,
				341,
				335,
				record.getChildren().at(1),
				{
					{
						pcpp::BerTagClass::Universal,
						pcpp::BerTagType::Primitive,
						pcpp::Asn1TagType::OctetString,
						2,
						0,
						record.getChildren().at(1).getChildren().at(0)
					},
					{
						pcpp::BerTagClass::Universal,
						pcpp::BerTagType::Primitive,
						pcpp::Asn1TagType::Enumerated,
						3,
						1,
						record.getChildren().at(1).getChildren().at(1)
					},
					{
						pcpp::BerTagClass::Universal,
						pcpp::BerTagType::Primitive,
						pcpp::Asn1TagType::Enumerated,
						3,
						1,
						record.getChildren().at(1).getChildren().at(2)
					},
					{
						pcpp::BerTagClass::Universal,
						pcpp::BerTagType::Primitive,
						pcpp::Asn1TagType::Integer,
						3,
						1,
						record.getChildren().at(1).getChildren().at(3)
					},
					{
						pcpp::BerTagClass::Universal,
						pcpp::BerTagType::Primitive,
						pcpp::Asn1TagType::Integer,
						3,
						1,
						record.getChildren().at(1).getChildren().at(4)
					},
					{
						pcpp::BerTagClass::Universal,
						pcpp::BerTagType::Primitive,
						pcpp::Asn1TagType::Boolean,
						3,
						1,
						record.getChildren().at(1).getChildren().at(5)
					},
					{
						pcpp::BerTagClass::ContextSpecific,
						pcpp::BerTagType::Primitive,
						pcpp::Asn1TagType::ObjectDescriptor,
						13,
						11,
						record.getChildren().at(1).getChildren().at(6)
					},
					{
						pcpp::BerTagClass::Universal,
						pcpp::BerTagType::Constructed,
						pcpp::Asn1TagType::Sequence,
						305,
						299,
						record.getChildren().at(1).getChildren().at(7),
						{
							{
								pcpp::BerTagClass::Universal,
								pcpp::BerTagType::Primitive,
								pcpp::Asn1TagType::OctetString,
								19,
								17,
								record.getChildren().at(1).getChildren().at(7).getChildren().at(0)
							},
							{
								pcpp::BerTagClass::Universal,
								pcpp::BerTagType::Primitive,
								pcpp::Asn1TagType::OctetString,
								15,
								13,
								record.getChildren().at(1).getChildren().at(7).getChildren().at(1)
							},
							{
								pcpp::BerTagClass::Universal,
								pcpp::BerTagType::Primitive,
								pcpp::Asn1TagType::OctetString,
								16,
								14,
								record.getChildren().at(1).getChildren().at(7).getChildren().at(2)
							},
							{
								pcpp::BerTagClass::Universal,
								pcpp::BerTagType::Primitive,
								pcpp::Asn1TagType::OctetString,
								22,
								20,
								record.getChildren().at(1).getChildren().at(7).getChildren().at(3)
							},
							{
								pcpp::BerTagClass::Universal,
								pcpp::BerTagType::Primitive,
								pcpp::Asn1TagType::OctetString,
								21,
								19,
								record.getChildren().at(1).getChildren().at(7).getChildren().at(4)
							},
							{
								pcpp::BerTagClass::Universal,
								pcpp::BerTagType::Primitive,
								pcpp::Asn1TagType::OctetString,
								28,
								26,
								record.getChildren().at(1).getChildren().at(7).getChildren().at(5)
							},
							{
								pcpp::BerTagClass::Universal,
								pcpp::BerTagType::Primitive,
								pcpp::Asn1TagType::OctetString,
								25,
								23,
								record.getChildren().at(1).getChildren().at(7).getChildren().at(6)
							},
							{
								pcpp::BerTagClass::Universal,
								pcpp::BerTagType::Primitive,
								pcpp::Asn1TagType::OctetString,
								18,
								16,
								record.getChildren().at(1).getChildren().at(7).getChildren().at(7)
							},
							{
								pcpp::BerTagClass::Universal,
								pcpp::BerTagType::Primitive,
								pcpp::Asn1TagType::OctetString,
								22,
								20,
								record.getChildren().at(1).getChildren().at(7).getChildren().at(8)
							},
							{
								pcpp::BerTagClass::Universal,
								pcpp::BerTagType::Primitive,
								pcpp::Asn1TagType::OctetString,
								23,
								21,
								record.getChildren().at(1).getChildren().at(7).getChildren().at(9)
							},
							{
								pcpp::BerTagClass::Universal,
								pcpp::BerTagType::Primitive,
								pcpp::Asn1TagType::OctetString,
								25,
								23,
								record.getChildren().at(1).getChildren().at(7).getChildren().at(10)
							},
							{
								pcpp::BerTagClass::Universal,
								pcpp::BerTagType::Primitive,
								pcpp::Asn1TagType::OctetString,
								13,
								11,
								record.getChildren().at(1).getChildren().at(7).getChildren().at(11)
							},
							{
								pcpp::BerTagClass::Universal,
								pcpp::BerTagType::Primitive,
								pcpp::Asn1TagType::OctetString,
								17,
								15,
								record.getChildren().at(1).getChildren().at(7).getChildren().at(12)
							},
							{
								pcpp::BerTagClass::Universal,
								pcpp::BerTagType::Primitive,
								pcpp::Asn1TagType::OctetString,
								12,
								10,
								record.getChildren().at(1).getChildren().at(7).getChildren().at(13)
							},
							{
								pcpp::BerTagClass::Universal,
								pcpp::BerTagType::Primitive,
								pcpp::Asn1TagType::OctetString,
								23,
								21,
								record.getChildren().at(1).getChildren().at(7).getChildren().at(14)
							}
						}
					}
				}
			}
		}
	};

	std::deque<ExpectedBerInfo> queue;
	queue.push_back(expectedBerInfo);

	while (!queue.empty())
	{
		auto front = queue.front();
		queue.pop_front();
		for (auto const& child : front.children) {
			queue.push_back(child);
		}

		PTF_ASSERT_EQUAL(front.record.getTagClass(), front.tagClass, enumclass);
		PTF_ASSERT_EQUAL(front.record.getBerTagType(), front.berType, enumclass);
		PTF_ASSERT_EQUAL(front.record.getAsn1TagType(), front.asn1Type, enumclass);
		PTF_ASSERT_EQUAL(front.record.getTotalLength(), front.totalLength);
		PTF_ASSERT_EQUAL(front.record.getValueLength(), front.valueLength);
	}

	delete buffer1;
};