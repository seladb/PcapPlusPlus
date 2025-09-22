#include "../TestDefinition.h"
#include "GeneralUtils.h"
#include "Logger.h"
#include <vector>

PTF_TEST_CASE(Base64EncodingTest)
{
	// Encode strings
	{
		std::vector<std::pair<std::string, std::string>> inputAndExpectedOutputs = {
			{ "a",			                   "YQ=="			                         },
			{ "bc",			                  "YmM="			                         },
			{ "def",			                 "ZGVm"			                         },
			{ "ghij",			                "Z2hpag=="			                     },
			{ "klmno",			               "a2xtbm8="                                 },
			{ "pqrstu",			              "cHFyc3R1"                                 },
			{ "1234567890",                      "MTIzNDU2Nzg5MA=="                         },
			{ "!@#$%^&&*()<>,.?/:;'\"{}[]\\|~`", "IUAjJCVeJiYqKCk8PiwuPy86Oycie31bXVx8fmA=" },
			{ "VWXYZ",			               "VldYWVo="                                 },
			{ "abcdefghi",                       "YWJjZGVmZ2hp"                             },
			{ "",			                    ""			                             },
			{ "\tABC\n",			             "CUFCQwo="                                 },
			{ R"(ab)",			               "YWI="			                         },
			{ "日한สअAΩЯש你🌍",                  "5pel7ZWc4Liq4KSFQc6p0K/XqeS9oPCfjI0="     },
		};

		for (const auto& inputAndExpectedOutput : inputAndExpectedOutputs)
		{
			PTF_ASSERT_EQUAL(pcpp::Base64::encode(inputAndExpectedOutput.first), inputAndExpectedOutput.second);
		}
	}

	// Encode byte arrays
	{
		std::vector<std::pair<std::vector<uint8_t>, std::string>> inputAndExpectedOutputs = {
			{ { 0x1 },			              "AQ=="     },
			{ { 0x1b, 0x2c },                   "Gyw="     },
			{ { 0x9f, 0x8e, 0x7d },             "n459"     },
			{ { 0x1, 0x2, 0x3, 0x4 },           "AQIDBA==" },
			{ { 0x1, 0x2, 0x3, 0x4, 0x5 },      "AQIDBAU=" },
			{ { 0x1, 0x2, 0x3, 0x4, 0x5, 0x6 }, "AQIDBAUG" },
			{ { 0x0, 0x0 },                     "AAA="     },
			{ { 0xff, 0xee, 0xdd },             "/+7d"     },
		};

		for (const auto& inputAndExpectedOutput : inputAndExpectedOutputs)
		{
			PTF_ASSERT_EQUAL(
			    pcpp::Base64::encode(inputAndExpectedOutput.first.data(), inputAndExpectedOutput.first.size()),
			    inputAndExpectedOutput.second);
			PTF_ASSERT_EQUAL(pcpp::Base64::encode(inputAndExpectedOutput.first), inputAndExpectedOutput.second);
			auto hexString =
			    pcpp::byteArrayToHexString(inputAndExpectedOutput.first.data(), inputAndExpectedOutput.first.size());
			PTF_ASSERT_EQUAL(pcpp::Base64::encodeHexString(hexString), inputAndExpectedOutput.second);
		}

		PTF_ASSERT_EQUAL(pcpp::Base64::encode(nullptr, 0), "");
	}

	// Invalid inputs
	{
		PTF_ASSERT_RAISES(pcpp::Base64::encode(nullptr, 10), std::invalid_argument, "Input buffer is null");
		pcpp::Logger::getInstance().suppressLogs();
		PTF_ASSERT_RAISES(pcpp::Base64::encodeHexString("invalid"), std::invalid_argument, "Invalid hex string");
		pcpp::Logger::getInstance().enableLogs();
	}
}  // Base64EncodingTest

PTF_TEST_CASE(Base64DecodingTest)
{
	// Decode strings
	{
		std::vector<std::pair<std::string, std::string>> inputAndExpectedOutputs = {
			{ "YQ==",			                         "a"			                   },
			{ "YmM=",			                         "bc"			                  },
			{ "ZGVm",			                         "def"			                 },
			{ "Z2hpag==",			                     "ghij"                            },
			{ "a2xtbm8=",			                     "klmno"                           },
			{ "cHFyc3R1",			                     "pqrstu"                          },
			{ "MTIzNDU2Nzg5MA==",                         "1234567890"                      },
			{ "IUAjJCVeJiYqKCk8PiwuPy86Oycie31bXVx8fmA=", "!@#$%^&&*()<>,.?/:;'\"{}[]\\|~`" },
			{ "VldYWVo=",			                     "VWXYZ"                           },
			{ "YWJjZGVmZ2hp",                             "abcdefghi"                       },
			{ "",			                             ""			                    },
			{ "CUFCQwo=",			                     "\tABC\n"                         },
			{ "YWI=",			                         R"(ab)"                           },
			{ "5pel7ZWc4Liq4KSFQc6p0K/XqeS9oPCfjI0=",     "日한สअAΩЯש你🌍"                  },
		};

		for (const auto& inputAndExpectedOutput : inputAndExpectedOutputs)
		{
			PTF_ASSERT_EQUAL(pcpp::Base64::decodeToString(inputAndExpectedOutput.first), inputAndExpectedOutput.second);
			PTF_ASSERT_EQUAL(pcpp::Base64::getDecodedSize(inputAndExpectedOutput.first),
			                 inputAndExpectedOutput.second.size());
		}
	}

	// Decode byte arrays
	{
		std::vector<std::pair<std::string, std::vector<uint8_t>>> inputAndExpectedOutputs = {
			{ "AQ==",     { 0x1 }                          },
			{ "Gyw=",     { 0x1b, 0x2c }                   },
			{ "n459",     { 0x9f, 0x8e, 0x7d }             },
			{ "AQIDBA==", { 0x1, 0x2, 0x3, 0x4 }           },
			{ "AQIDBAU=", { 0x1, 0x2, 0x3, 0x4, 0x5 }      },
			{ "AQIDBAUG", { 0x1, 0x2, 0x3, 0x4, 0x5, 0x6 } },
			{ "AAA=",     { 0x0, 0x0 }                     },
			{ "/+7d",     { 0xff, 0xee, 0xdd }             },
		};

		for (const auto& inputAndExpectedOutput : inputAndExpectedOutputs)
		{
			PTF_ASSERT_VECTORS_EQUAL(pcpp::Base64::decodeToByteVector(inputAndExpectedOutput.first),
			                         inputAndExpectedOutput.second);
			uint8_t buffer[50];
			auto decodedSize = pcpp::Base64::decodeToByteArray(inputAndExpectedOutput.first, buffer, 50);
			PTF_ASSERT_BUF_COMPARE(buffer, inputAndExpectedOutput.second.data(), decodedSize);
			PTF_ASSERT_EQUAL(
			    pcpp::Base64::decodeToHexString(inputAndExpectedOutput.first),
			    pcpp::byteArrayToHexString(inputAndExpectedOutput.second.data(), inputAndExpectedOutput.second.size()));
			PTF_ASSERT_EQUAL(pcpp::Base64::getDecodedSize(inputAndExpectedOutput.first),
			                 inputAndExpectedOutput.second.size());
		}
	}

	// Invalid inputs
	{
		PTF_ASSERT_RAISES(pcpp::Base64::decodeToHexString("abc"), std::invalid_argument,
		                  "Invalid base64 encoded data - Size not divisible by 4");
		PTF_ASSERT_RAISES(pcpp::Base64::decodeToHexString("a==="), std::invalid_argument,
		                  "Invalid base64 encoded data - Found more than 2 padding characters");
		std::vector<std::string> invalidCharacterInputs = { "::==", ":::=", "::::" };
		for (const auto& invalidCharacterInput : invalidCharacterInputs)
		{
			PTF_ASSERT_RAISES(pcpp::Base64::decodeToHexString(invalidCharacterInput), std::invalid_argument,
			                  "Invalid base64 encoded data - Invalid character");
		}
		uint8_t buffer[50];
		PTF_ASSERT_RAISES(pcpp::Base64::decodeToByteArray("YWJjZGVmZ2hp", buffer, 5), std::invalid_argument,
		                  "Not enough space in result buffer for decoded data, 9 bytes are required");

		PTF_ASSERT_RAISES(pcpp::Base64::getDecodedSize("abc"), std::invalid_argument,
		                  "Invalid base64 encoded data - Size not divisible by 4");
		PTF_ASSERT_RAISES(pcpp::Base64::getDecodedSize("a==="), std::invalid_argument,
		                  "Invalid base64 encoded data - Found more than 2 padding characters");
	}
}  // Base64DecodingTest
