#include "PemCodec.h"
#include "GeneralUtils.h"
#include <sstream>
#include <iostream>
#include <algorithm>

namespace pcpp
{
	std::string PemCodec::encode(const std::vector<uint8_t>& data, const std::string& label)
	{
		if (label.empty())
		{
			throw std::invalid_argument("PEM label cannot be empty");
		}

		if (data.empty())
		{
			throw std::invalid_argument("PEM data cannot be empty");
		}

		auto base64Str = Base64::encode(data);
		std::ostringstream oss;

		oss << pemBegin << label << pemDelimiter << "\n";

		auto base64StrSize = base64Str.size();
		for (size_t i = 0; i < base64StrSize; i += lineLength)
		{
			auto len = base64StrSize - i < lineLength ? base64StrSize - i : lineLength;
			oss.write(&base64Str[i], len);
			oss.put('\n');
		}

		oss << pemEnd << label << pemDelimiter << "\n";
		return oss.str();
	}

	std::vector<uint8_t> PemCodec::decode(const std::string& pemData, const std::string& expectedLabel)
	{
		std::istringstream iss(pemData);
		std::string line;
		std::string base64Data;
		std::string beginLabel, endLabel;
		bool inBody = false;

		while (std::getline(iss, line))
		{
			line.erase(std::remove(line.begin(), line.end(), '\r'), line.end());

			if (line.find(pemBegin) == 0)
			{
				if (inBody)
				{
					throw std::invalid_argument("Unexpected BEGIN while already inside a PEM block");
				}

				beginLabel = line.substr(pemBeginLen, line.find(pemDelimiter, pemBeginLen) - pemBeginLen);
				if (beginLabel.empty())
				{
					throw std::invalid_argument("Invalid BEGIN label in PEM");
				}

				if (!expectedLabel.empty() && beginLabel != expectedLabel)
				{
					throw std::invalid_argument("Unexpected BEGIN label in PEM - expected '" + expectedLabel +
					                            "' but got '" + beginLabel + "'");
				}

				if (line.compare(line.size() - pemDelimiterLen, pemDelimiterLen, pemDelimiter) != 0)
				{
					throw std::invalid_argument("Invalid BEGIN suffix in PEM");
				}

				inBody = true;
				continue;
			}

			if (line.find(pemEnd) == 0)
			{
				if (!inBody)
				{
					throw std::invalid_argument("END found before BEGIN in PEM");
				}

				endLabel = line.substr(pemEndLen, line.find(pemDelimiter, pemEndLen) - pemEndLen);
				if (endLabel != beginLabel)
				{
					throw std::invalid_argument("BEGIN and END labels do not match in PEM");
				}
				break;
			}

			if (inBody && !line.empty())
			{
				base64Data += line;
			}
		}

		if (beginLabel.empty() || endLabel.empty())
		{
			throw std::invalid_argument("Missing BEGIN or END in PEM data");
		}

		if (base64Data.empty())
		{
			throw std::invalid_argument("No base64 content found in PEM data");
		}

		return Base64::decodeToByteVector(base64Data);
	}
}  // namespace pcpp
