#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace pcpp
{
	class PemCodec
	{
	public:
		static std::string encode(const std::vector<uint8_t>& data, const std::string& label);
		static std::vector<uint8_t> decode(const std::string& pemData);

	private:
		static constexpr const char* pemDelimiter = "-----";
		static constexpr const char* pemBegin = "-----BEGIN ";
		static constexpr const char* pemEnd = "-----END ";
		static constexpr std::size_t pemBeginLen = 11;
		static constexpr std::size_t pemEndLen = 9;
		static constexpr std::size_t pemDelimiterLen = 5;
		static constexpr size_t lineLength = 64;
	};
}  // namespace pcpp
