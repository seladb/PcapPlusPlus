#pragma once

#include <type_traits>

namespace pcpp
{
	namespace internal
	{
		template <typename EnumClass> struct EnableBitMaskOperators : std::false_type
		{
		};

		template <typename EnumClass>
		using EnableIfBitMask = typename std::enable_if<EnableBitMaskOperators<EnumClass>::value, EnumClass>::type;

		template <typename EnumClass> constexpr EnableIfBitMask<EnumClass> operator|(EnumClass lhs, EnumClass rhs)
		{
			return static_cast<EnumClass>(static_cast<typename std::underlying_type<EnumClass>::type>(lhs) |
			                              static_cast<typename std::underlying_type<EnumClass>::type>(rhs));
		}

		template <typename EnumClass> constexpr EnableIfBitMask<EnumClass> operator&(EnumClass lhs, EnumClass rhs)
		{
			return static_cast<EnumClass>(static_cast<typename std::underlying_type<EnumClass>::type>(lhs) &
			                              static_cast<typename std::underlying_type<EnumClass>::type>(rhs));
		}

		template <typename EnumClass> constexpr EnableIfBitMask<EnumClass> operator^(EnumClass lhs, EnumClass rhs)
		{
			return static_cast<EnumClass>(static_cast<typename std::underlying_type<EnumClass>::type>(lhs) ^
			                              static_cast<typename std::underlying_type<EnumClass>::type>(rhs));
		}

		template <typename EnumClass> constexpr EnableIfBitMask<EnumClass> operator~(EnumClass rhs)
		{
			return static_cast<EnumClass>(~static_cast<typename std::underlying_type<EnumClass>::type>(rhs));
		}

		template <typename EnumClass> constexpr EnableIfBitMask<EnumClass>& operator|=(EnumClass& lhs, EnumClass rhs)
		{
			return lhs = lhs | rhs;
		}

		template <typename EnumClass> constexpr EnableIfBitMask<EnumClass>& operator&=(EnumClass& lhs, EnumClass rhs)
		{
			return lhs = lhs & rhs;
		}

		template <typename EnumClass> constexpr EnableIfBitMask<EnumClass>& operator^=(EnumClass& lhs, EnumClass rhs)
		{
			return lhs = lhs ^ rhs;
		}

		template <typename EnumClass> constexpr bool hasFlag(EnableIfBitMask<EnumClass> value, EnumClass flag)
		{
			return (value & flag) == flag;
		}
	}  // namespace internal
}  // namespace pcpp

#define PCPP_DECLARE_ENUM_FLAG(EnumClass)                                                                              \
	namespace pcpp                                                                                                     \
	{                                                                                                                  \
		namespace internal                                                                                             \
		{                                                                                                              \
			template <> struct EnableBitMaskOperators<EnumClass> : std::true_type                                      \
			{                                                                                                          \
			};                                                                                                         \
		}                                                                                                              \
	}

#define PCPP_USING_ENUM_FLAG_OPERATORS()                                                                               \
	using ::pcpp::internal::operator|;                                                                                 \
	using ::pcpp::internal::operator&;                                                                                 \
	using ::pcpp::internal::operator^;                                                                                 \
	using ::pcpp::internal::operator~;                                                                                 \
	using ::pcpp::internal::operator|=;                                                                                \
	using ::pcpp::internal::operator&=;                                                                                \
	using ::pcpp::internal::operator^=;                                                                                \
	using ::pcpp::internal::hasFlag;
