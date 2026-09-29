#include "../TestDefinition.h"
#include "Serializers.h"
#include <limits>
#include <sstream>
#include <string>

PTF_TEST_CASE(JsonSerializerTest)
{
	// An empty object / empty array just emits the bracket pair, with no
	// name key at the top level either.
	{
		std::ostringstream oss;
		pcpp::JsonSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
		}
		PTF_ASSERT_EQUAL(oss.str(), "{}");
	}
	{
		std::ostringstream oss;
		pcpp::JsonSerializer serializer(oss);
		{
			auto arr = serializer.writeArray(pcpp::FieldDescriptor{ 1, "root" });
		}
		PTF_ASSERT_EQUAL(oss.str(), "[]");
	}

	// A single string field inside an object: the key is written and
	// quoted, the value is written and quoted, and no comma precedes the
	// first field at a level.
	{
		std::ostringstream oss;
		pcpp::JsonSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeField(pcpp::FieldDescriptor{ 2, "name" }, std::string("value"));
		}
		PTF_ASSERT_EQUAL(oss.str(), R"({"name":"value"})");
	}

	// String VALUE escaping: '"', '\\', '\n' and '\t' are backslash-escaped;
	// every other character passes through unchanged.
	{
		std::ostringstream oss;
		pcpp::JsonSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeField(pcpp::FieldDescriptor{ 2, "value" }, std::string("a\"b\\c\nd\te"));
		}
		PTF_ASSERT_EQUAL(oss.str(), R"({"value":"a\"b\\c\nd\te"})");
	}

	// Field NAME escaping: writeKey() runs the name through the same
	// escapeQuotedString() as values, so a key containing quotes/backslashes
	// is escaped identically.
	{
		std::ostringstream oss;
		pcpp::JsonSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeField(pcpp::FieldDescriptor{ 2, "weird\"name\\here" }, std::string("ok"));
		}
		PTF_ASSERT_EQUAL(oss.str(), R"({"weird\"name\\here":"ok"})");
	}

	// Non-ASCII / other punctuation isn't in the escape set and is copied
	// through verbatim.
	{
		std::ostringstream oss;
		pcpp::JsonSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeField(pcpp::FieldDescriptor{ 2, "field" }, std::string("h\xc3\xa9llo/w\xc3\xb6rld"));
		}
		PTF_ASSERT_EQUAL(oss.str(), "{\"field\":\"h\xc3\xa9llo/w\xc3\xb6rld\"}");
	}

	// An empty string value is still wrapped in quotes.
	{
		std::ostringstream oss;
		pcpp::JsonSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeField(pcpp::FieldDescriptor{ 2, "empty" }, std::string(""));
		}
		PTF_ASSERT_EQUAL(oss.str(), R"({"empty":""})");
	}

	// writeField(const char*) forwards to the std::string overload, so a
	// C-string value is quoted and escaped the same way.
	{
		std::ostringstream oss;
		pcpp::JsonSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeField(pcpp::FieldDescriptor{ 2, "greeting" }, "hi \"there\"");
		}
		PTF_ASSERT_EQUAL(oss.str(), R"({"greeting":"hi \"there\""})");
	}

	// Multiple sibling fields in an object: comma separators appear between
	// fields but never before the first one.
	{
		std::ostringstream oss;
		pcpp::JsonSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeField(pcpp::FieldDescriptor{ 2, "a" }, static_cast<int64_t>(1));
			obj.writeField(pcpp::FieldDescriptor{ 3, "b" }, std::string("x"));
			obj.writeField(pcpp::FieldDescriptor{ 4, "c" }, true);
		}
		PTF_ASSERT_EQUAL(oss.str(), R"({"a":1,"b":"x","c":true})");
	}

	// Array elements have no keys (writeKey() skips the name whenever the
	// current context is Array) but are still comma-separated.
	{
		std::ostringstream oss;
		pcpp::JsonSerializer serializer(oss);
		{
			auto arr = serializer.writeArray(pcpp::FieldDescriptor{ 1, "root" });
			arr.writeField(pcpp::FieldDescriptor{ 2, "ignoredName" }, std::string("a"));
			arr.writeField(pcpp::FieldDescriptor{ 3, "ignoredName" }, std::string("b"));
			arr.writeField(pcpp::FieldDescriptor{ 4, "ignoredName" }, std::string("c"));
		}
		PTF_ASSERT_EQUAL(oss.str(), R"(["a","b","c"])");
	}

	// Nested object inside an object: the outer object's separator state is
	// independent of the inner one's, so the inner object's first field
	// gets no leading comma even though it isn't the first field overall,
	// and the outer object correctly resumes comma-separating once the
	// inner object closes.
	{
		std::ostringstream oss;
		pcpp::JsonSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeField(pcpp::FieldDescriptor{ 2, "before" }, static_cast<int64_t>(1));
			{
				auto inner = obj.writeObject(pcpp::FieldDescriptor{ 3, "nested" });
				inner.writeField(pcpp::FieldDescriptor{ 4, "x" }, static_cast<int64_t>(2));
				inner.writeField(pcpp::FieldDescriptor{ 5, "y" }, static_cast<int64_t>(3));
			}
			obj.writeField(pcpp::FieldDescriptor{ 6, "after" }, static_cast<int64_t>(4));
		}
		PTF_ASSERT_EQUAL(oss.str(), R"({"before":1,"nested":{"x":2,"y":3},"after":4})");
	}

	// Array of objects: each element still gets its own comma separator at
	// the array level, while carrying no key of its own.
	{
		std::ostringstream oss;
		pcpp::JsonSerializer serializer(oss);
		{
			auto arr = serializer.writeArray(pcpp::FieldDescriptor{ 1, "root" });
			{
				auto item1 = arr.writeObject(pcpp::FieldDescriptor{ 2, "ignored" });
				item1.writeField(pcpp::FieldDescriptor{ 3, "id" }, static_cast<int64_t>(1));
			}
			{
				auto item2 = arr.writeObject(pcpp::FieldDescriptor{ 4, "ignored" });
				item2.writeField(pcpp::FieldDescriptor{ 5, "id" }, static_cast<int64_t>(2));
			}
		}
		PTF_ASSERT_EQUAL(oss.str(), R"([{"id":1},{"id":2}])");
	}

	// Object containing an array-valued field: exercises m_ContextStack /
	// m_FirstAtLevel growing and shrinking correctly across mixed
	// object/array nesting.
	{
		std::ostringstream oss;
		pcpp::JsonSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeField(pcpp::FieldDescriptor{ 2, "name" }, std::string("pkt"));
			{
				auto tags = obj.writeArray(pcpp::FieldDescriptor{ 3, "tags" });
				tags.writeField(pcpp::FieldDescriptor{ 4, "t" }, std::string("a"));
				tags.writeField(pcpp::FieldDescriptor{ 5, "t" }, std::string("b"));
			}
		}
		PTF_ASSERT_EQUAL(oss.str(), R"({"name":"pkt","tags":["a","b"]})");
	}

	// Signed integer fields: negative, zero, positive, plus a narrower
	// signed width funneled through the non-virtual template overload into
	// the canonical int64_t virtual.
	{
		std::ostringstream oss;
		pcpp::JsonSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeField(pcpp::FieldDescriptor{ 2, "neg" }, static_cast<int64_t>(-42));
			obj.writeField(pcpp::FieldDescriptor{ 3, "zero" }, static_cast<int64_t>(0));
			obj.writeField(pcpp::FieldDescriptor{ 4, "pos" }, static_cast<int64_t>(42));
			obj.writeField(pcpp::FieldDescriptor{ 5, "shortNeg" }, static_cast<int16_t>(-7));
		}
		PTF_ASSERT_EQUAL(oss.str(), R"({"neg":-42,"zero":0,"pos":42,"shortNeg":-7})");
	}

	// Unsigned integers within the JS safe-integer range (<=
	// Number.MAX_SAFE_INTEGER, 2^53-1) are written as plain JSON numbers,
	// including through the narrower-width template overload. This also
	// pins the upper edge of the boundary: MAX_SAFE_INTEGER itself must
	// stay unquoted.
	{
		std::ostringstream oss;
		pcpp::JsonSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeField(pcpp::FieldDescriptor{ 2, "zero" }, static_cast<uint64_t>(0));
			obj.writeField(pcpp::FieldDescriptor{ 3, "small" }, static_cast<uint32_t>(65535));
			obj.writeField(pcpp::FieldDescriptor{ 4, "maxSafe" },
			               9007199254740991ULL);  // 2^53 - 1
		}
		PTF_ASSERT_EQUAL(oss.str(), R"({"zero":0,"small":65535,"maxSafe":9007199254740991})");
	}

	// Unsigned integers ABOVE the safe-integer threshold are quoted as JSON
	// strings instead, to avoid silent precision loss in JS-based parsers -
	// MAX_SAFE_INTEGER + 1 and UINT64_MAX are both quoted.
	{
		std::ostringstream oss;
		pcpp::JsonSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeField(pcpp::FieldDescriptor{ 2, "justOver" }, 9007199254740992ULL);  // 2^53
			obj.writeField(pcpp::FieldDescriptor{ 3, "max" }, std::numeric_limits<uint64_t>::max());
		}
		PTF_ASSERT_EQUAL(oss.str(), R"({"justOver":"9007199254740992","max":"18446744073709551615"})");
	}

	// Double fields use the stream's default floating-point formatting,
	// including negative and whole-number values.
	{
		std::ostringstream oss;
		pcpp::JsonSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeField(pcpp::FieldDescriptor{ 2, "frac" }, 3.5);
			obj.writeField(pcpp::FieldDescriptor{ 3, "neg" }, -2.25);
			obj.writeField(pcpp::FieldDescriptor{ 4, "whole" }, 0.0);
		}
		PTF_ASSERT_EQUAL(oss.str(), R"({"frac":3.5,"neg":-2.25,"whole":0})");
	}

	// Bool fields write the literal `true`/`false` tokens, not 1/0.
	{
		std::ostringstream oss;
		pcpp::JsonSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeField(pcpp::FieldDescriptor{ 2, "yes" }, true);
			obj.writeField(pcpp::FieldDescriptor{ 3, "no" }, false);
		}
		PTF_ASSERT_EQUAL(oss.str(), R"({"yes":true,"no":false})");
	}

	// Null fields write the literal `null` token.
	{
		std::ostringstream oss;
		pcpp::JsonSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeNullField(pcpp::FieldDescriptor{ 2, "missing" });
		}
		PTF_ASSERT_EQUAL(oss.str(), R"({"missing":null})");
	}

	// Hex fields are always written as a quoted, lower-case "0x..."-prefixed
	// string, regardless of the (always-unsigned) integer width used to
	// call them - including a zero value.
	{
		std::ostringstream oss;
		pcpp::JsonSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeHexField(pcpp::FieldDescriptor{ 2, "zero" }, static_cast<uint64_t>(0));
			obj.writeHexField(pcpp::FieldDescriptor{ 3, "byte" }, 0xFF);
			obj.writeHexField(pcpp::FieldDescriptor{ 4, "big" }, static_cast<uint64_t>(0xDEADBEEFULL));
		}
		PTF_ASSERT_EQUAL(oss.str(), R"({"zero":"0x0","byte":"0xff","big":"0xdeadbeef"})");
	}

	// Multiple root elements are not allowed
	{
		std::ostringstream oss;
		pcpp::JsonSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			PTF_ASSERT_RAISES(serializer.writeArray(pcpp::FieldDescriptor{ 1, "anotherRoot" }), std::logic_error,
			                  "Only one root value may be written per instance");
			PTF_ASSERT_RAISES(serializer.writeObject(pcpp::FieldDescriptor{ 1, "anotherRoot" }), std::logic_error,
			                  "Only one root value may be written per instance");
		}
	}
	{
		std::ostringstream oss;
		pcpp::JsonSerializer serializer(oss);
		{
			auto arr = serializer.writeArray(pcpp::FieldDescriptor{ 1, "root" });
			PTF_ASSERT_RAISES(serializer.writeArray(pcpp::FieldDescriptor{ 1, "anotherRoot" }), std::logic_error,
			                  "Only one root value may be written per instance");
			PTF_ASSERT_RAISES(serializer.writeObject(pcpp::FieldDescriptor{ 1, "anotherRoot" }), std::logic_error,
			                  "Only one root value may be written per instance");
		}
	}
}  // JsonSerializerTest
