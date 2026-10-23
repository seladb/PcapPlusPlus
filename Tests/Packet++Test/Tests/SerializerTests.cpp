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

PTF_TEST_CASE(YamlSerializerTest)
{
	// An empty root object produces an empty YAML document.
	{
		std::ostringstream oss;
		pcpp::YamlSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
		}
		PTF_ASSERT_EQUAL(oss.str(), "");
	}

	// An empty root array is represented by [].
	{
		std::ostringstream oss;
		pcpp::YamlSerializer serializer(oss);
		{
			auto arr = serializer.writeArray(pcpp::FieldDescriptor{ 1, "root" });
		}
		PTF_ASSERT_EQUAL(oss.str(), " []");
	}

	// A single string field.
	{
		std::ostringstream oss;
		pcpp::YamlSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeField(pcpp::FieldDescriptor{ 2, "name" }, std::string("value"));
		}
		PTF_ASSERT_EQUAL(oss.str(), "name: \"value\"");
	}

	// String values are always quoted and the JSON/YAML escape set is applied.
	{
		std::ostringstream oss;
		pcpp::YamlSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeField(pcpp::FieldDescriptor{ 2, "value" }, std::string("a\"b\\c\nd\te"));
		}
		PTF_ASSERT_EQUAL(oss.str(), "value: \"a\\\"b\\\\c\\nd\\te\"");
	}

	// Strings that could otherwise be interpreted as YAML scalars remain
	// strings because all string values are double-quoted.
	{
		std::ostringstream oss;
		pcpp::YamlSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeField(pcpp::FieldDescriptor{ 2, "boolString" }, std::string("true"));
			obj.writeField(pcpp::FieldDescriptor{ 3, "nullString" }, std::string("null"));
			obj.writeField(pcpp::FieldDescriptor{ 4, "numberString" }, std::string("123"));
			obj.writeField(pcpp::FieldDescriptor{ 5, "hashString" }, std::string("# comment"));
			obj.writeField(pcpp::FieldDescriptor{ 6, "dashString" }, std::string("- item"));
			obj.writeField(pcpp::FieldDescriptor{ 7, "colonString" }, std::string(": value"));
		}
		PTF_ASSERT_EQUAL(oss.str(), "boolString: \"true\"\n"
		                            "nullString: \"null\"\n"
		                            "numberString: \"123\"\n"
		                            "hashString: \"# comment\"\n"
		                            "dashString: \"- item\"\n"
		                            "colonString: \": value\"");
	}

	// Empty strings are still quoted strings, rather than null values.
	{
		std::ostringstream oss;
		pcpp::YamlSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeField(pcpp::FieldDescriptor{ 2, "empty" }, std::string(""));
		}
		PTF_ASSERT_EQUAL(oss.str(), "empty: \"\"");
	}

	// const char* forwards to the std::string overload.
	{
		std::ostringstream oss;
		pcpp::YamlSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeField(pcpp::FieldDescriptor{ 2, "greeting" }, "hi \"there\"");
		}
		PTF_ASSERT_EQUAL(oss.str(), "greeting: \"hi \\\"there\\\"\"");
	}

	// Multiple sibling fields are emitted on consecutive lines.
	{
		std::ostringstream oss;
		pcpp::YamlSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeField(pcpp::FieldDescriptor{ 2, "a" }, static_cast<int64_t>(1));
			obj.writeField(pcpp::FieldDescriptor{ 3, "b" }, std::string("x"));
			obj.writeField(pcpp::FieldDescriptor{ 4, "c" }, true);
		}
		PTF_ASSERT_EQUAL(oss.str(), "a: 1\n"
		                            "b: \"x\"\n"
		                            "c: true");
	}

	// Signed integer values: negative, zero, positive, and a narrower signed
	// integer exercising the templated overload.
	{
		std::ostringstream oss;
		pcpp::YamlSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeField(pcpp::FieldDescriptor{ 2, "neg" }, static_cast<int64_t>(-42));
			obj.writeField(pcpp::FieldDescriptor{ 3, "zero" }, static_cast<int64_t>(0));
			obj.writeField(pcpp::FieldDescriptor{ 4, "pos" }, static_cast<int64_t>(42));
			obj.writeField(pcpp::FieldDescriptor{ 5, "shortNeg" }, static_cast<int16_t>(-7));
		}
		PTF_ASSERT_EQUAL(oss.str(), "neg: -42\n"
		                            "zero: 0\n"
		                            "pos: 42\n"
		                            "shortNeg: -7");
	}

	// Unsigned values at and below the JavaScript safe-integer limit remain
	// numeric YAML scalars.
	{
		std::ostringstream oss;
		pcpp::YamlSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeField(pcpp::FieldDescriptor{ 2, "zero" }, static_cast<uint64_t>(0));
			obj.writeField(pcpp::FieldDescriptor{ 3, "small" }, static_cast<uint32_t>(65535));
			obj.writeField(pcpp::FieldDescriptor{ 4, "maxSafe" }, 9007199254740991ULL);
		}
		PTF_ASSERT_EQUAL(oss.str(), "zero: 0\n"
		                            "small: 65535\n"
		                            "maxSafe: 9007199254740991");
	}

	// Unsigned values above the safe-integer limit are quoted.
	{
		std::ostringstream oss;
		pcpp::YamlSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeField(pcpp::FieldDescriptor{ 2, "justOver" }, 9007199254740992ULL);
			obj.writeField(pcpp::FieldDescriptor{ 3, "max" }, std::numeric_limits<uint64_t>::max());
		}
		PTF_ASSERT_EQUAL(oss.str(), "justOver: \"9007199254740992\"\n"
		                            "max: \"18446744073709551615\"");
	}

	// Double values.
	{
		std::ostringstream oss;
		pcpp::YamlSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeField(pcpp::FieldDescriptor{ 2, "frac" }, 3.5);
			obj.writeField(pcpp::FieldDescriptor{ 3, "neg" }, -2.25);
			obj.writeField(pcpp::FieldDescriptor{ 4, "whole" }, 0.0);
		}
		PTF_ASSERT_EQUAL(oss.str(), "frac: 3.5\n"
		                            "neg: -2.25\n"
		                            "whole: 0");
	}

	// Boolean values use YAML's true/false literals.
	{
		std::ostringstream oss;
		pcpp::YamlSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeField(pcpp::FieldDescriptor{ 2, "yes" }, true);
			obj.writeField(pcpp::FieldDescriptor{ 3, "no" }, false);
		}
		PTF_ASSERT_EQUAL(oss.str(), "yes: true\n"
		                            "no: false");
	}

	// Null values use YAML's null literal.
	{
		std::ostringstream oss;
		pcpp::YamlSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeNullField(pcpp::FieldDescriptor{ 2, "missing" });
		}
		PTF_ASSERT_EQUAL(oss.str(), "missing: null");
	}

	// Hex values are emitted using the shared 0x-prefixed lower-case format.
	{
		std::ostringstream oss;
		pcpp::YamlSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeHexField(pcpp::FieldDescriptor{ 2, "zero" }, 0);
			obj.writeHexField(pcpp::FieldDescriptor{ 3, "byte" }, 0xFF);
			obj.writeHexField(pcpp::FieldDescriptor{ 4, "big" }, 0xDEADBEEFULL);
		}
		PTF_ASSERT_EQUAL(oss.str(), "zero: 0x0\n"
		                            "byte: 0xff\n"
		                            "big: 0xdeadbeef");
	}

	// An array of scalar values. Field names are ignored inside arrays.
	{
		std::ostringstream oss;
		pcpp::YamlSerializer serializer(oss);
		{
			auto arr = serializer.writeArray(pcpp::FieldDescriptor{ 1, "root" });
			arr.writeField(pcpp::FieldDescriptor{ 2, "ignored" }, std::string("a"));
			arr.writeField(pcpp::FieldDescriptor{ 3, "ignored" }, std::string("b"));
			arr.writeField(pcpp::FieldDescriptor{ 4, "ignored" }, std::string("c"));
		}
		PTF_ASSERT_EQUAL(oss.str(), "- \"a\"\n"
		                            "- \"b\"\n"
		                            "- \"c\"");
	}

	// An array of different scalar types exercises the array prefix for every
	// scalar-writing path.
	{
		std::ostringstream oss;
		pcpp::YamlSerializer serializer(oss);
		{
			auto arr = serializer.writeArray(pcpp::FieldDescriptor{ 1, "root" });
			arr.writeField(pcpp::FieldDescriptor{ 2, "ignored" }, static_cast<int64_t>(-1));
			arr.writeField(pcpp::FieldDescriptor{ 3, "ignored" }, static_cast<uint64_t>(2));
			arr.writeField(pcpp::FieldDescriptor{ 4, "ignored" }, 3.5);
			arr.writeField(pcpp::FieldDescriptor{ 5, "ignored" }, true);
			arr.writeNullField(pcpp::FieldDescriptor{ 6, "ignored" });
			arr.writeHexField(pcpp::FieldDescriptor{ 7, "ignored" }, 0xFF);
		}
		PTF_ASSERT_EQUAL(oss.str(), "- -1\n"
		                            "- 2\n"
		                            "- 3.5\n"
		                            "- true\n"
		                            "- null\n"
		                            "- 0xff");
	}

	// An empty array nested inside an object.
	{
		std::ostringstream oss;
		pcpp::YamlSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			{
				auto arr = obj.writeArray(pcpp::FieldDescriptor{ 2, "items" });
			}
		}
		PTF_ASSERT_EQUAL(oss.str(), "items: []");
	}

	// A non-empty array nested inside an object.
	{
		std::ostringstream oss;
		pcpp::YamlSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			{
				auto arr = obj.writeArray(pcpp::FieldDescriptor{ 2, "items" });
				arr.writeField(pcpp::FieldDescriptor{ 3, "item" }, std::string("a"));
				arr.writeField(pcpp::FieldDescriptor{ 4, "item" }, std::string("b"));
			}
		}
		PTF_ASSERT_EQUAL(oss.str(), "items:\n"
		                            "  - \"a\"\n"
		                            "  - \"b\"");
	}

	// Nested object inside an object. The indentation level must be restored
	// when the nested object closes.
	{
		std::ostringstream oss;
		pcpp::YamlSerializer serializer(oss);
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
		PTF_ASSERT_EQUAL(oss.str(), "before: 1\n"
		                            "nested:\n"
		                            "  x: 2\n"
		                            "  y: 3\n"
		                            "after: 4");
	}

	// An array of objects. The special m_WriteIdent/m_WriteNewLine handling
	// makes each object begin on the same sequence-item line as its first field.
	{
		std::ostringstream oss;
		pcpp::YamlSerializer serializer(oss);
		{
			auto arr = serializer.writeArray(pcpp::FieldDescriptor{ 1, "root" });
			{
				auto item1 = arr.writeObject(pcpp::FieldDescriptor{ 2, "ignored" });
				item1.writeField(pcpp::FieldDescriptor{ 3, "id" }, static_cast<int64_t>(1));
				item1.writeField(pcpp::FieldDescriptor{ 4, "name" }, std::string("one"));
			}
			{
				auto item2 = arr.writeObject(pcpp::FieldDescriptor{ 5, "ignored" });
				item2.writeField(pcpp::FieldDescriptor{ 6, "id" }, static_cast<int64_t>(2));
				item2.writeField(pcpp::FieldDescriptor{ 7, "name" }, std::string("two"));
			}
		}
		PTF_ASSERT_EQUAL(oss.str(), "- id: 1\n"
		                            "  name: \"one\"\n"
		                            "- id: 2\n"
		                            "  name: \"two\"");
	}

	// Nested array inside an array. This exercises the EmptyArray -> Array
	// transition independently from scalar elements.
	{
		std::ostringstream oss;
		pcpp::YamlSerializer serializer(oss);
		{
			auto outer = serializer.writeArray(pcpp::FieldDescriptor{ 1, "root" });
			{
				auto inner = outer.writeArray(pcpp::FieldDescriptor{ 2, "ignored" });
				inner.writeField(pcpp::FieldDescriptor{ 3, "ignored" }, static_cast<int64_t>(1));
				inner.writeField(pcpp::FieldDescriptor{ 4, "ignored" }, static_cast<int64_t>(2));
			}
			outer.writeField(pcpp::FieldDescriptor{ 5, "ignored" }, static_cast<int64_t>(3));
		}
		PTF_ASSERT_EQUAL(oss.str(), "- \n"
		                            "  - 1\n"
		                            "  - 2\n"
		                            "- 3");
	}

	// Mixed object/array nesting exercises restoration of both indentation and
	// newline state after an array closes.
	{
		std::ostringstream oss;
		pcpp::YamlSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeField(pcpp::FieldDescriptor{ 2, "name" }, std::string("pkt"));
			{
				auto tags = obj.writeArray(pcpp::FieldDescriptor{ 3, "tags" });
				tags.writeField(pcpp::FieldDescriptor{ 4, "tag" }, std::string("a"));
				tags.writeField(pcpp::FieldDescriptor{ 5, "tag" }, std::string("b"));
			}
			obj.writeField(pcpp::FieldDescriptor{ 6, "after" }, static_cast<int64_t>(42));
		}
		PTF_ASSERT_EQUAL(oss.str(), "name: \"pkt\"\n"
		                            "tags:\n"
		                            "  - \"a\"\n"
		                            "  - \"b\"\n"
		                            "after: 42");
	}

	// Multiple root elements are not allowed.
	{
		std::ostringstream oss;
		pcpp::YamlSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			PTF_ASSERT_RAISES(serializer.writeArray(pcpp::FieldDescriptor{ 2, "anotherRoot" }), std::logic_error,
			                  "Only one root value may be written per instance");
			PTF_ASSERT_RAISES(serializer.writeObject(pcpp::FieldDescriptor{ 3, "anotherRoot" }), std::logic_error,
			                  "Only one root value may be written per instance");
		}
	}
	{
		std::ostringstream oss;
		pcpp::YamlSerializer serializer(oss);
		{
			auto arr = serializer.writeArray(pcpp::FieldDescriptor{ 1, "root" });
			PTF_ASSERT_RAISES(serializer.writeArray(pcpp::FieldDescriptor{ 2, "anotherRoot" }), std::logic_error,
			                  "Only one root value may be written per instance");
			PTF_ASSERT_RAISES(serializer.writeObject(pcpp::FieldDescriptor{ 3, "anotherRoot" }), std::logic_error,
			                  "Only one root value may be written per instance");
		}
	}
}  // YamlSerializerTest

PTF_TEST_CASE(XmlSerializerTest)
{
	// An empty object / empty array emits the XML declaration header followed by
	// a self-closing element with the root tag name.
	{
		std::ostringstream oss;
		pcpp::XmlSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
		}
		PTF_ASSERT_EQUAL(oss.str(),
		                 R"(<?xml version="1.0" encoding="UTF-8"?>
<root>
</root>
)");
	}
	{
		std::ostringstream oss;
		pcpp::XmlSerializer serializer(oss);
		{
			auto arr = serializer.writeArray(pcpp::FieldDescriptor{ 1, "root" });
		}
		PTF_ASSERT_EQUAL(oss.str(),
		                 R"(<?xml version="1.0" encoding="UTF-8"?>
<root>
</root>
)");
	}

	// A single string field inside an object: the key forms the tag name,
	// and the value is wrapped inside opening and closing tags.
	{
		std::ostringstream oss;
		pcpp::XmlSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeField(pcpp::FieldDescriptor{ 2, "name" }, std::string("value"));
		}
		PTF_ASSERT_EQUAL(oss.str(),
		                 R"(<?xml version="1.0" encoding="UTF-8"?>
<root>
  <name>value</name>
</root>
)");
	}

	// String VALUE escaping: XML special characters ('&', '<', '>', '"', '\'')
	// are escaped into entity references (&amp;, &lt;, &gt;, &quot;, &apos;).
	{
		std::ostringstream oss;
		pcpp::XmlSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeField(pcpp::FieldDescriptor{ 2, "value" }, std::string("a&b<c>d\"e'f"));
		}
		PTF_ASSERT_EQUAL(oss.str(),
		                 R"(<?xml version="1.0" encoding="UTF-8"?>
<root>
  <value>a&amp;b&lt;c&gt;d&quot;e&apos;f</value>
</root>
)");
	}

	// Field NAME normalization / escaping: element tag names sanitize
	// invalid XML tag characters or convert them to valid identifiers.
	{
		std::ostringstream oss;
		pcpp::XmlSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeField(pcpp::FieldDescriptor{ 2, "weird_name_here" }, std::string("ok"));
		}
		PTF_ASSERT_EQUAL(oss.str(),
		                 R"(<?xml version="1.0" encoding="UTF-8"?>
<root>
  <weird_name_here>ok</weird_name_here>
</root>
)");
	}

	// Non-ASCII / UTF-8 characters pass through verbatim into text nodes.
	{
		std::ostringstream oss;
		pcpp::XmlSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeField(pcpp::FieldDescriptor{ 2, "field" }, std::string("h\xc3\xa9llo/w\xc3\xb6rld"));
		}
		PTF_ASSERT_EQUAL(
		    oss.str(),
		    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<root>\n  <field>h\xc3\xa9llo/w\xc3\xb6rld</field>\n</root>\n");
	}

	// An empty string value emits a self-closing child element.
	{
		std::ostringstream oss;
		pcpp::XmlSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeField(pcpp::FieldDescriptor{ 2, "empty" }, std::string(""));
		}
		PTF_ASSERT_EQUAL(oss.str(),
		                 R"(<?xml version="1.0" encoding="UTF-8"?>
<root>
  <empty/>
</root>
)");
	}

	// writeField(const char*) forwards to the std::string overload, so a
	// C-string value is escaped in text nodes the same way.
	{
		std::ostringstream oss;
		pcpp::XmlSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeField(pcpp::FieldDescriptor{ 2, "greeting" }, "hi & <there>");
		}
		PTF_ASSERT_EQUAL(oss.str(),
		                 R"(<?xml version="1.0" encoding="UTF-8"?>
<root>
  <greeting>hi &amp; &lt;there&gt;</greeting>
</root>
)");
	}

	// Multiple sibling fields in an object: consecutive child elements
	// are appended sequentially within the container tag.
	{
		std::ostringstream oss;
		pcpp::XmlSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeField(pcpp::FieldDescriptor{ 2, "a" }, static_cast<int64_t>(1));
			obj.writeField(pcpp::FieldDescriptor{ 3, "b" }, std::string("x"));
			obj.writeField(pcpp::FieldDescriptor{ 4, "c" }, true);
		}
		PTF_ASSERT_EQUAL(oss.str(),
		                 R"(<?xml version="1.0" encoding="UTF-8"?>
<root>
  <a>1</a>
  <b>x</b>
  <c>true</c>
</root>
)");
	}

	// Array elements repeat child elements under the parent wrapper.
	{
		std::ostringstream oss;
		pcpp::XmlSerializer serializer(oss);
		{
			auto arr = serializer.writeArray(pcpp::FieldDescriptor{ 1, "items" });
			arr.writeField(pcpp::FieldDescriptor{ 2, "item" }, std::string("a"));
			arr.writeField(pcpp::FieldDescriptor{ 3, "item" }, std::string("b"));
			arr.writeField(pcpp::FieldDescriptor{ 4, "item" }, std::string("c"));
		}
		PTF_ASSERT_EQUAL(oss.str(),
		                 R"(<?xml version="1.0" encoding="UTF-8"?>
<items>
  <item>a</item>
  <item>b</item>
  <item>c</item>
</items>
)");
	}

	// Array with null elements
	{
		std::ostringstream oss;
		pcpp::XmlSerializer serializer(oss);
		{
			auto arr = serializer.writeArray(pcpp::FieldDescriptor{ 1, "array" });
			arr.writeNullField(pcpp::FieldDescriptor{ 2, "element" });
		}
		PTF_ASSERT_EQUAL(oss.str(),
		                 R"(<?xml version="1.0" encoding="UTF-8"?>
<array>
  <element xsi:nil="true"/>
</array>
)");
	}

	// Nested object inside an object: creates nested XML tags cleanly and
	// closes tags in LIFO scope order.
	{
		std::ostringstream oss;
		pcpp::XmlSerializer serializer(oss);
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
		PTF_ASSERT_EQUAL(oss.str(),
		                 R"(<?xml version="1.0" encoding="UTF-8"?>
<root>
  <before>1</before>
  <nested>
    <x>2</x>
    <y>3</y>
  </nested>
  <after>4</after>
</root>
)");
	}

	// Array of objects: array elements containing nested objects render
	// repeated child tags.
	{
		std::ostringstream oss;
		pcpp::XmlSerializer serializer(oss);
		{
			auto arr = serializer.writeArray(pcpp::FieldDescriptor{ 1, "root" });
			{
				auto item1 = arr.writeObject(pcpp::FieldDescriptor{ 2, "item" });
				item1.writeField(pcpp::FieldDescriptor{ 3, "id" }, static_cast<int64_t>(1));
			}
			{
				auto item2 = arr.writeObject(pcpp::FieldDescriptor{ 4, "item" });
				item2.writeField(pcpp::FieldDescriptor{ 5, "id" }, static_cast<int64_t>(2));
			}
		}
		PTF_ASSERT_EQUAL(oss.str(),
		                 R"(<?xml version="1.0" encoding="UTF-8"?>
<root>
  <item>
    <id>1</id>
  </item>
  <item>
    <id>2</id>
  </item>
</root>
)");
	}

	// Object containing an array-valued field: verifies context management
	// across mixed object/array nesting.
	{
		std::ostringstream oss;
		pcpp::XmlSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeField(pcpp::FieldDescriptor{ 2, "name" }, std::string("pkt"));
			{
				auto tags = obj.writeArray(pcpp::FieldDescriptor{ 3, "tags" });
				tags.writeField(pcpp::FieldDescriptor{ 4, "t" }, std::string("a"));
				tags.writeField(pcpp::FieldDescriptor{ 5, "t" }, std::string("b"));
			}
		}
		PTF_ASSERT_EQUAL(oss.str(),
		                 R"(<?xml version="1.0" encoding="UTF-8"?>
<root>
  <name>pkt</name>
  <tags>
    <t>a</t>
    <t>b</t>
  </tags>
</root>
)");
	}

	// Signed integer fields: negative, zero, positive, plus a narrower
	// signed width funneled into the int64_t overload.
	{
		std::ostringstream oss;
		pcpp::XmlSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeField(pcpp::FieldDescriptor{ 2, "neg" }, static_cast<int64_t>(-42));
			obj.writeField(pcpp::FieldDescriptor{ 3, "zero" }, static_cast<int64_t>(0));
			obj.writeField(pcpp::FieldDescriptor{ 4, "pos" }, static_cast<int64_t>(42));
			obj.writeField(pcpp::FieldDescriptor{ 5, "shortNeg" }, static_cast<int16_t>(-7));
		}
		PTF_ASSERT_EQUAL(oss.str(),
		                 R"(<?xml version="1.0" encoding="UTF-8"?>
<root>
  <neg>-42</neg>
  <zero>0</zero>
  <pos>42</pos>
  <shortNeg>-7</shortNeg>
</root>
)");
	}

	// Unsigned integer fields: zero, small, and 64-bit maximum values are
	// serialized directly into element text content.
	{
		std::ostringstream oss;
		pcpp::XmlSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeField(pcpp::FieldDescriptor{ 2, "zero" }, static_cast<uint64_t>(0));
			obj.writeField(pcpp::FieldDescriptor{ 3, "small" }, static_cast<uint32_t>(65535));
			obj.writeField(pcpp::FieldDescriptor{ 4, "max" }, std::numeric_limits<uint64_t>::max());
		}
		PTF_ASSERT_EQUAL(oss.str(),
		                 R"(<?xml version="1.0" encoding="UTF-8"?>
<root>
  <zero>0</zero>
  <small>65535</small>
  <max>18446744073709551615</max>
</root>
)");
	}

	// Double fields use standard floating-point text formatting.
	{
		std::ostringstream oss;
		pcpp::XmlSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeField(pcpp::FieldDescriptor{ 2, "frac" }, 3.5);
			obj.writeField(pcpp::FieldDescriptor{ 3, "neg" }, -2.25);
			obj.writeField(pcpp::FieldDescriptor{ 4, "whole" }, 0.0);
		}
		PTF_ASSERT_EQUAL(oss.str(),
		                 R"(<?xml version="1.0" encoding="UTF-8"?>
<root>
  <frac>3.5</frac>
  <neg>-2.25</neg>
  <whole>0</whole>
</root>
)");
	}

	// Bool fields write literal `true`/`false` text inside elements.
	{
		std::ostringstream oss;
		pcpp::XmlSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeField(pcpp::FieldDescriptor{ 2, "yes" }, true);
			obj.writeField(pcpp::FieldDescriptor{ 3, "no" }, false);
		}
		PTF_ASSERT_EQUAL(oss.str(),
		                 R"(<?xml version="1.0" encoding="UTF-8"?>
<root>
  <yes>true</yes>
  <no>false</no>
</root>
)");
	}

	// Null fields emit self-closing elements.
	{
		std::ostringstream oss;
		pcpp::XmlSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeNullField(pcpp::FieldDescriptor{ 2, "missing" });
		}
		PTF_ASSERT_EQUAL(oss.str(),
		                 R"(<?xml version="1.0" encoding="UTF-8"?>
<root>
  <missing xsi:nil="true"/>
</root>
)");
	}

	// Hex fields are always written as a "0x..."-prefixed string inside text elements.
	{
		std::ostringstream oss;
		pcpp::XmlSerializer serializer(oss);
		{
			auto obj = serializer.writeObject(pcpp::FieldDescriptor{ 1, "root" });
			obj.writeHexField(pcpp::FieldDescriptor{ 2, "zero" }, static_cast<uint64_t>(0));
			obj.writeHexField(pcpp::FieldDescriptor{ 3, "byte" }, 0xFF);
			obj.writeHexField(pcpp::FieldDescriptor{ 4, "big" }, static_cast<uint64_t>(0xDEADBEEFULL));
		}
		PTF_ASSERT_EQUAL(oss.str(),
		                 R"(<?xml version="1.0" encoding="UTF-8"?>
<root>
  <zero>0x0</zero>
  <byte>0xff</byte>
  <big>0xdeadbeef</big>
</root>
)");
	}

	// Multiple root elements are not allowed
	{
		std::ostringstream oss;
		pcpp::XmlSerializer serializer(oss);
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
		pcpp::XmlSerializer serializer(oss);
		{
			auto arr = serializer.writeArray(pcpp::FieldDescriptor{ 1, "root" });
			PTF_ASSERT_RAISES(serializer.writeArray(pcpp::FieldDescriptor{ 1, "anotherRoot" }), std::logic_error,
			                  "Only one root value may be written per instance");
			PTF_ASSERT_RAISES(serializer.writeObject(pcpp::FieldDescriptor{ 1, "anotherRoot" }), std::logic_error,
			                  "Only one root value may be written per instance");
		}
	}
}  // XmlSerializerTest
