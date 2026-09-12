#include "Serializers.h"

#include <iomanip>
#include <ostream>
#include <sstream>
#include "json.hpp"

namespace pcpp
{
	namespace
	{
		// JS Number.MAX_SAFE_INTEGER == 2^53 - 1. Above this, a JSON number
		// literal can silently lose precision in JS-based parsers. Shared
		// by JsonSerializer and JsonSerializer2's uint64_t handling.
		constexpr uint64_t kMaxSafeJsonInteger = 9007199254740991ULL;

		void hexNumToStream(std::ostream& out, uint64_t number)
		{
			const std::ios_base::fmtflags flags = out.flags();
			out << "0x" << std::hex << number;
			out.flags(flags);
		}

		std::string hexNumToString(uint64_t number)
		{
			std::ostringstream oss;
			hexNumToStream(oss, number);
			return oss.str();
		}

		// Backslash-escapes a string for embedding in a double-quoted JSON
		// or YAML scalar — both formats use the same escape set for the
		// characters we care about here. Shared by JsonSerializer and
		// YamlSerializer.
		std::string escapeQuotedString(const std::string& s)
		{
			std::ostringstream oss;
			for (char c : s)
			{
				switch (c)
				{
				case '"':
					oss << "\\\"";
					break;
				case '\\':
					oss << "\\\\";
					break;
				case '\n':
					oss << "\\n";
					break;
				case '\t':
					oss << "\\t";
					break;
				default:
					oss << c;
				}
			}
			return oss.str();
		}
	}  // namespace

	// ============================================================
	// ISerializer
	// ============================================================

	ArrayScope ISerializer::writeArray(const FieldDescriptor& field)
	{
		return { this, field };
	}

	ObjectScope ISerializer::writeObject(const FieldDescriptor& field)
	{
		return { this, field };
	}

	// ============================================================
	// ScopeBase
	// ============================================================

	void ScopeBase::writeField(const FieldDescriptor& field, const std::string& value)
	{
		m_Serializer->writeField(field, value);
	}

	void ScopeBase::writeField(const FieldDescriptor& field, int64_t value)
	{
		m_Serializer->writeField(field, value);
	}

	void ScopeBase::writeField(const FieldDescriptor& field, uint64_t value)
	{
		m_Serializer->writeField(field, value);
	}

	void ScopeBase::writeField(const FieldDescriptor& field, double value)
	{
		m_Serializer->writeField(field, value);
	}

	void ScopeBase::writeField(const FieldDescriptor& field, bool value)
	{
		m_Serializer->writeField(field, value);
	}

	void ScopeBase::writeNullField(const FieldDescriptor& field)
	{
		m_Serializer->writeNullField(field);
	}

	void ScopeBase::writeHexField(const FieldDescriptor& field, uint64_t value)
	{
		m_Serializer->writeHexField(field, value);
	}

	void ScopeBase::startObject(const FieldDescriptor& field)
	{
		m_Serializer->startObject(field);
	}

	void ScopeBase::endObject()
	{
		m_Serializer->endObject();
	}

	void ScopeBase::startArray(const FieldDescriptor& field)
	{
		m_Serializer->startArray(field);
	}

	void ScopeBase::endArray()
	{
		m_Serializer->endArray();
	}

	// ============================================================
	// ArrayScope
	// ============================================================

	ArrayScope::ArrayScope(ISerializer* serializer, const FieldDescriptor& field) : ScopeBase(serializer)
	{
		m_Serializer->startArray(field);
	}

	ArrayScope::~ArrayScope()
	{
		m_Serializer->endArray();
	}

	// ============================================================
	// ObjectScope
	// ============================================================

	ObjectScope::ObjectScope(ISerializer* serializer, const FieldDescriptor& field) : ScopeBase(serializer)
	{
		m_Serializer->startObject(field);
	}

	ObjectScope::~ObjectScope()
	{
		m_Serializer->endObject();
	}

	// ============================================================
	// JsonSerializer
	// ============================================================

	JsonSerializer::JsonSerializer(std::ostream& out) : m_Out(out)
	{}

	void JsonSerializer::startObject(const FieldDescriptor& field)
	{
		writeKey(field.name);
		m_Out << '{';
		m_ContextStack.push_back(Context::Object);
		m_FirstAtLevel.push_back(true);
	}

	void JsonSerializer::endObject()
	{
		m_Out << '}';
		m_ContextStack.pop_back();
		m_FirstAtLevel.pop_back();
	}

	void JsonSerializer::startArray(const FieldDescriptor& field)
	{
		writeKey(field.name);
		m_Out << '[';
		m_ContextStack.push_back(Context::Array);
		m_FirstAtLevel.push_back(true);
	}

	void JsonSerializer::endArray()
	{
		m_Out << ']';
		m_ContextStack.pop_back();
		m_FirstAtLevel.pop_back();
	}

	void JsonSerializer::writeField(const FieldDescriptor& field, const std::string& value)
	{
		writeKey(field.name);
		m_Out << '"' << escapeQuotedString(value) << '"';
	}

	void JsonSerializer::writeField(const FieldDescriptor& field, int64_t value)
	{
		writeKey(field.name);
		m_Out << value;
	}

	void JsonSerializer::writeField(const FieldDescriptor& field, uint64_t value)
	{
		writeKey(field.name);
		// Only quote when the value could actually lose precision in a
		// JS-based JSON parser — not unconditionally for every uint64_t
		// caller, since narrower widths (uint8_t/16_t/32_t) also arrive
		// here via the canonical virtual and shouldn't be quoted needlessly.
		if (value > kMaxSafeJsonInteger)
			m_Out << '"' << value << '"';
		else
			m_Out << value;
	}

	void JsonSerializer::writeField(const FieldDescriptor& field, double value)
	{
		writeKey(field.name);
		m_Out << value;
	}

	void JsonSerializer::writeField(const FieldDescriptor& field, bool value)
	{
		writeKey(field.name);
		m_Out << (value ? "true" : "false");
	}

	void JsonSerializer::writeNullField(const FieldDescriptor& field)
	{
		writeKey(field.name);
		m_Out << "null";
	}

	void JsonSerializer::writeHexField(const FieldDescriptor& field, uint64_t value)
	{
		writeKey(field.name);
		m_Out << '"' << hexNumToString(value) << '"';
	}

	void JsonSerializer::writeSeparatorIfNeeded()
	{
		if (m_FirstAtLevel.empty())
			return;
		if (!m_FirstAtLevel.back())
			m_Out << ',';
		m_FirstAtLevel.back() = false;
	}

	void JsonSerializer::writeKey(const std::string& name)
	{
		writeSeparatorIfNeeded();
		if (m_ContextStack.empty())
			return;
		if (m_ContextStack.back() == Context::Array)
			return;
		m_Out << '"' << escapeQuotedString(name) << "\":";
	}

	// ============================================================
	// JsonSerializer2
	// ============================================================

	struct JsonSerializer2::Impl
	{
		struct Frame
		{
			// The key this container will be assigned under in ITS parent
			// once it closes (ignored if the parent turns out to be an
			// array — array elements are unnamed).
			std::string name;
			nlohmann::json value;
		};

		explicit Impl(std::ostream& outStream) : out(outStream)
		{}

		template <typename T> void assign(const std::string& name, T&& value)
		{
			if (stack.empty())
				return;  // scalar field written with nothing open — caller bug
			assignInto(stack.back().value, name, nlohmann::json(std::forward<T>(value)));
		}

		static void assignInto(nlohmann::json& container, const std::string& name, nlohmann::json value)
		{
			if (container.is_array())
				container.push_back(std::move(value));
			else
				container[name] = std::move(value);
		}

		void popContainer()
		{
			if (stack.empty())
				return;  // unbalanced end*() call — caller bug

			Frame finished = std::move(stack.back());
			stack.pop_back();

			if (stack.empty())
			{
				// outermost container just closed — one complete JSON
				// value (e.g. one packet, in per-packet NDJSON usage).
				// error_handler_t::replace avoids dump()'s default
				// behavior of THROWING on invalid UTF-8 (common in raw
				// packet payload bytes carried as string fields) —
				// replaces invalid sequences with U+FFFD instead. Default
				// (throwing) behavior turns any packet with binary
				// payload data into an exception on every export, which
				// is catastrophically slower than the normal path if
				// caught, or a hard crash if not.
				out << finished.value.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
				return;
			}

			assignInto(stack.back().value, finished.name, std::move(finished.value));
		}

		std::ostream& out;
		std::vector<Frame> stack;
	};

	JsonSerializer2::JsonSerializer2(std::ostream& out) : m_Impl(new Impl(out))
	{}
	JsonSerializer2::~JsonSerializer2() = default;

	void JsonSerializer2::startObject(const FieldDescriptor& field)
	{
		m_Impl->stack.push_back(Impl::Frame{ field.name, nlohmann::json::object() });
	}

	void JsonSerializer2::endObject()
	{
		m_Impl->popContainer();
	}

	void JsonSerializer2::startArray(const FieldDescriptor& field)
	{
		m_Impl->stack.push_back(Impl::Frame{ field.name, nlohmann::json::array() });
	}

	void JsonSerializer2::endArray()
	{
		m_Impl->popContainer();
	}

	void JsonSerializer2::writeField(const FieldDescriptor& field, const std::string& value)
	{
		m_Impl->assign(field.name, value);
	}

	void JsonSerializer2::writeField(const FieldDescriptor& field, int64_t value)
	{
		m_Impl->assign(field.name, value);
	}

	void JsonSerializer2::writeField(const FieldDescriptor& field, uint64_t value)
	{
		if (value > kMaxSafeJsonInteger)
			m_Impl->assign(field.name, std::to_string(value));
		else
			m_Impl->assign(field.name, value);
	}

	void JsonSerializer2::writeField(const FieldDescriptor& field, double value)
	{
		m_Impl->assign(field.name, value);
	}

	void JsonSerializer2::writeField(const FieldDescriptor& field, bool value)
	{
		m_Impl->assign(field.name, value);
	}

	void JsonSerializer2::writeNullField(const FieldDescriptor& field)
	{
		m_Impl->assign(field.name, nullptr);
	}

	void JsonSerializer2::writeHexField(const FieldDescriptor& field, uint64_t value)
	{
		m_Impl->assign(field.name, hexNumToString(value));
	}

	// ============================================================
	// YamlSerializer
	// ============================================================

	YamlSerializer::YamlSerializer(std::ostream& out) : m_Out(out)
	{}

	void YamlSerializer::writeIndent()
	{
		if (!m_WriteIdent)
		{
			m_WriteIdent = true;
			return;
		}
		// The outermost/root container contributes no visual indent (it
		// has no "-"/"key:" wrapper of its own to be nested under) — only
		// containers pushed while the stack was already non-empty do.
		size_t depth = m_ContextStack.empty() ? 0 : m_ContextStack.size() - 1;
		m_Out << std::string(depth * 2, ' ');
	}

	void YamlSerializer::writeNewlineIfNeeded()
	{
		if (m_WriteNewLine)
			m_Out << '\n';
		m_WriteNewLine = true;
	}

	void YamlSerializer::writeContainerHeader(const std::string& name)
	{
		if (m_ContextStack.empty())
			return;  // document root: nothing visible to write at all — writing
			         // indent(0)/newline here would leave a spurious leading blank line
		writeNewlineIfNeeded();
		writeIndent();
		if (isArrayContext())
		{
			m_Out << "- ";
			if (m_ContextStack.back() == Context::EmptyArray)
			{
				m_ContextStack.back() = Context::Array;
			}
		}
		else
			m_Out << name << ':';
	}

	void YamlSerializer::writeFieldPrefix(const std::string& name)
	{
		writeNewlineIfNeeded();
		writeIndent();
		if (isArrayContext())
		{
			m_Out << "- ";
			if (m_ContextStack.back() == Context::EmptyArray)
			{
				m_ContextStack.back() = Context::Array;
			}
			return;
		}
		m_Out << name << ": ";  // also covers the (degenerate) root-scalar case
	}

	void YamlSerializer::startObject(const FieldDescriptor& field)
	{
		writeContainerHeader(field.name);
		if (isArrayContext())
		{
			m_WriteIdent = false;
			m_WriteNewLine = false;
		}
		m_ContextStack.push_back(Context::Object);
	}

	void YamlSerializer::endObject()
	{
		m_ContextStack.pop_back();
	}

	void YamlSerializer::startArray(const FieldDescriptor& field)
	{
		writeContainerHeader(field.name);
		m_ContextStack.push_back(Context::EmptyArray);
	}

	void YamlSerializer::endArray()
	{
		if (m_ContextStack.back() == Context::EmptyArray)
		{
			m_Out << " []";
		}
		m_ContextStack.pop_back();
	}

	void YamlSerializer::writeField(const FieldDescriptor& field, const std::string& value)
	{
		writeFieldPrefix(field.name);
		m_Out << '"' << escapeQuotedString(value) << '"';
	}

	void YamlSerializer::writeField(const FieldDescriptor& field, int64_t value)
	{
		writeFieldPrefix(field.name);
		m_Out << value;
	}

	void YamlSerializer::writeField(const FieldDescriptor& field, uint64_t value)
	{
		writeFieldPrefix(field.name);
		// Same reasoning as JsonSerializer: only quote when the value
		// could actually lose precision in a JS-based consumer (many YAML
		// tools, e.g. js-yaml, are JS-based) — not unconditionally.
		if (value > kMaxSafeJsonInteger)
			m_Out << '"' << value << '"';
		else
			m_Out << value;
	}

	void YamlSerializer::writeField(const FieldDescriptor& field, double value)
	{
		writeFieldPrefix(field.name);
		m_Out << value;
	}

	void YamlSerializer::writeField(const FieldDescriptor& field, bool value)
	{
		writeFieldPrefix(field.name);
		m_Out << (value ? "true" : "false");
	}

	void YamlSerializer::writeNullField(const FieldDescriptor& field)
	{
		writeFieldPrefix(field.name);
		m_Out << "null";
	}

	void YamlSerializer::writeHexField(const FieldDescriptor& field, uint64_t value)
	{
		writeFieldPrefix(field.name);
		hexNumToStream(m_Out, value);
	}

	bool YamlSerializer::isArrayContext() const
	{
		return !m_ContextStack.empty() &&
		       (m_ContextStack.back() == Context::EmptyArray || m_ContextStack.back() == Context::Array);
	}

	// ============================================================
	// XmlSerializer
	// ============================================================

	namespace
	{
		bool isXmlControlChar(char c)
		{
			return (c >= 0x00 && c <= 0x1F) && c != '\t' && c != '\n' && c != '\r';
		}
	}  // namespace

	XmlSerializer::XmlSerializer(std::ostream& out, bool prettyPrint, const std::string& indentStr)
	    : m_Out(out), m_PrettyPrint(prettyPrint), m_IndentStr(indentStr)
	{
		// Write XML declaration
		m_Out << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
	}

	void XmlSerializer::startObject(const FieldDescriptor& field)
	{
		Context ctx;
		ctx.name = resolveElementName(field.name, "object");
		ctx.isArray = false;

		writeIndent();
		writeOpenTag(ctx.name);
		m_ContextStack.push_back(ctx);
	}

	void XmlSerializer::endObject()
	{
		if (m_ContextStack.empty())
			return;  // Unbalanced call - ignore

		Context ctx = m_ContextStack.back();
		m_ContextStack.pop_back();

		writeIndent();
		writeCloseTag(ctx.name);

		if (m_ContextStack.empty())
		{
			// Root object closed - all done
			m_Out << "\n";
		}
	}

	void XmlSerializer::startArray(const FieldDescriptor& field)
	{
		Context ctx;
		ctx.name = resolveElementName(field.name, "array");
		ctx.isArray = true;

		writeIndent();
		writeOpenTag(ctx.name);
		m_ContextStack.push_back(ctx);
	}

	void XmlSerializer::endArray()
	{
		if (m_ContextStack.empty())
			return;

		Context ctx = m_ContextStack.back();
		m_ContextStack.pop_back();

		writeIndent();
		writeCloseTag(ctx.name);
	}

	void XmlSerializer::writeField(const FieldDescriptor& field, const std::string& value)
	{
		writeValueElement(resolveElementName(field.name, "field"), escapeXML(value), false);
	}

	void XmlSerializer::writeField(const FieldDescriptor& field, int64_t value)
	{
		writeValueElement(resolveElementName(field.name, "field"), std::to_string(value), false);
	}

	void XmlSerializer::writeField(const FieldDescriptor& field, uint64_t value)
	{
		writeValueElement(resolveElementName(field.name, "field"), std::to_string(value), false);
	}

	void XmlSerializer::writeField(const FieldDescriptor& field, double value)
	{
		std::string strVal = std::to_string(value);
		// Remove trailing zeros for cleaner output (and the decimal point
		// itself if nothing remains after it). find_last_not_of('0') lands
		// on the last significant digit — e.g. for "1.500000" that's the
		// '5', not the '.' — so we must erase everything AFTER it, not
		// just the "whole fraction is zero" case where it happens to land
		// on the decimal point.
		size_t pos = strVal.find_last_not_of('0');
		if (pos != std::string::npos)
		{
			if (strVal[pos] == '.')
				--pos;
			strVal.erase(pos + 1);
		}
		writeValueElement(resolveElementName(field.name, "field"), strVal, false);
	}

	void XmlSerializer::writeField(const FieldDescriptor& field, bool value)
	{
		writeValueElement(resolveElementName(field.name, "field"), value ? "true" : "false", false);
	}

	void XmlSerializer::writeNullField(const FieldDescriptor& field)
	{
		// Create an empty element with xsi:nil attribute to represent null
		if (!m_ContextStack.empty() && m_ContextStack.back().isArray)
		{
			// In an array: <item xsi:nil="true"/>
			writeIndent();
			m_Out << "<item xsi:nil=\"true\"/>\n";
		}
		else
		{
			writeValueElement(resolveElementName(field.name, "field"), "", true);
		}
	}

	void XmlSerializer::writeHexField(const FieldDescriptor& field, uint64_t value)
	{
		writeValueElement(resolveElementName(field.name, "field"), hexNumToString(value), false);
	}

	// --- Private helper methods ---

	void XmlSerializer::writeOpenTag(const std::string& name)
	{
		m_Out << '<' << name << '>';
		if (m_PrettyPrint)
		{
			m_Out << '\n';
		}
	}

	void XmlSerializer::writeCloseTag(const std::string& name)
	{
		m_Out << "</" << name << '>';
		if (m_PrettyPrint)
		{
			m_Out << '\n';
		}
	}

	void XmlSerializer::writeValueElement(const std::string& name, const std::string& value, bool isNull)
	{
		writeIndent();
		m_Out << '<' << name;

		if (isNull)
		{
			m_Out << " xsi:nil=\"true\"";
		}

		if (value.empty() && !isNull)
		{
			// Empty value - self-closing tag
			m_Out << "/>\n";
		}
		else
		{
			m_Out << '>' << value << "</" << name << ">\n";
		}
	}

	void XmlSerializer::writeIndent()
	{
		if (!m_PrettyPrint || m_ContextStack.empty())
			return;

		size_t depth = m_ContextStack.size();
		// Cache indentation strings for performance
		if (m_IndentCache.size() <= depth)
		{
			m_IndentCache.resize(depth + 1);
			std::string indent;
			for (size_t i = 0; i < depth; ++i)
			{
				indent += m_IndentStr;
			}
			m_IndentCache[depth] = indent;
		}
		m_Out << m_IndentCache[depth];
	}

	std::string XmlSerializer::escapeXML(const std::string& s)
	{
		std::string result;
		result.reserve(s.size() + s.size() / 5);  // Pre-allocate for typical ~20% expansion

		for (char c : s)
		{
			// Filter out invalid XML control characters
			if (isXmlControlChar(c))
				continue;

			switch (c)
			{
			case '&':
				result += "&amp;";
				break;
			case '<':
				result += "&lt;";
				break;
			case '>':
				result += "&gt;";
				break;
			case '"':
				result += "&quot;";
				break;
			case '\'':
				result += "&apos;";
				break;
			default:
				result += c;
				break;
			}
		}
		return result;
	}

	bool XmlSerializer::isValidXMLName(const std::string& name)
	{
		if (name.empty())
			return false;

		// XML names must start with a letter or underscore
		char first = name[0];
		if (!((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') || first == '_' || first == ':'))
		{
			return false;
		}

		// Subsequent characters can be letters, digits, or certain punctuation
		for (size_t i = 1; i < name.length(); ++i)
		{
			char c = name[i];
			if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' ||
			      c == '.' || c == ':'))
			{
				return false;
			}
		}
		return true;
	}

	std::string XmlSerializer::resolveElementName(const std::string& name, const char* fallback)
	{
		return isValidXMLName(name) ? name : std::string(fallback);
	}
}  // namespace pcpp
