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

	void ISerializer::enforceOneRoot()
	{
		if (!m_ShouldEnforceOneRoot)
		{
			return;
		}

		if (m_RootWritten)
		{
			throw std::logic_error("Only one root value may be written per instance");
		}

		m_RootWritten = true;
	}

	ArrayScope ISerializer::writeArray(const FieldDescriptor& field)
	{
		enforceOneRoot();
		return { this, field };
	}

	ObjectScope ISerializer::writeObject(const FieldDescriptor& field)
	{
		enforceOneRoot();
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
}  // namespace pcpp
