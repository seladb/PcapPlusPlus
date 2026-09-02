#include "Serializers.h"

#include <iomanip>
#include <limits>
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

		/// RAII guard that saves an ostream's format flags and fill
		/// character on construction and restores them on destruction —
		/// including on exception unwinding. Needed because std::hex/
		/// std::setfill are "sticky": unlike std::setw (which resets
		/// itself after one formatted output), they persist on the stream
		/// until explicitly changed again. Without this guard, a
		/// hex-formatting write can leave e.g. setfill('0') active,
		/// silently corrupting the padding of any *unrelated* later write
		/// on the same stream.
		class StreamStateGuard
		{
		public:
			explicit StreamStateGuard(std::ostream& out) : m_Out(out), m_Flags(out.flags()), m_Fill(out.fill()) {}
			~StreamStateGuard()
			{
				m_Out.flags(m_Flags);
				m_Out.fill(m_Fill);
			}
			StreamStateGuard(const StreamStateGuard&) = delete;
			StreamStateGuard& operator=(const StreamStateGuard&) = delete;

		private:
			std::ostream& m_Out;
			std::ios_base::fmtflags m_Flags;
			char m_Fill;
		};

		/// Formats `value` as "0x" followed by `widthBytes * 2` zero-padded
		/// lowercase hex digits, masking off any bits beyond widthBytes.
		/// Used by JsonSerializer2, which needs an actual std::string to
		/// hand to nlohmann::json — JsonSerializer itself writes hex
		/// directly to its ostream instead (see JsonSerializer::writeHexField).
		std::string formatHex(uint64_t value, int widthBytes)
		{
			const uint64_t mask =
			    (widthBytes >= 8) ? std::numeric_limits<uint64_t>::max() : ((uint64_t(1) << (widthBytes * 8)) - 1);
			std::ostringstream oss;
			oss << "0x" << std::hex << std::nouppercase << std::setfill('0') << std::setw(widthBytes * 2)
			    << (value & mask);
			return oss.str();
		}

	}  // namespace

	// ============================================================
	// JsonSerializer
	// ============================================================

	JsonSerializer::JsonSerializer(std::ostream& out) : m_Out(out) {}

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
		m_Out << '"' << escape(value) << '"';
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

	void JsonSerializer::writeHexField(const FieldDescriptor& field, uint64_t value, int widthBytes)
	{
		writeKey(field.name);
		// Writes directly to m_Out (no intermediate std::string) — safe
		// only because StreamStateGuard restores m_Out's flags/fill on
		// scope exit, so std::hex/setfill('0') here can never leak into
		// later, unrelated writes on the same stream.
		const uint64_t mask =
		    (widthBytes >= 8) ? std::numeric_limits<uint64_t>::max() : ((uint64_t(1) << (widthBytes * 8)) - 1);
		{
			StreamStateGuard guard(m_Out);
			m_Out << '"' << "0x" << std::hex << std::nouppercase << std::setfill('0') << std::setw(widthBytes * 2)
			      << (value & mask) << '"';
		}
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
		m_Out << '"' << escape(name) << "\":";
	}

	std::string JsonSerializer::escape(const std::string& s)
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

		explicit Impl(std::ostream& outStream) : out(outStream) {}

		template <typename T>
		void assign(const std::string& name, T&& value)
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

	JsonSerializer2::JsonSerializer2(std::ostream& out) : m_Impl(new Impl(out)) {}
	JsonSerializer2::~JsonSerializer2() = default;

	void JsonSerializer2::startObject(const FieldDescriptor& field)
	{
		m_Impl->stack.push_back(Impl::Frame{ field.name, nlohmann::json::object() });
	}

	void JsonSerializer2::endObject() { m_Impl->popContainer(); }

	void JsonSerializer2::startArray(const FieldDescriptor& field)
	{
		m_Impl->stack.push_back(Impl::Frame{ field.name, nlohmann::json::array() });
	}

	void JsonSerializer2::endArray() { m_Impl->popContainer(); }

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

	void JsonSerializer2::writeNullField(const FieldDescriptor& field) { m_Impl->assign(field.name, nullptr); }

	void JsonSerializer2::writeHexField(const FieldDescriptor& field, uint64_t value, int widthBytes)
	{
		m_Impl->assign(field.name, formatHex(value, widthBytes));
	}

}  // namespace pcpp
