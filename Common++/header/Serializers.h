#pragma once

#include <cstdint>
#include <iosfwd>  // std::ostream forward declaration only — <ostream> is a Serializers.cpp concern
#include <memory>
#include <string>
#include <type_traits>
#include <vector>

namespace pcpp
{
	/// @class ISerializer
	/// Abstract interface for serializing structured data into a
	/// machine-readable format (JSON, YAML, XML, ...). Deliberately knows
	/// nothing about Packet or Layer — it only exposes generic containers
	/// (object/array) and scalar field writes. Packet::serialize() and
	/// Layer::serialize() decide entirely on their own what containers to
	/// open, what to name them, and what fields to write inside them; this
	/// interface has no "packet" or "layer" concept baked in at all.
	///
	/// This is a streaming *sink*: callers push data in as they walk their
	/// own structures, rather than building an intermediate tree first.
	///
	/// Field identity: every field/container is identified by both a name
	/// (string, human-readable, e.g. "srcIp") and an id (int, stable across
	/// renames, supplied by the caller — analogous to a protobuf field
	/// number). Concrete serializers may use either, both, or neither.
	///
	/// Lifecycle contract (enforced by convention, not by the type system):
	/// every startObject()/startArray() call must be matched by exactly one
	/// corresponding endObject()/endArray() call before the next sibling is
	/// written. Nesting is arbitrary. A top-level startObject()/startArray()
	/// call (no enclosing container yet) is valid and is how a caller opens
	/// its outermost structure — e.g. Packet::serialize() opens one root
	/// object for the whole packet.
	///
	/// Integer width: the *virtual* surface only ever deals in int64_t/
	/// uint64_t — deliberately, to keep the vtable (and every concrete
	/// serializer's override list) small. Every narrower int/uint type is
	/// accepted too, via the non-virtual template overloads below, which
	/// widen and forward to the canonical virtual. These templates must
	/// stay inline here (a template's definition has to be visible at
	/// every call site) — they're the one part of this interface that
	/// can't move to Serializers.cpp.
	class ISerializer
	{
	public:
		virtual ~ISerializer() = default;

		// --- Generic containers ---
		virtual void startObject(int id, const std::string& name) = 0;
		virtual void endObject() = 0;
		virtual void startArray(int id, const std::string& name) = 0;
		virtual void endArray() = 0;

		// --- Scalar field writes (canonical virtuals) ---
		virtual void writeField(int id, const std::string& name, const std::string& value,
		                         const std::string& semanticType = "") = 0;
		virtual void writeField(int id, const std::string& name, int64_t value,
		                         const std::string& semanticType = "") = 0;
		virtual void writeField(int id, const std::string& name, uint64_t value,
		                         const std::string& semanticType = "") = 0;
		virtual void writeField(int id, const std::string& name, double value,
		                         const std::string& semanticType = "") = 0;
		virtual void writeField(int id, const std::string& name, bool value,
		                         const std::string& semanticType = "") = 0;
		virtual void writeNullField(int id, const std::string& name) = 0;

		// --- Scalar field writes: any int/uint width (non-virtual) ---
		// SFINAE'd on is_integral + is_signed/is_unsigned, explicitly
		// excluding bool (which has its own exact overload above and must
		// never fall through to these).
		template <typename T, typename std::enable_if<std::is_integral<T>::value && std::is_signed<T>::value &&
		                                                    !std::is_same<T, bool>::value,
		                                                int>::type = 0>
		void writeField(int id, const std::string& name, T value, const std::string& semanticType = "")
		{
			writeField(id, name, static_cast<int64_t>(value), semanticType);
		}

		template <typename T, typename std::enable_if<std::is_integral<T>::value && std::is_unsigned<T>::value &&
		                                                    !std::is_same<T, bool>::value,
		                                                int>::type = 0>
		void writeField(int id, const std::string& name, T value, const std::string& semanticType = "")
		{
			writeField(id, name, static_cast<uint64_t>(value), semanticType);
		}

		// --- Hex-formatted integer field ---
		// Always unsigned: hex notation represents a bit pattern, not a
		// signed magnitude. Cast a signed value to its matching unsigned
		// type first if you need to hex-format it.
		virtual void writeHexField(int id, const std::string& name, uint64_t value, int widthBytes) = 0;

		template <typename T, typename std::enable_if<std::is_integral<T>::value && std::is_unsigned<T>::value,
		                                                int>::type = 0>
		void writeHexField(int id, const std::string& name, T value)
		{
			writeHexField(id, name, static_cast<uint64_t>(value), static_cast<int>(sizeof(T)));
		}
	};

	/// @class JsonSerializer
	/// Streams a field tree out as JSON, writing directly to a std::ostream
	/// — no intermediate string/DOM is built, so exporting a large pcap to
	/// NDJSON never holds more than one packet's worth of output in memory
	/// at a time. Hand-rolled (no JSON library dependency); see
	/// JsonSerializer2 for the nlohmann::json-based alternative.
	class JsonSerializer : public ISerializer
	{
	public:
		using ISerializer::writeField;
		using ISerializer::writeHexField;

		explicit JsonSerializer(std::ostream& out);

		void startObject(int id, const std::string& name) override;
		void endObject() override;
		void startArray(int id, const std::string& name) override;
		void endArray() override;

		void writeField(int id, const std::string& name, const std::string& value,
		                 const std::string& semanticType = "") override;
		void writeField(int id, const std::string& name, int64_t value,
		                 const std::string& semanticType = "") override;
		void writeField(int id, const std::string& name, uint64_t value,
		                 const std::string& semanticType = "") override;
		void writeField(int id, const std::string& name, double value,
		                 const std::string& semanticType = "") override;
		void writeField(int id, const std::string& name, bool value,
		                 const std::string& semanticType = "") override;
		void writeNullField(int id, const std::string& name) override;
		void writeHexField(int id, const std::string& name, uint64_t value, int widthBytes) override;

	private:
		enum class Context
		{
			Array,
			Object
		};

		void writeSeparatorIfNeeded();
		void writeKey(const std::string& name, const std::string& semanticType = "");
		static std::string escape(const std::string& s);

		std::ostream& m_Out;
		std::vector<Context> m_ContextStack;
		std::vector<bool> m_FirstAtLevel;
	};

	/// @class JsonSerializer2
	/// Alternative JSON implementation of ISerializer, built on
	/// nlohmann::json (PcapPlusPlus already vendors it under 3rdParty/json)
	/// instead of hand-rolled bracket/comma/escaping logic.
	///
	/// IMPORTANT TRADE-OFF vs JsonSerializer: this builds a real
	/// nlohmann::json tree in memory for whatever containers are currently
	/// open, and only writes bytes to the output stream when the
	/// OUTERMOST container closes. For the common case — one
	/// startObject()/endObject() pair per packet (NDJSON) — this holds at
	/// most one packet's tree in memory at a time, the same footprint
	/// JsonSerializer has. But wrapping an entire capture in one top-level
	/// startArray()/endArray() means the *entire* capture's tree gets
	/// buffered before anything is written — unlike JsonSerializer, which
	/// stays constant-memory regardless of nesting. Prefer JsonSerializer
	/// for that use case; JsonSerializer2 is best suited to per-packet
	/// NDJSON.
	///
	/// Implemented via pimpl (m_Impl): nlohmann::json needs to be a
	/// complete type wherever a Frame is actually stored, but pulling
	/// <nlohmann/json.hpp> into this header would force every consumer of
	/// Serializers.h — including anyone who only wants plain JsonSerializer
	/// — to compile it too. The pimpl confines that dependency to
	/// Serializers.cpp.
	class JsonSerializer2 : public ISerializer
	{
	public:
		using ISerializer::writeField;
		using ISerializer::writeHexField;

		explicit JsonSerializer2(std::ostream& out);
		~JsonSerializer2() override;  // must be out-of-line: ~unique_ptr<Impl>() needs Impl complete

		JsonSerializer2(const JsonSerializer2&) = delete;
		JsonSerializer2& operator=(const JsonSerializer2&) = delete;

		void startObject(int id, const std::string& name) override;
		void endObject() override;
		void startArray(int id, const std::string& name) override;
		void endArray() override;

		void writeField(int id, const std::string& name, const std::string& value,
		                 const std::string& semanticType = "") override;
		void writeField(int id, const std::string& name, int64_t value,
		                 const std::string& semanticType = "") override;
		void writeField(int id, const std::string& name, uint64_t value,
		                 const std::string& semanticType = "") override;
		void writeField(int id, const std::string& name, double value,
		                 const std::string& semanticType = "") override;
		void writeField(int id, const std::string& name, bool value,
		                 const std::string& semanticType = "") override;
		void writeNullField(int id, const std::string& name) override;
		void writeHexField(int id, const std::string& name, uint64_t value, int widthBytes) override;

	private:
		struct Impl;
		std::unique_ptr<Impl> m_Impl;
	};

}  // namespace pcpp
