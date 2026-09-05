#pragma once

#include <cstdint>
#include <iosfwd>  // std::ostream forward declaration only — <ostream> is a Serializers.cpp concern
#include <memory>
#include <string>
#include <type_traits>
#include <vector>

namespace pcpp
{
	/// @struct FieldDescriptor
	/// Documents ONE field a layer serializes — id/name/semanticType are
	/// the same values internalSerialize() actually writes, because
	/// writeField() below REQUIRES a FieldDescriptor rather than accepting
	/// raw (id, name) — so there is exactly one place each field's identity
	/// is ever written down, referenced both by internalSerialize() and by
	/// getFieldCatalog(). What this does NOT do: statically stop one
	/// layer's internalSerialize() from using another layer's
	/// FieldDescriptor constant (that would need FieldDescriptor<LayerT> +
	/// a CRTP base requiring every call go through a layer-bound method —
	/// evaluated and deliberately not used here, in favor of this simpler,
	/// non-templated version).
	struct FieldDescriptor
	{
		uint16_t id;
		std::string name;
	};

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
		virtual void startObject(const FieldDescriptor& field) = 0;
		virtual void endObject() = 0;
		virtual void startArray(const FieldDescriptor& field) = 0;
		virtual void endArray() = 0;

		// --- Scalar field writes (canonical virtuals) ---
		virtual void writeField(const FieldDescriptor& field, const std::string& value) = 0;
		virtual void writeField(const FieldDescriptor& field, int64_t value) = 0;
		virtual void writeField(const FieldDescriptor& field, uint64_t value) = 0;
		virtual void writeField(const FieldDescriptor& field, double value) = 0;
		virtual void writeField(const FieldDescriptor& field, bool value) = 0;
		virtual void writeNullField(const FieldDescriptor& field) = 0;

		virtual void writeField(const FieldDescriptor& field, const char* value)
		{
			writeField(field, std::string(value));
		}

		// --- Scalar field writes: any int/uint width (non-virtual) ---
		// SFINAE'd on is_integral + is_signed/is_unsigned, explicitly
		// excluding bool (which has its own exact overload above and must
		// never fall through to these).
		template <typename T, typename std::enable_if<std::is_integral<T>::value && std::is_signed<T>::value &&
		                                                    !std::is_same<T, bool>::value,
		                                                int>::type = 0>
		void writeField(const FieldDescriptor& field, T value)
		{
			writeField(field, static_cast<int64_t>(value));
		}

		template <typename T, typename std::enable_if<std::is_integral<T>::value && std::is_unsigned<T>::value &&
		                                                    !std::is_same<T, bool>::value,
		                                                int>::type = 0>
		void writeField(const FieldDescriptor& field, T value)
		{
			writeField(field, static_cast<uint64_t>(value));
		}

		// --- Hex-formatted integer field ---
		// Always unsigned: hex notation represents a bit pattern, not a
		// signed magnitude. Cast a signed value to its matching unsigned
		// type first if you need to hex-format it.
		virtual void writeHexField(const FieldDescriptor& field, uint64_t value, int widthBytes) = 0;

		template <typename T, typename std::enable_if<std::is_integral<T>::value && std::is_unsigned<T>::value,
		                                                int>::type = 0>
		void writeHexField(const FieldDescriptor& field, T value)
		{
			writeHexField(field, static_cast<uint64_t>(value), static_cast<int>(sizeof(T)));
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

		void startObject(const FieldDescriptor& field) override;
		void endObject() override;
		void startArray(const FieldDescriptor& field) override;
		void endArray() override;

		void writeField(const FieldDescriptor& field, const std::string& value) override;
		void writeField(const FieldDescriptor& field, int64_t value) override;
		void writeField(const FieldDescriptor& field, uint64_t value) override;
		void writeField(const FieldDescriptor& field, double value) override;
		void writeField(const FieldDescriptor& field, bool value) override;
		void writeNullField(const FieldDescriptor& field) override;
		void writeHexField(const FieldDescriptor& field, uint64_t value, int widthBytes) override;

	private:
		enum class Context
		{
			Array,
			Object
		};

		void writeSeparatorIfNeeded();
		void writeKey(const std::string& name);
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

		void startObject(const FieldDescriptor& field) override;
		void endObject() override;
		void startArray(const FieldDescriptor& field) override;
		void endArray() override;

		void writeField(const FieldDescriptor& field, const std::string& value) override;
		void writeField(const FieldDescriptor& field, int64_t value) override;
		void writeField(const FieldDescriptor& field, uint64_t value) override;
		void writeField(const FieldDescriptor& field, double value) override;
		void writeField(const FieldDescriptor& field, bool value) override;
		void writeNullField(const FieldDescriptor& field) override;
		void writeHexField(const FieldDescriptor& field, uint64_t value, int widthBytes) override;

	private:
		struct Impl;
		std::unique_ptr<Impl> m_Impl;
	};

	/// @class YamlSerializer
	/// Streams a field tree out as YAML (block style), writing directly to
	/// a std::ostream — same hand-rolled, no-third-party-dependency design
	/// as JsonSerializer. YAML's block style needs no comma/separator
	/// bookkeeping (unlike JSON) — every field or sequence item just starts
	/// on its own line at the current indent depth, so this is actually
	/// simpler than JsonSerializer in that one respect.
	///
	/// Every string value is written double-quoted rather than in YAML's
	/// bare "plain scalar" style, deliberately: plain scalars have a long
	/// list of characters/values that require quoting to avoid ambiguity
	/// (a value starting with '-', ':', '#'; strings that look like
	/// "true"/"false"/"null"/a number; leading/trailing whitespace; and
	/// more) — always double-quoting sidesteps that whole class of
	/// correctness issues, at the cost of slightly less idiomatic-looking
	/// output. Field NAMES (mapping keys) are written unquoted, on the
	/// assumption they're always simple identifiers, as they are
	/// everywhere in this codebase today — not arbitrary/untrusted data.
	class YamlSerializer : public ISerializer
	{
	public:
		using ISerializer::writeField;
		using ISerializer::writeHexField;

		explicit YamlSerializer(std::ostream& out);

		void startObject(const FieldDescriptor& field) override;
		void endObject() override;
		void startArray(const FieldDescriptor& field) override;
		void endArray() override;

		void writeField(const FieldDescriptor& field, const std::string& value) override;
		void writeField(const FieldDescriptor& field, int64_t value) override;
		void writeField(const FieldDescriptor& field, uint64_t value) override;
		void writeField(const FieldDescriptor& field, double value) override;
		void writeField(const FieldDescriptor& field, bool value) override;
		void writeNullField(const FieldDescriptor& field) override;
		void writeHexField(const FieldDescriptor& field, uint64_t value, int widthBytes) override;

	private:
		enum class Context
		{
			Array,
			Object
		};

		void writeIndent();
		void writeNewlineIfNeeded();
		// Called by startObject()/startArray(), BEFORE pushing the new
		// context: writes the line introducing the container (a bare "-"
		// for an array element, "name:" for an object member, or nothing
		// at the document root) — content follows on subsequent, more
		// deeply indented lines.
		void writeContainerHeader(const std::string& name);
		// Called by writeField()/writeNullField()/writeHexField(): writes
		// everything on the current line up to (not including) the value
		// itself — "- " inside an array, "name: " inside an object or at
		// the root. Caller writes the actual value immediately after.
		void writeFieldPrefix(const std::string& name);
		static std::string escape(const std::string& s);

		std::ostream& m_Out;
		std::vector<Context> m_ContextStack;
		bool m_WriteNewLine = false;
		bool m_WriteIdent = true;
	};

	/// @class XmlSerializer
	/// Streaming XML serializer that writes directly to a std::ostream.
	/// No external dependencies - hand-rolled XML 1.0 compliant output.
	///
	/// Produces pretty-printed XML with proper escaping, self-closing tags,
	/// and consistent array representation. Follows these conventions:
	/// - Objects become elements with nested children
	/// - Arrays become container elements with <item> children
	/// - Null values become empty elements with xsi:nil="true"
	/// - Binary/hex values are represented as strings with "0x" prefix
	///
	/// Memory usage: O(depth) - only tracks the current nesting level,
	/// not the entire document. Writes incrementally to the stream.
	class XmlSerializer : public ISerializer
	{
	public:
	    using ISerializer::writeField;
	    using ISerializer::writeHexField;

	    explicit XmlSerializer(std::ostream& out, bool prettyPrint = true, const std::string& indentStr = "  ");
	    ~XmlSerializer() override = default;

	    // Non-copyable to avoid stream ownership issues
	    XmlSerializer(const XmlSerializer&) = delete;
	    XmlSerializer& operator=(const XmlSerializer&) = delete;

	    void startObject(const FieldDescriptor& field) override;
	    void endObject() override;
	    void startArray(const FieldDescriptor& field) override;
	    void endArray() override;

	    void writeField(const FieldDescriptor& field, const std::string& value) override;
	    void writeField(const FieldDescriptor& field, int64_t value) override;
	    void writeField(const FieldDescriptor& field, uint64_t value) override;
	    void writeField(const FieldDescriptor& field, double value) override;
	    void writeField(const FieldDescriptor& field, bool value) override;
	    void writeNullField(const FieldDescriptor& field) override;
	    void writeHexField(const FieldDescriptor& field, uint64_t value, int widthBytes) override;

	private:
	    struct Context {
	        std::string name;      // Element name
	        bool isArray;          // True if this is an array container
	        bool hasChildren;      // True if we've written any child to this element
	        bool isRoot;           // True for the outermost element (no indentation)
	    };

	    // Core writing methods
	    void writeOpenTag(const std::string& name, bool selfClosing = false);
	    void writeCloseTag(const std::string& name);
	    void writeValueElement(const std::string& name, const std::string& value, bool isNull = false);
	    void writeIndent();
	    void writeRaw(const std::string& str);

	    // XML escaping (handles &, <, >, ", ')
	    static std::string escapeXML(const std::string& s);

	    // Checks if a string is safe to use as an XML name
	    static bool isValidXMLName(const std::string& name);

	    // State
	    std::ostream& m_Out;
	    std::vector<Context> m_ContextStack;
	    bool m_PrettyPrint;
	    std::string m_IndentStr;

	    // Optimization: pre-allocate indentation strings
	    mutable std::vector<std::string> m_IndentCache;
	};
}  // namespace pcpp
