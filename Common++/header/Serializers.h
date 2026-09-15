#pragma once

#include <cstdint>
#include <iosfwd>
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
		const uint16_t id;
		const std::string name;
		std::vector<FieldDescriptor> (*const children)();

		FieldDescriptor(uint16_t fieldId, std::string fieldName,
		                std::vector<FieldDescriptor> (*fieldChildren)() = nullptr)
		    : id(fieldId), name(std::move(fieldName)), children(fieldChildren)
		{}

		bool hasChildren() const
		{
			return children != nullptr;
		}
	};

	template <typename Derived> struct ObjectFieldDescriptor : FieldDescriptor
	{
		ObjectFieldDescriptor(uint16_t fieldId, std::string fieldName)
		    : FieldDescriptor(fieldId, std::move(fieldName), &Derived::all)
		{}
	};

	class ScopeBase;
	class ArrayScope;
	class ObjectScope;

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
		friend class ScopeBase;
		friend class ArrayScope;
		friend class ObjectScope;

	public:
		virtual ~ISerializer() = default;

		ArrayScope writeArray(const FieldDescriptor& field);
		ObjectScope writeObject(const FieldDescriptor& field);

	protected:
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
		virtual void writeHexField(const FieldDescriptor& field, uint64_t value) = 0;

		template <typename T,
		          typename std::enable_if<std::is_integral<T>::value && std::is_unsigned<T>::value, int>::type = 0>
		void writeHexField(const FieldDescriptor& field, T value)
		{
			writeHexField(field, static_cast<uint64_t>(value));
		}

		virtual void startObject(const FieldDescriptor& field) = 0;
		virtual void endObject() = 0;
		virtual void startArray(const FieldDescriptor& field) = 0;
		virtual void endArray() = 0;

		void enforceOneRoot();

		bool m_ShouldEnforceOneRoot = true;

	private:
		bool m_RootWritten = false;
	};

	class ScopeBase : public ISerializer
	{
	public:
		using ISerializer::writeField;

		void writeField(const FieldDescriptor& field, const std::string& value) override;
		void writeField(const FieldDescriptor& field, int64_t value) override;
		void writeField(const FieldDescriptor& field, uint64_t value) override;
		void writeField(const FieldDescriptor& field, double value) override;
		void writeField(const FieldDescriptor& field, bool value) override;
		void writeNullField(const FieldDescriptor& field) override;
		void writeHexField(const FieldDescriptor& field, uint64_t value) override;

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

	protected:
		void startObject(const FieldDescriptor& field) override;
		void endObject() override;
		void startArray(const FieldDescriptor& field) override;
		void endArray() override;

		explicit ScopeBase(ISerializer* serializer) : m_Serializer(serializer)
		{
			m_ShouldEnforceOneRoot = false;
		}

		ISerializer* m_Serializer;
	};

	class ArrayScope : public ScopeBase
	{
	public:
		using ScopeBase::writeField;

		ArrayScope(ISerializer* serializer, const FieldDescriptor& field);
		~ArrayScope() override;
	};

	class ObjectScope : public ScopeBase
	{
	public:
		using ScopeBase::writeField;

		ObjectScope(ISerializer* serializer, const FieldDescriptor& field);
		~ObjectScope() override;
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

	protected:
		void writeField(const FieldDescriptor& field, const std::string& value) override;
		void writeField(const FieldDescriptor& field, int64_t value) override;
		void writeField(const FieldDescriptor& field, uint64_t value) override;
		void writeField(const FieldDescriptor& field, double value) override;
		void writeField(const FieldDescriptor& field, bool value) override;
		void writeNullField(const FieldDescriptor& field) override;
		void writeHexField(const FieldDescriptor& field, uint64_t value) override;

		void startObject(const FieldDescriptor& field) override;
		void endObject() override;
		void startArray(const FieldDescriptor& field) override;
		void endArray() override;

	private:
		enum class Context
		{
			Array,
			Object
		};

		void writeSeparatorIfNeeded();
		void writeKey(const std::string& name);

		std::ostream& m_Out;
		std::vector<Context> m_ContextStack;
		std::vector<bool> m_FirstAtLevel;
	};
}  // namespace pcpp
