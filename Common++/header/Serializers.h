#pragma once

#include <cstdint>
#include <iosfwd>
#include <string>
#include <type_traits>
#include <vector>

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	/// @struct FieldDescriptor
	/// Describes a serializable field.
	struct FieldDescriptor
	{
		/// Stable numeric identifier of the field.
		const uint16_t id;

		/// Name of the field.
		const std::string name;

		/// Function returning the descriptors of the field's children, or nullptr if the field has no children.
		std::vector<FieldDescriptor> (*const getChildren)();

		/// Create a field descriptor.
		/// @param[in] fieldId The stable numeric identifier of the field
		/// @param[in] fieldName The name of the field
		/// @param[in] fieldChildren A function returning the field's child descriptors, or nullptr if the field has no
		/// children
		FieldDescriptor(uint16_t fieldId, std::string fieldName,
		                std::vector<FieldDescriptor> (*fieldChildren)() = nullptr)
		    : id(fieldId), name(std::move(fieldName)), getChildren(fieldChildren)
		{}

		/// Check whether the field has child fields.
		/// @return True if the field has child fields, false otherwise
		bool hasChildren() const
		{
			return getChildren != nullptr;
		}
	};

	/// @struct ObjectFieldDescriptor
	/// Describes a serializable object field and its child fields.
	template <typename Derived> struct ObjectFieldDescriptor : FieldDescriptor
	{
		/// Create an object field descriptor.
		/// @param[in] fieldId The stable numeric identifier of the field
		/// @param[in] fieldName The name of the field
		ObjectFieldDescriptor(uint16_t fieldId, std::string fieldName)
		    : FieldDescriptor(fieldId, std::move(fieldName), &Derived::all)
		{}
	};

	class ScopeBase;
	class ArrayScope;
	class ObjectScope;

	namespace internal
	{
		template <typename T>
		using EnableIfSignedIntegral =
		    std::enable_if_t<std::is_integral<T>::value && std::is_signed<T>::value && !std::is_same<T, bool>::value,
		                     int>;

		template <typename T>
		using EnableIfUnsignedIntegral =
		    std::enable_if_t<std::is_integral<T>::value && std::is_unsigned<T>::value && !std::is_same<T, bool>::value,
		                     int>;
	}  // namespace internal

	/// @class ISerializer
	/// Interface for streaming structured data to a serializer.
	class ISerializer
	{
		friend class ScopeBase;
		friend class ArrayScope;
		friend class ObjectScope;

	public:
		/// Destroy the serializer.
		virtual ~ISerializer() = default;

		/// Open an array field.
		/// @param[in] field The descriptor of the array field
		/// @return A scope representing the newly opened array
		ArrayScope writeArray(const FieldDescriptor& field);

		/// Open an object field.
		/// @param[in] field The descriptor of the object field
		/// @return A scope representing the newly opened object
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

		template <typename T, internal::EnableIfSignedIntegral<T> = 0>
		void writeField(const FieldDescriptor& field, T value)
		{
			writeField(field, static_cast<int64_t>(value));
		}

		template <typename T, internal::EnableIfUnsignedIntegral<T> = 0>
		void writeField(const FieldDescriptor& field, T value)
		{
			writeField(field, static_cast<uint64_t>(value));
		}

		virtual void writeHexField(const FieldDescriptor& field, uint64_t value) = 0;

		template <typename T, std::enable_if_t<std::is_integral<T>::value && std::is_unsigned<T>::value, int> = 0>
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

	/// @class ScopeBase
	/// Base class for serializer scopes.
	class ScopeBase : public ISerializer
	{
	public:
		using ISerializer::writeField;

		/// Write a string field.
		/// @param[in] field The descriptor of the field
		/// @param[in] value The string value to write
		void writeField(const FieldDescriptor& field, const std::string& value) override;

		/// Write a signed int64 field.
		/// @param[in] field The descriptor of the field
		/// @param[in] value The signed integer value to write
		void writeField(const FieldDescriptor& field, int64_t value) override;

		/// Write an unsigned int64 field.
		/// @param[in] field The descriptor of the field
		/// @param[in] value The unsigned integer value to write
		void writeField(const FieldDescriptor& field, uint64_t value) override;

		/// Write a floating-point field.
		/// @param[in] field The descriptor of the field
		/// @param[in] value The floating-point value to write
		void writeField(const FieldDescriptor& field, double value) override;

		/// Write a boolean field.
		/// @param[in] field The descriptor of the field
		/// @param[in] value The boolean value to write
		void writeField(const FieldDescriptor& field, bool value) override;

		/// Write a null field.
		/// @param[in] field The descriptor of the field
		void writeNullField(const FieldDescriptor& field) override;

		/// Write an unsigned integer field in hexadecimal notation.
		/// @param[in] field The descriptor of the field
		/// @param[in] value The unsigned integer value to write
		void writeHexField(const FieldDescriptor& field, uint64_t value) override;

		template <typename T, internal::EnableIfSignedIntegral<T> = 0>
		void writeField(const FieldDescriptor& field, T value)
		{
			writeField(field, static_cast<int64_t>(value));
		}

		template <typename T, internal::EnableIfUnsignedIntegral<T> = 0>
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

	/// @class ArrayScope
	/// RAII scope for a serialized array.
	class ArrayScope : public ScopeBase
	{
	public:
		using ScopeBase::writeField;

		/// Create an array scope.
		/// @param[in] serializer The serializer owning the array
		/// @param[in] field The descriptor of the array field
		ArrayScope(ISerializer* serializer, const FieldDescriptor& field);

		/// Close the array.
		~ArrayScope() override;
	};

	/// @class ObjectScope
	/// RAII scope for a serialized object.
	class ObjectScope : public ScopeBase
	{
	public:
		using ScopeBase::writeField;

		/// Create an object scope.
		/// @param[in] serializer The serializer owning the object
		/// @param[in] field The descriptor of the object field
		ObjectScope(ISerializer* serializer, const FieldDescriptor& field);

		/// Close the object.
		~ObjectScope() override;
	};

	/// @class JsonSerializer
	/// Serializer that writes JSON.
	class JsonSerializer : public ISerializer
	{
	public:
		using ISerializer::writeField;
		using ISerializer::writeHexField;

		/// Create a JSON serializer.
		/// @param[in] out The output stream to which JSON is written
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
