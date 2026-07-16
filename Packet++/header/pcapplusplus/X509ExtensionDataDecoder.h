#pragma once
#include "Asn1Codec.h"

/// @namespace pcpp
/// The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	/// @class X509ExtendedKeyUsagePurpose
	/// Represents an extended key usage purpose
	class X509ExtendedKeyUsagePurpose
	{
	public:
		/// Define enum types for extended key usage purposes
		enum Value : uint8_t
		{
			/// Server authentication
			ServerAuth,
			/// Client authentication
			ClientAuth,
			/// Code signing
			CodeSigning,
			/// Email protection
			EmailProtection,
			/// Time stamping
			TimeStamping,
			/// OCSP signing
			OCSPSigning,
			/// IPsec end system
			IPSecEndSystem,
			/// IPsec tunnel
			IPSecTunnel,
			/// IPsec user
			IPSecUser,
			// Any extended key usage
			AnyExtendedKeyUsage,
			/// Smart card logon
			SmartCardLogon,
			/// Encrypted file system
			EncryptedFileSystem,
			/// Document signing
			DocumentSigning,
			/// Unknown purpose value
			Unknown,
		};

		X509ExtendedKeyUsagePurpose() = default;

		constexpr X509ExtendedKeyUsagePurpose(Value value) : m_Value(value)
		{}

		/// @return A string representation of the purpose type
		std::string toString() const;

		/// @return The OID value of the purpose type
		std::string getOidValue() const;

		/// Creates an X509ExtendedKeyUsagePurpose from an OID value
		/// @param[in] value The ASN.1 object identifier
		/// @return The corresponding X509ExtendedKeyUsagePurpose value, or Unknown if no match is found
		static X509ExtendedKeyUsagePurpose fromOidValue(const Asn1ObjectIdentifier& value);

		// Allow switch and comparisons.
		constexpr operator Value() const
		{
			return m_Value;
		}

		// Prevent usage: if(X509ExtendedKeyUsagePurpose)
		explicit operator bool() const = delete;

	private:
		Value m_Value = Unknown;
	};

	/// @namespace X509Internal
	/// Internal implementation details for X.509 certificate parsing
	namespace X509Internal
	{
		/// @class X509ExtensionDataDecoder
		/// Base class for X.509 extension data decoders
		class X509ExtensionDataDecoder
		{
		protected:
			static std::unique_ptr<Asn1Record> decodeAsn1Data(const std::string& rawData,
			                                                  std::vector<uint8_t>& rawDataBytes);
		};

		/// @class X509BasicConstraintsDataDecoder
		/// Represents the data decoder for the basic constraints extension
		class X509BasicConstraintsDataDecoder : public X509ExtensionDataDecoder
		{
		public:
			/// A factory method that creates an instance of X509BasicConstraintsDataDecoder from raw data
			/// @param[in] rawData The raw data of the extension
			/// @return A unique pointer to an instance of X509BasicConstraintsDataDecoder
			static std::unique_ptr<X509BasicConstraintsDataDecoder> create(const std::string& rawData);

			/// @return True if the certificate is a CA, false otherwise
			bool isCA() const
			{
				return m_IsCA;
			}

			/// @return The path length constraint of the certificate
			int getPathLenConstraint() const
			{
				return m_PathLenConstraint;
			}

		private:
			X509BasicConstraintsDataDecoder(bool isCA, int pathLenConstraint)
			    : m_IsCA(isCA), m_PathLenConstraint(pathLenConstraint)
			{}
			static constexpr int isCAOffset = 0;
			static constexpr int pathLenConstraintOffset = 1;

			bool m_IsCA = false;
			int m_PathLenConstraint = 0;
		};

		/// @class X509SubjectKeyIdentifierDataDecoder
		/// Represents the data decoder for the subject key identifier extension
		class X509SubjectKeyIdentifierDataDecoder : public X509ExtensionDataDecoder
		{
		public:
			/// A factory method that creates an instance of X509SubjectKeyIdentifierDataDecoder from raw data
			/// @param[in] rawData The raw data of the extension
			/// @return A unique pointer to an instance of X509SubjectKeyIdentifierDataDecoder
			static std::unique_ptr<X509SubjectKeyIdentifierDataDecoder> create(const std::string& rawData);

			/// @return The subject key identifier value
			const std::string& getKeyIdentifier() const
			{
				return m_KeyIdentifier;
			}

		private:
			X509SubjectKeyIdentifierDataDecoder(const std::string& keyIdentifier) : m_KeyIdentifier(keyIdentifier)
			{}
			std::string m_KeyIdentifier;
		};

		/// @class X509KeyUsageDataDecoder
		/// Represents the data decoder for the key usage extension
		class X509KeyUsageDataDecoder : public X509ExtensionDataDecoder
		{
		public:
			/// A factory method that creates an instance of X509KeyUsageDataDecoder from raw data
			/// @param[in] rawData The raw data of the extension
			/// @return A unique pointer to an instance of X509KeyUsageDataDecoder
			static std::unique_ptr<X509KeyUsageDataDecoder> create(const std::string& rawData);

			/// @return The key usage value
			const std::string& getKeyUsage() const
			{
				return m_KeyUsage;
			}

		private:
			X509KeyUsageDataDecoder(const std::string& keyUsage) : m_KeyUsage(keyUsage)
			{}
			std::string m_KeyUsage;
		};

		/// @class X509ExtendedKeyUsageDataDecoder
		/// Represents the data decoder for the extended key usage extension
		class X509ExtendedKeyUsageDataDecoder : public X509ExtensionDataDecoder
		{
		public:
			/// A factory method that creates an instance of X509ExtendedKeyUsageDataDecoder from raw data
			/// @param[in] rawData The raw data of the extension
			/// @return A unique pointer to an instance of X509ExtendedKeyUsageDataDecoder
			static std::unique_ptr<X509ExtendedKeyUsageDataDecoder> create(const std::string& rawData);

			/// @return The extended key usage purpose list
			const std::vector<Asn1ObjectIdentifier>& getExtendedKeyUsagePurposes() const
			{
				return m_ExtendedKeyUsagePurposes;
			}

		private:
			X509ExtendedKeyUsageDataDecoder()
			{}
			std::vector<Asn1ObjectIdentifier> m_ExtendedKeyUsagePurposes;
		};
	}  // namespace X509Internal

	// Forward declarations
	class X509Extension;

	/// @class X509ExtensionData
	/// A base class for X509 extension data
	class X509ExtensionData
	{
		friend class X509Extension;

	public:
		virtual ~X509ExtensionData() = default;

		/// A templated method that accepts a class derived from X509ExtensionData as its template argument and attempts
		/// to cast the current instance to that type
		/// @tparam X509ExtensionDataType The type to cast to
		/// @return A pointer to the type after casting
		/// @throw std::runtime_error if the cast fails
		template <class X509ExtensionDataType> X509ExtensionDataType* castAs()
		{
			auto castedExtension = dynamic_cast<X509ExtensionDataType*>(this);
			if (castedExtension == nullptr)
			{
				throw std::runtime_error("Trying to cast X509 extension data to the wrong type");
			}
			return castedExtension;
		}
	};

	/// @class X509BasicConstraintsExtension
	/// Represents the data for the basic constraints extension
	class X509BasicConstraintsExtension : public X509ExtensionData
	{
		friend class X509Extension;

	public:
		/// @return True if the extension is a CA, false otherwise
		bool isCA() const
		{
			return m_IsCA;
		}

		/// @return The path length constraint
		int getPathLenConstraint() const
		{
			return m_PathLenConstraint;
		}

	private:
		explicit X509BasicConstraintsExtension(const std::string& rawExtensionData);
		bool m_IsCA = false;
		int m_PathLenConstraint = 0;
	};

	/// @class X509SubjectKeyIdentifierExtension
	/// Represents the data for the subject key identifier extension
	class X509SubjectKeyIdentifierExtension : public X509ExtensionData
	{
		friend class X509Extension;

	public:
		/// @return The subject key identifier value
		std::string getKeyIdentifier() const
		{
			return m_KeyIdentifier;
		};

	private:
		explicit X509SubjectKeyIdentifierExtension(const std::string& rawExtensionData);
		std::string m_KeyIdentifier;
	};

	/// @class X509KeyUsageExtension
	/// Represents the data for the key usage extension
	class X509KeyUsageExtension : public X509ExtensionData
	{
		friend class X509Extension;

	public:
		/// @return True if the digital signature bit is set, false otherwise
		bool isDigitalSignature() const;

		/// @return True if the non-repudiation bit is set, false otherwise
		bool isNonRepudiation() const;

		/// @return True if the key encipherment bit is set, false otherwise
		bool isKeyEncipherment() const;

		/// @return True if the data encipherment bit is set, false otherwise
		bool isDataEncipherment() const;

		/// @return True if the key agreement bit is set, false otherwise
		bool isKeyAgreement() const;

		/// @return True if the key certificate signing bit is set, false otherwise
		bool isKeyCertSign() const;

		/// @return True if the CRL signing bit is set, false otherwise
		bool isCRLSign() const;

		/// @return True if the encipher-only bit is set, false otherwise
		bool isEncipherOnly() const;

		/// @return True if the decipher-only bit is set, false otherwise
		bool isDecipherOnly() const;

	private:
		explicit X509KeyUsageExtension(const std::string& rawExtensionData);

		static constexpr int digitalSignatureLocation = 0;
		static constexpr int nonRepudiationLocation = 1;
		static constexpr int keyEnciphermentLocation = 2;
		static constexpr int dataEnciphermentLocation = 3;
		static constexpr int keyAgreementLocation = 4;
		static constexpr int keyCertSignLocation = 5;
		static constexpr int crlSignLocation = 6;
		static constexpr int encipherOnlyLocation = 7;
		static constexpr int decipherOnlyLocation = 8;

		bool isBitSet(size_t location) const;
		std::string m_BitString;
	};

	/// @class X509ExtendedKeyUsageExtension
	/// Represents the data for the extended key usage extension
	class X509ExtendedKeyUsageExtension : public X509ExtensionData
	{
		friend class X509Extension;

	public:
		/// @return A vector of extended key usage purposes
		const std::vector<X509ExtendedKeyUsagePurpose>& getPurposes() const
		{
			return m_Purposes;
		}

	private:
		explicit X509ExtendedKeyUsageExtension(const std::string& rawExtensionData);
		std::vector<X509ExtendedKeyUsagePurpose> m_Purposes;
	};
}  // namespace pcpp
