#pragma once
#include "Asn1Codec.h"
#include <iostream>

/// @namespace pcpp
/// The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	class X509ExtendedKeyUsagePurpose
	{
	public:
		/// Define enum types and the corresponding int values
		enum Value : uint8_t
		{
			ServerAuth,
			ClientAuth,
			CodeSigning,
			EmailProtection,
			TimeStamping,
			OCSPSigning,
			IPSecEndSystem,
			IPSecTunnel,
			IPSecUser,
			AnyExtendedKeyUsage,
			SmartCardLogon,
			EncryptedFileSystem,
			DocumentSigning,
			Unknown,
		};

		X509ExtendedKeyUsagePurpose() = default;
		constexpr X509ExtendedKeyUsagePurpose(Value value) : m_Value(value)
		{}

		/// @return A string representation of the operation type
		std::string toString() const;

		/// @return The OID value of the operation type
		std::string getOidValue() const;
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
		class X509ExtensionDataDecoder
		{
		protected:
			static std::unique_ptr<Asn1Record> decodeAsn1Data(const std::string& rawData,
			                                                  std::vector<uint8_t>& rawDataBytes);
		};

		class X509BasicConstraintsDataDecoder : public X509ExtensionDataDecoder
		{
		public:
			static std::unique_ptr<X509BasicConstraintsDataDecoder> create(const std::string& rawData);
			bool isCA() const
			{
				return m_IsCA;
			}
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

		class X509SubjectKeyIdentifierDataDecoder : public X509ExtensionDataDecoder
		{
		public:
			static std::unique_ptr<X509SubjectKeyIdentifierDataDecoder> create(const std::string& rawData);

			std::string getKeyIdentifier() const
			{
				return m_KeyIdentifier;
			}

		private:
			X509SubjectKeyIdentifierDataDecoder(const std::string& keyIdentifier) : m_KeyIdentifier(keyIdentifier)
			{}
			std::string m_KeyIdentifier;
		};

		class X509KeyUsageDataDecoder : public X509ExtensionDataDecoder
		{
		public:
			static std::unique_ptr<X509KeyUsageDataDecoder> create(const std::string& rawData);

			std::string getKeyUsage() const
			{
				return m_KeyUsage;
			}

		private:
			X509KeyUsageDataDecoder(const std::string& keyUsage) : m_KeyUsage(keyUsage)
			{}
			std::string m_KeyUsage;
		};

		class X509ExtendedKeyUsageDataDecoder : public X509ExtensionDataDecoder
		{
		public:
			static std::unique_ptr<X509ExtendedKeyUsageDataDecoder> create(const std::string& rawData);

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

	class X509ExtensionData
	{
		friend class X509Extension;

	public:
		virtual ~X509ExtensionData() = default;

		template <class X509ExtensionDataType> X509ExtensionDataType* castAs()
		{
			auto castedExtension = dynamic_cast<X509ExtensionDataType*>(this);
			if (castedExtension == nullptr)
			{
				throw std::runtime_error("Trying to cast X509 extension data to the wrong type");
			}
			return castedExtension;
		}

	protected:
		X509ExtensionData()
		{}
	};

	class X509BasicConstraintsExtension : public X509ExtensionData
	{
		friend class X509Extension;

	public:
		bool isCA() const
		{
			return m_IsCA;
		}
		int getPathLenConstraint() const
		{
			return m_PathLenConstraint;
		}

	private:
		explicit X509BasicConstraintsExtension(const std::string& rawExtensionData);
		bool m_IsCA = false;
		int m_PathLenConstraint = 0;
	};

	class X509SubjectKeyIdentifierExtension : public X509ExtensionData
	{
		friend class X509Extension;

	public:
		std::string getKeyIdentifier() const
		{
			return m_KeyIdentifier;
		};

	private:
		explicit X509SubjectKeyIdentifierExtension(const std::string& rawExtensionData);
		std::string m_KeyIdentifier;
	};

	class X509KeyUsageExtension : public X509ExtensionData
	{
		friend class X509Extension;

	public:
		bool isDigitalSignature() const;
		bool isNonRepudiation() const;
		bool isKeyEncipherment() const;
		bool isDataEncipherment() const;
		bool isKeyAgreement() const;
		bool isKeyCertSign() const;
		bool isCRLSign() const;
		bool isEncipherOnly() const;
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

	class X509ExtendedKeyUsageExtension : public X509ExtensionData
	{
		friend class X509Extension;

	public:
		const std::vector<X509ExtendedKeyUsagePurpose>& getPurposes() const
		{
			return m_Purposes;
		}

	private:
		explicit X509ExtendedKeyUsageExtension(const std::string& rawExtensionData);
		std::vector<X509ExtendedKeyUsagePurpose> m_Purposes;
	};
}  // namespace pcpp
