from typing import Generator
import tempfile
from datetime import datetime
from enum import Enum, auto
import subprocess
from contextlib import contextmanager
from pathlib import Path
import argparse

CERT_DIR = Path("certs")
CERT_DIR.mkdir(exist_ok=True)


class Algorithm(Enum):
    RSA = auto()
    ECDSA = auto()
    ED25519 = auto()
    DSA = auto()


class FileFormat(Enum):
    DER = "DER"
    PEM = "PEM"


def run(cmd):
    """Run a shell command, optionally with stdin."""
    print(f"Running: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)


@contextmanager
def optional_create_temp_file(content: str | None) -> Generator[str | None, None, None]:
    if content:
        with tempfile.NamedTemporaryFile(mode="w+") as tmpfile:
            tmpfile.write(content)
            tmpfile.flush()
            yield tmpfile.name
    else:
        yield None


@contextmanager
def gen_key(alg: Algorithm) -> Generator[str, None, None]:
    with tempfile.NamedTemporaryFile(mode="w+") as tmpfile:
        match alg:
            case Algorithm.RSA:
                run(
                    [
                        "openssl",
                        "genpkey",
                        "-algorithm",
                        "RSA",
                        "-out",
                        tmpfile.name,
                        "-pkeyopt",
                        "rsa_keygen_bits:2048",
                    ]
                )
            case Algorithm.ECDSA:
                run(
                    [
                        "openssl",
                        "ecparam",
                        "-name",
                        "prime256v1",
                        "-genkey",
                        "-noout",
                        "-out",
                        tmpfile.name,
                    ]
                )
            case Algorithm.ED25519:
                run(
                    [
                        "openssl",
                        "genpkey",
                        "-algorithm",
                        "ed25519",
                        "-out",
                        tmpfile.name,
                    ]
                )
            case Algorithm.DSA:
                with tempfile.NamedTemporaryFile(mode="w+") as dsa_param_file:
                    run(["openssl", "dsaparam", "-out", dsa_param_file.name, "2048"])
                    run(
                        ["openssl", "gendsa", "-out", tmpfile.name, dsa_param_file.name]
                    )

        yield tmpfile.name


@contextmanager
def gen_csr(key: str, conf: str | None = None) -> Generator[str, None, None]:
    with (
        optional_create_temp_file(conf) as conf_file,
        tempfile.NamedTemporaryFile(mode="w+") as tmpfile,
    ):
        cmd = ["openssl", "req", "-new", "-key", key, "-out", tmpfile.name]
        if conf:
            cmd.extend(["-config", conf_file])
        else:
            cmd.extend(["-subj", "/CN=example.com"])

        run(cmd)
        yield tmpfile.name


def gen_x509(
    key: str,
    csr: str,
    outfile_name: str,
    file_format: FileFormat,
    exts: str | None = None,
    serial: str | None = None,
    days: int = 365,
):
    outfile_path = CERT_DIR / f"x509_cert_{outfile_name}.{file_format.value.lower()}"
    cmd = [
        "openssl",
        "x509",
        "-req",
        "-in",
        str(csr),
        "-signkey",
        str(key),
        "-outform",
        file_format.value,
        "-out",
        str(outfile_path),
        "-days",
        str(days),
    ]
    if serial:
        cmd.extend(["-set_serial", serial])
    if exts:
        cmd.extend(["-extfile", exts, "-extensions", "v3_req"])

    run(cmd)


def generate_with_all_algorithms(file_format: FileFormat):
    for alg in list(Algorithm):
        with gen_key(alg) as key_file, gen_csr(key_file) as csr_file:
            gen_x509(key_file, csr_file, alg.name.lower(), file_format)


def generate_with_all_rdns(file_format: FileFormat):
    conf = """[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = req_distinguished_name

[ req_distinguished_name ]
C                      = US
ST                     = California
L                      = San Francisco
O                      = ExampleOrg
OU                     = DevOps
CN                     = example.com
emailAddress           = admin@example.com
serialNumber           = 123456789
title                  = Engineer
givenName              = John
surname                = Doe
initials               = JD
pseudonym              = jdoe
generationQualifier    = Jr
dnQualifier            = qualifier
postalCode             = 94105
street                 = 1234 Example Street
businessCategory       = IT
uniqueIdentifier       = UID12345
domainComponent        = example.com
"""

    with gen_key(Algorithm.ECDSA) as key_file, gen_csr(key_file, conf) as csr_file:
        gen_x509(key_file, csr_file, "all_rdns", file_format)


def generate_with_generalized_time(file_format: FileFormat):
    expiration_date = datetime(2051, 1, 2)
    days_until_2051 = expiration_date - datetime.now()
    with gen_key(Algorithm.ECDSA) as key_file, gen_csr(key_file) as csr_file:
        gen_x509(
            key_file,
            csr_file,
            "long_expiration",
            file_format,
            days=days_until_2051.days,
        )


def generate_with_many_extension_types(file_format: FileFormat):
    conf = """[ req ]
default_bits        = 2048
prompt              = no
default_md          = sha256
distinguished_name  = dn
req_extensions      = req_ext

[ dn ]
C = US
ST = California
L = San Francisco
O = Example Corp
OU = IT Department
CN = example.com
emailAddress = admin@example.com

[ req_ext ]
# Subject Alternative Name
subjectAltName = @alt_names

# Key Usage (suggested in CSRs)
keyUsage = digitalSignature, keyEncipherment, dataEncipherment

# Extended Key Usage
extendedKeyUsage = serverAuth, clientAuth, codeSigning, emailProtection, timeStamping, OCSPSigning

# Custom OID extension
1.2.3.4.5.6.7.8.1 = ASN1:UTF8String:Custom CSR Extension

[ alt_names ]
DNS.1 = example.com
DNS.2 = www.example.com
IP.1 = 192.168.1.10
email.1 = admin@example.com
    """

    exts = """[ v3_req ]
# Basic constraints: Not a CA cert
basicConstraints = critical,CA:true,pathlen:12

# Key usage - typical for TLS server/client certs
keyUsage = critical, digitalSignature, keyEncipherment, dataEncipherment, keyAgreement

# Extended key usage - multiple purposes
extendedKeyUsage = serverAuth, clientAuth, codeSigning, emailProtection, timeStamping, OCSPSigning

# Subject alternative names (DNS, IP, email)
subjectAltName = @alt_names

# Identifiers
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer

# Certificate policies OID (example)
certificatePolicies = 1.3.6.1.4.1.99999.1.1.1

# Policy constraints
policyConstraints = requireExplicitPolicy:0

# Inhibit anyPolicy
inhibitAnyPolicy = 1

# Name constraints (example: limit to example.com domain)
nameConstraints = permitted;DNS:.example.com

# CRL Distribution Points (URL)
crlDistributionPoints = URI:http://example.com/crl.pem

# Authority Information Access (OCSP and CA Issuers)
authorityInfoAccess = OCSP;URI:http://ocsp.example.com/, caIssuers;URI:http://example.com/ca.pem

# Subject Information Access (e.g., Time Stamping service)
subjectInfoAccess = timeStamping;URI:http://timestamp.example.com/

# Freshest CRL (delta CRL location)
freshestCRL = URI:http://example.com/delta-crl.pem

# TLS Feature (e.g., OCSP stapling required)
1.3.6.1.5.5.7.1.24 = ASN1:UTF8String:status_request

# OCSP No Check (for OCSP responder certs)
1.3.6.1.5.5.7.48.1.5 = ASN1:NULL

# Signed Certificate Timestamp List (CT)
1.3.6.1.4.1.11129.2.4.2 = DER:04:03:02:01

# Subject Directory Attributes (example, just a placeholder string)
2.5.29.9 = ASN1:UTF8String:Example subject directory attribute

# Custom OID extension (your custom extension)
1.2.3.4.5.6.7.8.1 = ASN1:UTF8String:Custom Certificate Extension

[ alt_names ]
DNS.1 = example.com
DNS.2 = www.example.com
IP.1 = 192.168.1.10
email.1 = admin@example.com
    """

    with (
        gen_key(Algorithm.RSA) as key_file,
        gen_csr(key_file, conf) as csr_file,
        tempfile.NamedTemporaryFile(mode="w+") as exts_file,
    ):
        exts_file.write(exts)
        exts_file.flush()
        gen_x509(
            key_file, csr_file, "many_extensions", file_format, exts=exts_file.name
        )


def generate_multilang(file_format: FileFormat):
    conf = """[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = req_distinguished_name
string_mask        = utf8only
utf8               = yes

[ req_distinguished_name ]
C  = US
ST = California
L  = San Francisco
O  = MultiLang Org
OU = שלום 你好 こんにちは 안녕하세요 नमस्ते สวัสดี 🌍🚀
CN = www.example.com
emailAddress = info@example.com
    """

    with gen_key(Algorithm.ECDSA) as key_file, gen_csr(key_file, conf) as csr_file:
        gen_x509(key_file, csr_file, "multilang", file_format)


def generate_with_leading_zeros_serial_number(file_format: FileFormat):
    with gen_key(Algorithm.ECDSA) as key_file, gen_csr(key_file) as csr_file:
        gen_x509(key_file, csr_file, "serial_lead_zeros", file_format, serial="0x80")


def main():
    parser = argparse.ArgumentParser(description="X509 generator")
    parser.add_argument("--file-format", choices=[fmt.value for fmt in FileFormat])
    args = parser.parse_args()
    file_format = FileFormat(args.file_format)

    generate_with_all_algorithms(file_format)
    generate_with_all_rdns(file_format)
    generate_with_generalized_time(file_format)
    generate_with_many_extension_types(file_format)
    generate_multilang(file_format)
    generate_with_leading_zeros_serial_number(file_format)

    print(f"All certificates generated in ./certs ({file_format.value} format)")


if __name__ == "__main__":
    main()
