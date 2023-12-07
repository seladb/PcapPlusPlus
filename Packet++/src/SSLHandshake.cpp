#define LOG_MODULE PacketLogModuleSSLLayer

#include "SSLHandshake.h"
#include "EndianPortable.h"
#include "Logger.h"
#include "md5.h"
#include <map>
#include <set>
#include <sstream>
#include <string.h>
#include <utility>

namespace pcpp {

// --------------
// SSLCipherSuite
// --------------

static const SSLCipherSuite Cipher1 =
    SSLCipherSuite(0x0000, SSL_KEYX_NULL, SSL_AUTH_NULL, SSL_SYM_NULL,
                   SSL_HASH_NULL, "TLS_NULL_WITH_NULL_NULL");
static const SSLCipherSuite Cipher2 =
    SSLCipherSuite(0x0001, SSL_KEYX_RSA, SSL_AUTH_RSA, SSL_SYM_NULL,
                   SSL_HASH_MD5, "TLS_RSA_WITH_NULL_MD5");
static const SSLCipherSuite Cipher3 =
    SSLCipherSuite(0x0002, SSL_KEYX_RSA, SSL_AUTH_RSA, SSL_SYM_NULL,
                   SSL_HASH_SHA, "TLS_RSA_WITH_NULL_SHA");
static const SSLCipherSuite Cipher4 =
    SSLCipherSuite(0x0003, SSL_KEYX_RSA, SSL_AUTH_RSA, SSL_SYM_RC4_40,
                   SSL_HASH_MD5, "TLS_RSA_EXPORT_WITH_RC4_40_MD5");
static const SSLCipherSuite Cipher5 =
    SSLCipherSuite(0x0004, SSL_KEYX_RSA, SSL_AUTH_RSA, SSL_SYM_RC4_128,
                   SSL_HASH_MD5, "TLS_RSA_WITH_RC4_128_MD5");
static const SSLCipherSuite Cipher6 =
    SSLCipherSuite(0x0005, SSL_KEYX_RSA, SSL_AUTH_RSA, SSL_SYM_RC4_128,
                   SSL_HASH_SHA, "TLS_RSA_WITH_RC4_128_SHA");
static const SSLCipherSuite Cipher7 =
    SSLCipherSuite(0x0006, SSL_KEYX_RSA, SSL_AUTH_RSA, SSL_SYM_RC2_CBC_40,
                   SSL_HASH_MD5, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5");
static const SSLCipherSuite Cipher8 =
    SSLCipherSuite(0x0007, SSL_KEYX_RSA, SSL_AUTH_RSA, SSL_SYM_IDEA_CBC,
                   SSL_HASH_SHA, "TLS_RSA_WITH_IDEA_CBC_SHA");
static const SSLCipherSuite Cipher9 =
    SSLCipherSuite(0x0008, SSL_KEYX_RSA, SSL_AUTH_RSA, SSL_SYM_DES40_CBC,
                   SSL_HASH_SHA, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA");
static const SSLCipherSuite Cipher10 =
    SSLCipherSuite(0x0009, SSL_KEYX_RSA, SSL_AUTH_RSA, SSL_SYM_DES_CBC,
                   SSL_HASH_SHA, "TLS_RSA_WITH_DES_CBC_SHA");
static const SSLCipherSuite Cipher11 =
    SSLCipherSuite(0x000A, SSL_KEYX_RSA, SSL_AUTH_RSA, SSL_SYM_3DES_EDE_CBC,
                   SSL_HASH_SHA, "TLS_RSA_WITH_3DES_EDE_CBC_SHA");
static const SSLCipherSuite Cipher12 =
    SSLCipherSuite(0x000B, SSL_KEYX_DH, SSL_AUTH_DSS, SSL_SYM_DES40_CBC,
                   SSL_HASH_SHA, "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA");
static const SSLCipherSuite Cipher13 =
    SSLCipherSuite(0x000C, SSL_KEYX_DH, SSL_AUTH_DSS, SSL_SYM_DES_CBC,
                   SSL_HASH_SHA, "TLS_DH_DSS_WITH_DES_CBC_SHA");
static const SSLCipherSuite Cipher14 =
    SSLCipherSuite(0x000D, SSL_KEYX_DH, SSL_AUTH_DSS, SSL_SYM_3DES_EDE_CBC,
                   SSL_HASH_SHA, "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA");
static const SSLCipherSuite Cipher15 =
    SSLCipherSuite(0x000E, SSL_KEYX_DH, SSL_AUTH_RSA, SSL_SYM_DES40_CBC,
                   SSL_HASH_SHA, "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA");
static const SSLCipherSuite Cipher16 =
    SSLCipherSuite(0x000F, SSL_KEYX_DH, SSL_AUTH_RSA, SSL_SYM_DES_CBC,
                   SSL_HASH_SHA, "TLS_DH_RSA_WITH_DES_CBC_SHA");
static const SSLCipherSuite Cipher17 =
    SSLCipherSuite(0x0010, SSL_KEYX_DH, SSL_AUTH_RSA, SSL_SYM_3DES_EDE_CBC,
                   SSL_HASH_SHA, "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA");
static const SSLCipherSuite Cipher18 =
    SSLCipherSuite(0x0011, SSL_KEYX_DHE, SSL_AUTH_DSS, SSL_SYM_DES40_CBC,
                   SSL_HASH_SHA, "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA");
static const SSLCipherSuite Cipher19 =
    SSLCipherSuite(0x0012, SSL_KEYX_DHE, SSL_AUTH_DSS, SSL_SYM_DES_CBC,
                   SSL_HASH_SHA, "TLS_DHE_DSS_WITH_DES_CBC_SHA");
static const SSLCipherSuite Cipher20 =
    SSLCipherSuite(0x0013, SSL_KEYX_DHE, SSL_AUTH_DSS, SSL_SYM_3DES_EDE_CBC,
                   SSL_HASH_SHA, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA");
static const SSLCipherSuite Cipher21 =
    SSLCipherSuite(0x0014, SSL_KEYX_DHE, SSL_AUTH_RSA, SSL_SYM_DES40_CBC,
                   SSL_HASH_SHA, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA");
static const SSLCipherSuite Cipher22 =
    SSLCipherSuite(0x0015, SSL_KEYX_DHE, SSL_AUTH_RSA, SSL_SYM_DES_CBC,
                   SSL_HASH_SHA, "TLS_DHE_RSA_WITH_DES_CBC_SHA");
static const SSLCipherSuite Cipher23 =
    SSLCipherSuite(0x0016, SSL_KEYX_DHE, SSL_AUTH_RSA, SSL_SYM_3DES_EDE_CBC,
                   SSL_HASH_SHA, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA");
static const SSLCipherSuite Cipher24 =
    SSLCipherSuite(0x0017, SSL_KEYX_DH, SSL_AUTH_anon, SSL_SYM_RC4_40,
                   SSL_HASH_MD5, "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5");
static const SSLCipherSuite Cipher25 =
    SSLCipherSuite(0x0018, SSL_KEYX_DH, SSL_AUTH_anon, SSL_SYM_RC4_128,
                   SSL_HASH_MD5, "TLS_DH_anon_WITH_RC4_128_MD5");
static const SSLCipherSuite Cipher26 =
    SSLCipherSuite(0x0019, SSL_KEYX_DH, SSL_AUTH_anon, SSL_SYM_DES40_CBC,
                   SSL_HASH_SHA, "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA");
static const SSLCipherSuite Cipher27 =
    SSLCipherSuite(0x001A, SSL_KEYX_DH, SSL_AUTH_anon, SSL_SYM_DES_CBC,
                   SSL_HASH_SHA, "TLS_DH_anon_WITH_DES_CBC_SHA");
static const SSLCipherSuite Cipher28 =
    SSLCipherSuite(0x001B, SSL_KEYX_DH, SSL_AUTH_anon, SSL_SYM_3DES_EDE_CBC,
                   SSL_HASH_SHA, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA");
static const SSLCipherSuite Cipher29 =
    SSLCipherSuite(0x001E, SSL_KEYX_KRB5, SSL_AUTH_KRB5, SSL_SYM_DES_CBC,
                   SSL_HASH_SHA, "TLS_KRB5_WITH_DES_CBC_SHA");
static const SSLCipherSuite Cipher30 =
    SSLCipherSuite(0x001F, SSL_KEYX_KRB5, SSL_AUTH_KRB5, SSL_SYM_3DES_EDE_CBC,
                   SSL_HASH_SHA, "TLS_KRB5_WITH_3DES_EDE_CBC_SHA");
static const SSLCipherSuite Cipher31 =
    SSLCipherSuite(0x0020, SSL_KEYX_KRB5, SSL_AUTH_KRB5, SSL_SYM_RC4_128,
                   SSL_HASH_SHA, "TLS_KRB5_WITH_RC4_128_SHA");
static const SSLCipherSuite Cipher32 =
    SSLCipherSuite(0x0021, SSL_KEYX_KRB5, SSL_AUTH_KRB5, SSL_SYM_IDEA_CBC,
                   SSL_HASH_SHA, "TLS_KRB5_WITH_IDEA_CBC_SHA");
static const SSLCipherSuite Cipher33 =
    SSLCipherSuite(0x0022, SSL_KEYX_KRB5, SSL_AUTH_KRB5, SSL_SYM_DES_CBC,
                   SSL_HASH_MD5, "TLS_KRB5_WITH_DES_CBC_MD5");
static const SSLCipherSuite Cipher34 =
    SSLCipherSuite(0x0023, SSL_KEYX_KRB5, SSL_AUTH_KRB5, SSL_SYM_3DES_EDE_CBC,
                   SSL_HASH_MD5, "TLS_KRB5_WITH_3DES_EDE_CBC_MD5");
static const SSLCipherSuite Cipher35 =
    SSLCipherSuite(0x0024, SSL_KEYX_KRB5, SSL_AUTH_KRB5, SSL_SYM_RC4_128,
                   SSL_HASH_MD5, "TLS_KRB5_WITH_RC4_128_MD5");
static const SSLCipherSuite Cipher36 =
    SSLCipherSuite(0x0025, SSL_KEYX_KRB5, SSL_AUTH_KRB5, SSL_SYM_IDEA_CBC,
                   SSL_HASH_MD5, "TLS_KRB5_WITH_IDEA_CBC_MD5");
static const SSLCipherSuite Cipher37 =
    SSLCipherSuite(0x0026, SSL_KEYX_KRB5, SSL_AUTH_KRB5, SSL_SYM_DES_CBC_40,
                   SSL_HASH_SHA, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA");
static const SSLCipherSuite Cipher38 =
    SSLCipherSuite(0x0027, SSL_KEYX_KRB5, SSL_AUTH_KRB5, SSL_SYM_RC2_CBC_40,
                   SSL_HASH_SHA, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA");
static const SSLCipherSuite Cipher39 =
    SSLCipherSuite(0x0028, SSL_KEYX_KRB5, SSL_AUTH_KRB5, SSL_SYM_RC4_40,
                   SSL_HASH_SHA, "TLS_KRB5_EXPORT_WITH_RC4_40_SHA");
static const SSLCipherSuite Cipher40 =
    SSLCipherSuite(0x0029, SSL_KEYX_KRB5, SSL_AUTH_KRB5, SSL_SYM_DES_CBC_40,
                   SSL_HASH_MD5, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5");
static const SSLCipherSuite Cipher41 =
    SSLCipherSuite(0x002A, SSL_KEYX_KRB5, SSL_AUTH_KRB5, SSL_SYM_RC2_CBC_40,
                   SSL_HASH_MD5, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5");
static const SSLCipherSuite Cipher42 =
    SSLCipherSuite(0x002B, SSL_KEYX_KRB5, SSL_AUTH_KRB5, SSL_SYM_RC4_40,
                   SSL_HASH_MD5, "TLS_KRB5_EXPORT_WITH_RC4_40_MD5");
static const SSLCipherSuite Cipher43 =
    SSLCipherSuite(0x002C, SSL_KEYX_PSK, SSL_AUTH_PSK, SSL_SYM_NULL,
                   SSL_HASH_SHA, "TLS_PSK_WITH_NULL_SHA");
static const SSLCipherSuite Cipher44 =
    SSLCipherSuite(0x002D, SSL_KEYX_DHE, SSL_AUTH_PSK, SSL_SYM_NULL,
                   SSL_HASH_SHA, "TLS_DHE_PSK_WITH_NULL_SHA");
static const SSLCipherSuite Cipher45 =
    SSLCipherSuite(0x002E, SSL_KEYX_RSA, SSL_AUTH_PSK, SSL_SYM_NULL,
                   SSL_HASH_SHA, "TLS_RSA_PSK_WITH_NULL_SHA");
static const SSLCipherSuite Cipher46 =
    SSLCipherSuite(0x002F, SSL_KEYX_RSA, SSL_AUTH_RSA, SSL_SYM_AES_128_CBC,
                   SSL_HASH_SHA, "TLS_RSA_WITH_AES_128_CBC_SHA");
static const SSLCipherSuite Cipher47 =
    SSLCipherSuite(0x0030, SSL_KEYX_DH, SSL_AUTH_DSS, SSL_SYM_AES_128_CBC,
                   SSL_HASH_SHA, "TLS_DH_DSS_WITH_AES_128_CBC_SHA");
static const SSLCipherSuite Cipher48 =
    SSLCipherSuite(0x0031, SSL_KEYX_DH, SSL_AUTH_RSA, SSL_SYM_AES_128_CBC,
                   SSL_HASH_SHA, "TLS_DH_RSA_WITH_AES_128_CBC_SHA");
static const SSLCipherSuite Cipher49 =
    SSLCipherSuite(0x0032, SSL_KEYX_DHE, SSL_AUTH_DSS, SSL_SYM_AES_128_CBC,
                   SSL_HASH_SHA, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA");
static const SSLCipherSuite Cipher50 =
    SSLCipherSuite(0x0033, SSL_KEYX_DHE, SSL_AUTH_RSA, SSL_SYM_AES_128_CBC,
                   SSL_HASH_SHA, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA");
static const SSLCipherSuite Cipher51 =
    SSLCipherSuite(0x0034, SSL_KEYX_DH, SSL_AUTH_anon, SSL_SYM_AES_128_CBC,
                   SSL_HASH_SHA, "TLS_DH_anon_WITH_AES_128_CBC_SHA");
static const SSLCipherSuite Cipher52 =
    SSLCipherSuite(0x0035, SSL_KEYX_RSA, SSL_AUTH_RSA, SSL_SYM_AES_256_CBC,
                   SSL_HASH_SHA, "TLS_RSA_WITH_AES_256_CBC_SHA");
static const SSLCipherSuite Cipher53 =
    SSLCipherSuite(0x0036, SSL_KEYX_DH, SSL_AUTH_DSS, SSL_SYM_AES_256_CBC,
                   SSL_HASH_SHA, "TLS_DH_DSS_WITH_AES_256_CBC_SHA");
static const SSLCipherSuite Cipher54 =
    SSLCipherSuite(0x0037, SSL_KEYX_DH, SSL_AUTH_RSA, SSL_SYM_AES_256_CBC,
                   SSL_HASH_SHA, "TLS_DH_RSA_WITH_AES_256_CBC_SHA");
static const SSLCipherSuite Cipher55 =
    SSLCipherSuite(0x0038, SSL_KEYX_DHE, SSL_AUTH_DSS, SSL_SYM_AES_256_CBC,
                   SSL_HASH_SHA, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA");
static const SSLCipherSuite Cipher56 =
    SSLCipherSuite(0x0039, SSL_KEYX_DHE, SSL_AUTH_RSA, SSL_SYM_AES_256_CBC,
                   SSL_HASH_SHA, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA");
static const SSLCipherSuite Cipher57 =
    SSLCipherSuite(0x003A, SSL_KEYX_DH, SSL_AUTH_anon, SSL_SYM_AES_256_CBC,
                   SSL_HASH_SHA, "TLS_DH_anon_WITH_AES_256_CBC_SHA");
static const SSLCipherSuite Cipher58 =
    SSLCipherSuite(0x003B, SSL_KEYX_RSA, SSL_AUTH_RSA, SSL_SYM_NULL,
                   SSL_HASH_SHA256, "TLS_RSA_WITH_NULL_SHA256");
static const SSLCipherSuite Cipher59 =
    SSLCipherSuite(0x003C, SSL_KEYX_RSA, SSL_AUTH_RSA, SSL_SYM_AES_128_CBC,
                   SSL_HASH_SHA256, "TLS_RSA_WITH_AES_128_CBC_SHA256");
static const SSLCipherSuite Cipher60 =
    SSLCipherSuite(0x003D, SSL_KEYX_RSA, SSL_AUTH_RSA, SSL_SYM_AES_256_CBC,
                   SSL_HASH_SHA256, "TLS_RSA_WITH_AES_256_CBC_SHA256");
static const SSLCipherSuite Cipher61 =
    SSLCipherSuite(0x003E, SSL_KEYX_DH, SSL_AUTH_DSS, SSL_SYM_AES_128_CBC,
                   SSL_HASH_SHA256, "TLS_DH_DSS_WITH_AES_128_CBC_SHA256");
static const SSLCipherSuite Cipher62 =
    SSLCipherSuite(0x003F, SSL_KEYX_DH, SSL_AUTH_RSA, SSL_SYM_AES_128_CBC,
                   SSL_HASH_SHA256, "TLS_DH_RSA_WITH_AES_128_CBC_SHA256");
static const SSLCipherSuite Cipher63 =
    SSLCipherSuite(0x0040, SSL_KEYX_DHE, SSL_AUTH_DSS, SSL_SYM_AES_128_CBC,
                   SSL_HASH_SHA256, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256");
static const SSLCipherSuite Cipher64 =
    SSLCipherSuite(0x0041, SSL_KEYX_RSA, SSL_AUTH_RSA, SSL_SYM_CAMELLIA_128_CBC,
                   SSL_HASH_SHA, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA");
static const SSLCipherSuite Cipher65 =
    SSLCipherSuite(0x0042, SSL_KEYX_DH, SSL_AUTH_DSS, SSL_SYM_CAMELLIA_128_CBC,
                   SSL_HASH_SHA, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA");
static const SSLCipherSuite Cipher66 =
    SSLCipherSuite(0x0043, SSL_KEYX_DH, SSL_AUTH_RSA, SSL_SYM_CAMELLIA_128_CBC,
                   SSL_HASH_SHA, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA");
static const SSLCipherSuite Cipher67 =
    SSLCipherSuite(0x0044, SSL_KEYX_DHE, SSL_AUTH_DSS, SSL_SYM_CAMELLIA_128_CBC,
                   SSL_HASH_SHA, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA");
static const SSLCipherSuite Cipher68 =
    SSLCipherSuite(0x0045, SSL_KEYX_DHE, SSL_AUTH_RSA, SSL_SYM_CAMELLIA_128_CBC,
                   SSL_HASH_SHA, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA");
static const SSLCipherSuite Cipher69 =
    SSLCipherSuite(0x0046, SSL_KEYX_DH, SSL_AUTH_anon, SSL_SYM_CAMELLIA_128_CBC,
                   SSL_HASH_SHA, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA");
static const SSLCipherSuite Cipher70 =
    SSLCipherSuite(0x0067, SSL_KEYX_DHE, SSL_AUTH_RSA, SSL_SYM_AES_128_CBC,
                   SSL_HASH_SHA256, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256");
static const SSLCipherSuite Cipher71 =
    SSLCipherSuite(0x0068, SSL_KEYX_DH, SSL_AUTH_DSS, SSL_SYM_AES_256_CBC,
                   SSL_HASH_SHA256, "TLS_DH_DSS_WITH_AES_256_CBC_SHA256");
static const SSLCipherSuite Cipher72 =
    SSLCipherSuite(0x0069, SSL_KEYX_DH, SSL_AUTH_RSA, SSL_SYM_AES_256_CBC,
                   SSL_HASH_SHA256, "TLS_DH_RSA_WITH_AES_256_CBC_SHA256");
static const SSLCipherSuite Cipher73 =
    SSLCipherSuite(0x006A, SSL_KEYX_DHE, SSL_AUTH_DSS, SSL_SYM_AES_256_CBC,
                   SSL_HASH_SHA256, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256");
static const SSLCipherSuite Cipher74 =
    SSLCipherSuite(0x006B, SSL_KEYX_DHE, SSL_AUTH_RSA, SSL_SYM_AES_256_CBC,
                   SSL_HASH_SHA256, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256");
static const SSLCipherSuite Cipher75 =
    SSLCipherSuite(0x006C, SSL_KEYX_DH, SSL_AUTH_anon, SSL_SYM_AES_128_CBC,
                   SSL_HASH_SHA256, "TLS_DH_anon_WITH_AES_128_CBC_SHA256");
static const SSLCipherSuite Cipher76 =
    SSLCipherSuite(0x006D, SSL_KEYX_DH, SSL_AUTH_anon, SSL_SYM_AES_256_CBC,
                   SSL_HASH_SHA256, "TLS_DH_anon_WITH_AES_256_CBC_SHA256");
static const SSLCipherSuite Cipher77 =
    SSLCipherSuite(0x0084, SSL_KEYX_RSA, SSL_AUTH_RSA, SSL_SYM_CAMELLIA_256_CBC,
                   SSL_HASH_SHA, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA");
static const SSLCipherSuite Cipher78 =
    SSLCipherSuite(0x0085, SSL_KEYX_DH, SSL_AUTH_DSS, SSL_SYM_CAMELLIA_256_CBC,
                   SSL_HASH_SHA, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA");
static const SSLCipherSuite Cipher79 =
    SSLCipherSuite(0x0086, SSL_KEYX_DH, SSL_AUTH_RSA, SSL_SYM_CAMELLIA_256_CBC,
                   SSL_HASH_SHA, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA");
static const SSLCipherSuite Cipher80 =
    SSLCipherSuite(0x0087, SSL_KEYX_DHE, SSL_AUTH_DSS, SSL_SYM_CAMELLIA_256_CBC,
                   SSL_HASH_SHA, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA");
static const SSLCipherSuite Cipher81 =
    SSLCipherSuite(0x0088, SSL_KEYX_DHE, SSL_AUTH_RSA, SSL_SYM_CAMELLIA_256_CBC,
                   SSL_HASH_SHA, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA");
static const SSLCipherSuite Cipher82 =
    SSLCipherSuite(0x0089, SSL_KEYX_DH, SSL_AUTH_anon, SSL_SYM_CAMELLIA_256_CBC,
                   SSL_HASH_SHA, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA");
static const SSLCipherSuite Cipher83 =
    SSLCipherSuite(0x008A, SSL_KEYX_PSK, SSL_AUTH_PSK, SSL_SYM_RC4_128,
                   SSL_HASH_SHA, "TLS_PSK_WITH_RC4_128_SHA");
static const SSLCipherSuite Cipher84 =
    SSLCipherSuite(0x008B, SSL_KEYX_PSK, SSL_AUTH_PSK, SSL_SYM_3DES_EDE_CBC,
                   SSL_HASH_SHA, "TLS_PSK_WITH_3DES_EDE_CBC_SHA");
static const SSLCipherSuite Cipher85 =
    SSLCipherSuite(0x008C, SSL_KEYX_PSK, SSL_AUTH_PSK, SSL_SYM_AES_128_CBC,
                   SSL_HASH_SHA, "TLS_PSK_WITH_AES_128_CBC_SHA");
static const SSLCipherSuite Cipher86 =
    SSLCipherSuite(0x008D, SSL_KEYX_PSK, SSL_AUTH_PSK, SSL_SYM_AES_256_CBC,
                   SSL_HASH_SHA, "TLS_PSK_WITH_AES_256_CBC_SHA");
static const SSLCipherSuite Cipher87 =
    SSLCipherSuite(0x008E, SSL_KEYX_DHE, SSL_AUTH_PSK, SSL_SYM_RC4_128,
                   SSL_HASH_SHA, "TLS_DHE_PSK_WITH_RC4_128_SHA");
static const SSLCipherSuite Cipher88 =
    SSLCipherSuite(0x008F, SSL_KEYX_DHE, SSL_AUTH_PSK, SSL_SYM_3DES_EDE_CBC,
                   SSL_HASH_SHA, "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA");
static const SSLCipherSuite Cipher89 =
    SSLCipherSuite(0x0090, SSL_KEYX_DHE, SSL_AUTH_PSK, SSL_SYM_AES_128_CBC,
                   SSL_HASH_SHA, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA");
static const SSLCipherSuite Cipher90 =
    SSLCipherSuite(0x0091, SSL_KEYX_DHE, SSL_AUTH_PSK, SSL_SYM_AES_256_CBC,
                   SSL_HASH_SHA, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA");
static const SSLCipherSuite Cipher91 =
    SSLCipherSuite(0x0092, SSL_KEYX_RSA, SSL_AUTH_PSK, SSL_SYM_RC4_128,
                   SSL_HASH_SHA, "TLS_RSA_PSK_WITH_RC4_128_SHA");
static const SSLCipherSuite Cipher92 =
    SSLCipherSuite(0x0093, SSL_KEYX_RSA, SSL_AUTH_PSK, SSL_SYM_3DES_EDE_CBC,
                   SSL_HASH_SHA, "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA");
static const SSLCipherSuite Cipher93 =
    SSLCipherSuite(0x0094, SSL_KEYX_RSA, SSL_AUTH_PSK, SSL_SYM_AES_128_CBC,
                   SSL_HASH_SHA, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA");
static const SSLCipherSuite Cipher94 =
    SSLCipherSuite(0x0095, SSL_KEYX_RSA, SSL_AUTH_PSK, SSL_SYM_AES_256_CBC,
                   SSL_HASH_SHA, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA");
static const SSLCipherSuite Cipher95 =
    SSLCipherSuite(0x0096, SSL_KEYX_RSA, SSL_AUTH_RSA, SSL_SYM_SEED_CBC,
                   SSL_HASH_SHA, "TLS_RSA_WITH_SEED_CBC_SHA");
static const SSLCipherSuite Cipher96 =
    SSLCipherSuite(0x0097, SSL_KEYX_DH, SSL_AUTH_DSS, SSL_SYM_SEED_CBC,
                   SSL_HASH_SHA, "TLS_DH_DSS_WITH_SEED_CBC_SHA");
static const SSLCipherSuite Cipher97 =
    SSLCipherSuite(0x0098, SSL_KEYX_DH, SSL_AUTH_RSA, SSL_SYM_SEED_CBC,
                   SSL_HASH_SHA, "TLS_DH_RSA_WITH_SEED_CBC_SHA");
static const SSLCipherSuite Cipher98 =
    SSLCipherSuite(0x0099, SSL_KEYX_DHE, SSL_AUTH_DSS, SSL_SYM_SEED_CBC,
                   SSL_HASH_SHA, "TLS_DHE_DSS_WITH_SEED_CBC_SHA");
static const SSLCipherSuite Cipher99 =
    SSLCipherSuite(0x009A, SSL_KEYX_DHE, SSL_AUTH_RSA, SSL_SYM_SEED_CBC,
                   SSL_HASH_SHA, "TLS_DHE_RSA_WITH_SEED_CBC_SHA");
static const SSLCipherSuite Cipher100 =
    SSLCipherSuite(0x009B, SSL_KEYX_DH, SSL_AUTH_anon, SSL_SYM_SEED_CBC,
                   SSL_HASH_SHA, "TLS_DH_anon_WITH_SEED_CBC_SHA");
static const SSLCipherSuite Cipher101 =
    SSLCipherSuite(0x009C, SSL_KEYX_RSA, SSL_AUTH_RSA, SSL_SYM_AES_128_GCM,
                   SSL_HASH_SHA256, "TLS_RSA_WITH_AES_128_GCM_SHA256");
static const SSLCipherSuite Cipher102 =
    SSLCipherSuite(0x009D, SSL_KEYX_RSA, SSL_AUTH_RSA, SSL_SYM_AES_256_GCM,
                   SSL_HASH_SHA384, "TLS_RSA_WITH_AES_256_GCM_SHA384");
static const SSLCipherSuite Cipher103 =
    SSLCipherSuite(0x009E, SSL_KEYX_DHE, SSL_AUTH_RSA, SSL_SYM_AES_128_GCM,
                   SSL_HASH_SHA256, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256");
static const SSLCipherSuite Cipher104 =
    SSLCipherSuite(0x009F, SSL_KEYX_DHE, SSL_AUTH_RSA, SSL_SYM_AES_256_GCM,
                   SSL_HASH_SHA384, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384");
static const SSLCipherSuite Cipher105 =
    SSLCipherSuite(0x00A0, SSL_KEYX_DH, SSL_AUTH_RSA, SSL_SYM_AES_128_GCM,
                   SSL_HASH_SHA256, "TLS_DH_RSA_WITH_AES_128_GCM_SHA256");
static const SSLCipherSuite Cipher106 =
    SSLCipherSuite(0x00A1, SSL_KEYX_DH, SSL_AUTH_RSA, SSL_SYM_AES_256_GCM,
                   SSL_HASH_SHA384, "TLS_DH_RSA_WITH_AES_256_GCM_SHA384");
static const SSLCipherSuite Cipher107 =
    SSLCipherSuite(0x00A2, SSL_KEYX_DHE, SSL_AUTH_DSS, SSL_SYM_AES_128_GCM,
                   SSL_HASH_SHA256, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256");
static const SSLCipherSuite Cipher108 =
    SSLCipherSuite(0x00A3, SSL_KEYX_DHE, SSL_AUTH_DSS, SSL_SYM_AES_256_GCM,
                   SSL_HASH_SHA384, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384");
static const SSLCipherSuite Cipher109 =
    SSLCipherSuite(0x00A4, SSL_KEYX_DH, SSL_AUTH_DSS, SSL_SYM_AES_128_GCM,
                   SSL_HASH_SHA256, "TLS_DH_DSS_WITH_AES_128_GCM_SHA256");
static const SSLCipherSuite Cipher110 =
    SSLCipherSuite(0x00A5, SSL_KEYX_DH, SSL_AUTH_DSS, SSL_SYM_AES_256_GCM,
                   SSL_HASH_SHA384, "TLS_DH_DSS_WITH_AES_256_GCM_SHA384");
static const SSLCipherSuite Cipher111 =
    SSLCipherSuite(0x00A6, SSL_KEYX_DH, SSL_AUTH_anon, SSL_SYM_AES_128_GCM,
                   SSL_HASH_SHA256, "TLS_DH_anon_WITH_AES_128_GCM_SHA256");
static const SSLCipherSuite Cipher112 =
    SSLCipherSuite(0x00A7, SSL_KEYX_DH, SSL_AUTH_anon, SSL_SYM_AES_256_GCM,
                   SSL_HASH_SHA384, "TLS_DH_anon_WITH_AES_256_GCM_SHA384");
static const SSLCipherSuite Cipher113 =
    SSLCipherSuite(0x00A8, SSL_KEYX_PSK, SSL_AUTH_PSK, SSL_SYM_AES_128_GCM,
                   SSL_HASH_SHA256, "TLS_PSK_WITH_AES_128_GCM_SHA256");
static const SSLCipherSuite Cipher114 =
    SSLCipherSuite(0x00A9, SSL_KEYX_PSK, SSL_AUTH_PSK, SSL_SYM_AES_256_GCM,
                   SSL_HASH_SHA384, "TLS_PSK_WITH_AES_256_GCM_SHA384");
static const SSLCipherSuite Cipher115 =
    SSLCipherSuite(0x00AA, SSL_KEYX_DHE, SSL_AUTH_PSK, SSL_SYM_AES_128_GCM,
                   SSL_HASH_SHA256, "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256");
static const SSLCipherSuite Cipher116 =
    SSLCipherSuite(0x00AB, SSL_KEYX_DHE, SSL_AUTH_PSK, SSL_SYM_AES_256_GCM,
                   SSL_HASH_SHA384, "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384");
static const SSLCipherSuite Cipher117 =
    SSLCipherSuite(0x00AC, SSL_KEYX_RSA, SSL_AUTH_PSK, SSL_SYM_AES_128_GCM,
                   SSL_HASH_SHA256, "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256");
static const SSLCipherSuite Cipher118 =
    SSLCipherSuite(0x00AD, SSL_KEYX_RSA, SSL_AUTH_PSK, SSL_SYM_AES_256_GCM,
                   SSL_HASH_SHA384, "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384");
static const SSLCipherSuite Cipher119 =
    SSLCipherSuite(0x00AE, SSL_KEYX_PSK, SSL_AUTH_PSK, SSL_SYM_AES_128_CBC,
                   SSL_HASH_SHA256, "TLS_PSK_WITH_AES_128_CBC_SHA256");
static const SSLCipherSuite Cipher120 =
    SSLCipherSuite(0x00AF, SSL_KEYX_PSK, SSL_AUTH_PSK, SSL_SYM_AES_256_CBC,
                   SSL_HASH_SHA384, "TLS_PSK_WITH_AES_256_CBC_SHA384");
static const SSLCipherSuite Cipher121 =
    SSLCipherSuite(0x00B0, SSL_KEYX_PSK, SSL_AUTH_PSK, SSL_SYM_NULL,
                   SSL_HASH_SHA256, "TLS_PSK_WITH_NULL_SHA256");
static const SSLCipherSuite Cipher122 =
    SSLCipherSuite(0x00B1, SSL_KEYX_PSK, SSL_AUTH_PSK, SSL_SYM_NULL,
                   SSL_HASH_SHA384, "TLS_PSK_WITH_NULL_SHA384");
static const SSLCipherSuite Cipher123 =
    SSLCipherSuite(0x00B2, SSL_KEYX_DHE, SSL_AUTH_PSK, SSL_SYM_AES_128_CBC,
                   SSL_HASH_SHA256, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256");
static const SSLCipherSuite Cipher124 =
    SSLCipherSuite(0x00B3, SSL_KEYX_DHE, SSL_AUTH_PSK, SSL_SYM_AES_256_CBC,
                   SSL_HASH_SHA384, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384");
static const SSLCipherSuite Cipher125 =
    SSLCipherSuite(0x00B4, SSL_KEYX_DHE, SSL_AUTH_PSK, SSL_SYM_NULL,
                   SSL_HASH_SHA256, "TLS_DHE_PSK_WITH_NULL_SHA256");
static const SSLCipherSuite Cipher126 =
    SSLCipherSuite(0x00B5, SSL_KEYX_DHE, SSL_AUTH_PSK, SSL_SYM_NULL,
                   SSL_HASH_SHA384, "TLS_DHE_PSK_WITH_NULL_SHA384");
static const SSLCipherSuite Cipher127 =
    SSLCipherSuite(0x00B6, SSL_KEYX_RSA, SSL_AUTH_PSK, SSL_SYM_AES_128_CBC,
                   SSL_HASH_SHA256, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256");
static const SSLCipherSuite Cipher128 =
    SSLCipherSuite(0x00B7, SSL_KEYX_RSA, SSL_AUTH_PSK, SSL_SYM_AES_256_CBC,
                   SSL_HASH_SHA384, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384");
static const SSLCipherSuite Cipher129 =
    SSLCipherSuite(0x00B8, SSL_KEYX_RSA, SSL_AUTH_PSK, SSL_SYM_NULL,
                   SSL_HASH_SHA256, "TLS_RSA_PSK_WITH_NULL_SHA256");
static const SSLCipherSuite Cipher130 =
    SSLCipherSuite(0x00B9, SSL_KEYX_RSA, SSL_AUTH_PSK, SSL_SYM_NULL,
                   SSL_HASH_SHA384, "TLS_RSA_PSK_WITH_NULL_SHA384");
static const SSLCipherSuite Cipher131 =
    SSLCipherSuite(0x00BA, SSL_KEYX_RSA, SSL_AUTH_RSA, SSL_SYM_CAMELLIA_128_CBC,
                   SSL_HASH_SHA256, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256");
static const SSLCipherSuite Cipher132 =
    SSLCipherSuite(0x00BB, SSL_KEYX_DH, SSL_AUTH_DSS, SSL_SYM_CAMELLIA_128_CBC,
                   SSL_HASH_SHA256, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256");
static const SSLCipherSuite Cipher133 =
    SSLCipherSuite(0x00BC, SSL_KEYX_DH, SSL_AUTH_RSA, SSL_SYM_CAMELLIA_128_CBC,
                   SSL_HASH_SHA256, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256");
static const SSLCipherSuite Cipher134 =
    SSLCipherSuite(0x00BD, SSL_KEYX_DHE, SSL_AUTH_DSS, SSL_SYM_CAMELLIA_128_CBC,
                   SSL_HASH_SHA256, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256");
static const SSLCipherSuite Cipher135 =
    SSLCipherSuite(0x00BE, SSL_KEYX_DHE, SSL_AUTH_RSA, SSL_SYM_CAMELLIA_128_CBC,
                   SSL_HASH_SHA256, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256");
static const SSLCipherSuite Cipher136 =
    SSLCipherSuite(0x00BF, SSL_KEYX_DH, SSL_AUTH_anon, SSL_SYM_CAMELLIA_128_CBC,
                   SSL_HASH_SHA256, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256");
static const SSLCipherSuite Cipher137 =
    SSLCipherSuite(0x00C0, SSL_KEYX_RSA, SSL_AUTH_RSA, SSL_SYM_CAMELLIA_256_CBC,
                   SSL_HASH_SHA256, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256");
static const SSLCipherSuite Cipher138 =
    SSLCipherSuite(0x00C1, SSL_KEYX_DH, SSL_AUTH_DSS, SSL_SYM_CAMELLIA_256_CBC,
                   SSL_HASH_SHA256, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256");
static const SSLCipherSuite Cipher139 =
    SSLCipherSuite(0x00C2, SSL_KEYX_DH, SSL_AUTH_RSA, SSL_SYM_CAMELLIA_256_CBC,
                   SSL_HASH_SHA256, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256");
static const SSLCipherSuite Cipher140 =
    SSLCipherSuite(0x00C3, SSL_KEYX_DHE, SSL_AUTH_DSS, SSL_SYM_CAMELLIA_256_CBC,
                   SSL_HASH_SHA256, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256");
static const SSLCipherSuite Cipher141 =
    SSLCipherSuite(0x00C4, SSL_KEYX_DHE, SSL_AUTH_RSA, SSL_SYM_CAMELLIA_256_CBC,
                   SSL_HASH_SHA256, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256");
static const SSLCipherSuite Cipher142 =
    SSLCipherSuite(0x00C5, SSL_KEYX_DH, SSL_AUTH_anon, SSL_SYM_CAMELLIA_256_CBC,
                   SSL_HASH_SHA256, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256");
static const SSLCipherSuite Cipher143 =
    SSLCipherSuite(0xC001, SSL_KEYX_ECDH, SSL_AUTH_ECDSA, SSL_SYM_NULL,
                   SSL_HASH_SHA, "TLS_ECDH_ECDSA_WITH_NULL_SHA");
static const SSLCipherSuite Cipher144 =
    SSLCipherSuite(0xC002, SSL_KEYX_ECDH, SSL_AUTH_ECDSA, SSL_SYM_RC4_128,
                   SSL_HASH_SHA, "TLS_ECDH_ECDSA_WITH_RC4_128_SHA");
static const SSLCipherSuite Cipher145 =
    SSLCipherSuite(0xC003, SSL_KEYX_ECDH, SSL_AUTH_ECDSA, SSL_SYM_3DES_EDE_CBC,
                   SSL_HASH_SHA, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA");
static const SSLCipherSuite Cipher146 =
    SSLCipherSuite(0xC004, SSL_KEYX_ECDH, SSL_AUTH_ECDSA, SSL_SYM_AES_128_CBC,
                   SSL_HASH_SHA, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA");
static const SSLCipherSuite Cipher147 =
    SSLCipherSuite(0xC005, SSL_KEYX_ECDH, SSL_AUTH_ECDSA, SSL_SYM_AES_256_CBC,
                   SSL_HASH_SHA, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA");
static const SSLCipherSuite Cipher148 =
    SSLCipherSuite(0xC006, SSL_KEYX_ECDHE, SSL_AUTH_ECDSA, SSL_SYM_NULL,
                   SSL_HASH_SHA, "TLS_ECDHE_ECDSA_WITH_NULL_SHA");
static const SSLCipherSuite Cipher149 =
    SSLCipherSuite(0xC007, SSL_KEYX_ECDHE, SSL_AUTH_ECDSA, SSL_SYM_RC4_128,
                   SSL_HASH_SHA, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA");
static const SSLCipherSuite Cipher150 =
    SSLCipherSuite(0xC008, SSL_KEYX_ECDHE, SSL_AUTH_ECDSA, SSL_SYM_3DES_EDE_CBC,
                   SSL_HASH_SHA, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA");
static const SSLCipherSuite Cipher151 =
    SSLCipherSuite(0xC009, SSL_KEYX_ECDHE, SSL_AUTH_ECDSA, SSL_SYM_AES_128_CBC,
                   SSL_HASH_SHA, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA");
static const SSLCipherSuite Cipher152 =
    SSLCipherSuite(0xC00A, SSL_KEYX_ECDHE, SSL_AUTH_ECDSA, SSL_SYM_AES_256_CBC,
                   SSL_HASH_SHA, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA");
static const SSLCipherSuite Cipher153 =
    SSLCipherSuite(0xC00B, SSL_KEYX_ECDH, SSL_AUTH_RSA, SSL_SYM_NULL,
                   SSL_HASH_SHA, "TLS_ECDH_RSA_WITH_NULL_SHA");
static const SSLCipherSuite Cipher154 =
    SSLCipherSuite(0xC00C, SSL_KEYX_ECDH, SSL_AUTH_RSA, SSL_SYM_RC4_128,
                   SSL_HASH_SHA, "TLS_ECDH_RSA_WITH_RC4_128_SHA");
static const SSLCipherSuite Cipher155 =
    SSLCipherSuite(0xC00D, SSL_KEYX_ECDH, SSL_AUTH_RSA, SSL_SYM_3DES_EDE_CBC,
                   SSL_HASH_SHA, "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA");
static const SSLCipherSuite Cipher156 =
    SSLCipherSuite(0xC00E, SSL_KEYX_ECDH, SSL_AUTH_RSA, SSL_SYM_AES_128_CBC,
                   SSL_HASH_SHA, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA");
static const SSLCipherSuite Cipher157 =
    SSLCipherSuite(0xC00F, SSL_KEYX_ECDH, SSL_AUTH_RSA, SSL_SYM_AES_256_CBC,
                   SSL_HASH_SHA, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA");
static const SSLCipherSuite Cipher158 =
    SSLCipherSuite(0xC010, SSL_KEYX_ECDHE, SSL_AUTH_RSA, SSL_SYM_NULL,
                   SSL_HASH_SHA, "TLS_ECDHE_RSA_WITH_NULL_SHA");
static const SSLCipherSuite Cipher159 =
    SSLCipherSuite(0xC011, SSL_KEYX_ECDHE, SSL_AUTH_RSA, SSL_SYM_RC4_128,
                   SSL_HASH_SHA, "TLS_ECDHE_RSA_WITH_RC4_128_SHA");
static const SSLCipherSuite Cipher160 =
    SSLCipherSuite(0xC012, SSL_KEYX_ECDHE, SSL_AUTH_RSA, SSL_SYM_3DES_EDE_CBC,
                   SSL_HASH_SHA, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA");
static const SSLCipherSuite Cipher161 =
    SSLCipherSuite(0xC013, SSL_KEYX_ECDHE, SSL_AUTH_RSA, SSL_SYM_AES_128_CBC,
                   SSL_HASH_SHA, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA");
static const SSLCipherSuite Cipher162 =
    SSLCipherSuite(0xC014, SSL_KEYX_ECDHE, SSL_AUTH_RSA, SSL_SYM_AES_256_CBC,
                   SSL_HASH_SHA, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA");
static const SSLCipherSuite Cipher163 =
    SSLCipherSuite(0xC015, SSL_KEYX_ECDH, SSL_AUTH_anon, SSL_SYM_NULL,
                   SSL_HASH_SHA, "TLS_ECDH_anon_WITH_NULL_SHA");
static const SSLCipherSuite Cipher164 =
    SSLCipherSuite(0xC016, SSL_KEYX_ECDH, SSL_AUTH_anon, SSL_SYM_RC4_128,
                   SSL_HASH_SHA, "TLS_ECDH_anon_WITH_RC4_128_SHA");
static const SSLCipherSuite Cipher165 =
    SSLCipherSuite(0xC017, SSL_KEYX_ECDH, SSL_AUTH_anon, SSL_SYM_3DES_EDE_CBC,
                   SSL_HASH_SHA, "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA");
static const SSLCipherSuite Cipher166 =
    SSLCipherSuite(0xC018, SSL_KEYX_ECDH, SSL_AUTH_anon, SSL_SYM_AES_128_CBC,
                   SSL_HASH_SHA, "TLS_ECDH_anon_WITH_AES_128_CBC_SHA");
static const SSLCipherSuite Cipher167 =
    SSLCipherSuite(0xC019, SSL_KEYX_ECDH, SSL_AUTH_anon, SSL_SYM_AES_256_CBC,
                   SSL_HASH_SHA, "TLS_ECDH_anon_WITH_AES_256_CBC_SHA");
static const SSLCipherSuite Cipher168 =
    SSLCipherSuite(0xC01A, SSL_KEYX_SRP, SSL_AUTH_SHA, SSL_SYM_3DES_EDE_CBC,
                   SSL_HASH_SHA, "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA");
static const SSLCipherSuite Cipher169 =
    SSLCipherSuite(0xC01B, SSL_KEYX_SRP, SSL_AUTH_RSA, SSL_SYM_3DES_EDE_CBC,
                   SSL_HASH_SHA, "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA");
static const SSLCipherSuite Cipher170 =
    SSLCipherSuite(0xC01C, SSL_KEYX_SRP, SSL_AUTH_DSS, SSL_SYM_3DES_EDE_CBC,
                   SSL_HASH_SHA, "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA");
static const SSLCipherSuite Cipher171 =
    SSLCipherSuite(0xC01D, SSL_KEYX_SRP, SSL_AUTH_SHA, SSL_SYM_AES_128_CBC,
                   SSL_HASH_SHA, "TLS_SRP_SHA_WITH_AES_128_CBC_SHA");
static const SSLCipherSuite Cipher172 =
    SSLCipherSuite(0xC01E, SSL_KEYX_SRP, SSL_AUTH_RSA, SSL_SYM_AES_128_CBC,
                   SSL_HASH_SHA, "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA");
static const SSLCipherSuite Cipher173 =
    SSLCipherSuite(0xC01F, SSL_KEYX_SRP, SSL_AUTH_DSS, SSL_SYM_AES_128_CBC,
                   SSL_HASH_SHA, "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA");
static const SSLCipherSuite Cipher174 =
    SSLCipherSuite(0xC020, SSL_KEYX_SRP, SSL_AUTH_SHA, SSL_SYM_AES_256_CBC,
                   SSL_HASH_SHA, "TLS_SRP_SHA_WITH_AES_256_CBC_SHA");
static const SSLCipherSuite Cipher175 =
    SSLCipherSuite(0xC021, SSL_KEYX_SRP, SSL_AUTH_RSA, SSL_SYM_AES_256_CBC,
                   SSL_HASH_SHA, "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA");
static const SSLCipherSuite Cipher176 =
    SSLCipherSuite(0xC022, SSL_KEYX_SRP, SSL_AUTH_DSS, SSL_SYM_AES_256_CBC,
                   SSL_HASH_SHA, "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA");
static const SSLCipherSuite Cipher177 =
    SSLCipherSuite(0xC023, SSL_KEYX_ECDHE, SSL_AUTH_ECDSA, SSL_SYM_AES_128_CBC,
                   SSL_HASH_SHA256, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256");
static const SSLCipherSuite Cipher178 =
    SSLCipherSuite(0xC024, SSL_KEYX_ECDHE, SSL_AUTH_ECDSA, SSL_SYM_AES_256_CBC,
                   SSL_HASH_SHA384, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384");
static const SSLCipherSuite Cipher179 =
    SSLCipherSuite(0xC025, SSL_KEYX_ECDH, SSL_AUTH_ECDSA, SSL_SYM_AES_128_CBC,
                   SSL_HASH_SHA256, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256");
static const SSLCipherSuite Cipher180 =
    SSLCipherSuite(0xC026, SSL_KEYX_ECDH, SSL_AUTH_ECDSA, SSL_SYM_AES_256_CBC,
                   SSL_HASH_SHA384, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384");
static const SSLCipherSuite Cipher181 =
    SSLCipherSuite(0xC027, SSL_KEYX_ECDHE, SSL_AUTH_RSA, SSL_SYM_AES_128_CBC,
                   SSL_HASH_SHA256, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256");
static const SSLCipherSuite Cipher182 =
    SSLCipherSuite(0xC028, SSL_KEYX_ECDHE, SSL_AUTH_RSA, SSL_SYM_AES_256_CBC,
                   SSL_HASH_SHA384, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384");
static const SSLCipherSuite Cipher183 =
    SSLCipherSuite(0xC029, SSL_KEYX_ECDH, SSL_AUTH_RSA, SSL_SYM_AES_128_CBC,
                   SSL_HASH_SHA256, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256");
static const SSLCipherSuite Cipher184 =
    SSLCipherSuite(0xC02A, SSL_KEYX_ECDH, SSL_AUTH_RSA, SSL_SYM_AES_256_CBC,
                   SSL_HASH_SHA384, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384");
static const SSLCipherSuite Cipher185 =
    SSLCipherSuite(0xC02B, SSL_KEYX_ECDHE, SSL_AUTH_ECDSA, SSL_SYM_AES_128_GCM,
                   SSL_HASH_SHA256, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
static const SSLCipherSuite Cipher186 =
    SSLCipherSuite(0xC02C, SSL_KEYX_ECDHE, SSL_AUTH_ECDSA, SSL_SYM_AES_256_GCM,
                   SSL_HASH_SHA384, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");
static const SSLCipherSuite Cipher187 =
    SSLCipherSuite(0xC02D, SSL_KEYX_ECDH, SSL_AUTH_ECDSA, SSL_SYM_AES_128_GCM,
                   SSL_HASH_SHA256, "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256");
static const SSLCipherSuite Cipher188 =
    SSLCipherSuite(0xC02E, SSL_KEYX_ECDH, SSL_AUTH_ECDSA, SSL_SYM_AES_256_GCM,
                   SSL_HASH_SHA384, "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384");
static const SSLCipherSuite Cipher189 =
    SSLCipherSuite(0xC02F, SSL_KEYX_ECDHE, SSL_AUTH_RSA, SSL_SYM_AES_128_GCM,
                   SSL_HASH_SHA256, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
static const SSLCipherSuite Cipher190 =
    SSLCipherSuite(0xC030, SSL_KEYX_ECDHE, SSL_AUTH_RSA, SSL_SYM_AES_256_GCM,
                   SSL_HASH_SHA384, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
static const SSLCipherSuite Cipher191 =
    SSLCipherSuite(0xC031, SSL_KEYX_ECDH, SSL_AUTH_RSA, SSL_SYM_AES_128_GCM,
                   SSL_HASH_SHA256, "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256");
static const SSLCipherSuite Cipher192 =
    SSLCipherSuite(0xC032, SSL_KEYX_ECDH, SSL_AUTH_RSA, SSL_SYM_AES_256_GCM,
                   SSL_HASH_SHA384, "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384");
static const SSLCipherSuite Cipher193 =
    SSLCipherSuite(0xC033, SSL_KEYX_ECDHE, SSL_AUTH_PSK, SSL_SYM_RC4_128,
                   SSL_HASH_SHA, "TLS_ECDHE_PSK_WITH_RC4_128_SHA");
static const SSLCipherSuite Cipher194 =
    SSLCipherSuite(0xC034, SSL_KEYX_ECDHE, SSL_AUTH_PSK, SSL_SYM_3DES_EDE_CBC,
                   SSL_HASH_SHA, "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA");
static const SSLCipherSuite Cipher195 =
    SSLCipherSuite(0xC035, SSL_KEYX_ECDHE, SSL_AUTH_PSK, SSL_SYM_AES_128_CBC,
                   SSL_HASH_SHA, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA");
static const SSLCipherSuite Cipher196 =
    SSLCipherSuite(0xC036, SSL_KEYX_ECDHE, SSL_AUTH_PSK, SSL_SYM_AES_256_CBC,
                   SSL_HASH_SHA, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA");
static const SSLCipherSuite Cipher197 =
    SSLCipherSuite(0xC037, SSL_KEYX_ECDHE, SSL_AUTH_PSK, SSL_SYM_AES_128_CBC,
                   SSL_HASH_SHA256, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256");
static const SSLCipherSuite Cipher198 =
    SSLCipherSuite(0xC038, SSL_KEYX_ECDHE, SSL_AUTH_PSK, SSL_SYM_AES_256_CBC,
                   SSL_HASH_SHA384, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384");
static const SSLCipherSuite Cipher199 =
    SSLCipherSuite(0xC039, SSL_KEYX_ECDHE, SSL_AUTH_PSK, SSL_SYM_NULL,
                   SSL_HASH_SHA, "TLS_ECDHE_PSK_WITH_NULL_SHA");
static const SSLCipherSuite Cipher200 =
    SSLCipherSuite(0xC03A, SSL_KEYX_ECDHE, SSL_AUTH_PSK, SSL_SYM_NULL,
                   SSL_HASH_SHA256, "TLS_ECDHE_PSK_WITH_NULL_SHA256");
static const SSLCipherSuite Cipher201 =
    SSLCipherSuite(0xC03B, SSL_KEYX_ECDHE, SSL_AUTH_PSK, SSL_SYM_NULL,
                   SSL_HASH_SHA384, "TLS_ECDHE_PSK_WITH_NULL_SHA384");
static const SSLCipherSuite Cipher202 =
    SSLCipherSuite(0xC03C, SSL_KEYX_RSA, SSL_AUTH_RSA, SSL_SYM_ARIA_128_CBC,
                   SSL_HASH_SHA256, "TLS_RSA_WITH_ARIA_128_CBC_SHA256");
static const SSLCipherSuite Cipher203 =
    SSLCipherSuite(0xC03D, SSL_KEYX_RSA, SSL_AUTH_RSA, SSL_SYM_ARIA_256_CBC,
                   SSL_HASH_SHA384, "TLS_RSA_WITH_ARIA_256_CBC_SHA384");
static const SSLCipherSuite Cipher204 =
    SSLCipherSuite(0xC03E, SSL_KEYX_DH, SSL_AUTH_DSS, SSL_SYM_ARIA_128_CBC,
                   SSL_HASH_SHA256, "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256");
static const SSLCipherSuite Cipher205 =
    SSLCipherSuite(0xC03F, SSL_KEYX_DH, SSL_AUTH_DSS, SSL_SYM_ARIA_256_CBC,
                   SSL_HASH_SHA384, "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384");
static const SSLCipherSuite Cipher206 =
    SSLCipherSuite(0xC040, SSL_KEYX_DH, SSL_AUTH_RSA, SSL_SYM_ARIA_128_CBC,
                   SSL_HASH_SHA256, "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256");
static const SSLCipherSuite Cipher207 =
    SSLCipherSuite(0xC041, SSL_KEYX_DH, SSL_AUTH_RSA, SSL_SYM_ARIA_256_CBC,
                   SSL_HASH_SHA384, "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384");
static const SSLCipherSuite Cipher208 =
    SSLCipherSuite(0xC042, SSL_KEYX_DHE, SSL_AUTH_DSS, SSL_SYM_ARIA_128_CBC,
                   SSL_HASH_SHA256, "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256");
static const SSLCipherSuite Cipher209 =
    SSLCipherSuite(0xC043, SSL_KEYX_DHE, SSL_AUTH_DSS, SSL_SYM_ARIA_256_CBC,
                   SSL_HASH_SHA384, "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384");
static const SSLCipherSuite Cipher210 =
    SSLCipherSuite(0xC044, SSL_KEYX_DHE, SSL_AUTH_RSA, SSL_SYM_ARIA_128_CBC,
                   SSL_HASH_SHA256, "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256");
static const SSLCipherSuite Cipher211 =
    SSLCipherSuite(0xC045, SSL_KEYX_DHE, SSL_AUTH_RSA, SSL_SYM_ARIA_256_CBC,
                   SSL_HASH_SHA384, "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384");
static const SSLCipherSuite Cipher212 =
    SSLCipherSuite(0xC046, SSL_KEYX_DH, SSL_AUTH_anon, SSL_SYM_ARIA_128_CBC,
                   SSL_HASH_SHA256, "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256");
static const SSLCipherSuite Cipher213 =
    SSLCipherSuite(0xC047, SSL_KEYX_DH, SSL_AUTH_anon, SSL_SYM_ARIA_256_CBC,
                   SSL_HASH_SHA384, "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384");
static const SSLCipherSuite Cipher214 =
    SSLCipherSuite(0xC048, SSL_KEYX_ECDHE, SSL_AUTH_ECDSA, SSL_SYM_ARIA_128_CBC,
                   SSL_HASH_SHA256, "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256");
static const SSLCipherSuite Cipher215 =
    SSLCipherSuite(0xC049, SSL_KEYX_ECDHE, SSL_AUTH_ECDSA, SSL_SYM_ARIA_256_CBC,
                   SSL_HASH_SHA384, "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384");
static const SSLCipherSuite Cipher216 =
    SSLCipherSuite(0xC04A, SSL_KEYX_ECDH, SSL_AUTH_ECDSA, SSL_SYM_ARIA_128_CBC,
                   SSL_HASH_SHA256, "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256");
static const SSLCipherSuite Cipher217 =
    SSLCipherSuite(0xC04B, SSL_KEYX_ECDH, SSL_AUTH_ECDSA, SSL_SYM_ARIA_256_CBC,
                   SSL_HASH_SHA384, "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384");
static const SSLCipherSuite Cipher218 =
    SSLCipherSuite(0xC04C, SSL_KEYX_ECDHE, SSL_AUTH_RSA, SSL_SYM_ARIA_128_CBC,
                   SSL_HASH_SHA256, "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256");
static const SSLCipherSuite Cipher219 =
    SSLCipherSuite(0xC04D, SSL_KEYX_ECDHE, SSL_AUTH_RSA, SSL_SYM_ARIA_256_CBC,
                   SSL_HASH_SHA384, "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384");
static const SSLCipherSuite Cipher220 =
    SSLCipherSuite(0xC04E, SSL_KEYX_ECDH, SSL_AUTH_RSA, SSL_SYM_ARIA_128_CBC,
                   SSL_HASH_SHA256, "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256");
static const SSLCipherSuite Cipher221 =
    SSLCipherSuite(0xC04F, SSL_KEYX_ECDH, SSL_AUTH_RSA, SSL_SYM_ARIA_256_CBC,
                   SSL_HASH_SHA384, "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384");
static const SSLCipherSuite Cipher222 =
    SSLCipherSuite(0xC050, SSL_KEYX_RSA, SSL_AUTH_RSA, SSL_SYM_ARIA_128_GCM,
                   SSL_HASH_SHA256, "TLS_RSA_WITH_ARIA_128_GCM_SHA256");
static const SSLCipherSuite Cipher223 =
    SSLCipherSuite(0xC051, SSL_KEYX_RSA, SSL_AUTH_RSA, SSL_SYM_ARIA_256_GCM,
                   SSL_HASH_SHA384, "TLS_RSA_WITH_ARIA_256_GCM_SHA384");
static const SSLCipherSuite Cipher224 =
    SSLCipherSuite(0xC052, SSL_KEYX_DHE, SSL_AUTH_RSA, SSL_SYM_ARIA_128_GCM,
                   SSL_HASH_SHA256, "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256");
static const SSLCipherSuite Cipher225 =
    SSLCipherSuite(0xC053, SSL_KEYX_DHE, SSL_AUTH_RSA, SSL_SYM_ARIA_256_GCM,
                   SSL_HASH_SHA384, "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384");
static const SSLCipherSuite Cipher226 =
    SSLCipherSuite(0xC054, SSL_KEYX_DH, SSL_AUTH_RSA, SSL_SYM_ARIA_128_GCM,
                   SSL_HASH_SHA256, "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256");
static const SSLCipherSuite Cipher227 =
    SSLCipherSuite(0xC055, SSL_KEYX_DH, SSL_AUTH_RSA, SSL_SYM_ARIA_256_GCM,
                   SSL_HASH_SHA384, "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384");
static const SSLCipherSuite Cipher228 =
    SSLCipherSuite(0xC056, SSL_KEYX_DHE, SSL_AUTH_DSS, SSL_SYM_ARIA_128_GCM,
                   SSL_HASH_SHA256, "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256");
static const SSLCipherSuite Cipher229 =
    SSLCipherSuite(0xC057, SSL_KEYX_DHE, SSL_AUTH_DSS, SSL_SYM_ARIA_256_GCM,
                   SSL_HASH_SHA384, "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384");
static const SSLCipherSuite Cipher230 =
    SSLCipherSuite(0xC058, SSL_KEYX_DH, SSL_AUTH_DSS, SSL_SYM_ARIA_128_GCM,
                   SSL_HASH_SHA256, "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256");
static const SSLCipherSuite Cipher231 =
    SSLCipherSuite(0xC059, SSL_KEYX_DH, SSL_AUTH_DSS, SSL_SYM_ARIA_256_GCM,
                   SSL_HASH_SHA384, "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384");
static const SSLCipherSuite Cipher232 =
    SSLCipherSuite(0xC05A, SSL_KEYX_DH, SSL_AUTH_anon, SSL_SYM_ARIA_128_GCM,
                   SSL_HASH_SHA256, "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256");
static const SSLCipherSuite Cipher233 =
    SSLCipherSuite(0xC05B, SSL_KEYX_DH, SSL_AUTH_anon, SSL_SYM_ARIA_256_GCM,
                   SSL_HASH_SHA384, "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384");
static const SSLCipherSuite Cipher234 =
    SSLCipherSuite(0xC05C, SSL_KEYX_ECDHE, SSL_AUTH_ECDSA, SSL_SYM_ARIA_128_GCM,
                   SSL_HASH_SHA256, "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256");
static const SSLCipherSuite Cipher235 =
    SSLCipherSuite(0xC05D, SSL_KEYX_ECDHE, SSL_AUTH_ECDSA, SSL_SYM_ARIA_256_GCM,
                   SSL_HASH_SHA384, "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384");
static const SSLCipherSuite Cipher236 =
    SSLCipherSuite(0xC05E, SSL_KEYX_ECDH, SSL_AUTH_ECDSA, SSL_SYM_ARIA_128_GCM,
                   SSL_HASH_SHA256, "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256");
static const SSLCipherSuite Cipher237 =
    SSLCipherSuite(0xC05F, SSL_KEYX_ECDH, SSL_AUTH_ECDSA, SSL_SYM_ARIA_256_GCM,
                   SSL_HASH_SHA384, "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384");
static const SSLCipherSuite Cipher238 =
    SSLCipherSuite(0xC060, SSL_KEYX_ECDHE, SSL_AUTH_RSA, SSL_SYM_ARIA_128_GCM,
                   SSL_HASH_SHA256, "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256");
static const SSLCipherSuite Cipher239 =
    SSLCipherSuite(0xC061, SSL_KEYX_ECDHE, SSL_AUTH_RSA, SSL_SYM_ARIA_256_GCM,
                   SSL_HASH_SHA384, "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384");
static const SSLCipherSuite Cipher240 =
    SSLCipherSuite(0xC062, SSL_KEYX_ECDH, SSL_AUTH_RSA, SSL_SYM_ARIA_128_GCM,
                   SSL_HASH_SHA256, "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256");
static const SSLCipherSuite Cipher241 =
    SSLCipherSuite(0xC063, SSL_KEYX_ECDH, SSL_AUTH_RSA, SSL_SYM_ARIA_256_GCM,
                   SSL_HASH_SHA384, "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384");
static const SSLCipherSuite Cipher242 =
    SSLCipherSuite(0xC064, SSL_KEYX_PSK, SSL_AUTH_PSK, SSL_SYM_ARIA_128_CBC,
                   SSL_HASH_SHA256, "TLS_PSK_WITH_ARIA_128_CBC_SHA256");
static const SSLCipherSuite Cipher243 =
    SSLCipherSuite(0xC065, SSL_KEYX_PSK, SSL_AUTH_PSK, SSL_SYM_ARIA_256_CBC,
                   SSL_HASH_SHA384, "TLS_PSK_WITH_ARIA_256_CBC_SHA384");
static const SSLCipherSuite Cipher244 =
    SSLCipherSuite(0xC066, SSL_KEYX_DHE, SSL_AUTH_PSK, SSL_SYM_ARIA_128_CBC,
                   SSL_HASH_SHA256, "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256");
static const SSLCipherSuite Cipher245 =
    SSLCipherSuite(0xC067, SSL_KEYX_DHE, SSL_AUTH_PSK, SSL_SYM_ARIA_256_CBC,
                   SSL_HASH_SHA384, "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384");
static const SSLCipherSuite Cipher246 =
    SSLCipherSuite(0xC068, SSL_KEYX_RSA, SSL_AUTH_PSK, SSL_SYM_ARIA_128_CBC,
                   SSL_HASH_SHA256, "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256");
static const SSLCipherSuite Cipher247 =
    SSLCipherSuite(0xC069, SSL_KEYX_RSA, SSL_AUTH_PSK, SSL_SYM_ARIA_256_CBC,
                   SSL_HASH_SHA384, "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384");
static const SSLCipherSuite Cipher248 =
    SSLCipherSuite(0xC06A, SSL_KEYX_PSK, SSL_AUTH_PSK, SSL_SYM_ARIA_128_GCM,
                   SSL_HASH_SHA256, "TLS_PSK_WITH_ARIA_128_GCM_SHA256");
static const SSLCipherSuite Cipher249 =
    SSLCipherSuite(0xC06B, SSL_KEYX_PSK, SSL_AUTH_PSK, SSL_SYM_ARIA_256_GCM,
                   SSL_HASH_SHA384, "TLS_PSK_WITH_ARIA_256_GCM_SHA384");
static const SSLCipherSuite Cipher250 =
    SSLCipherSuite(0xC06C, SSL_KEYX_DHE, SSL_AUTH_PSK, SSL_SYM_ARIA_128_GCM,
                   SSL_HASH_SHA256, "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256");
static const SSLCipherSuite Cipher251 =
    SSLCipherSuite(0xC06D, SSL_KEYX_DHE, SSL_AUTH_PSK, SSL_SYM_ARIA_256_GCM,
                   SSL_HASH_SHA384, "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384");
static const SSLCipherSuite Cipher252 =
    SSLCipherSuite(0xC06E, SSL_KEYX_RSA, SSL_AUTH_PSK, SSL_SYM_ARIA_128_GCM,
                   SSL_HASH_SHA256, "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256");
static const SSLCipherSuite Cipher253 =
    SSLCipherSuite(0xC06F, SSL_KEYX_RSA, SSL_AUTH_PSK, SSL_SYM_ARIA_256_GCM,
                   SSL_HASH_SHA384, "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384");
static const SSLCipherSuite Cipher254 =
    SSLCipherSuite(0xC070, SSL_KEYX_ECDHE, SSL_AUTH_PSK, SSL_SYM_ARIA_128_CBC,
                   SSL_HASH_SHA256, "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256");
static const SSLCipherSuite Cipher255 =
    SSLCipherSuite(0xC071, SSL_KEYX_ECDHE, SSL_AUTH_PSK, SSL_SYM_ARIA_256_CBC,
                   SSL_HASH_SHA384, "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384");
static const SSLCipherSuite Cipher256 = SSLCipherSuite(
    0xC072, SSL_KEYX_ECDHE, SSL_AUTH_ECDSA, SSL_SYM_CAMELLIA_128_CBC,
    SSL_HASH_SHA256, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256");
static const SSLCipherSuite Cipher257 = SSLCipherSuite(
    0xC073, SSL_KEYX_ECDHE, SSL_AUTH_ECDSA, SSL_SYM_CAMELLIA_256_CBC,
    SSL_HASH_SHA384, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384");
static const SSLCipherSuite Cipher258 = SSLCipherSuite(
    0xC074, SSL_KEYX_ECDH, SSL_AUTH_ECDSA, SSL_SYM_CAMELLIA_128_CBC,
    SSL_HASH_SHA256, "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256");
static const SSLCipherSuite Cipher259 = SSLCipherSuite(
    0xC075, SSL_KEYX_ECDH, SSL_AUTH_ECDSA, SSL_SYM_CAMELLIA_256_CBC,
    SSL_HASH_SHA384, "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384");
static const SSLCipherSuite Cipher260 = SSLCipherSuite(
    0xC076, SSL_KEYX_ECDHE, SSL_AUTH_RSA, SSL_SYM_CAMELLIA_128_CBC,
    SSL_HASH_SHA256, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256");
static const SSLCipherSuite Cipher261 = SSLCipherSuite(
    0xC077, SSL_KEYX_ECDHE, SSL_AUTH_RSA, SSL_SYM_CAMELLIA_256_CBC,
    SSL_HASH_SHA384, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384");
static const SSLCipherSuite Cipher262 = SSLCipherSuite(
    0xC078, SSL_KEYX_ECDH, SSL_AUTH_RSA, SSL_SYM_CAMELLIA_128_CBC,
    SSL_HASH_SHA256, "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256");
static const SSLCipherSuite Cipher263 = SSLCipherSuite(
    0xC079, SSL_KEYX_ECDH, SSL_AUTH_RSA, SSL_SYM_CAMELLIA_256_CBC,
    SSL_HASH_SHA384, "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384");
static const SSLCipherSuite Cipher264 =
    SSLCipherSuite(0xC07A, SSL_KEYX_RSA, SSL_AUTH_RSA, SSL_SYM_CAMELLIA_128_GCM,
                   SSL_HASH_SHA256, "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256");
static const SSLCipherSuite Cipher265 =
    SSLCipherSuite(0xC07B, SSL_KEYX_RSA, SSL_AUTH_RSA, SSL_SYM_CAMELLIA_256_GCM,
                   SSL_HASH_SHA384, "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384");
static const SSLCipherSuite Cipher266 =
    SSLCipherSuite(0xC07C, SSL_KEYX_DHE, SSL_AUTH_RSA, SSL_SYM_CAMELLIA_128_GCM,
                   SSL_HASH_SHA256, "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256");
static const SSLCipherSuite Cipher267 =
    SSLCipherSuite(0xC07D, SSL_KEYX_DHE, SSL_AUTH_RSA, SSL_SYM_CAMELLIA_256_GCM,
                   SSL_HASH_SHA384, "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384");
static const SSLCipherSuite Cipher268 =
    SSLCipherSuite(0xC07E, SSL_KEYX_DH, SSL_AUTH_RSA, SSL_SYM_CAMELLIA_128_GCM,
                   SSL_HASH_SHA256, "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256");
static const SSLCipherSuite Cipher269 =
    SSLCipherSuite(0xC07F, SSL_KEYX_DH, SSL_AUTH_RSA, SSL_SYM_CAMELLIA_256_GCM,
                   SSL_HASH_SHA384, "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384");
static const SSLCipherSuite Cipher270 =
    SSLCipherSuite(0xC080, SSL_KEYX_DHE, SSL_AUTH_DSS, SSL_SYM_CAMELLIA_128_GCM,
                   SSL_HASH_SHA256, "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256");
static const SSLCipherSuite Cipher271 =
    SSLCipherSuite(0xC081, SSL_KEYX_DHE, SSL_AUTH_DSS, SSL_SYM_CAMELLIA_256_GCM,
                   SSL_HASH_SHA384, "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384");
static const SSLCipherSuite Cipher272 =
    SSLCipherSuite(0xC082, SSL_KEYX_DH, SSL_AUTH_DSS, SSL_SYM_CAMELLIA_128_GCM,
                   SSL_HASH_SHA256, "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256");
static const SSLCipherSuite Cipher273 =
    SSLCipherSuite(0xC083, SSL_KEYX_DH, SSL_AUTH_DSS, SSL_SYM_CAMELLIA_256_GCM,
                   SSL_HASH_SHA384, "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384");
static const SSLCipherSuite Cipher274 =
    SSLCipherSuite(0xC084, SSL_KEYX_DH, SSL_AUTH_anon, SSL_SYM_CAMELLIA_128_GCM,
                   SSL_HASH_SHA256, "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256");
static const SSLCipherSuite Cipher275 =
    SSLCipherSuite(0xC085, SSL_KEYX_DH, SSL_AUTH_anon, SSL_SYM_CAMELLIA_256_GCM,
                   SSL_HASH_SHA384, "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384");
static const SSLCipherSuite Cipher276 = SSLCipherSuite(
    0xC086, SSL_KEYX_ECDHE, SSL_AUTH_ECDSA, SSL_SYM_CAMELLIA_128_GCM,
    SSL_HASH_SHA256, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256");
static const SSLCipherSuite Cipher277 = SSLCipherSuite(
    0xC087, SSL_KEYX_ECDHE, SSL_AUTH_ECDSA, SSL_SYM_CAMELLIA_256_GCM,
    SSL_HASH_SHA384, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384");
static const SSLCipherSuite Cipher278 = SSLCipherSuite(
    0xC088, SSL_KEYX_ECDH, SSL_AUTH_ECDSA, SSL_SYM_CAMELLIA_128_GCM,
    SSL_HASH_SHA256, "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256");
static const SSLCipherSuite Cipher279 = SSLCipherSuite(
    0xC089, SSL_KEYX_ECDH, SSL_AUTH_ECDSA, SSL_SYM_CAMELLIA_256_GCM,
    SSL_HASH_SHA384, "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384");
static const SSLCipherSuite Cipher280 = SSLCipherSuite(
    0xC08A, SSL_KEYX_ECDHE, SSL_AUTH_RSA, SSL_SYM_CAMELLIA_128_GCM,
    SSL_HASH_SHA256, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256");
static const SSLCipherSuite Cipher281 = SSLCipherSuite(
    0xC08B, SSL_KEYX_ECDHE, SSL_AUTH_RSA, SSL_SYM_CAMELLIA_256_GCM,
    SSL_HASH_SHA384, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384");
static const SSLCipherSuite Cipher282 = SSLCipherSuite(
    0xC08C, SSL_KEYX_ECDH, SSL_AUTH_RSA, SSL_SYM_CAMELLIA_128_GCM,
    SSL_HASH_SHA256, "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256");
static const SSLCipherSuite Cipher283 = SSLCipherSuite(
    0xC08D, SSL_KEYX_ECDH, SSL_AUTH_RSA, SSL_SYM_CAMELLIA_256_GCM,
    SSL_HASH_SHA384, "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384");
static const SSLCipherSuite Cipher284 =
    SSLCipherSuite(0xC08E, SSL_KEYX_PSK, SSL_AUTH_PSK, SSL_SYM_CAMELLIA_128_GCM,
                   SSL_HASH_SHA256, "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256");
static const SSLCipherSuite Cipher285 =
    SSLCipherSuite(0xC08F, SSL_KEYX_PSK, SSL_AUTH_PSK, SSL_SYM_CAMELLIA_256_GCM,
                   SSL_HASH_SHA384, "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384");
static const SSLCipherSuite Cipher286 =
    SSLCipherSuite(0xC090, SSL_KEYX_DHE, SSL_AUTH_PSK, SSL_SYM_CAMELLIA_128_GCM,
                   SSL_HASH_SHA256, "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256");
static const SSLCipherSuite Cipher287 =
    SSLCipherSuite(0xC091, SSL_KEYX_DHE, SSL_AUTH_PSK, SSL_SYM_CAMELLIA_256_GCM,
                   SSL_HASH_SHA384, "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384");
static const SSLCipherSuite Cipher288 =
    SSLCipherSuite(0xC092, SSL_KEYX_RSA, SSL_AUTH_PSK, SSL_SYM_CAMELLIA_128_GCM,
                   SSL_HASH_SHA256, "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256");
static const SSLCipherSuite Cipher289 =
    SSLCipherSuite(0xC093, SSL_KEYX_RSA, SSL_AUTH_PSK, SSL_SYM_CAMELLIA_256_GCM,
                   SSL_HASH_SHA384, "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384");
static const SSLCipherSuite Cipher290 =
    SSLCipherSuite(0xC094, SSL_KEYX_PSK, SSL_AUTH_PSK, SSL_SYM_CAMELLIA_128_CBC,
                   SSL_HASH_SHA256, "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256");
static const SSLCipherSuite Cipher291 =
    SSLCipherSuite(0xC095, SSL_KEYX_PSK, SSL_AUTH_PSK, SSL_SYM_CAMELLIA_256_CBC,
                   SSL_HASH_SHA384, "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384");
static const SSLCipherSuite Cipher292 =
    SSLCipherSuite(0xC096, SSL_KEYX_DHE, SSL_AUTH_PSK, SSL_SYM_CAMELLIA_128_CBC,
                   SSL_HASH_SHA256, "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256");
static const SSLCipherSuite Cipher293 =
    SSLCipherSuite(0xC097, SSL_KEYX_DHE, SSL_AUTH_PSK, SSL_SYM_CAMELLIA_256_CBC,
                   SSL_HASH_SHA384, "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384");
static const SSLCipherSuite Cipher294 =
    SSLCipherSuite(0xC098, SSL_KEYX_RSA, SSL_AUTH_PSK, SSL_SYM_CAMELLIA_128_CBC,
                   SSL_HASH_SHA256, "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256");
static const SSLCipherSuite Cipher295 =
    SSLCipherSuite(0xC099, SSL_KEYX_RSA, SSL_AUTH_PSK, SSL_SYM_CAMELLIA_256_CBC,
                   SSL_HASH_SHA384, "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384");
static const SSLCipherSuite Cipher296 = SSLCipherSuite(
    0xC09A, SSL_KEYX_ECDHE, SSL_AUTH_PSK, SSL_SYM_CAMELLIA_128_CBC,
    SSL_HASH_SHA256, "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256");
static const SSLCipherSuite Cipher297 = SSLCipherSuite(
    0xC09B, SSL_KEYX_ECDHE, SSL_AUTH_PSK, SSL_SYM_CAMELLIA_256_CBC,
    SSL_HASH_SHA384, "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384");
static const SSLCipherSuite Cipher298 =
    SSLCipherSuite(0xC09C, SSL_KEYX_RSA, SSL_AUTH_RSA, SSL_SYM_AES_128,
                   SSL_HASH_CCM, "TLS_RSA_WITH_AES_128_CCM");
static const SSLCipherSuite Cipher299 =
    SSLCipherSuite(0xC09D, SSL_KEYX_RSA, SSL_AUTH_RSA, SSL_SYM_AES_256,
                   SSL_HASH_CCM, "TLS_RSA_WITH_AES_256_CCM");
static const SSLCipherSuite Cipher300 =
    SSLCipherSuite(0xC09E, SSL_KEYX_DHE, SSL_AUTH_RSA, SSL_SYM_AES_128,
                   SSL_HASH_CCM, "TLS_DHE_RSA_WITH_AES_128_CCM");
static const SSLCipherSuite Cipher301 =
    SSLCipherSuite(0xC09F, SSL_KEYX_DHE, SSL_AUTH_RSA, SSL_SYM_AES_256,
                   SSL_HASH_CCM, "TLS_DHE_RSA_WITH_AES_256_CCM");
static const SSLCipherSuite Cipher302 =
    SSLCipherSuite(0xC0A0, SSL_KEYX_RSA, SSL_AUTH_RSA, SSL_SYM_AES_128,
                   SSL_HASH_CCM_8, "TLS_RSA_WITH_AES_128_CCM_8");
static const SSLCipherSuite Cipher303 =
    SSLCipherSuite(0xC0A1, SSL_KEYX_RSA, SSL_AUTH_RSA, SSL_SYM_AES_256,
                   SSL_HASH_CCM_8, "TLS_RSA_WITH_AES_256_CCM_8");
static const SSLCipherSuite Cipher304 =
    SSLCipherSuite(0xC0A2, SSL_KEYX_DHE, SSL_AUTH_RSA, SSL_SYM_AES_128,
                   SSL_HASH_CCM_8, "TLS_DHE_RSA_WITH_AES_128_CCM_8");
static const SSLCipherSuite Cipher305 =
    SSLCipherSuite(0xC0A3, SSL_KEYX_DHE, SSL_AUTH_RSA, SSL_SYM_AES_256,
                   SSL_HASH_CCM_8, "TLS_DHE_RSA_WITH_AES_256_CCM_8");
static const SSLCipherSuite Cipher306 =
    SSLCipherSuite(0xC0A4, SSL_KEYX_PSK, SSL_AUTH_PSK, SSL_SYM_AES_128,
                   SSL_HASH_CCM, "TLS_PSK_WITH_AES_128_CCM");
static const SSLCipherSuite Cipher307 =
    SSLCipherSuite(0xC0A5, SSL_KEYX_PSK, SSL_AUTH_PSK, SSL_SYM_AES_256,
                   SSL_HASH_CCM, "TLS_PSK_WITH_AES_256_CCM");
static const SSLCipherSuite Cipher308 =
    SSLCipherSuite(0xC0A6, SSL_KEYX_DHE, SSL_AUTH_PSK, SSL_SYM_AES_128,
                   SSL_HASH_CCM, "TLS_DHE_PSK_WITH_AES_128_CCM");
static const SSLCipherSuite Cipher309 =
    SSLCipherSuite(0xC0A7, SSL_KEYX_DHE, SSL_AUTH_PSK, SSL_SYM_AES_256,
                   SSL_HASH_CCM, "TLS_DHE_PSK_WITH_AES_256_CCM");
static const SSLCipherSuite Cipher310 =
    SSLCipherSuite(0xC0A8, SSL_KEYX_PSK, SSL_AUTH_PSK, SSL_SYM_AES_128,
                   SSL_HASH_CCM_8, "TLS_PSK_WITH_AES_128_CCM_8");
static const SSLCipherSuite Cipher311 =
    SSLCipherSuite(0xC0A9, SSL_KEYX_PSK, SSL_AUTH_PSK, SSL_SYM_AES_256,
                   SSL_HASH_CCM_8, "TLS_PSK_WITH_AES_256_CCM_8");
static const SSLCipherSuite Cipher312 =
    SSLCipherSuite(0xC0AA, SSL_KEYX_PSK, SSL_AUTH_DHE, SSL_SYM_AES_128,
                   SSL_HASH_CCM_8, "TLS_PSK_DHE_WITH_AES_128_CCM_8");
static const SSLCipherSuite Cipher313 =
    SSLCipherSuite(0xC0AB, SSL_KEYX_PSK, SSL_AUTH_DHE, SSL_SYM_AES_256,
                   SSL_HASH_CCM_8, "TLS_PSK_DHE_WITH_AES_256_CCM_8");
static const SSLCipherSuite Cipher314 =
    SSLCipherSuite(0xC0AC, SSL_KEYX_ECDHE, SSL_AUTH_ECDSA, SSL_SYM_AES_128,
                   SSL_HASH_CCM, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM");
static const SSLCipherSuite Cipher315 =
    SSLCipherSuite(0xC0AD, SSL_KEYX_ECDHE, SSL_AUTH_ECDSA, SSL_SYM_AES_256,
                   SSL_HASH_CCM, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM");
static const SSLCipherSuite Cipher316 =
    SSLCipherSuite(0xC0AE, SSL_KEYX_ECDHE, SSL_AUTH_ECDSA, SSL_SYM_AES_128,
                   SSL_HASH_CCM_8, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8");
static const SSLCipherSuite Cipher317 =
    SSLCipherSuite(0xC0AF, SSL_KEYX_ECDHE, SSL_AUTH_ECDSA, SSL_SYM_AES_256,
                   SSL_HASH_CCM_8, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8");
static const SSLCipherSuite Cipher318 = SSLCipherSuite(
    0xCCA8, SSL_KEYX_ECDHE, SSL_AUTH_RSA, SSL_SYM_CHACHA20_POLY1305,
    SSL_HASH_SHA256, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256");
static const SSLCipherSuite Cipher319 = SSLCipherSuite(
    0xCCA9, SSL_KEYX_ECDHE, SSL_AUTH_ECDSA, SSL_SYM_CHACHA20_POLY1305,
    SSL_HASH_SHA256, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256");
static const SSLCipherSuite Cipher320 = SSLCipherSuite(
    0xCCAA, SSL_KEYX_DHE, SSL_AUTH_RSA, SSL_SYM_CHACHA20_POLY1305,
    SSL_HASH_SHA256, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256");
static const SSLCipherSuite Cipher321 = SSLCipherSuite(
    0xCCAB, SSL_KEYX_PSK, SSL_AUTH_PSK, SSL_SYM_CHACHA20_POLY1305,
    SSL_HASH_SHA256, "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256");
static const SSLCipherSuite Cipher322 = SSLCipherSuite(
    0xCCAC, SSL_KEYX_ECDHE, SSL_AUTH_PSK, SSL_SYM_CHACHA20_POLY1305,
    SSL_HASH_SHA256, "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256");
static const SSLCipherSuite Cipher323 = SSLCipherSuite(
    0xCCAD, SSL_KEYX_DHE, SSL_AUTH_PSK, SSL_SYM_CHACHA20_POLY1305,
    SSL_HASH_SHA256, "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256");
static const SSLCipherSuite Cipher324 = SSLCipherSuite(
    0xCCAE, SSL_KEYX_RSA, SSL_AUTH_PSK, SSL_SYM_CHACHA20_POLY1305,
    SSL_HASH_SHA256, "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256");
static const SSLCipherSuite Cipher325 =
    SSLCipherSuite(0x1301, SSL_KEYX_NULL, SSL_AUTH_NULL, SSL_SYM_AES_128_GCM,
                   SSL_HASH_SHA256, "TLS_AES_128_GCM_SHA256");
static const SSLCipherSuite Cipher326 =
    SSLCipherSuite(0x1302, SSL_KEYX_NULL, SSL_AUTH_NULL, SSL_SYM_AES_256_GCM,
                   SSL_HASH_SHA384, "TLS_AES_256_GCM_SHA384");
static const SSLCipherSuite Cipher327 = SSLCipherSuite(
    0x1303, SSL_KEYX_NULL, SSL_AUTH_NULL, SSL_SYM_CHACHA20_POLY1305,
    SSL_HASH_SHA256, "TLS_CHACHA20_POLY1305_SHA256");
static const SSLCipherSuite Cipher328 =
    SSLCipherSuite(0x1304, SSL_KEYX_NULL, SSL_AUTH_NULL, SSL_SYM_AES_128_CCM,
                   SSL_HASH_SHA256, "TLS_AES_128_CCM_SHA256");
static const SSLCipherSuite Cipher329 =
    SSLCipherSuite(0x1305, SSL_KEYX_NULL, SSL_AUTH_NULL, SSL_SYM_AES_128_CCM_8,
                   SSL_HASH_SHA256, "TLS_AES_128_CCM_8_SHA256");

static std::map<uint16_t, SSLCipherSuite*> createCipherSuiteIdToObjectMap() {
    std::map<uint16_t, SSLCipherSuite*> result;

    result[0x0000] = (SSLCipherSuite*)&Cipher1;
    result[0x0001] = (SSLCipherSuite*)&Cipher2;
    result[0x0002] = (SSLCipherSuite*)&Cipher3;
    result[0x0003] = (SSLCipherSuite*)&Cipher4;
    result[0x0004] = (SSLCipherSuite*)&Cipher5;
    result[0x0005] = (SSLCipherSuite*)&Cipher6;
    result[0x0006] = (SSLCipherSuite*)&Cipher7;
    result[0x0007] = (SSLCipherSuite*)&Cipher8;
    result[0x0008] = (SSLCipherSuite*)&Cipher9;
    result[0x0009] = (SSLCipherSuite*)&Cipher10;
    result[0x000A] = (SSLCipherSuite*)&Cipher11;
    result[0x000B] = (SSLCipherSuite*)&Cipher12;
    result[0x000C] = (SSLCipherSuite*)&Cipher13;
    result[0x000D] = (SSLCipherSuite*)&Cipher14;
    result[0x000E] = (SSLCipherSuite*)&Cipher15;
    result[0x000F] = (SSLCipherSuite*)&Cipher16;
    result[0x0010] = (SSLCipherSuite*)&Cipher17;
    result[0x0011] = (SSLCipherSuite*)&Cipher18;
    result[0x0012] = (SSLCipherSuite*)&Cipher19;
    result[0x0013] = (SSLCipherSuite*)&Cipher20;
    result[0x0014] = (SSLCipherSuite*)&Cipher21;
    result[0x0015] = (SSLCipherSuite*)&Cipher22;
    result[0x0016] = (SSLCipherSuite*)&Cipher23;
    result[0x0017] = (SSLCipherSuite*)&Cipher24;
    result[0x0018] = (SSLCipherSuite*)&Cipher25;
    result[0x0019] = (SSLCipherSuite*)&Cipher26;
    result[0x001A] = (SSLCipherSuite*)&Cipher27;
    result[0x001B] = (SSLCipherSuite*)&Cipher28;
    result[0x001E] = (SSLCipherSuite*)&Cipher29;
    result[0x001F] = (SSLCipherSuite*)&Cipher30;
    result[0x0020] = (SSLCipherSuite*)&Cipher31;
    result[0x0021] = (SSLCipherSuite*)&Cipher32;
    result[0x0022] = (SSLCipherSuite*)&Cipher33;
    result[0x0023] = (SSLCipherSuite*)&Cipher34;
    result[0x0024] = (SSLCipherSuite*)&Cipher35;
    result[0x0025] = (SSLCipherSuite*)&Cipher36;
    result[0x0026] = (SSLCipherSuite*)&Cipher37;
    result[0x0027] = (SSLCipherSuite*)&Cipher38;
    result[0x0028] = (SSLCipherSuite*)&Cipher39;
    result[0x0029] = (SSLCipherSuite*)&Cipher40;
    result[0x002A] = (SSLCipherSuite*)&Cipher41;
    result[0x002B] = (SSLCipherSuite*)&Cipher42;
    result[0x002C] = (SSLCipherSuite*)&Cipher43;
    result[0x002D] = (SSLCipherSuite*)&Cipher44;
    result[0x002E] = (SSLCipherSuite*)&Cipher45;
    result[0x002F] = (SSLCipherSuite*)&Cipher46;
    result[0x0030] = (SSLCipherSuite*)&Cipher47;
    result[0x0031] = (SSLCipherSuite*)&Cipher48;
    result[0x0032] = (SSLCipherSuite*)&Cipher49;
    result[0x0033] = (SSLCipherSuite*)&Cipher50;
    result[0x0034] = (SSLCipherSuite*)&Cipher51;
    result[0x0035] = (SSLCipherSuite*)&Cipher52;
    result[0x0036] = (SSLCipherSuite*)&Cipher53;
    result[0x0037] = (SSLCipherSuite*)&Cipher54;
    result[0x0038] = (SSLCipherSuite*)&Cipher55;
    result[0x0039] = (SSLCipherSuite*)&Cipher56;
    result[0x003A] = (SSLCipherSuite*)&Cipher57;
    result[0x003B] = (SSLCipherSuite*)&Cipher58;
    result[0x003C] = (SSLCipherSuite*)&Cipher59;
    result[0x003D] = (SSLCipherSuite*)&Cipher60;
    result[0x003E] = (SSLCipherSuite*)&Cipher61;
    result[0x003F] = (SSLCipherSuite*)&Cipher62;
    result[0x0040] = (SSLCipherSuite*)&Cipher63;
    result[0x0041] = (SSLCipherSuite*)&Cipher64;
    result[0x0042] = (SSLCipherSuite*)&Cipher65;
    result[0x0043] = (SSLCipherSuite*)&Cipher66;
    result[0x0044] = (SSLCipherSuite*)&Cipher67;
    result[0x0045] = (SSLCipherSuite*)&Cipher68;
    result[0x0046] = (SSLCipherSuite*)&Cipher69;
    result[0x0067] = (SSLCipherSuite*)&Cipher70;
    result[0x0068] = (SSLCipherSuite*)&Cipher71;
    result[0x0069] = (SSLCipherSuite*)&Cipher72;
    result[0x006A] = (SSLCipherSuite*)&Cipher73;
    result[0x006B] = (SSLCipherSuite*)&Cipher74;
    result[0x006C] = (SSLCipherSuite*)&Cipher75;
    result[0x006D] = (SSLCipherSuite*)&Cipher76;
    result[0x0084] = (SSLCipherSuite*)&Cipher77;
    result[0x0085] = (SSLCipherSuite*)&Cipher78;
    result[0x0086] = (SSLCipherSuite*)&Cipher79;
    result[0x0087] = (SSLCipherSuite*)&Cipher80;
    result[0x0088] = (SSLCipherSuite*)&Cipher81;
    result[0x0089] = (SSLCipherSuite*)&Cipher82;
    result[0x008A] = (SSLCipherSuite*)&Cipher83;
    result[0x008B] = (SSLCipherSuite*)&Cipher84;
    result[0x008C] = (SSLCipherSuite*)&Cipher85;
    result[0x008D] = (SSLCipherSuite*)&Cipher86;
    result[0x008E] = (SSLCipherSuite*)&Cipher87;
    result[0x008F] = (SSLCipherSuite*)&Cipher88;
    result[0x0090] = (SSLCipherSuite*)&Cipher89;
    result[0x0091] = (SSLCipherSuite*)&Cipher90;
    result[0x0092] = (SSLCipherSuite*)&Cipher91;
    result[0x0093] = (SSLCipherSuite*)&Cipher92;
    result[0x0094] = (SSLCipherSuite*)&Cipher93;
    result[0x0095] = (SSLCipherSuite*)&Cipher94;
    result[0x0096] = (SSLCipherSuite*)&Cipher95;
    result[0x0097] = (SSLCipherSuite*)&Cipher96;
    result[0x0098] = (SSLCipherSuite*)&Cipher97;
    result[0x0099] = (SSLCipherSuite*)&Cipher98;
    result[0x009A] = (SSLCipherSuite*)&Cipher99;
    result[0x009B] = (SSLCipherSuite*)&Cipher100;
    result[0x009C] = (SSLCipherSuite*)&Cipher101;
    result[0x009D] = (SSLCipherSuite*)&Cipher102;
    result[0x009E] = (SSLCipherSuite*)&Cipher103;
    result[0x009F] = (SSLCipherSuite*)&Cipher104;
    result[0x00A0] = (SSLCipherSuite*)&Cipher105;
    result[0x00A1] = (SSLCipherSuite*)&Cipher106;
    result[0x00A2] = (SSLCipherSuite*)&Cipher107;
    result[0x00A3] = (SSLCipherSuite*)&Cipher108;
    result[0x00A4] = (SSLCipherSuite*)&Cipher109;
    result[0x00A5] = (SSLCipherSuite*)&Cipher110;
    result[0x00A6] = (SSLCipherSuite*)&Cipher111;
    result[0x00A7] = (SSLCipherSuite*)&Cipher112;
    result[0x00A8] = (SSLCipherSuite*)&Cipher113;
    result[0x00A9] = (SSLCipherSuite*)&Cipher114;
    result[0x00AA] = (SSLCipherSuite*)&Cipher115;
    result[0x00AB] = (SSLCipherSuite*)&Cipher116;
    result[0x00AC] = (SSLCipherSuite*)&Cipher117;
    result[0x00AD] = (SSLCipherSuite*)&Cipher118;
    result[0x00AE] = (SSLCipherSuite*)&Cipher119;
    result[0x00AF] = (SSLCipherSuite*)&Cipher120;
    result[0x00B0] = (SSLCipherSuite*)&Cipher121;
    result[0x00B1] = (SSLCipherSuite*)&Cipher122;
    result[0x00B2] = (SSLCipherSuite*)&Cipher123;
    result[0x00B3] = (SSLCipherSuite*)&Cipher124;
    result[0x00B4] = (SSLCipherSuite*)&Cipher125;
    result[0x00B5] = (SSLCipherSuite*)&Cipher126;
    result[0x00B6] = (SSLCipherSuite*)&Cipher127;
    result[0x00B7] = (SSLCipherSuite*)&Cipher128;
    result[0x00B8] = (SSLCipherSuite*)&Cipher129;
    result[0x00B9] = (SSLCipherSuite*)&Cipher130;
    result[0x00BA] = (SSLCipherSuite*)&Cipher131;
    result[0x00BB] = (SSLCipherSuite*)&Cipher132;
    result[0x00BC] = (SSLCipherSuite*)&Cipher133;
    result[0x00BD] = (SSLCipherSuite*)&Cipher134;
    result[0x00BE] = (SSLCipherSuite*)&Cipher135;
    result[0x00BF] = (SSLCipherSuite*)&Cipher136;
    result[0x00C0] = (SSLCipherSuite*)&Cipher137;
    result[0x00C1] = (SSLCipherSuite*)&Cipher138;
    result[0x00C2] = (SSLCipherSuite*)&Cipher139;
    result[0x00C3] = (SSLCipherSuite*)&Cipher140;
    result[0x00C4] = (SSLCipherSuite*)&Cipher141;
    result[0x00C5] = (SSLCipherSuite*)&Cipher142;
    result[0xC001] = (SSLCipherSuite*)&Cipher143;
    result[0xC002] = (SSLCipherSuite*)&Cipher144;
    result[0xC003] = (SSLCipherSuite*)&Cipher145;
    result[0xC004] = (SSLCipherSuite*)&Cipher146;
    result[0xC005] = (SSLCipherSuite*)&Cipher147;
    result[0xC006] = (SSLCipherSuite*)&Cipher148;
    result[0xC007] = (SSLCipherSuite*)&Cipher149;
    result[0xC008] = (SSLCipherSuite*)&Cipher150;
    result[0xC009] = (SSLCipherSuite*)&Cipher151;
    result[0xC00A] = (SSLCipherSuite*)&Cipher152;
    result[0xC00B] = (SSLCipherSuite*)&Cipher153;
    result[0xC00C] = (SSLCipherSuite*)&Cipher154;
    result[0xC00D] = (SSLCipherSuite*)&Cipher155;
    result[0xC00E] = (SSLCipherSuite*)&Cipher156;
    result[0xC00F] = (SSLCipherSuite*)&Cipher157;
    result[0xC010] = (SSLCipherSuite*)&Cipher158;
    result[0xC011] = (SSLCipherSuite*)&Cipher159;
    result[0xC012] = (SSLCipherSuite*)&Cipher160;
    result[0xC013] = (SSLCipherSuite*)&Cipher161;
    result[0xC014] = (SSLCipherSuite*)&Cipher162;
    result[0xC015] = (SSLCipherSuite*)&Cipher163;
    result[0xC016] = (SSLCipherSuite*)&Cipher164;
    result[0xC017] = (SSLCipherSuite*)&Cipher165;
    result[0xC018] = (SSLCipherSuite*)&Cipher166;
    result[0xC019] = (SSLCipherSuite*)&Cipher167;
    result[0xC01A] = (SSLCipherSuite*)&Cipher168;
    result[0xC01B] = (SSLCipherSuite*)&Cipher169;
    result[0xC01C] = (SSLCipherSuite*)&Cipher170;
    result[0xC01D] = (SSLCipherSuite*)&Cipher171;
    result[0xC01E] = (SSLCipherSuite*)&Cipher172;
    result[0xC01F] = (SSLCipherSuite*)&Cipher173;
    result[0xC020] = (SSLCipherSuite*)&Cipher174;
    result[0xC021] = (SSLCipherSuite*)&Cipher175;
    result[0xC022] = (SSLCipherSuite*)&Cipher176;
    result[0xC023] = (SSLCipherSuite*)&Cipher177;
    result[0xC024] = (SSLCipherSuite*)&Cipher178;
    result[0xC025] = (SSLCipherSuite*)&Cipher179;
    result[0xC026] = (SSLCipherSuite*)&Cipher180;
    result[0xC027] = (SSLCipherSuite*)&Cipher181;
    result[0xC028] = (SSLCipherSuite*)&Cipher182;
    result[0xC029] = (SSLCipherSuite*)&Cipher183;
    result[0xC02A] = (SSLCipherSuite*)&Cipher184;
    result[0xC02B] = (SSLCipherSuite*)&Cipher185;
    result[0xC02C] = (SSLCipherSuite*)&Cipher186;
    result[0xC02D] = (SSLCipherSuite*)&Cipher187;
    result[0xC02E] = (SSLCipherSuite*)&Cipher188;
    result[0xC02F] = (SSLCipherSuite*)&Cipher189;
    result[0xC030] = (SSLCipherSuite*)&Cipher190;
    result[0xC031] = (SSLCipherSuite*)&Cipher191;
    result[0xC032] = (SSLCipherSuite*)&Cipher192;
    result[0xC033] = (SSLCipherSuite*)&Cipher193;
    result[0xC034] = (SSLCipherSuite*)&Cipher194;
    result[0xC035] = (SSLCipherSuite*)&Cipher195;
    result[0xC036] = (SSLCipherSuite*)&Cipher196;
    result[0xC037] = (SSLCipherSuite*)&Cipher197;
    result[0xC038] = (SSLCipherSuite*)&Cipher198;
    result[0xC039] = (SSLCipherSuite*)&Cipher199;
    result[0xC03A] = (SSLCipherSuite*)&Cipher200;
    result[0xC03B] = (SSLCipherSuite*)&Cipher201;
    result[0xC03C] = (SSLCipherSuite*)&Cipher202;
    result[0xC03D] = (SSLCipherSuite*)&Cipher203;
    result[0xC03E] = (SSLCipherSuite*)&Cipher204;
    result[0xC03F] = (SSLCipherSuite*)&Cipher205;
    result[0xC040] = (SSLCipherSuite*)&Cipher206;
    result[0xC041] = (SSLCipherSuite*)&Cipher207;
    result[0xC042] = (SSLCipherSuite*)&Cipher208;
    result[0xC043] = (SSLCipherSuite*)&Cipher209;
    result[0xC044] = (SSLCipherSuite*)&Cipher210;
    result[0xC045] = (SSLCipherSuite*)&Cipher211;
    result[0xC046] = (SSLCipherSuite*)&Cipher212;
    result[0xC047] = (SSLCipherSuite*)&Cipher213;
    result[0xC048] = (SSLCipherSuite*)&Cipher214;
    result[0xC049] = (SSLCipherSuite*)&Cipher215;
    result[0xC04A] = (SSLCipherSuite*)&Cipher216;
    result[0xC04B] = (SSLCipherSuite*)&Cipher217;
    result[0xC04C] = (SSLCipherSuite*)&Cipher218;
    result[0xC04D] = (SSLCipherSuite*)&Cipher219;
    result[0xC04E] = (SSLCipherSuite*)&Cipher220;
    result[0xC04F] = (SSLCipherSuite*)&Cipher221;
    result[0xC050] = (SSLCipherSuite*)&Cipher222;
    result[0xC051] = (SSLCipherSuite*)&Cipher223;
    result[0xC052] = (SSLCipherSuite*)&Cipher224;
    result[0xC053] = (SSLCipherSuite*)&Cipher225;
    result[0xC054] = (SSLCipherSuite*)&Cipher226;
    result[0xC055] = (SSLCipherSuite*)&Cipher227;
    result[0xC056] = (SSLCipherSuite*)&Cipher228;
    result[0xC057] = (SSLCipherSuite*)&Cipher229;
    result[0xC058] = (SSLCipherSuite*)&Cipher230;
    result[0xC059] = (SSLCipherSuite*)&Cipher231;
    result[0xC05A] = (SSLCipherSuite*)&Cipher232;
    result[0xC05B] = (SSLCipherSuite*)&Cipher233;
    result[0xC05C] = (SSLCipherSuite*)&Cipher234;
    result[0xC05D] = (SSLCipherSuite*)&Cipher235;
    result[0xC05E] = (SSLCipherSuite*)&Cipher236;
    result[0xC05F] = (SSLCipherSuite*)&Cipher237;
    result[0xC060] = (SSLCipherSuite*)&Cipher238;
    result[0xC061] = (SSLCipherSuite*)&Cipher239;
    result[0xC062] = (SSLCipherSuite*)&Cipher240;
    result[0xC063] = (SSLCipherSuite*)&Cipher241;
    result[0xC064] = (SSLCipherSuite*)&Cipher242;
    result[0xC065] = (SSLCipherSuite*)&Cipher243;
    result[0xC066] = (SSLCipherSuite*)&Cipher244;
    result[0xC067] = (SSLCipherSuite*)&Cipher245;
    result[0xC068] = (SSLCipherSuite*)&Cipher246;
    result[0xC069] = (SSLCipherSuite*)&Cipher247;
    result[0xC06A] = (SSLCipherSuite*)&Cipher248;
    result[0xC06B] = (SSLCipherSuite*)&Cipher249;
    result[0xC06C] = (SSLCipherSuite*)&Cipher250;
    result[0xC06D] = (SSLCipherSuite*)&Cipher251;
    result[0xC06E] = (SSLCipherSuite*)&Cipher252;
    result[0xC06F] = (SSLCipherSuite*)&Cipher253;
    result[0xC070] = (SSLCipherSuite*)&Cipher254;
    result[0xC071] = (SSLCipherSuite*)&Cipher255;
    result[0xC072] = (SSLCipherSuite*)&Cipher256;
    result[0xC073] = (SSLCipherSuite*)&Cipher257;
    result[0xC074] = (SSLCipherSuite*)&Cipher258;
    result[0xC075] = (SSLCipherSuite*)&Cipher259;
    result[0xC076] = (SSLCipherSuite*)&Cipher260;
    result[0xC077] = (SSLCipherSuite*)&Cipher261;
    result[0xC078] = (SSLCipherSuite*)&Cipher262;
    result[0xC079] = (SSLCipherSuite*)&Cipher263;
    result[0xC07A] = (SSLCipherSuite*)&Cipher264;
    result[0xC07B] = (SSLCipherSuite*)&Cipher265;
    result[0xC07C] = (SSLCipherSuite*)&Cipher266;
    result[0xC07D] = (SSLCipherSuite*)&Cipher267;
    result[0xC07E] = (SSLCipherSuite*)&Cipher268;
    result[0xC07F] = (SSLCipherSuite*)&Cipher269;
    result[0xC080] = (SSLCipherSuite*)&Cipher270;
    result[0xC081] = (SSLCipherSuite*)&Cipher271;
    result[0xC082] = (SSLCipherSuite*)&Cipher272;
    result[0xC083] = (SSLCipherSuite*)&Cipher273;
    result[0xC084] = (SSLCipherSuite*)&Cipher274;
    result[0xC085] = (SSLCipherSuite*)&Cipher275;
    result[0xC086] = (SSLCipherSuite*)&Cipher276;
    result[0xC087] = (SSLCipherSuite*)&Cipher277;
    result[0xC088] = (SSLCipherSuite*)&Cipher278;
    result[0xC089] = (SSLCipherSuite*)&Cipher279;
    result[0xC08A] = (SSLCipherSuite*)&Cipher280;
    result[0xC08B] = (SSLCipherSuite*)&Cipher281;
    result[0xC08C] = (SSLCipherSuite*)&Cipher282;
    result[0xC08D] = (SSLCipherSuite*)&Cipher283;
    result[0xC08E] = (SSLCipherSuite*)&Cipher284;
    result[0xC08F] = (SSLCipherSuite*)&Cipher285;
    result[0xC090] = (SSLCipherSuite*)&Cipher286;
    result[0xC091] = (SSLCipherSuite*)&Cipher287;
    result[0xC092] = (SSLCipherSuite*)&Cipher288;
    result[0xC093] = (SSLCipherSuite*)&Cipher289;
    result[0xC094] = (SSLCipherSuite*)&Cipher290;
    result[0xC095] = (SSLCipherSuite*)&Cipher291;
    result[0xC096] = (SSLCipherSuite*)&Cipher292;
    result[0xC097] = (SSLCipherSuite*)&Cipher293;
    result[0xC098] = (SSLCipherSuite*)&Cipher294;
    result[0xC099] = (SSLCipherSuite*)&Cipher295;
    result[0xC09A] = (SSLCipherSuite*)&Cipher296;
    result[0xC09B] = (SSLCipherSuite*)&Cipher297;
    result[0xC09C] = (SSLCipherSuite*)&Cipher298;
    result[0xC09D] = (SSLCipherSuite*)&Cipher299;
    result[0xC09E] = (SSLCipherSuite*)&Cipher300;
    result[0xC09F] = (SSLCipherSuite*)&Cipher301;
    result[0xC0A0] = (SSLCipherSuite*)&Cipher302;
    result[0xC0A1] = (SSLCipherSuite*)&Cipher303;
    result[0xC0A2] = (SSLCipherSuite*)&Cipher304;
    result[0xC0A3] = (SSLCipherSuite*)&Cipher305;
    result[0xC0A4] = (SSLCipherSuite*)&Cipher306;
    result[0xC0A5] = (SSLCipherSuite*)&Cipher307;
    result[0xC0A6] = (SSLCipherSuite*)&Cipher308;
    result[0xC0A7] = (SSLCipherSuite*)&Cipher309;
    result[0xC0A8] = (SSLCipherSuite*)&Cipher310;
    result[0xC0A9] = (SSLCipherSuite*)&Cipher311;
    result[0xC0AA] = (SSLCipherSuite*)&Cipher312;
    result[0xC0AB] = (SSLCipherSuite*)&Cipher313;
    result[0xC0AC] = (SSLCipherSuite*)&Cipher314;
    result[0xC0AD] = (SSLCipherSuite*)&Cipher315;
    result[0xC0AE] = (SSLCipherSuite*)&Cipher316;
    result[0xC0AF] = (SSLCipherSuite*)&Cipher317;
    result[0xCCA8] = (SSLCipherSuite*)&Cipher318;
    result[0xCCA9] = (SSLCipherSuite*)&Cipher319;
    result[0xCCAA] = (SSLCipherSuite*)&Cipher320;
    result[0xCCAB] = (SSLCipherSuite*)&Cipher321;
    result[0xCCAC] = (SSLCipherSuite*)&Cipher322;
    result[0xCCAD] = (SSLCipherSuite*)&Cipher323;
    result[0xCCAE] = (SSLCipherSuite*)&Cipher324;
    result[0x1301] = (SSLCipherSuite*)&Cipher325;
    result[0x1302] = (SSLCipherSuite*)&Cipher326;
    result[0x1303] = (SSLCipherSuite*)&Cipher327;
    result[0x1304] = (SSLCipherSuite*)&Cipher328;
    result[0x1305] = (SSLCipherSuite*)&Cipher329;
    return result;
}

#define A 54059       /* a prime */
#define B 76963       /* another prime */
#define C 86969       /* yet another prime */
#define FIRST_HASH 37 /* also prime */
static uint32_t hashString(std::string str) {
    unsigned h = FIRST_HASH;
    for (std::string::size_type i = 0; i < str.size(); ++i) {
        h = (h * A) ^ (str[i] * B);
    }
    return h;
}

static std::map<uint32_t, SSLCipherSuite*>
createCipherSuiteStringToObjectMap() {
    std::map<uint32_t, SSLCipherSuite*> result;

    result[0x9F180F43] = (SSLCipherSuite*)&Cipher1;
    result[0x97D9341F] = (SSLCipherSuite*)&Cipher2;
    result[0x288FABA1] = (SSLCipherSuite*)&Cipher3;
    result[0x9179C5BD] = (SSLCipherSuite*)&Cipher4;
    result[0x68DF0C8F] = (SSLCipherSuite*)&Cipher5;
    result[0x5FB32DF1] = (SSLCipherSuite*)&Cipher6;
    result[0x2A1FC0FC] = (SSLCipherSuite*)&Cipher7;
    result[0x5BF6459E] = (SSLCipherSuite*)&Cipher8;
    result[0x60D692F4] = (SSLCipherSuite*)&Cipher9;
    result[0x26A21427] = (SSLCipherSuite*)&Cipher10;
    result[0xD3558C6D] = (SSLCipherSuite*)&Cipher11;
    result[0xAE2673E9] = (SSLCipherSuite*)&Cipher12;
    result[0xC63B19B0] = (SSLCipherSuite*)&Cipher13;
    result[0xFE49B3BC] = (SSLCipherSuite*)&Cipher14;
    result[0x625A86D5] = (SSLCipherSuite*)&Cipher15;
    result[0x60FF1BD4] = (SSLCipherSuite*)&Cipher16;
    result[0xE101D5C8] = (SSLCipherSuite*)&Cipher17;
    result[0x422859E8] = (SSLCipherSuite*)&Cipher18;
    result[0x88ABC503] = (SSLCipherSuite*)&Cipher19;
    result[0x44284B1] = (SSLCipherSuite*)&Cipher20;
    result[0xFD71B064] = (SSLCipherSuite*)&Cipher21;
    result[0x76F35237] = (SSLCipherSuite*)&Cipher22;
    result[0x7D93159D] = (SSLCipherSuite*)&Cipher23;
    result[0x6E9D1AE2] = (SSLCipherSuite*)&Cipher24;
    result[0xFA0974E4] = (SSLCipherSuite*)&Cipher25;
    result[0xEC27ACB1] = (SSLCipherSuite*)&Cipher26;
    result[0x6859C7A8] = (SSLCipherSuite*)&Cipher27;
    result[0x55FD3D14] = (SSLCipherSuite*)&Cipher28;
    result[0xA7650023] = (SSLCipherSuite*)&Cipher29;
    result[0xDC042011] = (SSLCipherSuite*)&Cipher30;
    result[0x94BFBF4D] = (SSLCipherSuite*)&Cipher31;
    result[0x2FE24162] = (SSLCipherSuite*)&Cipher32;
    result[0xC449D595] = (SSLCipherSuite*)&Cipher33;
    result[0xE11292AF] = (SSLCipherSuite*)&Cipher34;
    result[0x47D0643] = (SSLCipherSuite*)&Cipher35;
    result[0xC9ABBA3C] = (SSLCipherSuite*)&Cipher36;
    result[0x9F323A5F] = (SSLCipherSuite*)&Cipher37;
    result[0xFBF78046] = (SSLCipherSuite*)&Cipher38;
    result[0x859BD79F] = (SSLCipherSuite*)&Cipher39;
    result[0xF9FBBB39] = (SSLCipherSuite*)&Cipher40;
    result[0x63587748] = (SSLCipherSuite*)&Cipher41;
    result[0xF84CAE79] = (SSLCipherSuite*)&Cipher42;
    result[0xCA39F6F1] = (SSLCipherSuite*)&Cipher43;
    result[0xDC4D17C1] = (SSLCipherSuite*)&Cipher44;
    result[0x955FBE28] = (SSLCipherSuite*)&Cipher45;
    result[0x73ED7B86] = (SSLCipherSuite*)&Cipher46;
    result[0x14A51855] = (SSLCipherSuite*)&Cipher47;
    result[0x2CE54061] = (SSLCipherSuite*)&Cipher48;
    result[0x3360789A] = (SSLCipherSuite*)&Cipher49;
    result[0xDFEF59B6] = (SSLCipherSuite*)&Cipher50;
    result[0xE819855D] = (SSLCipherSuite*)&Cipher51;
    result[0x24CC3946] = (SSLCipherSuite*)&Cipher52;
    result[0x1CACB5FD] = (SSLCipherSuite*)&Cipher53;
    result[0x40193001] = (SSLCipherSuite*)&Cipher54;
    result[0xA3846DA2] = (SSLCipherSuite*)&Cipher55;
    result[0x8F3B7CF6] = (SSLCipherSuite*)&Cipher56;
    result[0xC7B09945] = (SSLCipherSuite*)&Cipher57;
    result[0xD8172F82] = (SSLCipherSuite*)&Cipher58;
    result[0xB6748503] = (SSLCipherSuite*)&Cipher59;
    result[0xDB105043] = (SSLCipherSuite*)&Cipher60;
    result[0x21E8AC2E] = (SSLCipherSuite*)&Cipher61;
    result[0x55096FC2] = (SSLCipherSuite*)&Cipher62;
    result[0x38F955AF] = (SSLCipherSuite*)&Cipher63;
    result[0xBA8C1D77] = (SSLCipherSuite*)&Cipher64;
    result[0x91128102] = (SSLCipherSuite*)&Cipher65;
    result[0xA7ED740E] = (SSLCipherSuite*)&Cipher66;
    result[0x75C4908B] = (SSLCipherSuite*)&Cipher67;
    result[0xBC6C5E87] = (SSLCipherSuite*)&Cipher68;
    result[0xA0499A2A] = (SSLCipherSuite*)&Cipher69;
    result[0x4F0FFC13] = (SSLCipherSuite*)&Cipher70;
    result[0xCCEE9996] = (SSLCipherSuite*)&Cipher71;
    result[0x8570DA22] = (SSLCipherSuite*)&Cipher72;
    result[0x75D4FD57] = (SSLCipherSuite*)&Cipher73;
    result[0x602E04D3] = (SSLCipherSuite*)&Cipher74;
    result[0x5EDC9C36] = (SSLCipherSuite*)&Cipher75;
    result[0xE66C167E] = (SSLCipherSuite*)&Cipher76;
    result[0x909F6D7B] = (SSLCipherSuite*)&Cipher77;
    result[0x3C35B1AA] = (SSLCipherSuite*)&Cipher78;
    result[0x6D4D1A2E] = (SSLCipherSuite*)&Cipher79;
    result[0xBF788317] = (SSLCipherSuite*)&Cipher80;
    result[0x5329738B] = (SSLCipherSuite*)&Cipher81;
    result[0x7D11AB2] = (SSLCipherSuite*)&Cipher82;
    result[0x461ACA21] = (SSLCipherSuite*)&Cipher83;
    result[0x15404ADD] = (SSLCipherSuite*)&Cipher84;
    result[0x3806AF6] = (SSLCipherSuite*)&Cipher85;
    result[0xB2D80EB6] = (SSLCipherSuite*)&Cipher86;
    result[0xE54425D1] = (SSLCipherSuite*)&Cipher87;
    result[0x476457CD] = (SSLCipherSuite*)&Cipher88;
    result[0x1D55E526] = (SSLCipherSuite*)&Cipher89;
    result[0x953C69E6] = (SSLCipherSuite*)&Cipher90;
    result[0x6ADE7E16] = (SSLCipherSuite*)&Cipher91;
    result[0xE8C7BBE8] = (SSLCipherSuite*)&Cipher92;
    result[0x623DC741] = (SSLCipherSuite*)&Cipher93;
    result[0xF403E1] = (SSLCipherSuite*)&Cipher94;
    result[0x90D8CADC] = (SSLCipherSuite*)&Cipher95;
    result[0xC30D1199] = (SSLCipherSuite*)&Cipher96;
    result[0x9CFB1B5D] = (SSLCipherSuite*)&Cipher97;
    result[0x2D3B99E8] = (SSLCipherSuite*)&Cipher98;
    result[0x4A9E8B0C] = (SSLCipherSuite*)&Cipher99;
    result[0x16BD2351] = (SSLCipherSuite*)&Cipher100;
    result[0x586BC20E] = (SSLCipherSuite*)&Cipher101;
    result[0x996B90AA] = (SSLCipherSuite*)&Cipher102;
    result[0x2F3871FE] = (SSLCipherSuite*)&Cipher103;
    result[0xF2DD519A] = (SSLCipherSuite*)&Cipher104;
    result[0x52615F23] = (SSLCipherSuite*)&Cipher105;
    result[0xDEE51337] = (SSLCipherSuite*)&Cipher106;
    result[0xB30890E2] = (SSLCipherSuite*)&Cipher107;
    result[0x40F3FF3E] = (SSLCipherSuite*)&Cipher108;
    result[0xE306EE17] = (SSLCipherSuite*)&Cipher109;
    result[0x870C6FCB] = (SSLCipherSuite*)&Cipher110;
    result[0xEB12CAEF] = (SSLCipherSuite*)&Cipher111;
    result[0x68795983] = (SSLCipherSuite*)&Cipher112;
    result[0x606BA9BE] = (SSLCipherSuite*)&Cipher113;
    result[0x2C33475A] = (SSLCipherSuite*)&Cipher114;
    result[0x640CAAEE] = (SSLCipherSuite*)&Cipher115;
    result[0x6603488A] = (SSLCipherSuite*)&Cipher116;
    result[0x8BA58643] = (SSLCipherSuite*)&Cipher117;
    result[0x16059E57] = (SSLCipherSuite*)&Cipher118;
    result[0x1B0606D3] = (SSLCipherSuite*)&Cipher119;
    result[0x1CF76007] = (SSLCipherSuite*)&Cipher120;
    result[0x618CE8F2] = (SSLCipherSuite*)&Cipher121;
    result[0xE264D3B6] = (SSLCipherSuite*)&Cipher122;
    result[0xB4C5AE63] = (SSLCipherSuite*)&Cipher123;
    result[0x95DF4757] = (SSLCipherSuite*)&Cipher124;
    result[0x1D1CF062] = (SSLCipherSuite*)&Cipher125;
    result[0xE7AA2826] = (SSLCipherSuite*)&Cipher126;
    result[0x38D94EE2] = (SSLCipherSuite*)&Cipher127;
    result[0x889BA306] = (SSLCipherSuite*)&Cipher128;
    result[0x5B816E75] = (SSLCipherSuite*)&Cipher129;
    result[0x6F18C4DD] = (SSLCipherSuite*)&Cipher130;
    result[0x2E1C05E0] = (SSLCipherSuite*)&Cipher131;
    result[0x5592CFF7] = (SSLCipherSuite*)&Cipher132;
    result[0x8221D38B] = (SSLCipherSuite*)&Cipher133;
    result[0x9538105C] = (SSLCipherSuite*)&Cipher134;
    result[0xF1100DD0] = (SSLCipherSuite*)&Cipher135;
    result[0xF492EF1F] = (SSLCipherSuite*)&Cipher136;
    result[0x226BD52C] = (SSLCipherSuite*)&Cipher137;
    result[0xBBACE99F] = (SSLCipherSuite*)&Cipher138;
    result[0xB3D4B66B] = (SSLCipherSuite*)&Cipher139;
    result[0x8C619440] = (SSLCipherSuite*)&Cipher140;
    result[0xE60B95C] = (SSLCipherSuite*)&Cipher141;
    result[0x24F48D07] = (SSLCipherSuite*)&Cipher142;
    result[0x15C7AF26] = (SSLCipherSuite*)&Cipher143;
    result[0xCBA219CC] = (SSLCipherSuite*)&Cipher144;
    result[0x9BD946BE] = (SSLCipherSuite*)&Cipher145;
    result[0x7CCA46FF] = (SSLCipherSuite*)&Cipher146;
    result[0x9FB51FA3] = (SSLCipherSuite*)&Cipher147;
    result[0xC82A275B] = (SSLCipherSuite*)&Cipher148;
    result[0x4472A583] = (SSLCipherSuite*)&Cipher149;
    result[0xDBA3A5CF] = (SSLCipherSuite*)&Cipher150;
    result[0x86338128] = (SSLCipherSuite*)&Cipher151;
    result[0x8CCE91E4] = (SSLCipherSuite*)&Cipher152;
    result[0xA81C6CA0] = (SSLCipherSuite*)&Cipher153;
    result[0x6D80815E] = (SSLCipherSuite*)&Cipher154;
    result[0xA383DEB0] = (SSLCipherSuite*)&Cipher155;
    result[0x52073879] = (SSLCipherSuite*)&Cipher156;
    result[0x5BA0B279] = (SSLCipherSuite*)&Cipher157;
    result[0xD787CCC9] = (SSLCipherSuite*)&Cipher158;
    result[0x9C86C6A9] = (SSLCipherSuite*)&Cipher159;
    result[0xDAE424E5] = (SSLCipherSuite*)&Cipher160;
    result[0x72C15ECE] = (SSLCipherSuite*)&Cipher161;
    result[0xF0E8FB6E] = (SSLCipherSuite*)&Cipher162;
    result[0xA2005D44] = (SSLCipherSuite*)&Cipher163;
    result[0x77F79962] = (SSLCipherSuite*)&Cipher164;
    result[0x25C8184C] = (SSLCipherSuite*)&Cipher165;
    result[0x2070F8A5] = (SSLCipherSuite*)&Cipher166;
    result[0x4189ED8D] = (SSLCipherSuite*)&Cipher167;
    result[0x94C21B1] = (SSLCipherSuite*)&Cipher168;
    result[0x1B0CB25C] = (SSLCipherSuite*)&Cipher169;
    result[0xF18127A0] = (SSLCipherSuite*)&Cipher170;
    result[0xC7FCA79A] = (SSLCipherSuite*)&Cipher171;
    result[0xC1DEE135] = (SSLCipherSuite*)&Cipher172;
    result[0xDA7143E9] = (SSLCipherSuite*)&Cipher173;
    result[0xE82B6A2] = (SSLCipherSuite*)&Cipher174;
    result[0x438EC1DD] = (SSLCipherSuite*)&Cipher175;
    result[0x6BE32FA9] = (SSLCipherSuite*)&Cipher176;
    result[0x18A5C375] = (SSLCipherSuite*)&Cipher177;
    result[0x24136C59] = (SSLCipherSuite*)&Cipher178;
    result[0x88529408] = (SSLCipherSuite*)&Cipher179;
    result[0xADAB33FC] = (SSLCipherSuite*)&Cipher180;
    result[0x79407DCB] = (SSLCipherSuite*)&Cipher181;
    result[0x64970FFF] = (SSLCipherSuite*)&Cipher182;
    result[0x8260DC9A] = (SSLCipherSuite*)&Cipher183;
    result[0x4B74FFFE] = (SSLCipherSuite*)&Cipher184;
    result[0x350DD5C8] = (SSLCipherSuite*)&Cipher185;
    result[0x53E057C] = (SSLCipherSuite*)&Cipher186;
    result[0x266020E1] = (SSLCipherSuite*)&Cipher187;
    result[0xE6DB4B9D] = (SSLCipherSuite*)&Cipher188;
    result[0x5A992E6] = (SSLCipherSuite*)&Cipher189;
    result[0x1B33C882] = (SSLCipherSuite*)&Cipher190;
    result[0x33579D2B] = (SSLCipherSuite*)&Cipher191;
    result[0x1BD7F7FF] = (SSLCipherSuite*)&Cipher192;
    result[0x39C59ED9] = (SSLCipherSuite*)&Cipher193;
    result[0x4F19FB95] = (SSLCipherSuite*)&Cipher194;
    result[0x8F4737BE] = (SSLCipherSuite*)&Cipher195;
    result[0x2567AA9E] = (SSLCipherSuite*)&Cipher196;
    result[0xEEF843DB] = (SSLCipherSuite*)&Cipher197;
    result[0x978C4E4F] = (SSLCipherSuite*)&Cipher198;
    result[0x2F8D17D9] = (SSLCipherSuite*)&Cipher199;
    result[0x7F80393A] = (SSLCipherSuite*)&Cipher200;
    result[0xDCA5AE1E] = (SSLCipherSuite*)&Cipher201;
    result[0x74AA95D7] = (SSLCipherSuite*)&Cipher202;
    result[0xB93174BB] = (SSLCipherSuite*)&Cipher203;
    result[0x46E274FC] = (SSLCipherSuite*)&Cipher204;
    result[0x9DC85330] = (SSLCipherSuite*)&Cipher205;
    result[0x972847B8] = (SSLCipherSuite*)&Cipher206;
    result[0xFCF61DAC] = (SSLCipherSuite*)&Cipher207;
    result[0x73C0029B] = (SSLCipherSuite*)&Cipher208;
    result[0xDA41D70F] = (SSLCipherSuite*)&Cipher209;
    result[0x12CBC4E7] = (SSLCipherSuite*)&Cipher210;
    result[0x8B2D5ACB] = (SSLCipherSuite*)&Cipher211;
    result[0x28C0C084] = (SSLCipherSuite*)&Cipher212;
    result[0x1602C1F8] = (SSLCipherSuite*)&Cipher213;
    result[0xF5FB9ED] = (SSLCipherSuite*)&Cipher214;
    result[0xE8E30E91] = (SSLCipherSuite*)&Cipher215;
    result[0x70BA7792] = (SSLCipherSuite*)&Cipher216;
    result[0x94C38076] = (SSLCipherSuite*)&Cipher217;
    result[0xE5B3483F] = (SSLCipherSuite*)&Cipher218;
    result[0x892DEBE3] = (SSLCipherSuite*)&Cipher219;
    result[0x65609E50] = (SSLCipherSuite*)&Cipher220;
    result[0xAB4F3F04] = (SSLCipherSuite*)&Cipher221;
    result[0x8BFC76DA] = (SSLCipherSuite*)&Cipher222;
    result[0xD4BDCD6] = (SSLCipherSuite*)&Cipher223;
    result[0xCAB8F54A] = (SSLCipherSuite*)&Cipher224;
    result[0xA10DCFC6] = (SSLCipherSuite*)&Cipher225;
    result[0xD6B71B71] = (SSLCipherSuite*)&Cipher226;
    result[0x6D775A2D] = (SSLCipherSuite*)&Cipher227;
    result[0x7997AD16] = (SSLCipherSuite*)&Cipher228;
    result[0x5338C632] = (SSLCipherSuite*)&Cipher229;
    result[0x45F0598D] = (SSLCipherSuite*)&Cipher230;
    result[0x2D8B6A99] = (SSLCipherSuite*)&Cipher231;
    result[0xE14DC125] = (SSLCipherSuite*)&Cipher232;
    result[0x1538351] = (SSLCipherSuite*)&Cipher233;
    result[0x1A8CE530] = (SSLCipherSuite*)&Cipher234;
    result[0xB01E69C4] = (SSLCipherSuite*)&Cipher235;
    result[0xCCBF70D3] = (SSLCipherSuite*)&Cipher236;
    result[0xEF664FE7] = (SSLCipherSuite*)&Cipher237;
    result[0xF6ED4F52] = (SSLCipherSuite*)&Cipher238;
    result[0x7D6522E] = (SSLCipherSuite*)&Cipher239;
    result[0xBDB5C9B9] = (SSLCipherSuite*)&Cipher240;
    result[0xD98D5C95] = (SSLCipherSuite*)&Cipher241;
    result[0x92B92727] = (SSLCipherSuite*)&Cipher242;
    result[0xB4FE570B] = (SSLCipherSuite*)&Cipher243;
    result[0x8DCF7F77] = (SSLCipherSuite*)&Cipher244;
    result[0x8208545B] = (SSLCipherSuite*)&Cipher245;
    result[0x39A13298] = (SSLCipherSuite*)&Cipher246;
    result[0xECB7070C] = (SSLCipherSuite*)&Cipher247;
    result[0xAFA95F8A] = (SSLCipherSuite*)&Cipher248;
    result[0x3D80E106] = (SSLCipherSuite*)&Cipher249;
    result[0x83AF9B7A] = (SSLCipherSuite*)&Cipher250;
    result[0x1FAAC2F6] = (SSLCipherSuite*)&Cipher251;
    result[0x2AF11F51] = (SSLCipherSuite*)&Cipher252;
    result[0xEDFD300D] = (SSLCipherSuite*)&Cipher253;
    result[0x91AA268F] = (SSLCipherSuite*)&Cipher254;
    result[0x9DF0E933] = (SSLCipherSuite*)&Cipher255;
    result[0xF3951A6A] = (SSLCipherSuite*)&Cipher256;
    result[0xE4FF8DCE] = (SSLCipherSuite*)&Cipher257;
    result[0xBE4DFC61] = (SSLCipherSuite*)&Cipher258;
    result[0xBB2CF025] = (SSLCipherSuite*)&Cipher259;
    result[0x354D38A8] = (SSLCipherSuite*)&Cipher260;
    result[0xE2444B9C] = (SSLCipherSuite*)&Cipher261;
    result[0xF8298D43] = (SSLCipherSuite*)&Cipher262;
    result[0x3EC413B7] = (SSLCipherSuite*)&Cipher263;
    result[0xE0C75BE9] = (SSLCipherSuite*)&Cipher264;
    result[0x7191BE45] = (SSLCipherSuite*)&Cipher265;
    result[0xDDE7C439] = (SSLCipherSuite*)&Cipher266;
    result[0xBE715415] = (SSLCipherSuite*)&Cipher267;
    result[0x6CF8F9A6] = (SSLCipherSuite*)&Cipher268;
    result[0x36D61242] = (SSLCipherSuite*)&Cipher269;
    result[0xFA9BA9ED] = (SSLCipherSuite*)&Cipher270;
    result[0x4588B179] = (SSLCipherSuite*)&Cipher271;
    result[0xB3C246FA] = (SSLCipherSuite*)&Cipher272;
    result[0x750EEB76] = (SSLCipherSuite*)&Cipher273;
    result[0xC50ACCB2] = (SSLCipherSuite*)&Cipher274;
    result[0x9555CD0E] = (SSLCipherSuite*)&Cipher275;
    result[0xF25A659B] = (SSLCipherSuite*)&Cipher276;
    result[0x1670E72F] = (SSLCipherSuite*)&Cipher277;
    result[0xDB0DD6BC] = (SSLCipherSuite*)&Cipher278;
    result[0x19CACD70] = (SSLCipherSuite*)&Cipher279;
    result[0xC54D5481] = (SSLCipherSuite*)&Cipher280;
    result[0x7BCCA2BD] = (SSLCipherSuite*)&Cipher281;
    result[0xA851374E] = (SSLCipherSuite*)&Cipher282;
    result[0xE887BEA] = (SSLCipherSuite*)&Cipher283;
    result[0xDECAA7F9] = (SSLCipherSuite*)&Cipher284;
    result[0x29DA73D5] = (SSLCipherSuite*)&Cipher285;
    result[0xAC69ECC9] = (SSLCipherSuite*)&Cipher286;
    result[0x6AE55625] = (SSLCipherSuite*)&Cipher287;
    result[0x2BB24546] = (SSLCipherSuite*)&Cipher288;
    result[0x7AB5F262] = (SSLCipherSuite*)&Cipher289;
    result[0x3DB83990] = (SSLCipherSuite*)&Cipher290;
    result[0xC852A244] = (SSLCipherSuite*)&Cipher291;
    result[0xA3C952C0] = (SSLCipherSuite*)&Cipher292;
    result[0xAF630C34] = (SSLCipherSuite*)&Cipher293;
    result[0xD4EE22B] = (SSLCipherSuite*)&Cipher294;
    result[0x83F4C5DF] = (SSLCipherSuite*)&Cipher295;
    result[0xCCF6F918] = (SSLCipherSuite*)&Cipher296;
    result[0x955C9E8C] = (SSLCipherSuite*)&Cipher297;
    result[0xF3559154] = (SSLCipherSuite*)&Cipher298;
    result[0xE0991C14] = (SSLCipherSuite*)&Cipher299;
    result[0x7F6BF424] = (SSLCipherSuite*)&Cipher300;
    result[0x4A129264] = (SSLCipherSuite*)&Cipher301;
    result[0xB25E29E3] = (SSLCipherSuite*)&Cipher302;
    result[0xA6E15A23] = (SSLCipherSuite*)&Cipher303;
    result[0x637C5C53] = (SSLCipherSuite*)&Cipher304;
    result[0x22794513] = (SSLCipherSuite*)&Cipher305;
    result[0x4CE30464] = (SSLCipherSuite*)&Cipher306;
    result[0xFDFE3B24] = (SSLCipherSuite*)&Cipher307;
    result[0xDC8A2074] = (SSLCipherSuite*)&Cipher308;
    result[0xFD448934] = (SSLCipherSuite*)&Cipher309;
    result[0xF4FC2B13] = (SSLCipherSuite*)&Cipher310;
    result[0xB10ECD53] = (SSLCipherSuite*)&Cipher311;
    result[0xF44F4BC7] = (SSLCipherSuite*)&Cipher312;
    result[0x49AF0BF] = (SSLCipherSuite*)&Cipher313;
    result[0xDFAF479A] = (SSLCipherSuite*)&Cipher314;
    result[0x82BF78CE] = (SSLCipherSuite*)&Cipher315;
    result[0x46CD83C9] = (SSLCipherSuite*)&Cipher316;
    result[0x8F7D7465] = (SSLCipherSuite*)&Cipher317;
    result[0xBD9CDFE5] = (SSLCipherSuite*)&Cipher318;
    result[0x92942203] = (SSLCipherSuite*)&Cipher319;
    result[0x783C98AD] = (SSLCipherSuite*)&Cipher320;
    result[0x92213B6D] = (SSLCipherSuite*)&Cipher321;
    result[0xCFCB1A55] = (SSLCipherSuite*)&Cipher322;
    result[0x54C2D55D] = (SSLCipherSuite*)&Cipher323;
    result[0xDCD6F114] = (SSLCipherSuite*)&Cipher324;
    result[0x6AD23C40] = (SSLCipherSuite*)&Cipher325;
    result[0x5F5239D4] = (SSLCipherSuite*)&Cipher326;
    result[0xAB27704B] = (SSLCipherSuite*)&Cipher327;
    result[0xA3178D0C] = (SSLCipherSuite*)&Cipher328;
    result[0x5DAAA195] = (SSLCipherSuite*)&Cipher329;

    return result;
}

std::set<uint16_t> createGreaseSet() {
    uint16_t greaseExtensions[] = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
                                   0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
                                   0xcaca, 0xdada, 0xeaea, 0xfafa};
    return std::set<uint16_t>(greaseExtensions, greaseExtensions + 16);
}

static const std::map<uint16_t, SSLCipherSuite*> CipherSuiteIdToObjectMap =
    createCipherSuiteIdToObjectMap();

static const std::map<uint32_t, SSLCipherSuite*> CipherSuiteStringToObjectMap =
    createCipherSuiteStringToObjectMap();

static const std::set<uint16_t> GreaseSet = createGreaseSet();

SSLCipherSuite* SSLCipherSuite::getCipherSuiteByID(uint16_t id) {
    std::map<uint16_t, SSLCipherSuite*>::const_iterator pos =
        CipherSuiteIdToObjectMap.find(id);
    if (pos == CipherSuiteIdToObjectMap.end())
        return nullptr;
    else
        return pos->second;
}

SSLCipherSuite* SSLCipherSuite::getCipherSuiteByName(std::string name) {
    uint32_t nameHash = hashString(std::move(name));
    std::map<uint32_t, SSLCipherSuite*>::const_iterator pos =
        CipherSuiteStringToObjectMap.find(nameHash);
    if (pos == CipherSuiteStringToObjectMap.end())
        return nullptr;
    else
        return pos->second;
}

// --------------------
// SSLExtension methods
// --------------------

SSLExtension::SSLExtension(uint8_t* data) { m_RawData = data; }

SSLExtensionType SSLExtension::getType() const {
    uint16_t typeAsInt = getTypeAsInt();
    if (typeAsInt <= 24 || typeAsInt == 35 || typeAsInt == 65281)
        return (SSLExtensionType)typeAsInt;

    return SSL_EXT_Unknown;
}

uint16_t SSLExtension::getTypeAsInt() const {
    return be16toh(getExtensionStruct()->extensionType);
}

uint16_t SSLExtension::getLength() const {
    return be16toh(getExtensionStruct()->extensionDataLength);
}

uint16_t SSLExtension::getTotalLength() const {
    return getLength() + 2 * sizeof(uint16_t);
}

uint8_t* SSLExtension::getData() const {
    if (getLength() > 0) {
        return getExtensionStruct()->extensionData;
    }

    return nullptr;
}

// ----------------------------------------
// SSLServerNameIndicationExtension methods
// ----------------------------------------

std::string SSLServerNameIndicationExtension::getHostName() const {
    uint8_t* hostNameLengthPos = getData() + sizeof(uint16_t) + sizeof(uint8_t);
    uint16_t hostNameLength = be16toh(*(uint16_t*)hostNameLengthPos);

    char* hostNameAsCharArr = new char[hostNameLength + 1];
    memset(hostNameAsCharArr, 0, hostNameLength + 1);
    memcpy(hostNameAsCharArr, hostNameLengthPos + sizeof(uint16_t),
           hostNameLength);

    std::string res = std::string(hostNameAsCharArr);
    delete[] hostNameAsCharArr;
    return res;
}

// -------------------------------------
// SSLSupportedVersionsExtension methods
// -------------------------------------

std::vector<SSLVersion>
SSLSupportedVersionsExtension::getSupportedVersions() const {
    std::vector<SSLVersion> result;
    uint16_t extensionLength = getLength();
    if (extensionLength == 2) // server hello message
    {
        result.push_back(SSLVersion(be16toh(*(uint16_t*)getData())));
    } else // client-hello message
    {
        uint8_t listLength = *getData();
        if (listLength != static_cast<uint8_t>(extensionLength - 1) ||
            listLength % 2 != 0)
            return result; // bad extension data

        uint8_t* dataPtr = getData() + sizeof(uint8_t);
        for (int i = 0; i < listLength / 2; i++) {
            result.push_back(SSLVersion(be16toh(*(uint16_t*)dataPtr)));
            dataPtr += sizeof(uint16_t);
        }
    }

    return result;
}

// -----------------------------------
// TLSSupportedGroupsExtension methods
// -----------------------------------

std::vector<uint16_t> TLSSupportedGroupsExtension::getSupportedGroups() const {
    std::vector<uint16_t> result;

    uint16_t extensionLength = getLength();
    if (extensionLength < sizeof(uint16_t))
        return result; // bad extension data

    uint16_t listLength = be16toh(*(uint16_t*)getData());
    if (listLength != (extensionLength - sizeof(uint16_t)) || listLength % 2 != 0)
        return result; // bad extension data

    uint8_t* dataPtr = getData() + sizeof(uint16_t);
    for (int i = 0; i < listLength / 2; i++) {
        result.push_back(be16toh(*(uint16_t*)dataPtr));
        dataPtr += sizeof(uint16_t);
    }

    return result;
}

// ---------------------------------
// TLSECPointFormatExtension methods
// ---------------------------------

std::vector<uint8_t> TLSECPointFormatExtension::getECPointFormatList() const {
    std::vector<uint8_t> result;

    uint16_t extensionLength = getLength();
    uint8_t listLength = *getData();
    if (listLength != static_cast<uint8_t>(extensionLength - 1))
        return result; // bad extension data

    uint8_t* dataPtr = getData() + sizeof(uint8_t);
    for (int i = 0; i < listLength; i++) {
        result.push_back(*dataPtr);
        dataPtr += sizeof(uint8_t);
    }

    return result;
}

// ---------------------------
// SSLHandshakeMessage methods
// ---------------------------

SSLHandshakeMessage::SSLHandshakeMessage(uint8_t* data, size_t dataLen,
                                         SSLHandshakeLayer* container) {
    m_Data = data;
    m_DataLen = dataLen;
    m_Container = container;
}

SSLHandshakeMessage*
SSLHandshakeMessage::createHandshakeMessage(uint8_t* data, size_t dataLen,
                                            SSLHandshakeLayer* container) {
    if (dataLen < sizeof(ssl_tls_handshake_layer))
        return nullptr;

    ssl_tls_handshake_layer* hsMsgHeader = (ssl_tls_handshake_layer*)data;

    if (dataLen >= 16 &&
        (be64toh(*(uint64_t*)data) <= 0xFFFFFF || hsMsgHeader->length1 >= 1))
        // possibly Encrypted Handshake Message
        // used heuristic:
        // - handshake layer of more than 16 byte
        // - first 5 bytes of the handshake message are zeroes
        // - or wrong message length is over 64K
        // - or message type makes so sense (handled through the switch statement)
        return new SSLUnknownMessage(data, dataLen, container);

    switch (hsMsgHeader->handshakeType) {
    case SSL_CLIENT_HELLO:
        return new SSLClientHelloMessage(data, dataLen, container);
    case SSL_SERVER_HELLO:
        return new SSLServerHelloMessage(data, dataLen, container);
    case SSL_HELLO_REQUEST:
        return new SSLHelloRequestMessage(data, dataLen, container);
    case SSL_CERTIFICATE:
        return new SSLCertificateMessage(data, dataLen, container);
    case SSL_SERVER_KEY_EXCHANGE:
        return new SSLServerKeyExchangeMessage(data, dataLen, container);
    case SSL_CERTIFICATE_REQUEST:
        return new SSLCertificateRequestMessage(data, dataLen, container);
    case SSL_CERTIFICATE_VERIFY:
        return new SSLCertificateVerifyMessage(data, dataLen, container);
    case SSL_CLIENT_KEY_EXCHANGE:
        return new SSLClientKeyExchangeMessage(data, dataLen, container);
    case SSL_FINISHED:
        return new SSLFinishedMessage(data, dataLen, container);
    case SSL_SERVER_DONE:
        return new SSLServerHelloDoneMessage(data, dataLen, container);
    case SSL_NEW_SESSION_TICKET:
        return new SSLNewSessionTicketMessage(data, dataLen, container);
    default:
        return new SSLUnknownMessage(data, dataLen, container);
    }
}

SSLHandshakeType SSLHandshakeMessage::getHandshakeType() const {
    ssl_tls_handshake_layer* handshakeLayer = (ssl_tls_handshake_layer*)m_Data;
    return (SSLHandshakeType)handshakeLayer->handshakeType;
}

size_t SSLHandshakeMessage::getMessageLength() const {
    ssl_tls_handshake_layer* handshakeLayer = (ssl_tls_handshake_layer*)m_Data;
    // TODO: add handshakeLayer->length1 to the calculation
    size_t len =
        sizeof(ssl_tls_handshake_layer) + be16toh(handshakeLayer->length2);
    if (len > m_DataLen)
        return m_DataLen;

    return len;
}

bool SSLHandshakeMessage::isMessageComplete() const {
    if (m_DataLen < sizeof(ssl_tls_handshake_layer))
        return false;

    ssl_tls_handshake_layer* handshakeLayer = (ssl_tls_handshake_layer*)m_Data;
    size_t len =
        sizeof(ssl_tls_handshake_layer) + be16toh(handshakeLayer->length2);
    return len <= m_DataLen;
}

// -----------------------------
// SSLClientHelloMessage methods
// -----------------------------

SSLClientHelloMessage::SSLClientHelloMessage(uint8_t* data, size_t dataLen,
                                             SSLHandshakeLayer* container)
    : SSLHandshakeMessage(data, dataLen, container) {
    size_t extensionLengthOffset =
        sizeof(ssl_tls_client_server_hello) + sizeof(uint8_t) +
        getSessionIDLength() + sizeof(uint16_t) +
        sizeof(uint16_t) * getCipherSuiteCount() + 2 * sizeof(uint8_t);
    if (extensionLengthOffset + sizeof(uint16_t) > m_DataLen)
        return;

    uint8_t* extensionLengthPos = m_Data + extensionLengthOffset;
    uint16_t extensionLength = getExtensionsLength();
    uint8_t* extensionPos = extensionLengthPos + sizeof(uint16_t);
    uint8_t* curPos = extensionPos;
    size_t messageLen = getMessageLength();
    size_t minSSLExtensionLen = 2 * sizeof(uint16_t);
    while ((curPos - extensionPos) < (int)extensionLength &&
           (curPos - m_Data) < (int)messageLen &&
           (int)messageLen - (curPos - m_Data) >= (int)minSSLExtensionLen) {
        SSLExtension* newExt = nullptr;
        uint16_t sslExtType = be16toh(*(uint16_t*)curPos);
        switch (sslExtType) {
        case SSL_EXT_SERVER_NAME:
            newExt = new SSLServerNameIndicationExtension(curPos);
            break;
        case SSL_EXT_SUPPORTED_VERSIONS:
            newExt = new SSLSupportedVersionsExtension(curPos);
            break;
        case SSL_EXT_SUPPORTED_GROUPS:
            newExt = new TLSSupportedGroupsExtension(curPos);
            break;
        case SSL_EXT_EC_POINT_FORMATS:
            newExt = new TLSECPointFormatExtension(curPos);
            break;
        default:
            newExt = new SSLExtension(curPos);
        }

        // Total length can be zero only if getLength() == 0xfffc which is way too
        // large and means that this extension (and packet) are malformed
        if (newExt->getTotalLength() == 0) {
            delete newExt;
            break;
        }

        m_ExtensionList.pushBack(newExt);
        curPos += newExt->getTotalLength();
    }
}

SSLVersion SSLClientHelloMessage::getHandshakeVersion() const {
    uint16_t handshakeVersion = be16toh(getClientHelloHeader()->handshakeVersion);
    return SSLVersion(handshakeVersion);
}

uint8_t SSLClientHelloMessage::getSessionIDLength() const {
    if (m_DataLen <= sizeof(ssl_tls_client_server_hello) + sizeof(uint8_t))
        return 0;

    uint8_t val = *(m_Data + sizeof(ssl_tls_client_server_hello));
    if ((size_t)val > m_DataLen - sizeof(ssl_tls_client_server_hello) - 1)
        return (uint8_t)(m_DataLen - sizeof(ssl_tls_client_server_hello) - 1);

    return val;
}

uint8_t* SSLClientHelloMessage::getSessionID() const {
    if (getSessionIDLength() > 0)
        return (m_Data + sizeof(ssl_tls_client_server_hello) + 1);
    else
        return nullptr;
}

int SSLClientHelloMessage::getCipherSuiteCount() const {
    size_t cipherSuiteOffset = sizeof(ssl_tls_client_server_hello) +
                               sizeof(uint8_t) + getSessionIDLength();
    if (cipherSuiteOffset + sizeof(uint16_t) > m_DataLen)
        return 0;

    uint16_t cipherSuiteLen = *(uint16_t*)(m_Data + cipherSuiteOffset);
    return be16toh(cipherSuiteLen) / 2;
}

SSLCipherSuite* SSLClientHelloMessage::getCipherSuite(int index) const {
    bool isValid;
    uint16_t id = getCipherSuiteID(index, isValid);
    return (isValid ? SSLCipherSuite::getCipherSuiteByID(id) : nullptr);
}

uint16_t SSLClientHelloMessage::getCipherSuiteID(int index,
                                                 bool& isValid) const {
    if (index < 0 || index >= getCipherSuiteCount()) {
        isValid = false;
        return 0;
    }

    size_t cipherSuiteStartOffset = sizeof(ssl_tls_client_server_hello) +
                                    sizeof(uint8_t) + getSessionIDLength() +
                                    sizeof(uint16_t);
    if (cipherSuiteStartOffset + sizeof(uint16_t) * (index + 1) > m_DataLen) {
        isValid = false;
        return 0;
    }

    isValid = true;
    uint16_t* cipherSuiteStartPos = (uint16_t*)(m_Data + cipherSuiteStartOffset);
    return be16toh(*(cipherSuiteStartPos + index));
}

uint8_t SSLClientHelloMessage::getCompressionMethodsValue() const {
    size_t offset = sizeof(ssl_tls_client_server_hello) + sizeof(uint8_t) +
                    getSessionIDLength() + sizeof(uint16_t) +
                    sizeof(uint16_t) * getCipherSuiteCount() + sizeof(uint8_t);
    if (offset + sizeof(uint8_t) > m_DataLen)
        return 0xff;

    uint8_t* pos = m_Data + offset;
    return *pos;
}

int SSLClientHelloMessage::getExtensionCount() const {
    return m_ExtensionList.size();
}

uint16_t SSLClientHelloMessage::getExtensionsLength() const {
    size_t extensionLengthOffset =
        sizeof(ssl_tls_client_server_hello) + sizeof(uint8_t) +
        getSessionIDLength() + sizeof(uint16_t) +
        sizeof(uint16_t) * getCipherSuiteCount() + 2 * sizeof(uint8_t);
    if (extensionLengthOffset + sizeof(uint16_t) > m_DataLen)
        return 0;

    uint8_t* extensionLengthPos = m_Data + extensionLengthOffset;
    return be16toh(*(uint16_t*)extensionLengthPos);
}

SSLExtension* SSLClientHelloMessage::getExtension(int index) const {
    return const_cast<SSLExtension*>(m_ExtensionList.at(index));
}

SSLExtension* SSLClientHelloMessage::getExtensionOfType(uint16_t type) const {
    size_t vecSize = m_ExtensionList.size();
    for (size_t i = 0; i < vecSize; i++) {
        SSLExtension* curElem = const_cast<SSLExtension*>(m_ExtensionList.at(i));
        if (curElem->getTypeAsInt() == type)
            return curElem;
    }

    return nullptr;
}

SSLExtension*
SSLClientHelloMessage::getExtensionOfType(SSLExtensionType type) const {
    size_t vecSize = m_ExtensionList.size();
    for (size_t i = 0; i < vecSize; i++) {
        SSLExtension* curElem = const_cast<SSLExtension*>(m_ExtensionList.at(i));
        if (curElem->getType() == type)
            return curElem;
    }

    return nullptr;
}

SSLClientHelloMessage::ClientHelloTLSFingerprint
SSLClientHelloMessage::generateTLSFingerprint() const {
    SSLClientHelloMessage::ClientHelloTLSFingerprint result;

    // extract version
    result.tlsVersion = getHandshakeVersion().asUInt();

    // extract cipher suites
    int cipherSuiteCount = getCipherSuiteCount();
    for (int i = 0; i < cipherSuiteCount; i++) {
        bool isValid = false;
        uint16_t cipherSuiteID = getCipherSuiteID(i, isValid);
        if (isValid && GreaseSet.find(cipherSuiteID) == GreaseSet.end())
            result.cipherSuites.push_back(cipherSuiteID);
    }

    // extract extensions
    int extensionCount = getExtensionCount();
    for (int i = 0; i < extensionCount; i++) {
        uint16_t extensionType = getExtension(i)->getTypeAsInt();
        if (GreaseSet.find(extensionType) != GreaseSet.end())
            continue;

        result.extensions.push_back(extensionType);
    }

    // extract supported groups
    TLSSupportedGroupsExtension* supportedGroupsExt =
        getExtensionOfType<TLSSupportedGroupsExtension>();
    if (supportedGroupsExt != nullptr) {
        std::vector<uint16_t> supportedGroups =
            supportedGroupsExt->getSupportedGroups();
        for (std::vector<uint16_t>::const_iterator iter = supportedGroups.begin();
             iter != supportedGroups.end(); iter++)
            if (GreaseSet.find(*iter) == GreaseSet.end())
                result.supportedGroups.push_back(*iter);
    }

    // extract EC point formats
    TLSECPointFormatExtension* ecPointFormatExt =
        getExtensionOfType<TLSECPointFormatExtension>();
    if (ecPointFormatExt != nullptr) {
        result.ecPointFormats = ecPointFormatExt->getECPointFormatList();
    }

    return result;
}

std::string SSLClientHelloMessage::toString() const {
    return "Client Hello message";
}

// ------------------------------------------------
// SSLClientHelloMessage::ClientHelloTLSFingerprint
// ------------------------------------------------

std::string SSLClientHelloMessage::ClientHelloTLSFingerprint::toString() {
    std::stringstream tlsFingerprint;

    // add version
    tlsFingerprint << tlsVersion << ",";

    // add cipher suites
    bool firstCipher = true;
    for (std::vector<uint16_t>::const_iterator iter = cipherSuites.begin();
         iter != cipherSuites.end(); iter++) {
        tlsFingerprint << (firstCipher ? "" : "-") << *iter;
        firstCipher = false;
    }
    tlsFingerprint << ",";

    // add extensions
    bool firstExtension = true;
    for (std::vector<uint16_t>::const_iterator iter = extensions.begin();
         iter != extensions.end(); iter++) {
        tlsFingerprint << (firstExtension ? "" : "-") << *iter;
        firstExtension = false;
    }
    tlsFingerprint << ",";

    // add supported groups
    bool firstGroup = true;
    for (std::vector<uint16_t>::const_iterator iter = supportedGroups.begin();
         iter != supportedGroups.end(); iter++) {
        tlsFingerprint << (firstGroup ? "" : "-") << (*iter);
        firstGroup = false;
    }
    tlsFingerprint << ",";

    // add EC point formats
    bool firstPointFormat = true;
    for (std::vector<uint8_t>::iterator iter = ecPointFormats.begin();
         iter != ecPointFormats.end(); iter++) {
        tlsFingerprint << (firstPointFormat ? "" : "-") << (int)(*iter);
        firstPointFormat = false;
    }

    return tlsFingerprint.str();
}

std::string SSLClientHelloMessage::ClientHelloTLSFingerprint::toMD5() {
    return toStringAndMD5().second;
}

std::pair<std::string, std::string>
SSLClientHelloMessage::ClientHelloTLSFingerprint::toStringAndMD5() {
    std::string str = toString();
    MD5 md5;
    return std::pair<std::string, std::string>(str, md5(str));
}

// -----------------------------
// SSLServerHelloMessage methods
// -----------------------------

SSLServerHelloMessage::SSLServerHelloMessage(uint8_t* data, size_t dataLen,
                                             SSLHandshakeLayer* container)
    : SSLHandshakeMessage(data, dataLen, container) {
    size_t extensionLengthOffset = sizeof(ssl_tls_client_server_hello) +
                                   sizeof(uint8_t) + getSessionIDLength() +
                                   sizeof(uint16_t) + sizeof(uint8_t);
    if (extensionLengthOffset + sizeof(uint16_t) > m_DataLen)
        return;

    uint8_t* extensionLengthPos = m_Data + extensionLengthOffset;
    uint16_t extensionLength = getExtensionsLength();
    uint8_t* extensionPos = extensionLengthPos + sizeof(uint16_t);
    uint8_t* curPos = extensionPos;
    size_t messageLen = getMessageLength();
    size_t minSSLExtensionLen = 2 * sizeof(uint16_t);
    while ((curPos - extensionPos) < (int)extensionLength &&
           (curPos - m_Data) < (int)messageLen &&
           (int)messageLen - (curPos - m_Data) >= (int)minSSLExtensionLen) {
        SSLExtension* newExt = nullptr;
        uint16_t sslExtType = be16toh(*(uint16_t*)curPos);
        switch (sslExtType) {
        case SSL_EXT_SERVER_NAME:
            newExt = new SSLServerNameIndicationExtension(curPos);
            break;
        case SSL_EXT_SUPPORTED_VERSIONS:
            newExt = new SSLSupportedVersionsExtension(curPos);
            break;
        case SSL_EXT_SUPPORTED_GROUPS:
            newExt = new TLSSupportedGroupsExtension(curPos);
            break;
        case SSL_EXT_EC_POINT_FORMATS:
            newExt = new TLSECPointFormatExtension(curPos);
            break;
        default:
            newExt = new SSLExtension(curPos);
        }

        if (newExt->getTotalLength() == 0) {
            delete newExt;
            break;
        }

        m_ExtensionList.pushBack(newExt);
        curPos += newExt->getTotalLength();
    }
}

SSLVersion SSLServerHelloMessage::getHandshakeVersion() const {
    SSLSupportedVersionsExtension* supportedVersionsExt =
        getExtensionOfType<SSLSupportedVersionsExtension>();
    if (supportedVersionsExt != nullptr) {
        std::vector<SSLVersion> supportedVersions =
            supportedVersionsExt->getSupportedVersions();
        if (supportedVersions.size() == 1)
            return supportedVersions[0];
    }

    uint16_t handshakeVersion = be16toh(getServerHelloHeader()->handshakeVersion);
    return SSLVersion(handshakeVersion);
}
uint8_t SSLServerHelloMessage::getSessionIDLength() const {
    if (m_DataLen <= sizeof(ssl_tls_client_server_hello) + sizeof(uint8_t))
        return 0;

    uint8_t val = *(m_Data + sizeof(ssl_tls_client_server_hello));
    if ((size_t)val > m_DataLen - sizeof(ssl_tls_client_server_hello) - 1)
        return (uint8_t)(m_DataLen - sizeof(ssl_tls_client_server_hello) - 1);

    return val;
}

uint8_t* SSLServerHelloMessage::getSessionID() const {
    if (getSessionIDLength() > 0)
        return (m_Data + sizeof(ssl_tls_client_server_hello) + 1);
    else
        return nullptr;
}

SSLCipherSuite* SSLServerHelloMessage::getCipherSuite() const {
    bool isValid;
    uint16_t id = getCipherSuiteID(isValid);
    return (isValid ? SSLCipherSuite::getCipherSuiteByID(id) : nullptr);
}

uint16_t SSLServerHelloMessage::getCipherSuiteID(bool& isValid) const {
    size_t cipherSuiteStartOffset = sizeof(ssl_tls_client_server_hello) +
                                    sizeof(uint8_t) + getSessionIDLength();
    if (cipherSuiteStartOffset + sizeof(uint16_t) > m_DataLen) {
        isValid = false;
        return 0;
    }

    isValid = true;
    uint16_t* cipherSuiteStartPos = (uint16_t*)(m_Data + cipherSuiteStartOffset);
    return be16toh(*(cipherSuiteStartPos));
}

uint8_t SSLServerHelloMessage::getCompressionMethodsValue() const {
    size_t offset = sizeof(ssl_tls_client_server_hello) + sizeof(uint8_t) +
                    getSessionIDLength() + sizeof(uint16_t);
    if (offset + sizeof(uint8_t) > m_DataLen)
        return 0xff;

    uint8_t* pos = m_Data + offset;
    return *pos;
}

int SSLServerHelloMessage::getExtensionCount() const {
    return m_ExtensionList.size();
}

uint16_t SSLServerHelloMessage::getExtensionsLength() const {
    size_t extensionLengthOffset = sizeof(ssl_tls_client_server_hello) +
                                   sizeof(uint8_t) + getSessionIDLength() +
                                   sizeof(uint16_t) + sizeof(uint8_t);
    if (extensionLengthOffset + sizeof(uint16_t) > m_DataLen)
        return 0;

    uint16_t* extensionLengthPos = (uint16_t*)(m_Data + extensionLengthOffset);
    return be16toh(*extensionLengthPos);
}

SSLExtension* SSLServerHelloMessage::getExtension(int index) const {
    if (index < 0 || index >= (int)m_ExtensionList.size())
        return nullptr;

    return const_cast<SSLExtension*>(m_ExtensionList.at(index));
}

SSLExtension* SSLServerHelloMessage::getExtensionOfType(uint16_t type) const {
    size_t vecSize = m_ExtensionList.size();
    for (size_t i = 0; i < vecSize; i++) {
        SSLExtension* curElem = const_cast<SSLExtension*>(m_ExtensionList.at(i));
        if (curElem->getType() == type)
            return curElem;
    }

    return nullptr;
}

SSLExtension*
SSLServerHelloMessage::getExtensionOfType(SSLExtensionType type) const {
    size_t vecSize = m_ExtensionList.size();
    for (size_t i = 0; i < vecSize; i++) {
        SSLExtension* curElem = const_cast<SSLExtension*>(m_ExtensionList.at(i));
        if (curElem->getType() == type)
            return curElem;
    }

    return nullptr;
}

SSLServerHelloMessage::ServerHelloTLSFingerprint
SSLServerHelloMessage::generateTLSFingerprint() const {
    SSLServerHelloMessage::ServerHelloTLSFingerprint result;

    // extract version
    result.tlsVersion = getHandshakeVersion().asUInt();

    // extract cipher suite
    bool isValid;
    uint16_t cipherSuite = getCipherSuiteID(isValid);
    result.cipherSuite = (isValid ? cipherSuite : 0);

    // extract extensions
    int extensionCount = getExtensionCount();
    for (int i = 0; i < extensionCount; i++) {
        uint16_t extensionType = getExtension(i)->getTypeAsInt();
        result.extensions.push_back(extensionType);
    }

    return result;
}

std::string SSLServerHelloMessage::toString() const {
    return "Server Hello message";
}

// ------------------------------------------------
// SSLServerHelloMessage::ServerHelloTLSFingerprint
// ------------------------------------------------

std::string SSLServerHelloMessage::ServerHelloTLSFingerprint::toString() {
    std::stringstream tlsFingerprint;

    // add version and cipher suite
    tlsFingerprint << tlsVersion << "," << cipherSuite << ",";

    // add extensions
    bool firstExtension = true;
    for (std::vector<uint16_t>::const_iterator iter = extensions.begin();
         iter != extensions.end(); iter++) {
        tlsFingerprint << (firstExtension ? "" : "-") << *iter;
        firstExtension = false;
    }

    return tlsFingerprint.str();
}

std::string SSLServerHelloMessage::ServerHelloTLSFingerprint::toMD5() {
    return toStringAndMD5().second;
}

std::pair<std::string, std::string>
SSLServerHelloMessage::ServerHelloTLSFingerprint::toStringAndMD5() {
    std::string str = toString();
    MD5 md5;
    return std::pair<std::string, std::string>(str, md5(str));
}

// -----------------------------
// SSLCertificateMessage methods
// -----------------------------

SSLCertificateMessage::SSLCertificateMessage(uint8_t* data, size_t dataLen,
                                             SSLHandshakeLayer* container)
    : SSLHandshakeMessage(data, dataLen, container) {
    if (dataLen < sizeof(ssl_tls_handshake_layer) +
                      sizeof(uint8_t) * 3) // certificates length (3B)
        return;

    size_t messageLen = getMessageLength();
    // read certificates length
    // TODO: certificates length is 3B. Currently assuming the MSB is 0 and
    // reading only 2 LSBs
    uint8_t* curPos = data + sizeof(ssl_tls_handshake_layer) + sizeof(uint8_t);
    uint16_t certificatesLength = be16toh(*(uint16_t*)(curPos));
    if (certificatesLength == 0)
        return;

    // advance to position of first certificate
    curPos += sizeof(uint16_t);

    while (true) {
        // try to read certificate length (3B)
        // TODO: certificate length is 3B. Currently assuming the MSB is 0 and
        // reading only 2 LSBs
        if (curPos + 3 * sizeof(uint8_t) - data > (int)messageLen)
            break;

        // read certificate length
        curPos += sizeof(uint8_t);
        uint16_t certificateLength = be16toh(*(uint16_t*)(curPos));

        // advance to start position of certificate
        curPos += sizeof(uint16_t);

        // if packet doesn't contain the full certificate, read only what you got
        // from current position till the end of the packet
        bool certificateFull = true;
        if (curPos - data + certificateLength > (int)messageLen) {
            certificateLength = messageLen - (curPos - data);
            certificateFull = false;
        }

        PCPP_LOG_DEBUG("Parsing certificate: pos="
                       << (int)(curPos - data) << "; len=" << certificateLength);
        SSLx509Certificate* newCert =
            new SSLx509Certificate(curPos, certificateLength, certificateFull);
        m_CertificateList.pushBack(newCert);

        curPos += certificateLength;
    }
}

std::string SSLCertificateMessage::toString() const {
    return "Certificate message";
}

int SSLCertificateMessage::getNumOfCertificates() const {
    return m_CertificateList.size();
}

SSLx509Certificate* SSLCertificateMessage::getCertificate(int index) const {
    if (index < 0 || index > (int)m_CertificateList.size()) {
        PCPP_LOG_DEBUG("certificate index out of range: asked for index "
                       << index << ", total size is " << m_CertificateList.size());
        return nullptr;
    }

    return const_cast<SSLx509Certificate*>(m_CertificateList.at(index));
}

// ------------------------------
// SSLHelloRequestMessage methods
// ------------------------------

std::string SSLHelloRequestMessage::toString() const {
    return "Hello Request message";
}

// ---------------------------------
// SSLServerHelloDoneMessage methods
// ---------------------------------

std::string SSLServerHelloDoneMessage::toString() const {
    return "Server Hello Done message";
}

// -----------------------------------
// SSLServerKeyExchangeMessage methods
// -----------------------------------

uint8_t* SSLServerKeyExchangeMessage::getServerKeyExchangeParams() const {
    if (getMessageLength() > sizeof(ssl_tls_handshake_layer))
        return (m_Data + sizeof(ssl_tls_handshake_layer));

    return nullptr;
}

size_t SSLServerKeyExchangeMessage::getServerKeyExchangeParamsLength() const {
    size_t msgLength = getMessageLength();
    if (msgLength <= sizeof(ssl_tls_handshake_layer))
        return 0;

    return msgLength - sizeof(ssl_tls_handshake_layer);
}

std::string SSLServerKeyExchangeMessage::toString() const {
    return "Server Key Exchange message";
}

// -----------------------------------
// SSLClientKeyExchangeMessage methods
// -----------------------------------

uint8_t* SSLClientKeyExchangeMessage::getClientKeyExchangeParams() const {
    if (getMessageLength() > sizeof(ssl_tls_handshake_layer))
        return (m_Data + sizeof(ssl_tls_handshake_layer));

    return nullptr;
}

size_t SSLClientKeyExchangeMessage::getClientKeyExchangeParamsLength() const {
    size_t msgLength = getMessageLength();
    if (msgLength <= sizeof(ssl_tls_handshake_layer))
        return 0;

    return msgLength - sizeof(ssl_tls_handshake_layer);
}

std::string SSLClientKeyExchangeMessage::toString() const {
    return "Client Key Exchange message";
}

// ------------------------------------
// SSLCertificateRequestMessage methods
// ------------------------------------

SSLCertificateRequestMessage::SSLCertificateRequestMessage(
    uint8_t* data, size_t dataLen, SSLHandshakeLayer* container)
    : SSLHandshakeMessage(data, dataLen, container) {
    size_t minMessageSize = sizeof(ssl_tls_handshake_layer) +
                            sizeof(uint8_t); // certificate types count (1B)
    if (dataLen < minMessageSize)
        return;

    size_t messageLen = getMessageLength();
    if (messageLen < minMessageSize)
        return;

    uint8_t certificateTypesCount =
        *(uint8_t*)(data + sizeof(ssl_tls_handshake_layer));

    if (certificateTypesCount > messageLen - minMessageSize)
        certificateTypesCount = messageLen - minMessageSize;

    uint8_t* pos = data + sizeof(ssl_tls_handshake_layer) + sizeof(uint8_t);
    for (uint8_t i = 0; i < certificateTypesCount; i++) {
        uint8_t certType = *(uint8_t*)(pos + i);
        if (certType == 0 || (certType > 6 && certType < 20) ||
            (certType > 20 && certType < 64) || certType > 64)
            m_ClientCertificateTypes.push_back(SSL_CCT_UNKNOWN);
        else
            m_ClientCertificateTypes.push_back(
                static_cast<SSLClientCertificateType>(certType));
    }
}

std::vector<SSLClientCertificateType>&
SSLCertificateRequestMessage::getCertificateTypes() {
    return m_ClientCertificateTypes;
}

uint8_t* SSLCertificateRequestMessage::getCertificateAuthorityData() const {
    size_t messageLen = getMessageLength();
    size_t offset = sizeof(ssl_tls_handshake_layer) + sizeof(uint8_t) +
                    m_ClientCertificateTypes.size() + sizeof(uint16_t);
    if (offset >= messageLen)
        return nullptr;

    return m_Data + offset;
}

size_t SSLCertificateRequestMessage::getCertificateAuthorityLength() const {
    size_t messageLen = getMessageLength();
    size_t offset = sizeof(ssl_tls_handshake_layer) + sizeof(uint8_t) +
                    m_ClientCertificateTypes.size();
    if (offset + sizeof(uint16_t) >= messageLen)
        return 0;

    uint16_t certAuthLen = be16toh(*(uint16_t*)(m_Data + offset));

    offset += sizeof(uint16_t);

    if (messageLen - offset < certAuthLen)
        return messageLen - offset;

    return certAuthLen;
}

std::string SSLCertificateRequestMessage::toString() const {
    return "Certificate Request message";
}

// -----------------------------------
// SSLCertificateVerifyMessage methods
// -----------------------------------

uint8_t* SSLCertificateVerifyMessage::getSignedHash() const {
    if (getMessageLength() > sizeof(ssl_tls_handshake_layer))
        return (m_Data + sizeof(ssl_tls_handshake_layer));

    return nullptr;
}

size_t SSLCertificateVerifyMessage::getSignedHashLength() const {
    size_t msgLength = getMessageLength();
    if (msgLength <= sizeof(ssl_tls_handshake_layer))
        return 0;

    return msgLength - sizeof(ssl_tls_handshake_layer);
}

std::string SSLCertificateVerifyMessage::toString() const {
    return "Certificate Verify message";
}

// --------------------------
// SSLFinishedMessage methods
// --------------------------

uint8_t* SSLFinishedMessage::getSignedHash() const {
    if (getMessageLength() > sizeof(ssl_tls_handshake_layer))
        return (m_Data + sizeof(ssl_tls_handshake_layer));

    return nullptr;
}

size_t SSLFinishedMessage::getSignedHashLength() const {
    size_t msgLength = getMessageLength();
    if (msgLength <= sizeof(ssl_tls_handshake_layer))
        return 0;

    return msgLength - sizeof(ssl_tls_handshake_layer);
}

std::string SSLFinishedMessage::toString() const { return "Finished message"; }

// ----------------------------------
// SSLNewSessionTicketMessage methods
// ----------------------------------

uint8_t* SSLNewSessionTicketMessage::getSessionTicketData() const {
    if (getMessageLength() > sizeof(ssl_tls_handshake_layer))
        return (m_Data + sizeof(ssl_tls_handshake_layer));

    return nullptr;
}

size_t SSLNewSessionTicketMessage::getSessionTicketDataLength() const {
    size_t msgLength = getMessageLength();
    if (msgLength <= sizeof(ssl_tls_handshake_layer))
        return 0;

    return msgLength - sizeof(ssl_tls_handshake_layer);
}

std::string SSLNewSessionTicketMessage::toString() const {
    return "New Session Ticket message";
}

// -------------------------
// SSLUnknownMessage methods
// -------------------------

SSLHandshakeType SSLUnknownMessage::getHandshakeType() const {
    // if message type is unknown, it may be some encrypted message so message
    // type isn't necessarily written in clear in the first byte. So always return
    // SSL_HANDSHAKE_UNKNOWN
    return SSL_HANDSHAKE_UNKNOWN;
}

size_t SSLUnknownMessage::getMessageLength() const {
    // if message type is unknown, it may be some encrypted message so message
    // length isn't necessarily written in clear. So in this case assume message
    // is in length of all remaining data
    return m_DataLen;
}

std::string SSLUnknownMessage::toString() const { return "Unknown message"; }

} // namespace pcpp
