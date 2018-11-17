/*
* asn1_der_tag_bytes.h
*
*  Created on: Jan 17, 2017
*      Author: alexandru catana
*/

#ifndef __ASN1_DER_TAG_BYTES__
#define __ASN1_DER_TAG_BYTES__

#define ASN1_BOOLEAN					0x01
#define ASN1_INTEGER					0x02
#define ASN1_BIT_STRING					0x03
#define ASN1_OCTET_STRING				0x04
#define ASN1_NULL						0x05
#define ASN1_OBJECT_IDENTIFIER			0x06
#define ASN1_PRINTABLE_STRING			0x13
#define ASN1_IA5_STRING					0x16
#define ASN1_UTCTIME					0x17
#define ASN1_SEQUENCE					0x30
#define ASN1_SET						0x31
#define ASN1_BMP_STRING					0x1E
#define ASN1_UTF8_STRING				0x0C
#define ASN1_EXTENDED_CERTIFICATE		0xA0

#include <map>

std::map<std::string, std::vector<byte>> x509_oids =
{
    { "common_name",            { 0x55, 0x04, 0x03 } }, // absolute oid: 2.5.4.3 common name
    { "country",                { 0x55, 0x04, 0x06 } },// absolute oid: 2.5.4.6 country name
    { "locality",               { 0x55, 0x04, 0x07 } }, // absolute oid: 2.5.4.7 locality name
    { "state",                  { 0x55, 0x04, 0x08 } }, // absolute oid: 2.5.4.8 state or province name
    { "organisation", 			{ 0x55, 0x04, 0x0A } }, // absolute oid: 2.5.4.10 organisation name
    { "organisational_unit", 	{ 0x55, 0x04, 0x0B } }, // absolute oid: 2.5.4.11 organisation unit name
    { "email", 					{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01 } }, // absolute oid: 1.2.840.113549.1.9.1 email address
};

std::map<std::string, std::vector<byte>> encryption_algorithms_oids =
{
    { "rsa_encryption", 			{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 } }, // absolute oid: 1.2.840.113549.1.1.1 rsa
    { "md2_with_rsa_encryption", 	{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x02 } }, // absolute oid: 1.2.840.113549.1.1.2 md2_with_rsa_encryption
    { "md4_with_rsa_encryption", 	{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x03 } }, // absolute oid: 1.2.840.113549.1.1.3 md4_with_rsa_encryption
    { "md5_with_rsa_encryption", 	{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04 } }, // absolute oid: 1.2.840.113549.1.1.4 md4_with_rsa_encryption
    { "sha1_with_rsa_encryption", 	{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05 } }, // absolute oid: 1.2.840.113549.1.1.5 sha1_with_rsa_encryption
    { "rsa_oaep_encryption_set", 	{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x06 } }, // absolute oid: 1.2.840.113549.1.1.6 rsa_oaep_encryption_set
    { "id_rsaes_oaep", 				{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x07 } }, // absolute oid: 1.2.840.113549.1.1.7 id_rsaes_oaep
    { "id_mgf1", 					{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08 } }, // absolute oid: 1.2.840.113549.1.1.8 id_mgf1
    { "id-pSpecified", 				{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x09 } }, // absolute oid: 1.2.840.113549.1.1.9 id-pSpecified
    { "rsassa_pss", 				{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a } }, // absolute oid: 1.2.840.113549.1.1.10 rsassa_pss
    { "sha256_with_rsa_encryption", { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b } }, // absolute oid: 1.2.840.113549.1.1.11 sha256_with_rsa_encryption
    { "sha384_with_rsa_encryption", { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c } }, // absolute oid: 1.2.840.113549.1.1.12 sha256_with_rsa_encryption
    { "sha512_with_rsa_encryption", { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c } }, // absolute oid: 1.2.840.113549.1.1.13 sha256_with_rsa_encryption
    { "sha224_with_rsa_encryption", { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0e } }, // absolute oid: 1.2.840.113549.1.1.14 sha256_with_rsa_encryption
};


#endif
