#ifndef __X509_CERTIFICATE_PARSER__
#define __X509_CERTIFICATE_PARSER__

#include <string>
#include <deque>
#include "cryptopp/asn.h"

using namespace CryptoPP;

class IssuerOrSubjectName
{
private:
    std::string m_common_name;
    std::string m_country;
    std::string m_locality;
    std::string m_organisation;
    std::string m_organisation_unit;
    std::string m_email;
    std::string m_state;

public:
    IssuerOrSubjectName();
    std::string getCommonName() const { return m_common_name; }
    std::string getCountry() const { return m_country; }
    std::string getLocality() const { return m_locality; }
    std::string getOrganization() const { return m_organisation; }
    std::string getOrganizationUnit() const { return m_organisation_unit; }
    std::string getEmail() const { return m_email; }
    std::string getState() const { return m_state; }

    void setCommonName(std::string common_name) { this->m_common_name = common_name; }
    void setCountry(std::string country) { this->m_country = country; }
    void setLocality(std::string locality) { this->m_locality = locality; }
    void setOrganisation(std::string  organisation) { this->m_organisation = organisation; }
    void setOrganisationUnit(std::string organisation_unit) { this->m_organisation_unit = organisation_unit; }
    void setEmail(std::string email) { this->m_email = email; }
    void setState(std::string state) { this->m_state = state; }
};

class X509CertificateParser
{

private:
    IssuerOrSubjectName m_issuer_name;
    IssuerOrSubjectName m_subject_name;

    std::vector<std::pair<std::string, int>> m_validity_from_ar;
    std::vector<std::pair<std::string, int>> m_validity_until_ar;

    bool m_is_issuer;

    std::vector<byte> m_serial_no;
    std::string m_encryption_algorithm;
    std::string m_public_key_algorithm;
    std::string m_private_key_algorithm;

    int m_version;
    int m_exponent;
    std::vector<byte> m_modulus;
    std::vector<byte> m_signature;

    void save_oid_and_value(std::string oid_type, std::string value);

    void parse_tbs_certificate(CryptoPP::BufferedTransformation & tbs_certificate);
    void parse_issuer_or_subject(CryptoPP::BufferedTransformation & issuer_or_subject, bool is_issuer);
    void get_string_and_its_oid(CryptoPP::BufferedTransformation & oid_seq);
    void get_oid_type(const std::string& oid_ar, const int& len, std::string &out_type);

    void get_validity_time(CryptoPP::BufferedTransformation & validity_seq);
    void initialise_validity_arrays(std::vector<std::pair<std::string, int>> & validity_ar);

    void get_serial_number(CryptoPP::BufferedTransformation & serial_no_seq);
    void get_algorithm_type(CryptoPP::BufferedTransformation & algorithm_seq);

    void get_certificate_version(CryptoPP::BufferedTransformation & version_seq);

    void read_spki(CryptoPP::BufferedTransformation & spki_sequence);
    int  get_sequence_len(CryptoPP::BufferedTransformation & byte_sequence);
    void get_len_from_bytes(const std::deque<int>& byte_queue, int& out_len);

    void get_public_or_private_key_algorithm_type(CryptoPP::BufferedTransformation & alg_type_sequence, bool is_public_key);
    void get_public_key_modulus(CryptoPP::BufferedTransformation & modulus_sequence);

    void parse_signature(CryptoPP::BufferedTransformation & signature_seq);
    void get_signature(CryptoPP::BufferedTransformation & signature_seq);

public:
    X509CertificateParser(char* certificate, int cert_len);
    void print_certificate_content();
};

#endif
