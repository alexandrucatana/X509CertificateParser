#include <cmath>

#include "../parser/certificate_parser.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/pubkey.h"
#include "cryptopp/queue.h"

#include "cryptopp/rsa.h"
#include "cryptopp/md5.h"
#include "cryptopp/integer.h"
#include "cryptopp/oids.h"
#include "cryptopp/files.h"

#include "../parser/asn1_der_tag_bytes.h"

IssuerOrSubjectName::IssuerOrSubjectName()
{}

X509CertificateParser::X509CertificateParser(char* certificate, int cert_len)
{
    initialise_validity_arrays(m_validity_from_ar);
    initialise_validity_arrays(m_validity_until_ar);

    //const std::string tmp_buffer(certificate, cert_len);
    CryptoPP::ByteQueue l_cert;
    l_cert.Put2((const byte *)(certificate), cert_len, true, true);
    byte asn1_type;


    CryptoPP::BERSequenceDecoder x509Cert(l_cert);
    int x509_cert_len = l_cert.MaxRetrievable();
    x509_cert_len = x509Cert.MaxRetrievable();

    x509Cert.Peek(asn1_type);
    CryptoPP::BERSequenceDecoder tbs_cert(x509Cert);
    int tbs_cert_len = tbs_cert.MaxRetrievable();


    parse_tbs_certificate(tbs_cert);
    x509_cert_len = x509Cert.MaxRetrievable();

    parse_signature(x509Cert);

    x509Cert.SkipAll();
}

void X509CertificateParser::initialise_validity_arrays(std::vector<std::pair<std::string, int>> & validity_ar)
{
    validity_ar.push_back(std::pair<std::string, int>("year", 0));
    validity_ar.push_back(std::pair<std::string, int>("month", 0));
    validity_ar.push_back(std::pair<std::string, int>("day", 0));
    validity_ar.push_back(std::pair<std::string, int>("hour", 0));
    validity_ar.push_back(std::pair<std::string, int>("minute", 0));
    validity_ar.push_back(std::pair<std::string, int>("seconds", 0));
}

void X509CertificateParser::get_signature(CryptoPP::BufferedTransformation & signature_seq)
{
    byte cur_byte, exponent_len;
    int signature_len = 0;

    // get signature length
    signature_len = get_sequence_len(signature_seq);

    int counter = 0;
    while(counter < signature_len)
    {
        signature_seq.Get(cur_byte);
        m_signature.push_back(cur_byte);
        counter++;
    }
}

void X509CertificateParser::parse_signature(CryptoPP::BufferedTransformation & signature_seq)
{
    get_public_or_private_key_algorithm_type(signature_seq, false);
    get_signature(signature_seq);
}

void X509CertificateParser::get_certificate_version(CryptoPP::BufferedTransformation & version_seq)
{
    byte tag, len, value;
    // consume version tag byte
    version_seq.Get(tag);
    // consume len byte
    version_seq.Get(tag);
    // get version type (must be an integer)
    version_seq.Get(tag);

    if(tag != ASN1_INTEGER)
    {
        return;
    }

    version_seq.Get(len);
    if(len != 1)
    {
        // something's wrong here if the len is not 1 byte
        return;
    }

    version_seq.Get(value);
    // the certificate version is always 1 higher than the byte value
    this->m_version = value + 1;
}

void X509CertificateParser::get_oid_type(const std::string& oid, const int& oid_len, std::string &out_type)
{
    for (auto map_el : x509_oids)
    {
        std::vector<byte> values = map_el.second;
        int count = 0;
        for (auto value : values)
        {
            byte cur_byte = oid[count];
            if (value != cur_byte)
            {
                break;
            }
            ++count;
        }
        if (count == oid_len)
        {
            out_type = map_el.first;
            return;
        }
    }
}

void X509CertificateParser::get_string_and_its_oid(CryptoPP::BufferedTransformation & oid_seq)
{
    byte oid_len, oid_byte;
    std::string oid;
    oid_seq.Get(oid_len);

    // get oid first
    int len_count = 0;
    while (len_count < oid_len)
    {
        oid_seq.Get(oid_byte);
        oid += oid_byte;
        ++len_count;
    }

    std::string oid_type = "";
    // search for the oid name
    get_oid_type(oid, oid_len, oid_type);


    // then get the value associated to the oid
    byte value_len, value_byte;
    std::string value;
    len_count = 0;
    // consume type (in this case a string)
    oid_seq.Get(value_byte);
    // then get len
    oid_seq.Get(value_len);

    while (len_count < value_len)
    {
        oid_seq.Get(value_byte);
        value += value_byte;
        ++len_count;
    }

    // save oid  and its value
    save_oid_and_value(oid_type, value);
}

void X509CertificateParser::get_validity_time(CryptoPP::BufferedTransformation & validity_seq)
{
    byte len_byte, type_byte, content_byte;
    std::string validity_from, validity_until;

    // VALIDITY FROM
    validity_seq.Get(type_byte);
    if (type_byte != ASN1_UTCTIME)
        return;

    validity_seq.Get(len_byte);
    int counter = 0;

    while (counter < len_byte)
    {
        validity_seq.Get(content_byte);
        validity_from += content_byte;
        counter++;
    }

    // VALIDITY UNTIL
    validity_seq.Get(type_byte);
    if (type_byte != ASN1_UTCTIME)
        return;

    validity_seq.Get(len_byte);
    counter = 0;

    while (counter < len_byte)
    {
        validity_seq.Get(content_byte);
        validity_until += content_byte;
        counter++;
    }

    // fill validity_from_ar
    int substr_counter = 0, ar_counter = 0;
    for (auto validity : m_validity_from_ar)
    {
        std::string substr = validity_from.substr(substr_counter, 2);

        int int_val = atoi(substr.c_str());
        validity.second = int_val;
        m_validity_from_ar.at(ar_counter++) = validity;
        substr_counter += 2;
    }

    // fill validity_until_ar
    substr_counter = 0, ar_counter = 0;
    for (auto validity : m_validity_until_ar)
    {
        std::string substr = validity_until.substr(substr_counter, 2);

        int int_val = atoi(substr.c_str());
        validity.second = int_val;
        m_validity_until_ar.at(ar_counter++) = validity;
        substr_counter += 2;
    }
}

void X509CertificateParser::save_oid_and_value(std::string oid_type, std::string value)
{
    if (oid_type == "common_name")
    {
        if (m_is_issuer)
        {
            m_issuer_name.setCommonName(value);
        }
        else
        {
            m_subject_name.setCommonName(value);
        }
    }
    else if (oid_type == "country")
    {
        if (m_is_issuer)
        {
            m_issuer_name.setCountry(value);
        }
        else
        {
            m_subject_name.setCountry(value);
        }
    }
    else if (oid_type == "locality")
    {
        if (m_is_issuer)
        {
            m_issuer_name.setLocality(value);
        }
        else
        {
            m_subject_name.setLocality(value);
        }
    }
    else if (oid_type == "organisation")
    {
        if (m_is_issuer)
        {
            m_issuer_name.setOrganisation(value);
        }
        else
        {
            m_subject_name.setOrganisation(value);
        }
    }
    else if (oid_type == "organisational_unit")
    {
        if (m_is_issuer)
        {
            m_issuer_name.setOrganisationUnit(value);
        }
        else
        {
            m_subject_name.setOrganisationUnit(value);
        }
    }
    else if (oid_type == "email")
    {
        if (m_is_issuer)
        {
            m_issuer_name.setEmail(value);
        }
        else
        {
            m_subject_name.setEmail(value);
        }
    }
    else if (oid_type == "state")
    {
        if (m_is_issuer)
        {
            m_issuer_name.setState(value);
        }
        else
        {
            m_subject_name.setState(value);
        }
    }
}

void X509CertificateParser::parse_issuer_or_subject(CryptoPP::BufferedTransformation & issuer_or_subject, bool is_issuer)
{
    ByteQueue message_queue;
    issuer_or_subject.TransferAllTo(message_queue);
    int queue_len = message_queue.MaxRetrievable();
    byte asn1_type = 0, cur_set_len = 0;
    message_queue.Get(asn1_type);
    bool terminate = false;

    m_is_issuer = is_issuer;

    while (!terminate)
    {
        switch (asn1_type)
        {
            case ASN1_SET:
            {
                message_queue.Get(cur_set_len);
                // in this case, a set is followed by a sequence
                // so I substitute the type and length bytes (2 bytes) plus the set length.
                queue_len -= 2 + cur_set_len;
                message_queue.GetNextMessage();
                message_queue.Get(asn1_type);
                break;
            }
            case ASN1_SEQUENCE:
            {
                // consume the len byte
                message_queue.Get(cur_set_len);
                message_queue.GetNextMessage();
                message_queue.Get(asn1_type);
                break;
            }

            case ASN1_OBJECT_IDENTIFIER:
            {
                get_string_and_its_oid(message_queue);
                message_queue.GetNextMessage();
                message_queue.Get(asn1_type);
                if (queue_len == 0)
                {
                    terminate = true;
                }
                break;
            }
        }
    }
}

void X509CertificateParser::get_serial_number(CryptoPP::BufferedTransformation & serial_no_seq)
{
    byte type_byte, length_byte, content_byte;
    serial_no_seq.Get(type_byte);

    if (type_byte != ASN1_INTEGER)
    {
        // wrong type
        return;
    }

    serial_no_seq.Get(length_byte);
    int ar_counter = 0;
    while (ar_counter < length_byte)
    {
        serial_no_seq.Get(content_byte);
        m_serial_no.push_back(content_byte);
        ++ar_counter;
    }
}

void X509CertificateParser::get_algorithm_type(CryptoPP::BufferedTransformation & algorithm_seq)
{
    byte type_byte, length_byte, content_byte;
    algorithm_seq.Get(type_byte);

    if(type_byte != ASN1_OBJECT_IDENTIFIER)
    {
        // wrong type
        return;
    }

    algorithm_seq.Get(length_byte);
    int ar_counter = 0;
    std::vector<byte> algorithm_bytes;
    while (ar_counter < length_byte)
    {
        algorithm_seq.Get(content_byte);
        algorithm_bytes.push_back(content_byte);
        ++ar_counter;
    }

    for (auto map_el : encryption_algorithms_oids)
    {
        std::vector<byte> values = map_el.second;
        int count = 0;
        for (auto value : values)
        {
            byte cur_byte = algorithm_bytes[count];
            if (value != cur_byte)
            {
                break;
            }
            ++count;
        }
        if (count == length_byte)
        {
            m_encryption_algorithm = map_el.first;
            return;
        }
    }
}

void X509CertificateParser::get_len_from_bytes(const std::deque<int>& byte_queue, int& out_len)
{
    int byte_counter = 0;
    for(auto dec_byte : byte_queue)
    {
        int cur_no = dec_byte;
        out_len += cur_no << (8 * byte_counter);
        byte_counter++;
    }
}

int X509CertificateParser::get_sequence_len(CryptoPP::BufferedTransformation & byte_sequence)
{
    int seq_len = 0, len_offset = 0;
    int normal_max_len = 0x80;
    byte iteration_byte, cur_byte;
    byte_sequence.Peek(cur_byte);
    if(cur_byte == 0)
    {
        byte_sequence.Get(cur_byte);
    }

    // consume type byte
    byte_sequence.Get(cur_byte);

    // get length in decimal
    byte_sequence.Get(iteration_byte);
    if(iteration_byte <= normal_max_len)
    {
        return seq_len;
    }

    len_offset =  iteration_byte - normal_max_len;
    std::deque<int> byte_queue;
    for(int ii = 0; ii < len_offset; ++ii)
    {
        // get bytes which will give us the sequence length.
        byte_sequence.Get(iteration_byte);
        int dec_byte = iteration_byte;
        byte_queue.push_front(dec_byte);
    }

    get_len_from_bytes(byte_queue, seq_len);
    return seq_len;
}

void X509CertificateParser::get_public_key_modulus(CryptoPP::BufferedTransformation & modulus_sequence)
{
    byte cur_byte, exponent_len;
    int modulus_len = 0;
    // consume bit_string length
    get_sequence_len(modulus_sequence);
    // consume sequence length
    get_sequence_len(modulus_sequence);
    // get modulus length
    modulus_len = get_sequence_len(modulus_sequence);

    int counter = 0;
    while(counter < modulus_len)
    {
        modulus_sequence.Get(cur_byte);
        m_modulus.push_back(cur_byte);
        counter++;
    }

    modulus_sequence.Get(cur_byte);
    if(cur_byte == ASN1_INTEGER)
    {
        modulus_sequence.Get(exponent_len);
        counter = 0;
        std::deque<byte> exp_queue;
        while(counter < exponent_len)
        {
            modulus_sequence.Get(cur_byte);
            exp_queue.push_front(cur_byte);
            counter++;
        }

        int two_byte_counter = 0;
        for(auto exp_byte : exp_queue)
        {
            int exp_int = exp_byte;
            m_exponent += exp_int << (8 * two_byte_counter);
            two_byte_counter++;
        }
    }
}

void X509CertificateParser::get_public_or_private_key_algorithm_type(
		CryptoPP::BufferedTransformation & alg_type_sequence, bool is_public_key)
{
    byte cur_byte, alg_len_byte, seq_len_byte, oid_byte;
    std::string alg_type;
    alg_type_sequence.Peek(cur_byte);

    if(cur_byte != ASN1_SEQUENCE)
    {
        return;
    }

    // consume sequence tag and seq len byte
    alg_type_sequence.Get(cur_byte);
    alg_type_sequence.Get(seq_len_byte);

    // get oid type
    alg_type_sequence.Get(oid_byte);
    if(oid_byte != ASN1_OBJECT_IDENTIFIER)
    {
        return;
    }

    alg_type_sequence.Get(alg_len_byte);
    std::vector<byte> alg_type_bytes;
    int counter = 0;
    for(; counter < alg_len_byte; ++counter)
    {
        alg_type_sequence.Get(cur_byte);
        alg_type_bytes.push_back(cur_byte);
    }

    // alg_len_byte + oid and len bytes from the sequence
    counter += 2;
    // consume possible remaining sequence bytes
    while(counter < seq_len_byte)
    {
        alg_type_sequence.Get(cur_byte);
        ++counter;
    }

    for (auto map_el : encryption_algorithms_oids)
    {
        std::vector<byte> values = map_el.second;
        int count = 0;
        for (auto value : values)
        {
            byte cur_byte = alg_type_bytes[count];
            if (value != cur_byte)
            {
                break;
            }
            ++count;
        }
        if (count == alg_len_byte)
        {
            if(is_public_key)
            {
                m_public_key_algorithm = map_el.first;
            }
            else
            {
                m_private_key_algorithm = map_el.first;
            }
            return;
        }
    }
}

void X509CertificateParser::read_spki(CryptoPP::BufferedTransformation & spki_sequence)
{
    get_public_or_private_key_algorithm_type(spki_sequence, true);
    get_public_key_modulus(spki_sequence);
}

void X509CertificateParser::parse_tbs_certificate(CryptoPP::BufferedTransformation & tbs_certificate)
{
    byte tag;
    tbs_certificate.Peek(tag);
    int len = tbs_certificate.MaxRetrievable();

    if(tag == ASN1_EXTENDED_CERTIFICATE)
    {
        get_certificate_version(tbs_certificate);
    }
    len = tbs_certificate.MaxRetrievable();

    get_serial_number(tbs_certificate);
    len = tbs_certificate.MaxRetrievable();

    CryptoPP::BERSequenceDecoder signature(tbs_certificate);
    get_algorithm_type(signature);
    signature.SkipAll();
    len = tbs_certificate.MaxRetrievable();

    // Next: issuer               Name,
    CryptoPP::BERSequenceDecoder issuerName(tbs_certificate);
    parse_issuer_or_subject(issuerName, true);
    issuerName.SkipAll();
    len = tbs_certificate.MaxRetrievable();

    // Next: validity             Validity,
    CryptoPP::BERSequenceDecoder validity(tbs_certificate);
    get_validity_time(validity);
    validity.SkipAll();
    len = tbs_certificate.MaxRetrievable();


    // Next: subject              Name,
    CryptoPP::BERSequenceDecoder subjectName(tbs_certificate);
    parse_issuer_or_subject(subjectName, false);
    subjectName.SkipAll();
    len = tbs_certificate.MaxRetrievable();


    // subjectPublicKeyInfo SubjectPublicKeyInfo,
    CryptoPP::BERSequenceDecoder spki(tbs_certificate);
    read_spki(spki);
    spki.SkipAll();
    len = tbs_certificate.MaxRetrievable();
    tbs_certificate.SkipAll();
}

void X509CertificateParser::print_certificate_content()
{
    std::cout << "Encryption Algorithm: " << m_encryption_algorithm << std::endl;
    std::cout << "Exponent: " << m_exponent << std::endl;

    std::cout << "Issuer Name: " << std::endl;
    std::cout << "    Common Name :" << m_issuer_name.getCommonName() << std::endl;
    std::cout << "    Country :" << m_issuer_name.getCountry() << std::endl;
    std::cout << "    State :" << m_issuer_name.getState() << std::endl;
    std::cout << "    Locality :" << m_issuer_name.getLocality() << std::endl;
    std::cout << "    Email :" << m_issuer_name.getEmail() << std::endl;
    std::cout << "    Organization :" << m_issuer_name.getOrganization() << std::endl;
    std::cout << "    Organization Unit :" << m_issuer_name.getOrganizationUnit() << std::endl;


    //std::cout << "Modulus: " << m_modulus << std::endl;
    std::cout << "Private Key Algorithm: " << m_private_key_algorithm << std::endl;
    std::cout << "Public Key Algorithm: " << m_encryption_algorithm << std::endl;


    std::cout << "Validity from: " << std::endl;
    for(const auto& valid_from: m_validity_from_ar)
    {
        std::cout << valid_from.first << " : " << valid_from.second << std::endl;
    }

    std::cout << "Validity until: " << std::endl;
    for(const auto& valid_until: m_validity_until_ar)
    {
        std::cout << valid_until.first << " : " << valid_until.second << std::endl;
    }
}
