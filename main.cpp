#include <string>
#include <iostream>
#include <fstream>
#include <memory>
#include <stdexcept>

#include <stdio.h>
#include <stdlib.h>

#include "parser/certificate_parser.h"

using namespace std;

void read_bin_file(const std::string& path_to_file, char*& out_buffer, int& out_len)
{
	streampos size;

	ifstream file (path_to_file, ios::in|ios::binary|ios::ate);
	if (file.is_open())
	{
		size = file.tellg();
		out_len = size;
		out_buffer = new char [size];
		file.seekg (0, ios::beg);
		file.read (out_buffer, size);
		file.close();
	}
}


int main(int argc, char **argv)
{
	char *certificate_buffer;
	int certificate_len;
    string path_to_certificate;
    if(argc > 1)
    {
        path_to_certificate = argv[1];
    }
    else
    {
        std::cout << "Usage: Provide a X509 certificate to be parsed" << std::endl;
        return 0;
    }

    read_bin_file(path_to_certificate, certificate_buffer, certificate_len);
	X509CertificateParser parser(certificate_buffer, certificate_len);
    parser.print_certificate_content();

	delete[] certificate_buffer;

	return 0;
}
