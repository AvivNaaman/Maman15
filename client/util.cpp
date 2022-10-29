#include <string>
#include <iomanip>
#include "util.h"
#include <cryptopp/base64.h>
#include "protocol.h"

inline unsigned char parse_hex(char digit) {
	if ('a' <= digit && digit <= 'f') {
		return digit - 'a' + 10;
	}
	else if ('0' <= digit && digit <= '9') {
		return digit - '0';
	} 
	else {
		throw std::domain_error("Char is not hexadecimal!");
	}
}

inline unsigned char parse_hex_byte(const char* hexdigits) {
	char first = hexdigits[0];
	char second = hexdigits[1];
	return (parse_hex(first) << 4) + parse_hex(second);
}

void Uid::parse(const std::string& input, unsigned char* destination) {
	// validate size
	if (input.length() != USER_ID_SIZE_BYTES * 2)
		throw std::invalid_argument("Input string is not in the correct length.");

	// parse each couple of chars
	for (int i = 0; i < USER_ID_SIZE_BYTES; ++i) {
		destination[i] = parse_hex_byte(input.c_str() + 2 * i);
	}
}

void Uid::write(std::ostream &out_s, unsigned char* source, size_t len) {
	for (int i = 0; i < len; ++i)
		out_s << std::hex << std::setw(2) << std::setfill('0') << (int) static_cast <unsigned char>(source[i]);
}


std::string Base64::encode(const std::string& str)
{
	std::string encoded;
	CryptoPP::StringSource ss(str, true,
		new CryptoPP::Base64Encoder(
			new CryptoPP::StringSink(encoded),
			false
		) // Base64Encoder
	); // StringSource

	return encoded;
}

std::string Base64::decode(const std::string& str)
{
	std::string decoded;
	CryptoPP::StringSource ss(str, true,
		new CryptoPP::Base64Decoder(
			new CryptoPP::StringSink(decoded)
		) // Base64Decoder
	); // StringSource

	return decoded;
}

#include <fstream>
const std::string MeInfo::FILE_NAME = "me.info";

MeInfo::MeInfo() {
	_file_loaded = false;
	if (try_load()) {
		_file_loaded = true;
	}
}


void MeInfo::save() {
	std::ofstream info_file(FILE_NAME);

	if (!info_file.is_open()) {
		return;
	}

	info_file << this->user_name << std::endl;

	Uid::write(info_file, this->header_user_id, sizeof(this->header_user_id));

	info_file << std::endl << Base64::encode(this->rsa_private_key);
}


bool MeInfo::try_load() {
	try {
		std::ifstream info_file(FILE_NAME);

		if (!info_file.is_open()) {
			return false;
		}
		// user name
		std::getline(info_file, this->user_name);

		std::string temp_line;

		// user id
		info_file >> temp_line;
		if (temp_line.empty()) return false;

		Uid::parse(temp_line, this->header_user_id);
		// TODO: Validate this!
#define PRIVATE_KEY_SIZE_BASE64 (844)


		// private key
		info_file >> temp_line;
		if (temp_line.length() != PRIVATE_KEY_SIZE_BASE64) {
			return false;
		}

		// decode & set
		rsa_private_key = Base64::decode(temp_line);
		return true;
	}
	catch (const std::exception& ex) {
		return false;
	}
}

bool MeInfo::is_loaded() {
	return _file_loaded;
}