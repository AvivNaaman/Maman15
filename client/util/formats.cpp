#include "formats.h"
#include <string>
#include <iomanip>
#include <cryptopp/base64.h>
#include <cstdint>

/// <summary>
/// Converts a single hex to char into it's value
/// </summary>
inline uint8_t Uuid::parse_hex(char digit) {
	if ('0' <= digit && digit <= '9') {
		return digit - '0';
	}
	// support both UPPER and lower case hex bytes
	digit = ('a' <= digit && digit <= 'f') ? digit : digit + ('a' - 'A');
	if ('a' <= digit && digit <= 'f') {
		return digit - 'a' + 10;
	}
	else {
		throw std::domain_error("Char is not hexadecimal!");
	}
}

/// <summary>
/// Converts a byte 2-hex-chars to it's value
/// </summary>
inline uint8_t Uuid::parse_hex_byte(const char* hexdigits) {
	uint8_t first = hexdigits[0];
	uint8_t second = hexdigits[1];
	return (parse_hex(first) << 4) + parse_hex(second);
}


void Uuid::parse(const std::string& input, unsigned char* destination) {
	// validate size
	if (input.length() != Uuid::UUID_SIZE_BYTES * 2)
		throw std::invalid_argument("Input string is not in the correct length.");

	// parse each couple of chars
	for (int i = 0; i < Uuid::UUID_SIZE_BYTES; ++i) {
		destination[i] = parse_hex_byte(input.c_str() + 2 * i);
	}
}

void Uuid::write(std::ostream& out_s, unsigned char* source, size_t len) {
	for (size_t i = 0; i < len; ++i)
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