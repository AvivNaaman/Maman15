#include <string>
#include <iomanip>
#include "util.h"

unsigned char parse_hex(char digit) {
	if ('A' <= digit && digit <= 'F') {
		return digit - 'A' + 10;
	}
	else {
		return digit - '0';
	}
}

unsigned char parse_hex_byte(const char* hexdigits) {
	char first = hexdigits[0];
	char second = hexdigits[1];
	return (parse_hex(first) << 4) + parse_hex(second);
}

void parse_uid(const std::string& input, unsigned char* destination) {
	for (int i = 0; i < input.length() / 2; ++i) {
		destination[i] = parse_hex_byte(input.c_str() + 2 * i);
	}
}

void write_uid(std::ostream &out_s, unsigned char* source, size_t len) {
	for (int i = 0; i < len; ++i)
		out_s << std::hex << std::setfill('0') << std::setw(2) << source[i];
}