#include <string>
#include <ostream>

// This file includes tools for formatting text and data, such as UUID and Base64.

/// <summary>
/// A helper class to perform read/write operations on UIDs with streams.
/// </summary>
class Uuid {
	/// <summary>
	/// number of bytse in a UUID
	/// </summary>
	static const int UUID_SIZE_BYTES = 16;

public:
	/// <summary>
	/// parses uuid from hex string to a buffer.
	/// </summary>
	static void parse(const std::string& input, unsigned char* destination);

	/// <summary>
	/// writes uuid from buffer to hex string
	/// </summary>
	static void write(std::ostream& out_s, unsigned char* source, size_t len);

private:
	/// <summary>
	/// Converts a byte 2-hex-chars to it's value
	/// </summary>
	static inline uint8_t parse_hex_byte(const char* hexdigits);

	/// <summary>
	/// Converts a single hex to char into it's value
	/// </summary>
	static inline uint8_t parse_hex(char digit);
};

/// <summary>
/// A helper class to perform encoding/decoding operations on base64 strings.
/// </summary>
class Base64 {
public:
	/// <summary>
	/// Encodes a string to it's base64 representation.
	/// </summary>
	static std::string decode(const std::string& source);

	/// <summary>
	/// Decodes a base64 string to it's respresentation.
	/// </summary>
	static std::string encode(const std::string& source);
};
