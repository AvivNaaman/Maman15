#include <string>
#include <ostream>
/// <summary>
/// A helper class to perform read/write operations on UIDs with streams.
/// </summary>
class Uuid {
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
