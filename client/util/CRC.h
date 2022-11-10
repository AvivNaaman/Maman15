#pragma once
#include <stdint.h>
#include <string>

class CRC
{
	uint32_t crc;
	size_t nchar;
public:
	/// <summary>
	/// Constructs a new CRC Handler.
	/// </summary>
	CRC();

	/// <summary>
	/// Calculates the CRC of a specified file, and returns it's digest value.
	/// </summary>
	/// <param name="filePath">The file to calculate it's CRC</param>
	/// <returns>The CRC of the file, as digest</returns>
	uint32_t calculate(std::string filePath);

	/// <summary>
	/// Returns the digest value of the last calculated CRC.
	/// </summary>
	uint32_t digest();

private:
	/// <summary>
	/// Updates the CRC value by the read block & it's size
	/// </summary>
	/// <param name="buf">The read block</param>
	/// <param name="size">The block's size</param>
	void update(char* buf, uint32_t size);
};

