#pragma once
#include <stdint.h>
#include <string>

class CRC
{
	uint32_t crc;
	size_t nchar;
public:
	CRC();
	uint32_t calculate(std::string filePath);
	uint32_t digest();
private:
	void update(char* buf, uint32_t size);
};

