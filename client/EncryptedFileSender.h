#pragma once
#include <filesystem>
#include <boost/asio.hpp>
#include <aes.h>
#include "protocol.h"

class EncryptedFileSender
{
	unsigned char _aes_key[AES_KEY_LENGTH_BYTES];
	CryptoPP::AES::Encryption _aes_encryption;
	static const CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
public:
	EncryptedFileSender();
	void set_key(std::string key);
	void send_local_file(std::string, boost::asio::ip::tcp::socket &socket);
	static size_t calculate_encrypted_size(size_t plain_size);
};

