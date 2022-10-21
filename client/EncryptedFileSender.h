#pragma once
#include <filesystem>
#include <boost/asio.hpp>
#include <cryptopp/aes.h>
#include "protocol.h"

class EncryptedFileSender
{
	/// <summary>
	/// Holds the current AES Key.
	/// </summary>
	unsigned char _aes_key[AES_KEY_LENGTH_BYTES];
	/// <summary>
	/// AES Encryption provider reference.
	/// </summary>
	CryptoPP::AES::Encryption _aes_encryption;
	/// <summary>
	/// Holds the IV for the AES encryption
	/// </summary>
	static const CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
public:
	/// <summary>
	/// Creates a new encrypted file sender.
	/// </summary>
	EncryptedFileSender();
	/// <summary>
	/// Sets the encryption key for the file sender.
	/// </summary>
	void set_key(std::string key);
	/// <summary>
	/// Encrypts and sends a file through the socket.
	/// </summary>
	/// <param name="plain_size"></param>
	void send_local_file(std::string, boost::asio::ip::tcp::socket& socket);
	/// <summary>
	/// Returns the file size, after it was encrypted.
	/// </summary>
	static size_t calculate_encrypted_size(size_t plain_size);
};

