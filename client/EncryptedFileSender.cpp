#include "EncryptedFileSender.h"
#include "protocol.h"
#include <fstream>

#include <modes.h>
#include <aes.h>
#include <filters.h>
#include <files.h>

const CryptoPP::byte EncryptedFileSender::iv[CryptoPP::AES::BLOCKSIZE] = { 0 };

EncryptedFileSender::EncryptedFileSender() {}

void EncryptedFileSender::set_key(std::string key)
{
	memcpy_s(_aes_key, sizeof(_aes_key), key.c_str(), key.length());
}

#define CHUNK_SIZE (1024)

void EncryptedFileSender::send_local_file(std::string path,
	boost::asio::ip::tcp::socket& socket) {
	std::ifstream to_send(path, std::ios::binary);

	/*char tmp[CryptoPP::AES::BLOCKSIZE];
	memcpy((char*)_aes_key, "Sixteen byte key", 16);
	CryptoPP::AES::Encryption aesEncryption(_aes_key, sizeof(_aes_key));
	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

	std::string cipher;
	CryptoPP::FileSource fs(to_send, true, new CryptoPP::StreamTransformationFilter(cbcEncryption, new CryptoPP::StringSink(cipher)));*/
	std::string content((std::istreambuf_iterator<char>(to_send)), std::istreambuf_iterator<char>());
	boost::asio::write(socket, boost::asio::buffer(content));
}

size_t EncryptedFileSender::calculate_encrypted_size(size_t plain_size) {
	return plain_size;//(ceil(plain_size / CryptoPP::AES::BLOCKSIZE) + 1) * CryptoPP::AES::BLOCKSIZE;
}
