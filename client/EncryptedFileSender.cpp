#include "EncryptedFileSender.h"
#include "protocol.h"
#include <fstream>

#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include "AESWrapper.h"

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

	CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption e;
	e.SetKeyWithIV(_aes_key, sizeof(_aes_key), iv);
	std::string cipher;
	CryptoPP::FileSource fs(to_send, true, new CryptoPP::StreamTransformationFilter(e, new CryptoPP::StringSink(cipher)));
	boost::asio::write(socket, boost::asio::buffer(cipher));
}

size_t EncryptedFileSender::calculate_encrypted_size(size_t plain_size) {
	return (ceil(plain_size / CryptoPP::AES::BLOCKSIZE) + 1) * CryptoPP::AES::BLOCKSIZE;
}
