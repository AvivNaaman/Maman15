#include "EncryptedFileSender.h"
#include "protocol.h"
#include <fstream>

#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>

const CryptoPP::byte EncryptedFileSender::iv[CryptoPP::AES::BLOCKSIZE] = { 0 };

EncryptedFileSender::EncryptedFileSender(std::filesystem::path path, std::string key) : file_path(path), _aes_key(key) {}

#define CHUNK_SIZE (1024)

void EncryptedFileSender::send(boost::asio::ip::tcp::socket& socket) {
	std::ifstream to_send(file_path, std::ios::binary);

	unsigned char key_temp[AES_KEY_LENGTH_BYTES];
	memcpy(key_temp, _aes_key.c_str(), sizeof(key_temp));

	CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption e;

	e.SetKeyWithIV(key_temp, sizeof(key_temp), iv);

	std::string cipher;
	CryptoPP::FileSource fs(to_send, true, new CryptoPP::StreamTransformationFilter(e, new CryptoPP::StringSink(cipher)));
	boost::asio::write(socket, boost::asio::buffer(cipher));
}

size_t EncryptedFileSender::encrypted_size() {
	return (ceil(std::filesystem::file_size(file_path) / CryptoPP::AES::BLOCKSIZE) + 1) * CryptoPP::AES::BLOCKSIZE;
}
