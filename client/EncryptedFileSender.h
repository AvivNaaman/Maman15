#pragma once
#include <filesystem>
#include <boost/asio.hpp>
#include <aes.h>
class EncryptedFileSender
{
	std::string _aes_key;
	CryptoPP::
public:
	EncryptedFileSender();
	void set_key(char* key, int key_length);
	void send_local_file(std::filesystem::path, boost::asio::ip::tcp::socket &socket);
};

