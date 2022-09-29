#pragma once
#include <filesystem>
#include <boost/asio.hpp>
class EncryptedFileSender
{
	std::string _aes_key;
public:
	EncryptedFileSender(std::string aes_key);
	void send_local_file(std::filesystem::path, boost::asio::ip::tcp::socket &socket);
};

