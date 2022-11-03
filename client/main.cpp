#include <iostream>
#include <fstream>
#include "Client.h"

auto TRANSFER_FILE_NAME = "transfer.info";

class TransferInfo {
public:
	std::string host;
	int port = -1;
	std::string user_name;
	std::filesystem::path file_path;
};

TransferInfo get_transfer_information() {
	TransferInfo result;
	std::string temp;
	std::ifstream info_file(TRANSFER_FILE_NAME);

	if (!info_file.is_open()) {
		throw std::invalid_argument("Transfer file does not exist!");
	}

	std::getline(info_file, temp);
	auto sep_index = temp.find(':');
	result.host = temp.substr(0, sep_index);
	auto port = temp.substr(sep_index + 1);
	result.port = std::stoi(port);

	std::getline(info_file, result.user_name);
	std::getline(info_file, temp);
	result.file_path = temp;

	return result;
}

int main() {
	try {
		auto tinfo = get_transfer_information();
		Client c(tinfo.host, tinfo.port);
		std::cout << "Client connected." << std::endl;

		if (!c.is_registered()) {
			c.register_user(tinfo.user_name);
			std::cout << "Registration succeeded." << std::endl;
		}
		else {
			std::cout << "Client is already registered with the server.";
		}

		c.exchange_keys();
		std::cout << "Keys exchanged." << std::endl;

		c.send_file(tinfo.file_path);
		std::cout << "File sent & verified." << std::endl;

		return 0;
	}
	catch (const std::exception& ex) {
		std::cerr << "Exception! " << ex.what() << std::endl;
		return 1;
	}
}
