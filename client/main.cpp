#include <iostream>
#include <fstream>
#include "Client.h"

auto TRANSFER_FILE_NAME = "transfer.info";

class TransferInfo {
public:
	std::string host;
	int port;
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
	auto tinfo = get_transfer_information();
	char address[] = "localhost";
	Client c(address, 8085);
//	c.register_user("Aviv Naaman");
//	c.exchange_keys();
//	c.send_file("/Users/avivnaaman/Desktop/cropper.py");
	return 0;
}