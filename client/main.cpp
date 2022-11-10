#include <iostream>
#include <fstream>
#include "Client.h"


class TransferInfo {
public:
	std::string host;
	int port = -1;
	std::string user_name;
	std::filesystem::path file_path;

	/// <summary>
	/// Loads a transfer file info data from the specified file path.
	/// </summary>
	/// <param name="file_name">The file name to load the data from.</param>
	TransferInfo(std::string transfer_file_name) {
		std::string temp;
		std::ifstream info_file(transfer_file_name);

		if (!info_file.is_open()) {
			throw std::invalid_argument("Transfer file does not exist!");
		}

		// parse host:port.
		std::getline(info_file, temp);
		auto sep_index = temp.find(':');
		host = temp.substr(0, sep_index);
		auto port_str = temp.substr(sep_index + 1);
		port = std::stoi(port_str);

		// get user name & file to upload path.
		std::getline(info_file, user_name);
		std::getline(info_file, temp);
		file_path = temp;
	}
};

int main() {
	try {
		auto tinfo = TransferInfo("transfer.info");

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

		if (c.send_file(tinfo.file_path)) {
			std::cout << "File sent & verified." << std::endl;
		}
		else {
			std::cerr << "Failed to send file! Upload won't verify!" << std::endl;
		}

		return 0;
	}
	catch (const std::exception& ex) {
		std::cerr << "Exception! " << ex.what() << std::endl;
		return 1;
	}
}
