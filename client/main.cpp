#include <iostream>
#include <fstream>
#include "Client.h"

// The transfer file is just a helper for the batch operations execution
// it has nothing to do with the internal client logic itself.
// therefore I've placed it here.
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

		if (info_file.eof()) {
			throw std::runtime_error("Invalid file: " + transfer_file_name + "!");
		}

		// get user name & file to upload path.
		std::getline(info_file, user_name);

		if (info_file.eof()) {
			throw std::runtime_error("Invalid file: " + transfer_file_name + "!");
		}

		std::getline(info_file, temp);
		file_path = temp;
	}
};

int main() {
	try {
		auto tinfo = TransferInfo("transfer.info");


		std::cout << "Connecting client... ";
		Client client(tinfo.host, tinfo.port);
		std::cout << "Client connected." << std::endl;


		if (!client.is_registered()) {
			std::cout << "Registering client... ";
			if (client.register_user(tinfo.user_name)) {
				std::cout << "Registration succeeded." << std::endl;
			}
			else {
				std::cerr << "Registration failed! Perhaps you've re-used a user name?" << std::endl;
				return -1;
			}
		}
		else {
			std::cout << "Client is already registered with the server." << std::endl;
		}


		std::cout << "Exchanging keys... ";
		client.exchange_keys();
		std::cout << "Keys exchanged." << std::endl;


		std::cout << "Uploading file... ";

		if (client.send_file(tinfo.file_path)) {
			std::cout << "File sent & verified." << std::endl;
		}
		else {
			std::cerr << "Failed to send file! Upload won't verify!" << std::endl;
			return -1;
		}

		return 0;
	}
	catch (const std::exception& ex) {
		std::cerr << "Exception! " << ex.what() << std::endl;
		return 1;
	}
}
