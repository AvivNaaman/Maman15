//
// Created by Aviv Naaman on 17/09/2022.
//

#include <fstream>
#include "Client.h"

using boost::asio::ip::tcp;

const std::string Client::INFO_FILE_NAME = "me.info";

Client::Client(const std::string& host, int port):
		srv_resolver(client_io_ctx), socket(client_io_ctx) {
	// connect socket
	auto endpoint = srv_resolver.resolve(host, std::to_string(port));
	boost::asio::connect(socket, endpoint);

	// try loading client info from older sessions
	load_info_file();
}

void Client::load_info_file() {
	std::ifstream info_file(Client::INFO_FILE_NAME);

	if (!info_file.is_open()) {
		return;
	}

	std::getline(info_file, this->user_name);

	std::string temp_line;

	info_file >> temp_line;
	parse_uid(temp_line, this->user_id);

	info_file >> temp_line;
}
