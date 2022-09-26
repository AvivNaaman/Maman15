//
// Created by Aviv Naaman on 17/09/2022.
//

#include <fstream>
#include "Client.h"
#include "protocol.h"
#include "util.h"

using boost::asio::ip::tcp;

const std::string Client::INFO_FILE_NAME = "me.info";


Client::Client(const std::string& host, int port) :
	srv_resolver(client_io_ctx),
	socket(client_io_ctx) {
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

void Client::register_user(std::string user_name) {
	RegisterRequestType data;

	if (user_name.length() > MAX_NAME_SIZE - 1)
		throw std::invalid_argument("user_name");

	strcpy(data.user_name, user_name.c_str());
	data.code = ClientRequestsType::Register;
	data.payload_size = sizeof(data.user_name);

	autofill_request(&data);

	write_data_to_socket(&data, this->socket);
}