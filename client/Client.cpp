#include <fstream>
#include "Client.h"
#include "protocol.h"
#include "util.h"
#include <iostream>

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

void Client::save_info_file() {
	std::ofstream info_file(Client::INFO_FILE_NAME);

	if (!info_file.is_open()) {
		return;
	}

	info_file << this->user_name;

	write_uid(info_file, this->user_id, sizeof(this->user_id));

	info_file << this->public_key;
}

void Client::prepare_request(ClientRequestBase& to_prepare, ClientRequestsCode code)
{
	to_prepare.version = SUPPORTED_PROTOCOL_VERSION;
	to_prepare.code = code;
	memcpy(to_prepare.user_id, this->user_id, sizeof(this->user_id));
}

void Client::register_user(std::string user_name) {
	RegisterRequestType request;

	if (user_name.length() > MAX_NAME_SIZE - 1)
		throw std::invalid_argument("user_name");

	strcpy(request.user_name, user_name.c_str());
	request.code = ClientRequestsCode::RequestCodeRegister;
	request.payload_size = sizeof(request.user_name);

	prepare_request(request);
	write_data_to_socket(&request, this->socket);

	ServerResponseHeader header;
	read_data_from_socket(&header, this->socket);

	if (header.code != ServerResponseCode::ResponseCodeRegisterSuccess) {
		std::cerr << "Invalid response from server. Aborting.";
		return;
	}

	RegisterSuccess payload;
	read_data_from_socket(&payload, this->socket);

	memcpy(this->user_id, payload.user_id, sizeof(this->user_id));

	std::cout << "Registered client successfully!";
}

void Client::exchange_keys()
{
	KeyExchangeRequestType request;
	prepare_request(request, ClientRequestsCode::RequestCodeKeyExchange);
	request.code
}
