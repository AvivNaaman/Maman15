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


bool Client::load_info_file() {
	std::ifstream info_file(Client::INFO_FILE_NAME);

	if (!info_file.is_open()) {
		return false;
	}
	// user name
	std::getline(info_file, this->user_name);

	std::string temp_line;

	// user id
	info_file >> temp_line;
	if (temp_line.empty()) return false;
	Uid::parse(temp_line, this->user_id);

	// private key
	info_file >> temp_line;
	// decode & set
	auto private_key = Base64::decode(temp_line);
	rsa.setKey(private_key);

	return true;
}

void Client::save_info_file() {
	std::ofstream info_file(Client::INFO_FILE_NAME);

	if (!info_file.is_open()) {
		return;
	}

	info_file << this->user_name << std::endl;

	Uid::write(info_file, this->user_id, sizeof(this->user_id));

	info_file << std::endl << Base64::encode(this->rsa.get_private_key()) << std::endl;
}

void Client::prepare_request(ClientRequestBase& to_prepare, ClientRequestsCode code, size_t actual_size)
{
	to_prepare.version = SUPPORTED_PROTOCOL_VERSION;
	to_prepare.code = code;
	to_prepare.payload_size = actual_size - sizeof(ClientRequestBase);
	memcpy(to_prepare.user_id, this->user_id, sizeof(this->user_id));
}


void Client::register_user(std::string user_name) {
	RegisterRequestType request;

	if (user_name.length() > MAX_NAME_SIZE - 1)
		throw std::invalid_argument("user_name");

	memcpy(request.user_name, user_name.c_str(), sizeof(request.user_name));

	prepare_request(request, ClientRequestsCode::RequestCodeRegister, sizeof(request));
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

	this->user_name = user_name;
}

void Client::exchange_keys()
{
	KeyExchangeRequestType request;
	prepare_request(request, ClientRequestsCode::RequestCodeKeyExchange, sizeof(request));

	// generate key pair, send public key
	rsa.gen_key();
	memcpy(request.public_key, rsa.get_public_key().c_str(), sizeof(request.public_key));
	memcpy(request.user_name, user_name.c_str(), sizeof(request.user_name));
	write_data_to_socket(&request, socket);
	
	ServerResponseHeader header;
	read_data_from_socket(&header, socket);
	if (header.code != ServerResponseCode::ResponseCodeExchangeAes) {
		std::cerr << "Invalid response from server. Aborting.";
		return;
	}

	save_info_file();
}
