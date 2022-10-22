#include <fstream>
#include "Client.h"
#include "protocol.h"
#include "util.h"
#include <iostream>
#include "CRC.h"

using boost::asio::ip::tcp;

const std::string Client::INFO_FILE_NAME = "me.info";


Client::Client(const std::string& host, int port) :
	srv_resolver(client_io_ctx),
	socket(client_io_ctx),
	file_sender() {
	// connect socket
	auto endpoint = srv_resolver.resolve(host, std::to_string(port));
	boost::asio::connect(socket, endpoint);

	// try loading client info from older sessions
	if (load_info_file())
		_registered = true;
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
	Uid::parse(temp_line, this->header_user_id);

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

	Uid::write(info_file, this->header_user_id, sizeof(this->header_user_id));

	info_file << std::endl << Base64::encode(this->rsa.get_private_key());
}

template <class T>
inline T Client::get_request(ClientRequestsCode code)
{
	static_assert(std::is_base_of<ClientRequestBase, T>::value, "T must inherit from ClientRequestBase!");
	T to_prepare;
	to_prepare.version = PROTOCOL_VERSION;
	to_prepare.code = code;
	to_prepare.payload_size = sizeof(T) - sizeof(ClientRequestBase);
	memcpy(to_prepare.header_user_id, this->header_user_id, sizeof(this->header_user_id));
	return to_prepare;
}

inline ServerResponseHeader Client::get_header() {
	ServerResponseHeader header;
	SocketHelper::read_static(&header, this->socket);

	/*if (header.code != ServerResponseCode::ResponseCodeRegisterSuccess) {
		std::cerr << "Invalid response from server! Aborting.";
		throw std::exception("Unexpected response code!");
	}*/

	return header;
}

void Client::register_user(std::string user_name) {
	if (_registered)
		throw std::exception("User already registered!");

	if (user_name.length() > MAX_USER_NAME_LENGTH - 1)
		throw std::invalid_argument("user_name");

	auto request = get_request<RegisterRequestType>(ClientRequestsCode::RequestCodeRegister);
	memcpy(request.user_name, user_name.c_str(), sizeof(request.user_name));
	SocketHelper::write_static(&request, this->socket);

	auto header = get_header();

	RegisterSuccess payload;
	SocketHelper::read_static(&payload, this->socket);

	memcpy(this->header_user_id, payload.client_id, sizeof(this->header_user_id));

	std::cout << "Registered client successfully!";

	this->user_name = user_name;
}

void Client::exchange_keys()
{
	auto request = get_request<KeyExchangeRequestType>(ClientRequestsCode::RequestCodeKeyExchange);

	// generate key pair, send public key
	rsa.gen_key();
	memcpy(request.public_key, rsa.get_public_key().c_str(), sizeof(request.public_key));
	memcpy(request.user_name, user_name.c_str(), sizeof(request.user_name));
	SocketHelper::write_static(&request, socket);

	auto header = get_header();

	KeyExchangeSuccess payload;
	SocketHelper::read_static(&payload, this->socket);

	auto key_exp_size = header.payload_size - sizeof(KeyExchangeSuccess);
	auto key_dest = new char[key_exp_size];
	SocketHelper::read_dynamic(key_dest, socket, key_exp_size);
	std::string aes_key = rsa.decrypt(std::string(key_dest, key_exp_size));

	file_sender.set_key(aes_key);
	save_info_file();
}

#define SEND_FILE_RETRY_COUNT (3)

void Client::send_file(std::filesystem::path file_path)
{
	auto file_crc = CRC().calculate(file_path.string());
	int tries_left = SEND_FILE_RETRY_COUNT;
	auto file_name = file_path.filename().string();
	bool upload_verified = false;

	while (tries_left > 0 && !upload_verified) {
		tries_left--;

		// send the file
		auto request = get_request<SendFileRequestType>(ClientRequestsCode::RequestCodeUploadFile);
		strcpy_s(request.file_name, sizeof(request.file_name), file_name.c_str());
		memcpy_s(request.client_id, sizeof(request.header_user_id), this->header_user_id, sizeof(this->header_user_id));
		request.content_size = file_sender.calculate_encrypted_size(file_size(file_path));
		SocketHelper::write_static(&request, socket);
		file_sender.send_local_file(file_path.string(), socket);

		// fetch response
		auto header = get_header();
		FileUploadSuccess payload;
		SocketHelper::read_static(&payload, this->socket);

		// validate checksum
		ClientRequestsCode c = (tries_left > 0) ? ClientRequestsCode::RequestCodeInvalidChecksumRetry : ClientRequestsCode::RequestCodeInvalidChecksumAbort;
		if (payload.checksum == file_crc) {
			upload_verified = true;
			c = ClientRequestsCode::RequestCodeValidChecksum;
		}

		// Update server with the checksum validation result
		auto crequest = get_request<ChecksumStatusRequest>(ClientRequestsCode::RequestCodeValidChecksum);
		strcpy_s(crequest.file_name, sizeof(crequest.file_name), file_name.c_str());
		memcpy(crequest.client_id, this->header_user_id, sizeof(this->header_user_id));
		SocketHelper::write_static(&crequest, socket);

		// wait for server response before continue
		get_header();
	}
}

bool Client::is_registered()
{
	return _registered;
}
