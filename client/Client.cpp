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
	info_file() {

	// connect socket
	auto endpoint = srv_resolver.resolve(host, std::to_string(port));
	boost::asio::connect(socket, endpoint);

	if (info_file.is_loaded()) {
		this->_registered = true;
		rsa.setKey(info_file.rsa_private_key);
	}
}

template <class T>
inline T Client::get_request(ClientRequestsCode code)
{
	static_assert(std::is_base_of<ClientRequestBase, T>::value, "T must inherit from ClientRequestBase!");
	T to_prepare;
	to_prepare.version = PROTOCOL_VERSION;
	to_prepare.code = code;
	to_prepare.payload_size = sizeof(T) - sizeof(ClientRequestBase);
	memcpy_s(to_prepare.header_user_id, sizeof(to_prepare.header_user_id), info_file.header_user_id, sizeof(info_file.header_user_id));
	return to_prepare;
}

inline ServerResponseHeader Client::get_header(ServerResponseCode code) {
	ServerResponseHeader header;
	SocketHelper::recieve_static(&header, this->socket);

	if (header.code != code) {
		throw std::runtime_error("Unexpected response code from server: " + std::to_string(code));
	}

	return header;
}

void Client::register_user(std::string user_name) {
	// make sure data is OK
	if (_registered)
		throw std::runtime_error("User already registered!");

	if (user_name.length() > MAX_USER_NAME_LENGTH - 1)
		throw std::invalid_argument("Specified user name cannot be longer than " + std::to_string(MAX_USER_NAME_LENGTH - 1) + " chars!");

	// Build & Send request
	auto request = get_request<RegisterRequestType>(ClientRequestsCode::RequestCodeRegister);
	strcpy_s(request.user_name, sizeof(request.user_name), user_name.c_str());
	SocketHelper::send_static(&request, this->socket);

	// Fetch response
	auto header = get_header(ServerResponseCode::ResponseCodeRegisterSuccess);
	RegisterSuccess payload;
	SocketHelper::recieve_static(&payload, this->socket);

	// Temporarily save assigned user id
	memcpy_s(info_file.header_user_id, sizeof(info_file.header_user_id), payload.client_id, sizeof(payload.client_id));

	// generate key pair - because registered.
	rsa.gen_key();

	info_file.user_name = user_name;
	info_file.rsa_private_key = rsa.get_private_key();
	_registered = true;

	info_file.save();
}

void Client::exchange_keys()
{
	if (!_registered) {
		throw std::runtime_error("Client must be registered to exchange keys!");
	}

	auto request = get_request<KeyExchangeRequestType>(ClientRequestsCode::RequestCodeKeyExchange);
	// send public key
	auto pubkey = rsa.get_public_key();
	memcpy_s(request.public_key, sizeof(request.public_key), pubkey.c_str(), pubkey.length());
	strcpy_s(request.user_name, sizeof(request.user_name), info_file.user_name.c_str());
	SocketHelper::send_static(&request, socket);

	auto header = get_header(ServerResponseCode::ResponseCodeExchangeAes);

	KeyExchangeSuccess payload;
	SocketHelper::recieve_static(&payload, this->socket);

	auto key_exp_size = header.payload_size - sizeof(KeyExchangeSuccess);
	auto key_dest = new char[key_exp_size];
	SocketHelper::recieve_dynamic(key_dest, socket, key_exp_size);
	std::string aes_key = rsa.decrypt(std::string(key_dest, key_exp_size));
	this->aes_key = aes_key;
}

unsigned int Client::upload_single_file(std::filesystem::path file_path) {
	if (!_registered) {
		throw std::runtime_error("User must be registered & have keys to begin file upload!");
	}

	EncryptedFileSender file_sender(file_path, aes_key);
	// send the file
	auto file_name = file_path.filename().string();
	auto request = get_request<SendFileRequestType>(ClientRequestsCode::RequestCodeUploadFile);
	strcpy_s(request.file_name, sizeof(request.file_name), file_name.c_str());
	memcpy_s(request.client_id, sizeof(request.header_user_id), info_file.header_user_id, sizeof(info_file.header_user_id));
	request.content_size = file_sender.encrypted_size();

	SocketHelper::send_static(&request, socket);
	file_sender.send(socket);

	// fetch response
	auto header = get_header(ServerResponseCode::ResponseCodeFileUploaded);
	FileUploadSuccess payload;
	SocketHelper::recieve_static(&payload, this->socket);

	// return sever CRC
	return payload.checksum;
}

void Client::send_file(std::filesystem::path file_path)
{
	// file details
	auto file_name = file_path.filename().string();
	auto file_crc = CRC().calculate(file_path.string());

	if (file_name.length() > MAX_FILENAME_SIZE - 1) {
		throw std::invalid_argument("Name of file cannot be longer than " + std::to_string(MAX_FILENAME_SIZE - 1) + " chars!");
	}

	// recovery process variables
	int tries_left = SEND_FILE_RETRY_COUNT;
	auto upload_verified = false;

	while (tries_left > 0 && !upload_verified) {
		tries_left--;

		auto server_checksum = upload_single_file(file_path);

		// validate checksum
		ClientRequestsCode status_code = (tries_left > 0) ? ClientRequestsCode::RequestCodeInvalidChecksumRetry : ClientRequestsCode::RequestCodeInvalidChecksumAbort;
		if (server_checksum == file_crc) {
			upload_verified = true;
			status_code = ClientRequestsCode::RequestCodeValidChecksum;
		}

		// Update server with the checksum validation result
		auto crequest = get_request<ChecksumStatusRequest>(status_code);
		strcpy_s(crequest.file_name, sizeof(crequest.file_name), file_name.c_str());
		memcpy_s(crequest.client_id, sizeof(crequest.client_id), info_file.header_user_id, sizeof(info_file.header_user_id));
		SocketHelper::send_static(&crequest, socket);

		// wait for server OK response before continuing.
		get_header(ServerResponseCode::ResponseCodeMessageOk);
	}
}

bool Client::is_registered()
{
	return _registered;
}
