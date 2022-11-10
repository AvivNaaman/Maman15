#include <fstream>
#include "Client.h"
#include "protocol.h"
#include <iostream>
#include "util/CRC.h"
#include "util/SocketHelper.h"

const std::string Client::INFO_FILE_NAME = "me.info";


Client::Client(const std::string& host, int port) :
	srv_resolver(client_io_ctx),
	socket(client_io_ctx),
	info_file() {

	// connect socket
	auto endpoint = srv_resolver.resolve(host, std::to_string(port));
	boost::asio::connect(socket, endpoint);

	// load data from file, including rsa private key
	if (info_file.is_loaded()) {
		this->_registered = true;
		rsa.setKey(info_file.rsa_private_key);
	}
}

template <class T>
inline T Client::get_request(ClientRequestsCode code)
{
	// make sure this is a valid resuest (during compilation only!)
	static_assert(std::is_base_of<ClientRequestBase, T>::value, "T must inherit from ClientRequestBase!");
	T to_prepare{};
	// assign shared fields
	to_prepare.version = PROTOCOL_VERSION;
	to_prepare.code = code;
	to_prepare.payload_size = sizeof(T) - sizeof(ClientRequestBase);
	memcpy_s(to_prepare.header_user_id, sizeof(to_prepare.header_user_id), info_file.header_user_id, sizeof(info_file.header_user_id));
	return to_prepare;
}

inline ServerResponseHeader Client::get_header(ServerResponseCode code) {
	ServerResponseHeader header;
	SocketHelper::recieve_static(&header, this->socket);

	// using function may catch if needs to be done.
	if (header.code != code) {
		throw std::runtime_error("Unexpected response code from server: " + std::to_string(code));
	}

	return header;
}

bool Client::register_user(std::string user_name) {
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
	try {
		auto header = get_header(ServerResponseCode::ResponseCodeRegisterSuccess);
	}
	catch (const std::runtime_error&) {
		// failed to register!
		return false;
	}

	RegisterSuccess payload;
	SocketHelper::recieve_static(&payload, this->socket);

	// Temporarily save assigned user id
	memcpy_s(info_file.header_user_id, sizeof(info_file.header_user_id), payload.client_id, sizeof(payload.client_id));

	// generate key pair - because registered.
	rsa.gen_key();

	// save data & info file
	info_file.user_name = user_name;
	info_file.rsa_private_key = rsa.get_private_key();
	info_file.save();

	_registered = true;
	return true;
}

void Client::exchange_keys()
{
	if (!_registered) {
		throw std::runtime_error("Client must be registered to exchange keys!");
	}

	// send public key
	auto request = get_request<KeyExchangeRequestType>(ClientRequestsCode::RequestCodeKeyExchange);
	auto pubkey = rsa.get_public_key();
	memcpy_s(request.public_key, sizeof(request.public_key), pubkey.c_str(), pubkey.length());
	strcpy_s(request.user_name, sizeof(request.user_name), info_file.user_name.c_str());
	SocketHelper::send_static(&request, socket);

	auto header = get_header(ServerResponseCode::ResponseCodeExchangeAes);

	KeyExchangeSuccess payload;
	SocketHelper::recieve_static(&payload, this->socket);

	// get variable size from socket by specified payload
	auto key_exp_size = header.payload_size - sizeof(KeyExchangeSuccess);
	auto key_dest = new char[key_exp_size];
	SocketHelper::recieve_dynamic(key_dest, socket, key_exp_size);

	// decrypt fetched AES key using private RSA key
	std::string aes_key = rsa.decrypt(std::string(key_dest, key_exp_size));
	this->aes_key = aes_key;
}

unsigned int Client::request_file_upload(std::filesystem::path file_path) {
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

bool Client::send_file(std::filesystem::path file_path)
{
	if (!std::filesystem::is_regular_file(file_path)) {
		throw std::runtime_error("File doesn't exist: " + file_path.string());
	}

	// file details
	auto file_name = file_path.filename().string();

	if (file_name.length() > MAX_FILENAME_SIZE - 1) {
		throw std::invalid_argument("Name of file cannot be longer than " + std::to_string(MAX_FILENAME_SIZE - 1) + " chars!");
	}

	auto file_crc = CRC().calculate(file_path.string());

	// recovery process variables
	int tries_left = SEND_FILE_RETRY_COUNT + 1;
	auto upload_verified = false;

	while (tries_left > 0 && !upload_verified) {
		tries_left--;

		auto server_checksum = request_file_upload(file_path);

		// validate checksum - and choose status to return for server.
		ClientRequestsCode status_code = ClientRequestsCode::RequestCodeInvalidChecksumAbort;
		if (server_checksum == file_crc) {
			upload_verified = true;
			status_code = ClientRequestsCode::RequestCodeValidChecksum;
		}
		else if (tries_left > 0) {
			status_code = ClientRequestsCode::RequestCodeInvalidChecksumRetry;
		}

		// Update server with the checksum validation result
		auto crequest = get_request<ChecksumStatusRequest>(status_code);
		strcpy_s(crequest.file_name, sizeof(crequest.file_name), file_name.c_str());
		memcpy_s(crequest.client_id, sizeof(crequest.client_id), info_file.header_user_id, sizeof(info_file.header_user_id));
		SocketHelper::send_static(&crequest, socket);

		// wait for server OK response before continuing.
		get_header(ServerResponseCode::ResponseCodeMessageOk);
	}

	return upload_verified;
}

bool Client::is_registered()
{
	return _registered;
}
