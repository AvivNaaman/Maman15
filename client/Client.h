#pragma once


#include <string>
#include <filesystem>
#include <boost/asio.hpp>
#include "util.h"
#include "protocol.h"
#include "RSADecryptor.h"

using boost::asio::ip::tcp;

/**
 * Implements a client for the encrypted file server protocol.
 */
class Client {
private:
	/* Socket, Resolver and IO Context */
	boost::asio::io_context client_io_ctx;
	tcp::resolver srv_resolver;
	tcp::socket socket;

	/// <summary>
	/// Current user's user name.
	/// </summary>
	std::string user_name;

	/// <summary>
	/// Current user's ID
	/// </summary>
	u_char user_id[USER_ID_BYTE_LENGTH];

	// public + private + AES objects
	RSADecryptor rsa;
public:
	static const std::string INFO_FILE_NAME;

	/// <summary>
	/// Starts a new client session to the secure file server.
	/// </summary>
	/// <param name="host">The server's host name</param>
	/// <param name="port">The server's port number.</param>
	Client(const std::string& host, int port);

	/// <summary>
	/// Requests a registration from the server.
	/// </summary>
	/// <param name="name">The user name to provide for the server</param>
	/// <returns>The server - generated user ID</returns>
	void register_user(std::string name);


	/// <summary>
	/// Executes a key-exchange of the client with the server.
	/// </summary>
	/// <returns>the server's secret AES Key.</returns>
	void exchange_keys();

	/// <summary>
	///  Sends a file to the server.
	/// </summary>
	/// <param name="file_path">The local file path to send.</param>
	void send_file(std::filesystem::path file_path);

private:

	/// <summary>
	/// Loads the information file data of an already registered user to the client.
	/// </summary>
	/// <returns>Whether the file read & parsed successfully.</returns>
	bool load_info_file();

	/// <summary>
	/// Saves the current client's registered user data to the information file.
	/// </summary>
	void save_info_file();

	/// <summary>
	/// Prepares a request object to send.
	/// </summary>
	/// <param name="to_prepare">The object to prepare</param>
	/// <param name="code">The request code to send</param>
	void prepare_request(ClientRequestBase& to_prepare, ClientRequestsCode code, size_t actual_size);
};

