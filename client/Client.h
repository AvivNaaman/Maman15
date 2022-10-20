#pragma once


#include <string>
#include <filesystem>
#include <boost/asio.hpp>
#include "util.h"
#include "protocol.h"
#include "RSADecryptor.h"
#include "EncryptedFileSender.h"

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
	EncryptedFileSender file_sender;
	bool _registered = false;

	/// <summary>
	/// Current user's user name.
	/// </summary>
	std::string user_name;

	/// <summary>
	/// Current user's ID
	/// </summary>
	u_char header_user_id[USER_ID_SIZE_BYTES];

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

	bool is_registered();
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
	/// Returns a request object, with filled header values, to send to the server.
	/// </summary>
	/// <typeparam name="T">The type of request object to construct. Must inherit ClientRequestBase.</typeparam>
	/// <param name="code">The resuest code.</param>
	/// <returns>The constructed request data.</returns>
	template <class T>
	inline T get_request(ClientRequestsCode code);

	/// <summary>
	/// Fetches the server's response from the socket, and returns the header.
	/// </summary>
	/// <returns>The header's value</returns>
	inline ServerResponseHeader get_header();
};

