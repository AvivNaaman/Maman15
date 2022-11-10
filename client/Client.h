#pragma once


#include <string>
#include <filesystem>
#include <boost/asio.hpp>
#include "MeInfo.h"
#include "protocol.h"
#include "RSAManager.h"
#include "EncryptedFileSender.h"

using boost::asio::ip::tcp;

/**
 * Implements a client for the encrypted file server protocol.
 */
class Client {
private:
	/* Socket, Resolver, IO Context */
	boost::asio::io_context client_io_ctx;
	tcp::resolver srv_resolver;
	tcp::socket socket;
	/// <summary>
	/// Whether the current client's user is registered.
	/// </summary>
	bool _registered = false;


	RSAManager rsa;
	std::string aes_key;
	MeInfo info_file;
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
	void exchange_keys();

	/// <summary>
	///  Sends a file to the server.
	/// </summary>
	/// <param name="file_path">The local file path to send.</param>
	/// <returns>Whether file upload executed succesfuuly, or failed otherwise</returns>
	bool send_file(std::filesystem::path file_path);

	/// <summary>
	/// Returns whether the current client is a registered user in the server.
	/// </summary>
	/// <returns></returns>
	bool is_registered();
private:

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
	/// Validates that the response header code matches the expected response, throws std::exception otherwise.
	/// </summary>
	/// <param name="code"></param>
	/// <returns>The header's value</returns>
	inline ServerResponseHeader get_header(ServerResponseCode code);

	/// <summary>
	/// Executes upload request of a single file, and returns the result CRC if succeeded.
	/// </summary>
	/// <returns></returns>
	unsigned int request_file_upload(std::filesystem::path file_path);
};

