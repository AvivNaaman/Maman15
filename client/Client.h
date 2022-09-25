//
// Created by Aviv Naaman on 17/09/2022.
//

#ifndef CLIENT_CLIENT_H
#define CLIENT_CLIENT_H


#include <string>
#include <filesystem>
#include <boost/asio.hpp>
#include "util.h"

using boost::asio::ip::tcp;

/**
 * Implements a client for the encrypted file server protocol.
 */
class Client {
private:
	boost::asio::io_context client_io_ctx;
	tcp::resolver srv_resolver;
	tcp::socket socket;

	std::string user_name;
	u_char user_id[USER_ID_BYTE_LENGTH];

	// public + private + AES keys
public:
	static const std::string INFO_FILE_NAME;

	/**
	 * Starts a new client session.
	 * @param server_endpoint The server endpoint name (e.g. IP Address or hostname)
	 * @param port The server destination port
	 * @param data_file_name The client data file name.
	 */
	Client(const std::string &host, int port);

	/**
	 * Requests a registration from the server.
	 * @param name The user name to provide for the server
	 * @return The server-generated user ID
	 */
	char *register_user(std::string name);

	/**
	 * Executes a key-exchange with the server.
	 * @return the server's secret AES Key.
	 */
	char *exchange_keys();

	/**
	 * Sends a file to the server.
	 * @param file_path The local file path to send.
	 */
	void send_file(std::filesystem::path file_path);

private:
	void load_info_file();
	void save_info_file();
};


#endif //CLIENT_CLIENT_H
