#pragma once

#include <boost/asio.hpp>
#include <iostream>
#include "protocol.h"

/// <summary>
/// This class provides helper methods to handle socket operations with boost::asio::ip::tcp::socket objects.
/// </summary>
class SocketHelper {
private:
	/// <summary>
	/// Helper union to switch between raw & structual representation of a struct memory
	/// </summary>
	/// <typeparam name="T"></typeparam>
	template <typename T>
	union _SocketData {
		unsigned char as_buffer[sizeof(T)];
		T as_original;
	};
public:
	/// <summary>
	/// Recieved a static struct's data from the socket.
	/// </summary>
	template <typename T>
	static void recieve_static(T* dest_data,
		boost::asio::ip::tcp::socket& src) {
		auto* dest = (_SocketData<T>*)dest_data;
		boost::asio::read(src, boost::asio::buffer(dest->as_buffer, sizeof(dest->as_buffer)));
	}

	/// <summary>
	/// Recieves a dynamic amount of a struct's data from the socket.
	/// </summary>
	template <typename T>
	static void recieve_dynamic(T* dest_data,
		boost::asio::ip::tcp::socket& src,
		size_t read_count) {
		unsigned char* temp = (unsigned char*)dest_data;
		boost::asio::read(src, boost::asio::buffer(temp, read_count));
	}

	/// <summary>
	/// Sends a static data in struct through the socket.
	/// </summary>
	template <typename T>
	static void send_static(T* source_data,
		boost::asio::ip::tcp::socket& dest) {
		auto src = (_SocketData<T>*)source_data;
		boost::asio::write(dest, boost::asio::buffer(src->as_buffer, sizeof(src->as_buffer)));
	}
};

/// <summary>
/// A helper class to perform read/write operations on UIDs with streams.
/// </summary>
class Uid {
public:
	/// <summary>
	/// parses uid from string to a buffer.
	/// </summary>
	static void parse(const std::string& input, unsigned char* destination);
	static void write(std::ostream& out_s, unsigned char* source, size_t len);
};

/// <summary>
/// A helper class to perform encoding/decoding operations on base64 strings.
/// </summary>
class Base64 {
public:
	/// <summary>
	/// Encodes a string to it's base64 representation.
	/// </summary>
	static std::string decode(const std::string& source);
	/// <summary>
	/// Decodes a base64 string to it's respresentation.
	/// </summary>
	/// <param name="source"></param>
	/// <returns></returns>
	static std::string encode(const std::string& source);
};


class MeInfo {
	bool _file_loaded;
	static const std::string FILE_NAME;
	bool try_load();
public:

	/// <summary>
	/// Current user's user name.
	/// </summary>
	std::string user_name;

	/// <summary>
	/// Current user's ID
	/// </summary>
	u_char header_user_id[USER_ID_SIZE_BYTES] = { 0 };

	std::string rsa_private_key;

	MeInfo();
	void save();
	bool is_loaded();
};