#pragma once

#include <boost/asio.hpp>
#include <iostream>

/// <summary>
/// This class provides helper methods to handle socket operations with boost::asio::ip::tcp::socket objects.
/// </summary>
class SocketHelper {
private:
	/// <summary>
	/// 
	/// </summary>
	/// <typeparam name="T"></typeparam>
	template <typename T>
	union _SocketData {
		unsigned char as_buffer[sizeof(T)];
		T as_original;
	};
public:
	template <typename T>
	static void read_static(T* dest_data,
		boost::asio::ip::tcp::socket& src) {
		auto* dest = (_SocketData<T>*)dest_data;
		boost::asio::read(src, boost::asio::buffer(dest->as_buffer, sizeof(dest->as_buffer)));
	}

	template <typename T>
	static void read_dynamic(T* dest_data,
		boost::asio::ip::tcp::socket& src,
		size_t read_count) {
		unsigned char* temp = (unsigned char*)dest_data;
		boost::asio::read(src, boost::asio::buffer(temp, read_count));
	}

	template <typename T>
	static void write_static(T* source_data,
		boost::asio::ip::tcp::socket& dest) {
		auto src = (_SocketData<T>*)source_data;
		boost::asio::write(dest, boost::asio::buffer(src->as_buffer, sizeof(src->as_buffer)));
	}
};

class Uid {
public:
	static void parse(const std::string& input, unsigned char* destination);
	static void write(std::ostream& out_s, unsigned char* source, size_t len);
};


class Base64 {
public:
	static std::string decode(const std::string& source);
	static std::string encode(const std::string& source);
};