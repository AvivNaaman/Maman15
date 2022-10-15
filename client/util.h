#pragma once

#include <boost/asio.hpp>
#include <iostream>

template <typename T>
union SocketData {
	unsigned char as_buffer[sizeof(T)];
	T as_original;
};

template <typename T>
void read_static_data_from_socket(T* dest_data,
	boost::asio::ip::tcp::socket& src) {
	auto* dest = (SocketData<T>*)dest_data;
	boost::asio::read(src, boost::asio::buffer(dest->as_buffer, sizeof(dest->as_buffer)));
}

template <typename T>
void read_dynamic_data_from_socket(T* dest_data,
	boost::asio::ip::tcp::socket& src,
	size_t read_count) {
	unsigned char *temp = (unsigned char*)dest_data;
	boost::asio::read(src, boost::asio::buffer(temp, read_count));
}

template <typename T>
void write_data_to_socket(T* source_data,
	boost::asio::ip::tcp::socket& dest) {
	auto src = (SocketData<T>*)source_data;
	boost::asio::write(dest, boost::asio::buffer(src->as_buffer, sizeof(src->as_buffer)));
}

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