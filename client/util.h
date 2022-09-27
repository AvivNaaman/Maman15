#pragma once

#include <boost/asio.hpp>
#include <iostream>

template <typename T>
union SocketData {
	unsigned char as_buffer[sizeof(T)];
	T as_original;
};

template <typename T>
void read_data_from_socket(T* dest_data,
	boost::asio::ip::tcp::socket& src) {
	auto *dest = (SocketData<T>*)dest_data;
	boost::asio::read(src, boost::asio::buffer(dest->as_buffer, sizeof(dest->as_buffer)));
}


template <typename T>
void write_data_to_socket(T* source_data,
	boost::asio::ip::tcp::socket& dest) {
	auto src = (SocketData<T>*)source_data;
	boost::asio::write(dest, boost::asio::buffer(src->as_buffer, sizeof(src->as_buffer)));
}

void parse_uid(const std::string& input, unsigned char* destination);

void write_uid(std::ostream& out_s, unsigned char* source, size_t len);