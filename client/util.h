#pragma once

#include <boost/asio.hpp>

template <typename T>
union SocketData {
	unsigned char ch[sizeof(T)];
	T variable;
};

template <typename T>
void read_data_from_socket(SocketData<T>* dest,
	const boost::asio::ip::tcp::socket& src) {
	boost::asio::read(src, boost::asio::buffer(dest->ch, sizeof(dest->ch)));
}


template <typename T>
void write_data_to_socket(T* source_data,
	boost::asio::ip::tcp::socket& dest) {
	SocketData<T>* src = (SocketData<T>*)source_data;
	boost::asio::write(dest, boost::asio::buffer(src->ch, sizeof(src->ch)));
}

template <typename T>
void autofill_request(T* data) {
	ClientRequestBase* bptr = (ClientRequestBase*)data;
	bptr->version = 1;
}

void parse_uid(const std::string& input, unsigned char* destination);

