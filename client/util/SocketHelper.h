#include <boost/asio.hpp>

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




