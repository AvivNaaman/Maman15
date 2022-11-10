#pragma once

#include <boost/asio.hpp>
#include <iostream>
#include "protocol.h"

/// <summary>
/// This class holds information and data for the client,
/// and enables storing them permanently.
/// </summary>
class MeInfo {

	static const std::string FILE_NAME;

	/// <summary>
	/// Indicates whether the current client data was correctly loaded from the local source.
	/// </summary>
	bool _file_loaded;

	/// <summary>
	/// Tries to load the client data from the local source.
	/// </summary>
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

	/// <summary>
	/// Current private RSA key of the client.
	/// </summary>
	std::string rsa_private_key;


	/// <summary>
	/// Creates an instance of the client data, trying to load the data from the local source.
	/// </summary>
	MeInfo();

	/// <summary>
	/// Saves the current data into the local source.
	/// </summary>
	void save();


	/// <summary>
	/// Returns whether settings file was loaded to the data class.
	/// </summary>
	bool is_loaded();
};