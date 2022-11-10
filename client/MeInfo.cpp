#include <string>
#include <iomanip>
#include "MeInfo.h"
#include "util/formats.h"
#include <cryptopp/base64.h>
#include "protocol.h"


#include <fstream>
const std::string MeInfo::FILE_NAME = "me.info";

MeInfo::MeInfo() {
	_file_loaded = false;

	if (try_load()) {
		_file_loaded = true;
	}
}


void MeInfo::save() {
	std::ofstream info_file(FILE_NAME);

	if (!info_file.is_open()) {
		return;
	}

	info_file << this->user_name << std::endl;

	Uuid::write(info_file, this->header_user_id, sizeof(this->header_user_id));

	info_file << std::endl << Base64::encode(this->rsa_private_key);

	// file is up-to-date with loaded data!
	_file_loaded = true;
}


bool MeInfo::try_load() {
	try {
		std::ifstream info_file(FILE_NAME);

		if (!info_file.is_open()) {
			return false;
		}
		// user name
		std::getline(info_file, this->user_name);

		std::string temp_line;

		// user id
		info_file >> temp_line;
		if (temp_line.empty()) return false;

		Uuid::parse(temp_line, this->header_user_id);

		// private key
		info_file >> temp_line;

		// decode & set
		rsa_private_key = Base64::decode(temp_line);
		return true;
	}
	catch (const std::exception&) {
		return false;
	}
}

bool MeInfo::is_loaded() {
	return _file_loaded;
}