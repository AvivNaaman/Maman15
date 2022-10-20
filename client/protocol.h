/*
This file contains protocol specific defintitions such as codes, sizes and data types.
*/

#pragma once
#include <cstdint>

#define AES_KEY_LENGTH_BYTES (16)
#define RSA_KEY_LENGTH_BITS (1024)

#define PUBLIC_KEY_SIZE_BYTES (160)
#define USER_ID_SIZE_BYTES (16)
#define MAX_USER_NAME_LENGTH (255)
#define PUBLIC_KEY_EXPORTED_SIZE (160) // TODO: Check automatic formula option.
#define MAX_FILENAME_SIZE (255)
#define EXCHANGED_AES_KEY_SIZE_LIMIT (512)

#define PROTOCOL_VERSION (3)

/// <summary>
/// The codes for each client request.
/// </summary>
enum ClientRequestsCode : uint16_t {
	RequestCodeRegister = 1100,
	RequestCodeKeyExchange = 1101,
	RequestCodeUploadFile = 1103,
	RequestCodeValidChecksum = 1104,
	RequestCodeInvalidChecksumRetry = 1105,
	RequestCodeInvalidChecksumAbort = 1106
};

/// <summary>
/// The codes for each server response.
/// </summary>
enum ServerResponseCode : uint16_t {
	ResponseCodeRegisterSuccess = 2100,
	ResponseCodeExchangeAes = 2102,
	ResponseCodeFileUploaded = 2103,
	ResponseCodeMessageOk = 2104,
	ResponseCodeServerError = 0
};



#pragma pack(push, 1)

/* Requests Data */
struct ClientRequestBase {
	unsigned char header_user_id[USER_ID_SIZE_BYTES];
	unsigned char version;
	ClientRequestsCode code;
	unsigned int payload_size;
};

struct RegisterRequestType : ClientRequestBase {
	char user_name[MAX_USER_NAME_LENGTH];
};

struct KeyExchangeRequestType : ClientRequestBase {
	char user_name[MAX_USER_NAME_LENGTH];
	char public_key[PUBLIC_KEY_SIZE_BYTES];
};

struct SendFileRequestType : ClientRequestBase {
	unsigned char client_id[USER_ID_SIZE_BYTES];
	unsigned int content_size;
	char file_name[MAX_FILENAME_SIZE];
};

struct ChecksumStatusRequest : ClientRequestBase {
	unsigned char client_id[USER_ID_SIZE_BYTES];
	char file_name[MAX_FILENAME_SIZE];
};


/* Responses Data */
struct ServerResponseHeader {
	unsigned char version;
	ServerResponseCode code;
	unsigned int payload_size;
};

struct RegisterSuccess {
	unsigned char client_id[USER_ID_SIZE_BYTES];
};


struct KeyExchangeSuccess {
	unsigned char client_id[USER_ID_SIZE_BYTES];
};

struct FileUploadSuccess {
	unsigned char client_id[USER_ID_SIZE_BYTES];
	unsigned int content_size;
	char file_name[MAX_FILENAME_SIZE];
	unsigned int checksum;
};


#pragma pack(pop)