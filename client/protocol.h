#pragma once

#define AES_KEY_LENGTH_BITS (128)
#define RSA_KEY_LENGTH_BITS (1024)

#define PUBLIC_KEY_SIZE_BYTES (160)
#define USER_ID_BYTE_LENGTH (16)
#define MAX_NAME_SIZE (255)
#define PUBLICKEY_SEND_SIZE (160) // TODO: Check automatic formula option.
#define MAX_FILENAME_SIZE (255)
#define EXCHANGED_AES_KEY_SIZE_LIMIT (512)

#define SUPPORTED_PROTOCOL_VERSION (1)

enum ClientRequestsCode : uint16_t {
	RequestCodeRegister = 1100,
	RequestCodeKeyExchange = 1101,
	RequestCodeUploadFile = 1103,
	RequestCodeValidChecksum = 1104,
	RequestCodeInvalidChecksumRetry = 1105,
	RequestCodeInvalidChecksumAbort = 1106
};

enum ServerResponseCode : uint16_t {
	ResponseCodeRegisterSuccess = 2100,
	ResponseCodeExchangeAes = 2102,
	ResponseCodeFileUploaded = 2103,
	ResponseCodeMessageOk = 2104,
	ResponseCodeServerError = 0
};



#pragma pack(push, 1)

struct ClientRequestBase {
	unsigned char user_id[USER_ID_BYTE_LENGTH];
	unsigned char version;
	ClientRequestsCode code;
	unsigned int payload_size;
};

struct RegisterRequestType : ClientRequestBase {
	char user_name[MAX_NAME_SIZE];
};

struct KeyExchangeRequestType : ClientRequestBase {
	char user_name[MAX_NAME_SIZE];
	char public_key[PUBLIC_KEY_SIZE_BYTES];
};

struct SendFileRequestType : ClientRequestBase {
	unsigned char user_id[USER_ID_BYTE_LENGTH];
	unsigned int content_size;
	char file_name[MAX_FILENAME_SIZE];
};

struct CRCValidationResult : ClientRequestBase {
	// there are no fields. preserved for future use & compatibillity.
};



struct ServerResponseHeader {
	unsigned char version;
	ServerResponseCode code;
	unsigned int payload_size;
};

struct RegisterSuccess {
	unsigned char user_id[USER_ID_BYTE_LENGTH];
};

struct KeyExchangeSuccess {
	unsigned char user_id[USER_ID_BYTE_LENGTH];
	unsigned char EncryptedAESKey[EXCHANGED_AES_KEY_SIZE_LIMIT];
};

struct FileUploadSuccess {
	unsigned char user_id[USER_ID_BYTE_LENGTH];
	unsigned int content_size;
	char file_name[MAX_FILENAME_SIZE];
	unsigned int checksum;
};


#pragma pack(pop)