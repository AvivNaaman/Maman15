#pragma once

#define AES_KEY_LENGTH_BITS (128)
#define RSA_KEY_LENGTH_BITS (1024)

#define PUBLIC_KEY_SIZE_BYTES (160)
#define USER_ID_BYTE_LENGTH (16)
#define MAX_NAME_SIZE (255)
#define PUBLICKEY_SEND_SIZE (160) // TODO: Check automatic formula option.
#define MAX_FILENAME_SIZE (255)
#define EXCHANGED_AES_KEY_SIZE_LIMIT (512)

enum ClientRequestsType : uint16_t {
	Register = 1100,
	KeyExchange = 1101,
	UploadFile = 1103,
	ValidChecksum = 1104,
	InvalidChecksumRetry = 1105,
	InvalidChecksumAbort = 1106
};

enum ServerResponseType : uint16_t {
	RegisterSuccess = 2100,
	ExchangeAes = 2102,
	FileUploaded = 2103,
	MessageOk = 2104,
	ServerError = 0
};



#pragma pack(push, 1)

struct ClientRequestBase {
	unsigned char user_id[USER_ID_BYTE_LENGTH];
	unsigned char version;
	ClientRequestsType code;
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



struct ServerResponseBase {
	unsigned char user_id[USER_ID_BYTE_LENGTH];
	unsigned char version;
	ServerResponseType code;
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