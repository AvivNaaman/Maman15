#include "RSADecryptor.h"
#include "protocol.h"

RSADecryptor::RSADecryptor() {}

void RSADecryptor::setKey(std::string key)
{
	CryptoPP::StringSource ss(key, true);
	_privateKey.Load(ss);
}

void RSADecryptor::gen_key()
{
	_privateKey.Initialize(_rng, RSA_KEY_LENGTH_BITS);
	_initialized = true;
}

std::string RSADecryptor::decrypt(const char* cipher, unsigned int length)
{
	std::string decrypted;
	CryptoPP::RSAES_OAEP_SHA_Decryptor d(_privateKey);
	CryptoPP::StringSource ss_cipher(cipher, true, new CryptoPP::PK_DecryptorFilter(_rng, d, new CryptoPP::StringSink(decrypted)));
	return decrypted;
}

std::string RSADecryptor::get_public_key()
{
	CryptoPP::RSAFunction publicKey(_privateKey);
	std::string key;
	CryptoPP::StringSink ss(key);
	publicKey.Save(ss);
	return key;
}

std::string RSADecryptor::get_private_key()
{
	std::string key;
	CryptoPP::StringSink ss(key);
	_privateKey.Save(ss);
	return key;
}
