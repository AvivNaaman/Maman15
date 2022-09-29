#pragma once

#include "protocol.h"
#include <string>
#include <rsa.h>
#include <osrng.h>

class RSADecryptor
{
private:
	CryptoPP::AutoSeededRandomPool _rng;
	CryptoPP::RSA::PrivateKey _privateKey;
	bool _initialized = false;
public:
	/// <summary>
	/// Creates a new, empty instance of a decryptor.
	/// </summary>
	RSADecryptor();

	/// <summary>
	/// Loads an existing RSA private key into the decryptor.
	/// </summary>
	/// <param name="key">The key to load.</param>
	void setKey(std::string key);

	/// <summary>
	/// Generates a new RSA key pair, overriding the current, if such one is present.
	/// </summary>
	void gen_key();

	/// <summary>
	/// Decrypts a byte sequence of size, using the private key.
	/// </summary>
	/// <param name="cipher">The encrypted byte sequence.</param>
	/// <param name="length">The sequence length.</param>
	/// <returns>A string consists of the decrypted data.</returns>
	std::string decrypt(const char* cipher, unsigned int length);

	/// <summary>
	/// Retruns the public key, associated with the current private key.
	/// </summary>
	/// <returns></returns>
	std::string get_public_key();
};

