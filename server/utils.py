import zlib
from socket import socket
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA


CHUNK_SIZE = 1024


def crc(file_name) -> int:
    """ Returns a 32-bit CRC calculation using zlib, iterating each line for a step. """
    prev = 0
    for eachLine in open(file_name, "rb"):
        prev = zlib.crc32(eachLine, prev)
    return prev & 0xFFFFFFFF


def socket_to_local_file(src: socket, file_name: str, filesize: int, aes_key: bytes):
    """ Saves a file from socket to a local file, decrypting it's contents using AES. """
    size_left = filesize
    cipher = AES.new(aes_key, AES.MODE_CBC)

    with open(file_name, 'wb') as f:
        while size_left:
            # fetch from socket
            to_recv = min(CHUNK_SIZE, size_left)
            to_write = src.recv(to_recv)
            # decrypt data
            to_write = cipher.decrypt(to_write)
            # write to file and continue
            f.write(to_write)
            size_left -= to_recv


def encrypt_with_rsa(publickey, short_data):
    """ Encrypts some short data using RSA by the provided public key. """
    loaded_key = RSA.importKey(publickey)
    return PKCS1_OAEP.new(loaded_key).encrypt(short_data)
