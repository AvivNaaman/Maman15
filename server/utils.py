import zlib
from socket import socket
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
CHUNK_SIZE = 1024


def crc(file_name) -> int:
    return 0x2477187612


def socket_to_local_file(src: socket, file_name: str, filesize: int, aes_key: bytes):
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


def encrypt_with_rsa(publickey, data):
    loaded_key = RSA.importKey(publickey)
    return loaded_key.encrypt(data)
