import os
import threading
from socket import socket

from utils import crc, encrypt_with_rsa
from db import Database
from protocol import RequestHeader, RegisterRequestContent, \
    KeyExchangeContent, FileUploadContent, \
    VerifyChecksumContent, parse_request_part, \
    ClientRequestPart, AES_KEY_SIZE_BYTES, \
    ClientRequestType


class ClientSession(threading.Thread):
    def __init__(self, client_socket: socket, database: Database):
        super().__init__(daemon=True)
        self.__client = client_socket
        self.__db = database

    def run(self):
        # Until connection is closed, handle requests
        while True:
            # Get Header
            header: RequestHeader = parse_request_part(self.__client, ClientRequestPart.Header)

            if header.request_type == ClientRequestType.Register:
                self.register(header)
            elif header.request_type == ClientRequestType.KeyExchange:
                self.key_exchange(header)
            elif header.request_type == ClientRequestType.UploadFile:
                self.upload_file(header)
            elif header.request_type == ClientRequestType.VerifyChecksum:
                self.verify_checksum(header)

    def register(self, header):
        reg_content: RegisterRequestContent = parse_request_part(self.__client, ClientRequestPart.RegisterContent)
        self.__db.register_user(header.user_id, reg_content.user_name)
        # TODO: Return OK
        pass

    def key_exchange(self, header):
        keyx_content: KeyExchangeContent = parse_request_part(self.__client, ClientRequestPart.KeyExchangeContent)
        # Gen AES Key
        aes_key = os.urandom(AES_KEY_SIZE_BYTES)
        # Save AES Key to database, along with public key
        self.__db.save_keys(keyx_content.public_key, aes_key)
        # TODO: Return this encrypted AES Key using the socket.
        encrypted_aes = encrypt_with_rsa(keyx_content.public_key, aes_key)

    def upload_file(self, header):
        upload_content: FileUploadContent = parse_request_part(self.__client,
                                                               ClientRequestPart.UploadFileInfoContent)
        # TODO: Return CRC
        file_crc = crc()
        pass

    def verify_checksum(self, header):
        # TODO: Do we have a file for each user? If so, use the header to query.
        # TODO: Otherwise, save it in the upload_file method, and use it in the current session.
        self.__db.verify_file()
        # TODO: Return OK
        pass
