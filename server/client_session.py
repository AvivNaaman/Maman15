import os
import threading
import uuid
from socket import socket

import utils
from utils import crc, encrypt_with_rsa
from db import Database
from protocol import *


# TODO: Check whether protocol should support just login.

class ClientSession(threading.Thread):
    def __init__(self, client_socket: socket, database: Database):
        super().__init__(daemon=True)
        self.__client = client_socket
        self.__db = database

    def run(self):
        # Until connection is closed, handle requests
        while True:
            # Get Header
            header: RequestHeader = receive_request_part(self.__client, ClientRequestPart.Header)
            header_request = ClientRequestType(header.code)
            # Execute logic by request type
            self.HANDLERS_MAP[header_request](header)

    def register(self, _):
        reg_content: RegisterRequestContent = receive_request_part(self.__client, ClientRequestPart.RegisterContent)

        new_id = self.__db.register_user(reg_content.name)

        payload = RegisterSuccessResponse(new_id.bytes)
        response = get_response(ServerResponseType.RegisterSuccess, payload)

        self.__client.send(response)

    def key_exchange(self, header):
        keyx_content: KeyExchangeContent = receive_request_part(self.__client, ClientRequestPart.KeyExchangeContent)

        # Gen AES Key
        aes_key = os.urandom(AES_KEY_SIZE_BYTES)

        # Save AES Key to database, along with public key
        self.__db.save_keys(header.user_id, keyx_content.public_key, aes_key)

        # TODO: Return this encrypted AES Key using the socket.
        encrypted_aes = encrypt_with_rsa(keyx_content.public_key, aes_key)

    def upload_file(self, header):
        upload_content: FileUploadContent = receive_request_part(self.__client,
                                                                 ClientRequestPart.UploadFileInfoContent)
        current_user_id = header.user_id
        aes_key = self.__db.get_aes_for_user(uuid.UUID(bytes=current_user_id))

        # Generate file name
        dest_file_name = current_user_id + '.dat'
        utils.socket_to_local_file(self.__client, dest_file_name, upload_content.file_size, aes_key)

        # TODO: Return CRC
        file_crc = crc(dest_file_name)

    def verify_checksum(self, header):
        # TODO: Do we have a file for each user? If so, use the header to query.
        # TODO: Otherwise, save it in the upload_file method, and use it in the current session.
        self.__db.verify_file(header.user_id)

        # TODO: Return OK
        pass

    HANDLERS_MAP = {
        ClientRequestType.Register: register,
        ClientRequestType.KeyExchange: key_exchange,
        ClientRequestType.UploadFile: upload_file,
        ClientRequestType.ValidChecksum: verify_checksum
    }
