import os
import threading
import uuid
from socket import socket

import utils
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
            self.HANDLERS_MAP[header_request](self, header)

    def register(self, header: RequestHeader):
        reg_content: RegisterRequestContent = receive_request_part(self.__client, ClientRequestPart.RegisterContent)

        new_id = self.__db.register_user(reg_content.name)

        payload = RegisterSuccessResponse(new_id.bytes)
        response = get_response(ServerResponseType.RegisterSuccess, payload)

        self.__client.send(response)

    def key_exchange(self, header: RequestHeader):
        keyx_content: KeyExchangeContent = receive_request_part(self.__client, ClientRequestPart.KeyExchangeContent)

        # Gen AES Key
        aes_key = os.urandom(AES_KEY_SIZE_BYTES)

        uid = uuid.UUID(bytes=header.user_id)
        # Save AES Key to database, along with public key
        self.__db.save_keys(uid, keyx_content.public_key, aes_key)

        # Encrypt AES Key, and return it.
        encrypted_aes = utils.encrypt_with_rsa(keyx_content.public_key, aes_key)
        payload = KeyExchangeResponse(header.user_id, encrypted_aes)
        response = get_response(ServerResponseType.ExchangeAes, payload, len(encrypted_aes))

        self.__client.send(response)

    def upload_file(self, header: RequestHeader):
        upload_content: FileUploadContent = receive_request_part(self.__client,
                                                                 ClientRequestPart.UploadFileInfoContent)
        current_user_id = header.user_id
        aes_key = self.__db.get_aes_for_user(uuid.UUID(bytes=current_user_id))
        u = self.__db.users[uuid.UUID(bytes=current_user_id)]

        # Generate file name & create dir
        try:
            os.mkdir(u.name)
        except FileExistsError:
            pass

        dest_file_name = os.path.join(u.name, upload_content.file_name)
        utils.socket_to_local_file(self.__client, dest_file_name, upload_content.file_size, aes_key)
        self.__db.add_file(current_user_id, upload_content.file_name, dest_file_name)

        # Return CRC
        file_crc = utils.crc32().calculate(dest_file_name)
        payload = FileUploadResponse(current_user_id, upload_content.file_size, upload_content.file_name, file_crc)
        response = get_response(ServerResponseType.ExchangeAes, payload)

        self.__client.send(response)

    def verify_checksum(self, header: RequestHeader):
        self.__db.verify_file(uuid.UUID(bytes=header.user_id))
        self.default_response()

    def default_response(self, *args, **kwargs):
        self.__client.send(get_response(ServerResponseType.MessageOk))

    def invalid_checksum_abort(self, header: RequestHeader):
        self.__db.remove_file(uuid.UUID(bytes=header.user_id))
        self.default_response()

    HANDLERS_MAP = {
        ClientRequestType.Register: register,
        ClientRequestType.KeyExchange: key_exchange,
        ClientRequestType.UploadFile: upload_file,
        ClientRequestType.ValidChecksum: verify_checksum,
        ClientRequestType.InvalidChecksumRetry: default_response,
        ClientRequestType.InvalidChecksumAbort: invalid_checksum_abort
    }
