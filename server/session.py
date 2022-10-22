import logging
import os
import threading

import utils
from db import Database
from protocol import *

class ClientSession(threading.Thread):
    def __init__(self, client_socket: socket, database: Database):
        super().__init__(daemon=True)
        self.__client = client_socket
        self.__db = database
        self.__logger = logging.getLogger("ClientSession")

    def run(self):
        try:
            # Until connection is closed, handle requests
            while True:
                self.handle_single_request()
        except IOError:
            pass
        except Exception as ex:
            self.__logger.error("Error raised while processing client!")
            raise ex


    def handle_single_request(self):
        # Get Header
        header: RequestHeader = receive_request_part(self.__client, RequestHeader)
        header_request = ClientRequestCodes(header.code)

        request_content_type = RequestCodeToDataTypeMap[header.code]
        content = receive_request_part(self.__client, request_content_type)

        if header.code != ClientRequestCodes.Register:
            self.__db.set_last_seen(header.user_id)

        # Execute extra logic by request type
        self.HANDLERS_MAP[header_request](self, header, content)

    def register(self, header: RequestHeader, content: RegisterRequestContent):

        if self.__db.user_exists(content.name):
            self.__client.send(get_response(ServerResponseCodes.RegistrationFailed))
            self.__logger.debug(f"Failed registration of duplicated user name {content.name}")
            return

        new_id = self.__db.register_user(content.name)

        payload = RegisterSuccessResponse(new_id.bytes)
        response = get_response(ServerResponseCodes.RegisterSuccess, payload)

        self.__client.send(response)

    def key_exchange(self, header: RequestHeader, content: KeyExchangeContent):

        # Gen AES Key
        aes_key = os.urandom(AES_KEY_SIZE_BYTES)

        # Save AES Key to database, along with public key
        self.__db.save_keys(header.user_id, content.public_key, aes_key)

        # Encrypt AES Key, and return it.
        encrypted_aes = utils.encrypt_with_rsa(content.public_key, aes_key)
        payload = KeyExchangeResponse(header.user_id.bytes, encrypted_aes)
        response = get_response(ServerResponseCodes.ExchangeAes, payload, len(encrypted_aes))

        self.__client.send(response)

    def upload_file(self, header: RequestHeader, content: FileUploadContent):
        aes_key = self.__db.get_aes_for_user(header.user_id)
        if aes_key is None:
            raise ValueError("AES Key not found for specified user.")
        u = self.__db.users[header.user_id]

        # Generate file name & create dir
        try:
            os.mkdir(u.name)
        except FileExistsError:
            pass

        dest_file_name = os.path.join(u.name, content.file_name)
        utils.socket_to_local_file(self.__client, dest_file_name, content.file_size, aes_key)
        self.__db.add_file(header.user_id, content.file_name, dest_file_name)

        # Return CRC
        file_crc = utils.crc32().calculate(dest_file_name)
        payload = FileUploadResponse(header.user_id.bytes, content.file_size, content.file_name, file_crc)
        response = get_response(ServerResponseCodes.ExchangeAes, payload)

        self.__client.send(response)

    def checksum_status(self, header: RequestHeader, content: ChecksumStatusContent):
        if header.code == ClientRequestCodes.ValidChecksum:
            self.__db.verify_file(header.user_id)
        elif header.code == ClientRequestCodes.InvalidChecksumAbort:
            self.__db.remove_file(header.user_id)
        self.default_response()

    def default_response(self, *args, **kwargs):
        self.__client.send(get_response(ServerResponseCodes.MessageOk))

    
    # Maps Request types to their logic handlers
    HANDLERS_MAP = {
        ClientRequestCodes.Register: register,
        ClientRequestCodes.KeyExchange: key_exchange,
        ClientRequestCodes.UploadFile: upload_file,
        ClientRequestCodes.ValidChecksum: checksum_status,
        ClientRequestCodes.InvalidChecksumRetry: checksum_status,
        ClientRequestCodes.InvalidChecksumAbort: checksum_status
    }