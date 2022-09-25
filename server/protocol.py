from dataclasses import dataclass
from enum import Enum, auto
from socket import socket
import struct


class ClientRequestType(Enum):
    Register = 1100
    KeyExchange = 1101
    UploadFile = 1103
    ValidChecksum = 1104
    InvalidChecksumRetry = 1105
    InvalidChecksumAbort = 1106


class ServerResponseType(Enum):
    RegisterSuccess = 2100
    ExchangeAes = 2102
    FileUploaded = 2103
    MessageOk = 2104
    ServerError = -1


# Little endian: unsigned short | 16-char string
HEADER_STRUCT_FORMAT = "<16sBHL"


@dataclass(frozen=True)
class RequestHeader:
    user_id: str
    version: int
    code: ClientRequestType
    payload_size: int


REGISTER_REQUEST_FORMAT = "<255s"


@dataclass(frozen=True)
class RegisterRequestContent:
    name: str


KEY_EXCHANGE_FORMAT = "<255s160s"


@dataclass(frozen=True)
class KeyExchangeContent:
    name: str
    public_key: bytes


FILE_UPLOAD_FORMAT = "<255sQ"


@dataclass(frozen=True)
class FileUploadContent:
    file_name: str
    file_size: int


VERIFY_CHECKSUM_FORMAT = "<255s"


@dataclass(frozen=True)
class VerifyChecksumContent:
    pass


class ClientRequestPart(Enum):
    Header = 0
    RegisterContent = auto()
    KeyExchangeContent = auto()
    UploadFileInfoContent = auto()
    VerifyChecksumContent = auto()


RequestParseInfoMap = {
    ClientRequestPart.Header: (HEADER_STRUCT_FORMAT, RequestHeader),
    ClientRequestPart.RegisterContent: (REGISTER_REQUEST_FORMAT, RegisterRequestContent),
    ClientRequestPart.KeyExchangeContent: (KEY_EXCHANGE_FORMAT, KeyExchangeContent),
    ClientRequestPart.UploadFileInfoContent: (KEY_EXCHANGE_FORMAT, KeyExchangeContent),
    ClientRequestPart.VerifyChecksumContent: (VERIFY_CHECKSUM_FORMAT, VerifyChecksumContent),
}

AES_KEY_SIZE_BYTES = 10


def parse_request_part(client: socket, req_type: ClientRequestPart):
    fmt, type_to_construct = RequestParseInfoMap[req_type]
    recv_size = struct.calcsize(fmt)
    read_bytes = client.recv(recv_size)
    parsed_args = struct.unpack(fmt, read_bytes)
    return type_to_construct(*parsed_args)
