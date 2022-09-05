from dataclasses import dataclass
from enum import Enum, auto
from socket import socket
import struct


class ClientRequestType(Enum):
    Register = 0
    KeyExchange = auto()
    UploadFile = auto()
    VerifyChecksum = auto()


class ServerResponseType(Enum):
    RegisterSuccess = 0,
    ExchangeAes = 1,
    FileUploaded = 2,
    ServerError = 3


# Little endian: unsigned short | 16-char string
HEADER_STRUCT_FORMAT = "<H16s"


@dataclass(frozen=True)
class RequestHeader:
    request_type: ClientRequestType
    user_id: str


REGISTER_REQUEST_FORMAT = "<127s"


@dataclass(frozen=True)
class RegisterRequestContent:
    user_name: str


KEY_EXCHANGE_FORMAT = "<160s"


@dataclass(frozen=True)
class KeyExchangeContent:
    public_key: bytes


FILE_UPLOAD_FORMAT = "<255sQ"


@dataclass(frozen=True)
class FileUploadContent:
    file_name: str
    file_size: int


VERIFY_CHECKSUM_FORMAT = "<255s"


@dataclass(frozen=True)
class VerifyChecksumContent:
    file_name: str


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
