from dataclasses import dataclass, fields
from enum import Enum, auto
from socket import socket
import struct

# ASCII with range(256) to support garbage.
TEXT_ENCODING = 'charmap'


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


class AutoParseDataClassStrings:
    def __post_init__(self):
        process_strings(self)


# Little endian: unsigned short | 16-char string
HEADER_STRUCT_FORMAT = "<16sBHL"


@dataclass
class RequestHeader(AutoParseDataClassStrings):
    user_id: str
    version: int
    code: ClientRequestType
    payload_size: int


REGISTER_REQUEST_FORMAT = "<255s"


@dataclass
class RegisterRequestContent(AutoParseDataClassStrings):
    name: str


KEY_EXCHANGE_FORMAT = "<255s160s"


@dataclass
class KeyExchangeContent(AutoParseDataClassStrings):
    name: str
    public_key: bytes


FILE_UPLOAD_FORMAT = "<255sQ"


@dataclass
class FileUploadContent(AutoParseDataClassStrings):
    file_name: str
    file_size: int


VERIFY_CHECKSUM_FORMAT = "<255s"


@dataclass
class VerifyChecksumContent(AutoParseDataClassStrings):
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


def remove_null_terminator(input_string: str) -> str:
    return input_string.split('\0', 1)[0]


def process_strings(data_class):
    """
    This method parses all strings in dataclass (received as bytes) to a string,
    and crops the string at the null terminator.
    """
    for field in fields(data_class):
        if field.type is not str:
            continue

        value = getattr(data_class, field.name)
        if type(value) is not bytes:
            continue

        # Decode bytes
        value = value.decode(TEXT_ENCODING)
        # Remove null terminator if exists
        if '\0' in value:
            value = remove_null_terminator(value)
        setattr(data_class, field.name, value)


def parse_request_part(client: socket, req_type: ClientRequestPart):
    fmt, type_to_construct = RequestParseInfoMap[req_type]
    recv_size = struct.calcsize(fmt)
    read_bytes = client.recv(recv_size)
    parsed_args = struct.unpack(fmt, read_bytes)
    result = type_to_construct(*parsed_args)
    process_strings(result)
    return result
