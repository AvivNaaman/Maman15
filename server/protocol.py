from dataclasses import dataclass, fields
from enum import Enum, auto
from socket import socket
import struct
from typing import Any

# ASCII with range(256) to support garbage.
TEXT_ENCODING = 'charmap'

USER_ID_LENGTH_BYTES = 16
AES_KEY_SIZE_BYTES = 16
MAX_USERNAME_SIZE = 255
MAX_FILENAME_SIZE = 255
PUBLIC_KEY_SIZE_BYTES = 160
CHECKSUM_SIZE_BYTES = 16
CURRENT_VERSION_NUMBER = 3


class ClientRequestType(Enum):
    Register = 1100
    KeyExchange = 1101
    UploadFile = 1103
    ValidChecksum = 1104
    InvalidChecksumRetry = 1105
    InvalidChecksumAbort = 1106


class ServerResponseType(Enum):
    RegisterSuccess = 2100
    RegistrationFailed = 2101
    ExchangeAes = 2102
    FileUploaded = 2103
    MessageOk = 2104


class AutoParseDataClassStrings:
    def __post_init__(self):
        process_strings(self)


# Little endian: unsigned short | 16-char string
REQUEST_HEADER_FMT = f"<{USER_ID_LENGTH_BYTES}sBHL"


@dataclass
class RequestHeader(AutoParseDataClassStrings):
    user_id: bytes
    version: int
    code: ClientRequestType
    payload_size: int


REQUEST_REGISTER_FMT = f"<{MAX_USERNAME_SIZE}s"


@dataclass
class RegisterRequestContent(AutoParseDataClassStrings):
    name: str


REQUEST_KEY_EXCHANGE_FORMAT = f"<{MAX_USERNAME_SIZE}s{PUBLIC_KEY_SIZE_BYTES}s"


@dataclass
class KeyExchangeContent(AutoParseDataClassStrings):
    name: str
    public_key: bytes


REQUEST_UPLOAD_FORMAT = f"<{USER_ID_LENGTH_BYTES}sL{MAX_FILENAME_SIZE}s"


@dataclass
class FileUploadContent(AutoParseDataClassStrings):
    user_id: bytes
    file_size: int
    file_name: str


REQUEST_VERIFY_CHECKSUM_FMT = f"<{USER_ID_LENGTH_BYTES}s{MAX_FILENAME_SIZE}s"


@dataclass
class ChecksumStatusContent(AutoParseDataClassStrings):
    user_id: bytes
    file_name: str


class ClientRequestPart(Enum):
    Header = 0
    RegisterContent = auto()
    KeyExchangeContent = auto()
    UploadFileInfoContent = auto()
    VerifyChecksumContent = auto()


RequestParseInfoMap = {
    ClientRequestPart.Header: (REQUEST_HEADER_FMT, RequestHeader),
    ClientRequestPart.RegisterContent: (REQUEST_REGISTER_FMT, RegisterRequestContent),
    ClientRequestPart.KeyExchangeContent: (REQUEST_KEY_EXCHANGE_FORMAT, KeyExchangeContent),
    ClientRequestPart.UploadFileInfoContent: (REQUEST_UPLOAD_FORMAT, FileUploadContent),
    ClientRequestPart.VerifyChecksumContent: (REQUEST_VERIFY_CHECKSUM_FMT, ChecksumStatusContent),
}



@dataclass
class ResponseHeader:
    version: int = CURRENT_VERSION_NUMBER
    code: ServerResponseType = ServerResponseType.MessageOk
    payload_size: int = 0


@dataclass
class RegisterSuccessResponse:
    client_id: bytes


@dataclass
class KeyExchangeResponse:
    client_id: bytes
    aes_key: bytes


@dataclass
class FileUploadResponse:
    client_id: bytes
    content_size: int
    file_name: str
    cksum: int


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


def receive_request_part(client: socket, req_type: ClientRequestPart) -> Any:
    fmt, type_to_construct = RequestParseInfoMap[req_type]
    recv_size = struct.calcsize(fmt)
    read_bytes = client.recv(recv_size)
    if not read_bytes:
        raise IOError
    parsed_args = struct.unpack(fmt, read_bytes)
    result = type_to_construct(*parsed_args)
    process_strings(result)
    return result


ResponseEncodeMap = {
    ResponseHeader: "<BHL",
    RegisterSuccessResponse: f"<{USER_ID_LENGTH_BYTES}s",
    KeyExchangeResponse: f"<{USER_ID_LENGTH_BYTES}s{{0}}s",
    FileUploadResponse: f"<{USER_ID_LENGTH_BYTES}sL{MAX_FILENAME_SIZE}sL",
}


def getattr_with_autocast(o, name):
    """ Gets an attribute, and casts enums to their values. """
    val = getattr(o, name)
    if issubclass(type(val), Enum):
        return val.value
    elif isinstance(val, str):
        return bytes(val, TEXT_ENCODING)
    return val


def encode_response_part(obj_to_encode: Any, *format_lengths):
    fmt = ResponseEncodeMap[type(obj_to_encode)]
    fmt = fmt.format(*format_lengths)
    vals = [getattr_with_autocast(obj_to_encode, f.name) for f in fields(obj_to_encode)]
    return struct.pack(fmt, *vals)


def get_response(code: ServerResponseType, payload=None, *format_lengths) -> bytes:
    """
    Returns a bytes response of the server to a client, for a certain response part.
    :param code: The response type code
    :param payload: The payload data. Possibly None.
    :param format_lengths: A collection of integers, specifying variable-lengths for packing the payload data.
    """
    if payload is not None:
        payload_bytes = encode_response_part(payload, *format_lengths)
    else:
        payload_bytes = bytes(0)

    header = ResponseHeader(code=code, payload_size=len(payload_bytes))
    header_bytes = encode_response_part(header)

    return header_bytes + payload_bytes

