from dataclasses import dataclass, fields
from enum import Enum
from socket import socket
import struct
from typing import Any, Dict, Type
from uuid import UUID

from utils import ClientDisconnectedException

# ASCII with range(256) to support encoding of other chars.
TEXT_ENCODING = 'charmap'

# Global size constants
USER_ID_LENGTH_BYTES = 16
AES_KEY_SIZE_BYTES = 16
MAX_USERNAME_SIZE = 255
MAX_FILENAME_SIZE = 255
PUBLIC_KEY_SIZE_BYTES = 160
CHECKSUM_SIZE_BYTES = 16
CURRENT_VERSION_NUMBER = 3


################################## Request parsing ##################################

class ClientRequestCodes(Enum):
    Register = 1100
    KeyExchange = 1101
    UploadFile = 1103
    ValidChecksum = 1104
    InvalidChecksumRetry = 1105
    InvalidChecksumAbort = 1106


class RequestPartBase:
    """ This base class helps to make auto type casting for dataclass fields from network data types. """
    def __post_init__(self):
        """
        This method parses all bytes objects in dataclass to other types, specified by dataclass.
        It is always called by python after the objects construction and assignment.
        """
        for field in fields(self):
            value = getattr(self, field.name)

            # Parse Null-terminated string from bytes
            if field.type is str and type(value) is bytes:
                # Decode bytes
                value = value.decode(TEXT_ENCODING)
                # Remove null terminator if exists
                value = value.split('\0', 1)[0]
                    
            # Parse UUID
            elif field.type is UUID and type(value) is bytes:
                value = UUID(bytes=value)
                
            # Parse Enum
            elif issubclass(field.type, Enum):
                value = field.type(value)
                
            else:
                continue
            setattr(self, field.name, value)


# These dataclasses hold the request information

@dataclass
class RequestHeader(RequestPartBase):
    user_id: UUID
    version: int
    code: ClientRequestCodes
    payload_size: int


@dataclass
class RegisterRequestContent(RequestPartBase):
    name: str


@dataclass
class KeyExchangeContent(RequestPartBase):
    name: str
    public_key: bytes


@dataclass
class FileUploadContent(RequestPartBase):
    user_id: UUID
    file_size: int
    file_name: str


@dataclass
class ChecksumStatusContent(RequestPartBase):
    user_id: UUID
    file_name: str


# This maps request codes to their data types.
RequestCodeToDataTypeMap = {
    ClientRequestCodes.Register: RegisterRequestContent,
    ClientRequestCodes.KeyExchange: KeyExchangeContent,
    ClientRequestCodes.UploadFile: FileUploadContent,
    ClientRequestCodes.ValidChecksum: ChecksumStatusContent,
    ClientRequestCodes.InvalidChecksumRetry: ChecksumStatusContent,
    ClientRequestCodes.InvalidChecksumAbort: ChecksumStatusContent,
}

# This maps data type to it's structual format.
RequestParseInfoMap: Dict[Type, str] = {
    RequestHeader: f"<{USER_ID_LENGTH_BYTES}sBHL",
    RegisterRequestContent: f"<{MAX_USERNAME_SIZE}s",
    KeyExchangeContent: f"<{MAX_USERNAME_SIZE}s{PUBLIC_KEY_SIZE_BYTES}s",
    FileUploadContent: f"<{USER_ID_LENGTH_BYTES}sL{MAX_FILENAME_SIZE}s",
    ChecksumStatusContent: f"<{USER_ID_LENGTH_BYTES}s{MAX_FILENAME_SIZE}s",
}


def receive_request_part(client: socket, req_type: Type) -> Any:
    """ Recieves and parses a request from the socket into a dataclass, and returns it. """
    # get format & bytes to read
    fmt = RequestParseInfoMap[req_type]
    recv_size = struct.calcsize(fmt)
    read_bytes = client.recv(recv_size)

    if not read_bytes:
        raise ClientDisconnectedException()

    # unpack & construct dataclass
    parsed_args = struct.unpack(fmt, read_bytes)
    result = req_type(*parsed_args)
    return result


################################## Response builders ##################################

class ServerResponseCodes(Enum):
    RegisterSuccess = 2100
    RegistrationFailed = 2101
    ExchangeAes = 2102
    FileUploaded = 2103
    MessageOk = 2104


# These data classes hold the response information
@dataclass
class ResponseHeader:
    version: int = CURRENT_VERSION_NUMBER
    code: ServerResponseCodes = ServerResponseCodes.MessageOk
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


# This maps data type to it's structual format.
ResponseEncodeMap = {
    ResponseHeader: "<BHL",
    RegisterSuccessResponse: f"<{USER_ID_LENGTH_BYTES}s",
    KeyExchangeResponse: f"<{USER_ID_LENGTH_BYTES}s{{0}}s",
    FileUploadResponse: f"<{USER_ID_LENGTH_BYTES}sL{MAX_FILENAME_SIZE}sL",
}


def getattr_and_cast(o, name):
    """ Gets an attribute of class, and casts enums or strings to their sendable values. """
    val = getattr(o, name)
    # cast enum -> integer
    if issubclass(type(val), Enum):
        return val.value
    # cast string -> bytes
    elif isinstance(val, str):
        return bytes(val, TEXT_ENCODING)
    # default
    return val


def encode_response_part(obj_to_encode: Any, *format_lengths) -> bytes:
    """ 
    encodes a dataclass to it's format, and returns the encoding as bytes.
    :param obj_to_encode The data class to cast into bytes.
    :param format_lengths A sequence of integers, specfiying lengths of variable-sized buffers.
    """
    # fetch format & put argument sizes in the right places
    fmt = ResponseEncodeMap[type(obj_to_encode)]
    fmt = fmt.format(*format_lengths)
    # get values to pack (cast as needed), and cast them to encodable types.
    vals = [getattr_and_cast(obj_to_encode, f.name) for f in fields(obj_to_encode)]
    return struct.pack(fmt, *vals)


def build_response(code: ServerResponseCodes, payload=None, *format_lengths) -> bytes:
    """
    Returns a full bytes-response of the server to a client, for a certain response part.
    :param code: The response type code
    :param payload: The payload data. Possibly None.
    :param format_lengths: A collection of integers, specifying variable-lengths for packing the payload data.
    """
    # encode content if such one exist
    if payload is not None:
        payload_bytes = encode_response_part(payload, *format_lengths)
    else:
        payload_bytes = bytes(0)

    # encode header
    header = ResponseHeader(code=code, payload_size=len(payload_bytes))
    header_bytes = encode_response_part(header)

    # Return all the information
    return header_bytes + payload_bytes
