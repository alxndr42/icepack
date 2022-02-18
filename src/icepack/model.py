from enum import Enum
from typing import List, Union

from pydantic import BaseModel, PydanticValueError, validator


class UnsupportedValueError(PydanticValueError):
    """Unsupported value in metadata."""
    code = 'unsupported_value'
    msg_template = 'Unsupported {key}: {value}'


class Checksum(str, Enum):
    """Supported checksum types."""
    SHA256 = 'sha256'


class Compression(str, Enum):
    """Supported compression types."""
    BZ2 = 'bz2'


class Encryption(str, Enum):
    """Supported encryption types."""
    AGE = 'age'


class DirEntry(BaseModel):
    """Directory entry metadata."""
    key: str
    name: str

    @validator('name')
    def trailing_slash(cls, v):
        if not v.endswith('/'):
            raise ValueError('Name must end with a slash.')
        return v

    def is_dir(self):
        return True


class FileEntry(BaseModel):
    """File entry metadata."""
    key: str
    name: str
    size: int
    compression: str
    stored_size: int
    stored_checksum: str

    @validator('name')
    def no_trailing_slash(cls, v):
        if v.endswith('/'):
            raise ValueError('Name must not end with a slash.')
        return v

    @validator('compression')
    def supported_compression(cls, v, field):
        check_enum_value(Compression, v, field.name)
        return v

    def is_dir(self):
        return False


class Metadata(BaseModel):
    """Archive metadata."""
    archive_name: str
    checksum_function: str
    encryption: str
    entry_key: str
    entries: List[Union[FileEntry, DirEntry]] = []

    @validator('checksum_function')
    def supported_checksum(cls, v, field):
        check_enum_value(Checksum, v, field.name)
        return v

    @validator('encryption')
    def supported_encryption(cls, v, field):
        check_enum_value(Encryption, v, field.name)
        return v


def check_enum_value(enum_cls, value, key):
    """Raise UnsupportedValueError if value is invalid."""
    match = [e for e in enum_cls if e.value == value]
    if not match:
        raise UnsupportedValueError(key=key, value=value)
