from enum import Enum
from typing import List, Optional, Union

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
    GZ = 'gz'
    NONE = 'none'


class Encryption(str, Enum):
    """Supported encryption types."""
    AGE = 'age'


class EntryType(str, Enum):
    """Supported entry types."""
    DIR = 'dir'
    FILE = 'file'


class DirEntry(BaseModel):
    """Directory entry metadata."""
    entry_type: str = EntryType.DIR
    name: str
    mode: Optional[int] = None
    mtime: Optional[int] = None

    @validator('entry_type')
    def correct_type(cls, v):
        if v != EntryType.DIR:
            raise ValueError('Incorrect entry type.')
        return v

    def is_dir(self):
        return True


class FileEntry(BaseModel):
    """File entry metadata."""
    entry_type: str = EntryType.FILE
    name: str
    size: int
    mode: Optional[int] = None
    mtime: Optional[int] = None
    compression: str
    stored_name: str
    stored_size: int
    stored_checksum: str

    @validator('entry_type')
    def correct_type(cls, v):
        if v != EntryType.FILE:
            raise ValueError('Incorrect entry type.')
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
    comment: Optional[str] = None
    checksum_type: str
    encryption: str
    encryption_key: str
    entries: List[Union[FileEntry, DirEntry]] = []

    @validator('checksum_type')
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
