import bz2
import json
from pathlib import Path
from shutil import copyfileobj, rmtree

from pydantic import ValidationError

from icepack.error import InvalidArchiveError
from icepack.helper import Age, File, SSH, Zip
from icepack.meta import SECRET_KEY, PUBLIC_KEY, ALLOWED_SIGNERS
from icepack.model import Checksum, Compression, Encryption
from icepack.model import DirEntry, FileEntry, Metadata


_BUFFER_SIZE = 64 * 1024
_MAX_ATTEMPTS = 3


class IcepackBase():
    """icepack base class."""

    def __init__(self, archive_path, key_path):
        self.archive_path = archive_path.resolve()
        self.secret_key = key_path / SECRET_KEY
        self.public_key = key_path / PUBLIC_KEY
        self.allowed_signers = key_path / ALLOWED_SIGNERS
        if not self.secret_key.is_file():
            raise Exception(f'Missing secret key: {self.secret_key}')
        if not self.public_key.is_file():
            raise Exception(f'Missing public key: {self.public_key}')
        if not self.allowed_signers.is_file():
            raise Exception(f'Missing allowed_signers: {self.allowed_signers}')
        self._tempdir = None
        self._zipfile = None

    def close(self, silent=False):
        """Close the archive and delete all temporary files."""
        if self._tempdir is not None:
            rmtree(self._tempdir, ignore_errors=True)
        if self._zipfile is not None:
            self._zipfile.close(silent=silent)

    def _mktemp(self):
        """Return the Path of a new temporary file."""
        if self._tempdir is None:
            File.mktemp(directory=True)
        return File.mktemp(parent=self._tempdir)


class IcepackReader(IcepackBase):
    """icepack reader."""

    def __init__(self, archive_path, key_path):
        super().__init__(archive_path, key_path)
        if not self.archive_path.is_file():
            raise Exception(f'Invalid archive path: {self.archive_path}')
        self._zipfile = Zip(self.archive_path)
        self._load_metadata()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        failed = exc_type is not None
        self.close(silent=failed)

    def extract_entry(self, entry, base_path):
        """Extract entry to base_path."""
        if entry not in self.metadata.entries:
            raise Exception('Invalid entry.')
        dst_path = base_path.joinpath(entry.name).resolve()
        if not str(dst_path).startswith(str(base_path)):
            raise InvalidArchiveError(f'Invalid entry name: {entry.name}')
        if entry.is_dir():
            dst_path.mkdir(parents=True, exist_ok=True)
            return dst_path
        age_path = self._zipfile.extract_entry(entry.stored_name)
        age_stat = age_path.stat()
        if age_stat.st_size != entry.stored_size:
            raise InvalidArchiveError('Incorrect file size.')
        if File.sha256(age_path) != entry.stored_checksum:
            raise InvalidArchiveError('Incorrect checksum.')
        tmp_path = self._mktemp()
        try:
            Age.decrypt(age_path, tmp_path, self.metadata.encryption_key)
        except Exception:
            raise Exception('Failed to decrypt entry.')
        age_path.unlink()
        dst_path.parent.mkdir(parents=True, exist_ok=True)
        with open(tmp_path, 'rb') as tmp_file:
            with bz2.open(tmp_file, 'rb') as src:
                with open(dst_path, 'wb') as dst:
                    copyfileobj(src, dst, _BUFFER_SIZE)
        tmp_path.unlink()
        return dst_path

    def _load_metadata(self):
        """Extract and validate the metadata."""
        meta_path, sig_path = self._zipfile.extract_metadata()
        try:
            SSH.verify(meta_path, sig_path, self.allowed_signers)
        except Exception:
            raise Exception('Failed to verify metadata signature.')
        for attempt in range(0, _MAX_ATTEMPTS):
            try:
                bz2_bytes = Age.decrypt_bytes(meta_path, self.secret_key)
                break
            except Exception:
                if attempt == _MAX_ATTEMPTS - 1:
                    raise Exception('Failed to decrypt metadata.')
        json_bytes = bz2.decompress(bz2_bytes)
        try:
            self.metadata = Metadata.parse_raw(json_bytes)
        except ValidationError as e:
            for err in e.errors():
                if err['type'] == 'value_error.unsupported_value':
                    raise InvalidArchiveError(err['msg'])
                else:
                    raise InvalidArchiveError('Invalid metadata.')
        meta_path.unlink()
        sig_path.unlink()


class IcepackWriter(IcepackBase):
    """icepack writer."""

    def __init__(self, archive_path, key_path, extra_recipients=None):
        super().__init__(archive_path, key_path)
        if self.archive_path.is_dir():
            raise Exception(f'Invalid archive path: {self.archive_path}')
        self._zipfile = Zip(self.archive_path, mode='w')
        self.metadata = Metadata(
            archive_name=self.archive_path.name,
            checksum_type=Checksum.SHA256,
            encryption=Encryption.AGE,
            encryption_key=Age.keygen()[0])
        self._index = 1
        self._recipients = [self.public_key.read_text().strip()]
        if extra_recipients is not None:
            self._recipients.extend(extra_recipients)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        failed = exc_type is not None
        self.close(silent=failed)
        if failed:
            self.archive_path.unlink()

    def add_entry(self, source, base_path):
        """Add source to the archive."""
        name = str(source.relative_to(base_path))
        if source.is_dir():
            entry = DirEntry(name=name)
        else:
            tmp_path = self._mktemp()
            with open(source, 'rb') as src:
                with bz2.open(tmp_path, 'wb') as tmp_file:
                    copyfileobj(src, tmp_file, _BUFFER_SIZE)
            age_path = self._mktemp()
            try:
                Age.encrypt(tmp_path, age_path, self.metadata.encryption_key)
            except Exception:
                raise Exception('Failed to encrypt entry.')
            tmp_path.unlink()
            stored_name = '{:08}'.format(self._index)
            entry = FileEntry(
                name=name,
                size=source.stat().st_size,
                compression=Compression.BZ2,
                stored_name=stored_name,
                stored_size=age_path.stat().st_size,
                stored_checksum=File.sha256(age_path))
            self._zipfile.add_entry(stored_name, age_path)
            self._index += 1
            age_path.unlink()
        self.metadata.entries.append(entry)

    def add_metadata(self):
        """Add the metadata file."""
        json_bytes = self.metadata.json().encode()
        bz2_bytes = bz2.compress(json_bytes)
        meta_path = self._mktemp()
        try:
            Age.encrypt_bytes(bz2_bytes, meta_path, self._recipients)
        except Exception:
            raise Exception('Failed to encrypt metadata.')
        for attempt in range(0, _MAX_ATTEMPTS):
            try:
                sig_path = SSH.sign(meta_path, self.secret_key)
                break
            except Exception:
                if attempt == _MAX_ATTEMPTS - 1:
                    raise Exception('Failed to sign metadata.')
        self._zipfile.add_metadata(meta_path, sig_path)
        meta_path.unlink()
        sig_path.unlink()


def create_archive(
        src_path,
        dst_path,
        key_path,
        extra_recipients=None,
        log=lambda msg: None):
    """Create an archive at dst_path from src_path."""
    src_path = src_path.resolve()
    dst_path = dst_path.resolve()
    if src_path.is_file():
        sources = [src_path]
    elif src_path.is_dir():
        sources = list(File.children(src_path))
        sources.sort(key=_source_key)
    else:
        raise Exception(f'Invalid source: {src_path}')
    base = src_path.parent
    with IcepackWriter(dst_path, key_path, extra_recipients=extra_recipients) as archive:  # noqa
        for source in sources:
            log(source.relative_to(base))
            archive.add_entry(source, base)
        archive.add_metadata()


def extract_archive(src_path, dst_path, key_path, log=lambda msg: None):
    """Extract the archive at src_path to dst_path, or list the content."""
    src_path = src_path.resolve()
    if dst_path:
        dst_path = dst_path.resolve()
        if not dst_path.is_dir():
            raise Exception(f'Invalid destination: {dst_path}')
    with IcepackReader(src_path, key_path) as archive:
        for entry in archive.metadata.entries:
            log(entry.name)
            if dst_path:
                archive.extract_entry(entry, dst_path)


def _source_key(path):
    """Sort key for Paths."""
    key = str(path).casefold()
    if path.is_dir:
        key += '/'
    return key
