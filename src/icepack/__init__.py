import bz2
import gzip
import json
import os
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

    def __init__(self, archive_path, key_path, mode=False, mtime=False):
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
        self._mode = mode
        self._mtime = mtime

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

    def __init__(self, archive_path, key_path, mode=False, mtime=False):
        super().__init__(archive_path, key_path, mode=mode, mtime=mtime)
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
        """Extract entry to base_path and return its Path."""
        if entry not in self.metadata.entries:
            raise Exception('Invalid entry.')
        dst_path = base_path.joinpath(entry.name).resolve()
        if not str(dst_path).startswith(str(base_path)):
            raise InvalidArchiveError(f'Invalid entry name: {entry.name}')
        if entry.is_dir():
            dst_path.mkdir(parents=True, exist_ok=True)
            if self._mode and entry.mode is not None:
                dst_path.chmod(entry.mode)
            if self._mtime and entry.mtime is not None:
                os.utime(dst_path, ns=(entry.mtime, entry.mtime))
            return dst_path
        age_path = self._zipfile.extract_entry(entry.stored_name)
        age_stat = age_path.stat()
        if age_stat.st_size != entry.stored_size:
            raise InvalidArchiveError('Incorrect file size.')
        if File.sha256(age_path) != entry.stored_checksum:
            raise InvalidArchiveError('Incorrect checksum.')
        dst_path.parent.mkdir(parents=True, exist_ok=True)
        if entry.compression == Compression.NONE:
            self._decrypt_path(age_path, dst_path)
            age_path.unlink()
        else:
            tmp_path = self._mktemp()
            self._decrypt_path(age_path, tmp_path)
            age_path.unlink()
            self._uncompress_path(tmp_path, dst_path, entry.compression)
            tmp_path.unlink()
        if self._mode and entry.mode is not None:
            dst_path.chmod(entry.mode)
        if self._mtime and entry.mtime is not None:
            os.utime(dst_path, ns=(entry.mtime, entry.mtime))
        return dst_path

    def _decrypt_path(self, src_path, dst_path):
        """Decrypt src_path to dst_path."""
        try:
            Age.decrypt(src_path, dst_path, self.metadata.encryption_key)
        except Exception:
            raise Exception('Failed to decrypt entry.')

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

    def _uncompress_path(self, src_path, dst_path, compression):
        """Uncompressed src_path to dst_path."""
        with open(dst_path, 'wb') as dst:
            with open(src_path, 'rb') as src_file:
                if compression == Compression.BZ2:
                    with bz2.open(src_file, 'rb') as src:
                        copyfileobj(src, dst, _BUFFER_SIZE)
                elif compression == Compression.GZ:
                    with gzip.open(src_file, 'rb') as src:
                        copyfileobj(src, dst, _BUFFER_SIZE)
                else:
                    raise Exception('Unsupported compression.')


class IcepackWriter(IcepackBase):
    """icepack writer."""

    def __init__(
            self,
            archive_path,
            key_path,
            comment=None,
            compression=Compression.GZ,
            mode=False,
            mtime=False,
            recipients=None):
        super().__init__(archive_path, key_path, mode=mode, mtime=mtime)
        if self.archive_path.is_dir():
            raise Exception(f'Invalid archive path: {self.archive_path}')
        self._zipfile = Zip(self.archive_path, mode='w')
        self.metadata = Metadata(
            archive_name=self.archive_path.name,
            comment=comment,
            checksum_type=Checksum.SHA256,
            encryption=Encryption.AGE,
            encryption_key=Age.keygen()[0])
        self._index = 1
        self._compression = compression
        if recipients:
            self._recipients = recipients
        else:
            self._recipients = [self.public_key.read_text().strip()]

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
        source_stat = source.stat()
        if source.is_dir():
            entry = DirEntry(name=name)
        else:
            if self._compression == Compression.NONE:
                age_path = self._encrypt_path(source)
            else:
                tmp_path = self._compress_path(source)
                age_path = self._encrypt_path(tmp_path)
                tmp_path.unlink()
            stored_name = '{:08}'.format(self._index)
            entry = FileEntry(
                name=name,
                size=source_stat.st_size,
                compression=self._compression,
                stored_name=stored_name,
                stored_size=age_path.stat().st_size,
                stored_checksum=File.sha256(age_path))
            self._zipfile.add_entry(stored_name, age_path)
            self._index += 1
            age_path.unlink()
        if self._mode:
            entry.mode = source_stat.st_mode & 0o7777
        if self._mtime:
            entry.mtime = source_stat.st_mtime_ns
        self.metadata.entries.append(entry)

    def add_metadata(self):
        """Add the metadata file."""
        json_bytes = self.metadata.json(exclude_none=True).encode()
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

    def _compress_path(self, src_path):
        """Return the temporary Path of the compressed src_path."""
        tmp_path = self._mktemp()
        with open(src_path, 'rb') as src:
            if self._compression == Compression.BZ2:
                with bz2.open(tmp_path, 'wb') as dst:
                    copyfileobj(src, dst, _BUFFER_SIZE)
            elif self._compression == Compression.GZ:
                with gzip.open(tmp_path, 'wb') as dst:
                    copyfileobj(src, dst, _BUFFER_SIZE)
            else:
                raise Exception('Unsupported compression.')
        return tmp_path

    def _encrypt_path(self, src_path):
        """Return the temporary Path of the encrypted src_path."""
        tmp_path = self._mktemp()
        try:
            Age.encrypt(src_path, tmp_path, self.metadata.encryption_key)
        except Exception:
            raise Exception('Failed to encrypt entry.')
        return tmp_path


def create_archive(
        src_path,
        dst_path,
        key_path,
        comment=None,
        compression=Compression.GZ,
        mode=False,
        mtime=False,
        recipients=None,
        log=lambda msg: None):
    """Convenience function for archive creation."""
    src_path = src_path.resolve()
    dst_path = dst_path.resolve()
    base_path = src_path.parent
    if src_path.is_file():
        sources = [src_path]
    elif src_path.is_dir():
        sources = list(File.children(src_path))
        sources.sort(key=_sort_key)
    else:
        raise Exception(f'Invalid source: {src_path}')
    if recipients is not None:
        public_key = (key_path / PUBLIC_KEY).read_text().strip()
        signers = SSH.get_signers(key_path)
        aliases = {alias: key for key, alias in signers if alias is not None}
        resolved = list(map(lambda r: aliases.get(r, r), recipients))
        resolved.insert(0, public_key)
        recipients = resolved
    if recipients is not None:
        for r in recipients:
            if not r.startswith('ssh-'):
                raise Exception(f'Invalid recipient: {r}')
    kwargs = {
        'comment': comment,
        'compression': compression,
        'mode': mode,
        'mtime': mtime,
        'recipients': recipients,
    }
    with IcepackWriter(dst_path, key_path, **kwargs) as archive:
        for source in sources:
            log(source.relative_to(base_path))
            archive.add_entry(source, base_path)
        archive.add_metadata()


def extract_archive(
        src_path,
        dst_path,
        key_path,
        mode=False,
        mtime=False,
        log=lambda msg: None):
    """Convenience function for archive extraction."""
    src_path = src_path.resolve()
    dst_path = dst_path.resolve()
    if not dst_path.is_dir():
        raise Exception(f'Invalid destination: {dst_path}')
    kwargs = {
        'mode': mode,
        'mtime': mtime,
    }
    with IcepackReader(src_path, key_path, **kwargs) as archive:
        if archive.metadata.comment:
            log(f'Comment: {archive.metadata.comment}')
        for entry in archive.metadata.entries:
            log(entry.name)
            archive.extract_entry(entry, dst_path)
        if mtime:
            # Fix directory mtimes
            dirs = [e for e in archive.metadata.entries if e.is_dir()]
            for d in dirs:
                archive.extract_entry(d, dst_path)


def _sort_key(path):
    """Sort key for Paths."""
    key = str(path).casefold()
    if path.is_dir:
        key += '/'
    return key
