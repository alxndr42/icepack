import bz2
import json
from pathlib import Path
from shutil import copyfileobj, rmtree

from icepack.error import InvalidArchiveError
from icepack.helper import Age, File, SSH, Zip
from icepack.meta import SECRET_KEY, PUBLIC_KEY, ALLOWED_SIGNERS


_BUFFER_SIZE = 64 * 1024
_VALID_CHECKSUM = ['sha256']
_VALID_COMPRESSION = ['bz2']
_VALID_ENCRYPTION = ['age']


# TODO Add context manager functions
class Icepack():
    """icepack archive manager."""

    def __init__(self, path, key_path, mode='r', extra_recipients=None):
        if mode not in ['r', 'w']:
            raise Exception(f'Unsupported mode: {mode}')
        if mode == 'r' and not path.is_file():
            raise Exception(f'Invalid archive path: {path}')
        elif mode == 'w' and path.is_dir():
            raise Exception(f'Invalid archive path: {path}')
        self.path = path.resolve()
        if not isinstance(key_path, Path):
            raise Exception(f'Invalid key path: {key_path}')
        self.secret_key = key_path / SECRET_KEY
        self.public_key = key_path / PUBLIC_KEY
        self.allowed_signers = key_path / ALLOWED_SIGNERS
        if not self.secret_key.is_file():
            raise Exception(f'Invalid secret key: {self.secret_key}')
        if not self.public_key.is_file():
            raise Exception(f'Invalid public key: {self.public_key}')
        if not self.allowed_signers.is_file():
            raise Exception(f'Invalid allowed_signers: {self.allowed_signers}')
        self._mode = mode
        self._temp_dir = File.mktemp(directory=True)
        if mode == 'r':
            self._zipfile = Zip(self.path)
            self._load_metadata()
        else:
            self._zipfile = Zip(self.path, mode='w')
            self.metadata = {
                'archive_name': path.name,
                'checksum_function': 'sha256',
                'encryption': 'age',
                'entry_key': Age.keygen()[0],
                'entries': [],
            }
            self._index = 1
            self._recipients = [self.public_key.read_text()]
            if extra_recipients is not None:
                self._recipients.extend(extra_recipients)

    def add_entry(self, source, base_path):
        """Add source to the archive."""
        if self._mode != 'w':
            raise Exception('Not in write mode.')
        key = '{:08}'.format(self._index)
        entry = {
            'key': key,
            'name': self._archive_name(source, base_path),
        }
        if source.is_file():
            stat = source.stat()
            entry['size'] = stat.st_size
            entry['compression'] = 'bz2'
            bz2_path = File.mktemp(parent=self._temp_dir)
            with open(source, 'rb') as src:
                with bz2.open(bz2_path, 'wb') as bz2_file:
                    copyfileobj(src, bz2_file, _BUFFER_SIZE)
            age_path = File.mktemp(parent=self._temp_dir)
            Age.encrypt(bz2_path, age_path, self.metadata['entry_key'])
            bz2_path.unlink()
            entry['stored_size'] = age_path.stat().st_size
            entry['stored_checksum'] = File.sha256(age_path)
            self._zipfile.add_entry(key, age_path)
            age_path.unlink()
        else:
            self._zipfile.add_entry(key, None)
        self.metadata['entries'].append(entry)
        self._index += 1

    def close(self):
        """Close the archive and delete all temporary files."""
        if self._mode == 'w':
            self._add_metadata()
        self._zipfile.close()
        rmtree(self._temp_dir, ignore_errors=True)

    def extract_entry(self, entry, base_path):
        """Extract entry to base_path."""
        if self._mode != 'r':
            raise Exception('Not in read mode.')
        if entry not in self.metadata['entries']:
            raise Exception('Invalid entry.')
        name = entry['name']
        entry_path = base_path.joinpath(name).resolve()
        if not str(entry_path).startswith(str(base_path)):
            raise InvalidArchiveError(f'Invalid entry name: {name}')
        if name.endswith('/'):
            entry_path.mkdir(parents=True, exist_ok=True)
            return entry_path
        age_path = self._zipfile.extract_entry(entry['key'])
        age_stat = age_path.stat()
        if age_stat.st_size != entry['stored_size']:
            raise InvalidArchiveError('Incorrect file size.')
        if File.sha256(age_path) != entry['stored_checksum']:
            raise InvalidArchiveError('Incorrect checksum.')
        bz2_path = File.mktemp(parent=self._temp_dir)
        Age.decrypt(age_path, bz2_path, self.metadata['entry_key'])
        age_path.unlink()
        entry_path.parent.mkdir(parents=True, exist_ok=True)
        with open(bz2_path, 'rb') as bz2_file:
            with bz2.open(bz2_file, 'rb') as src:
                with open(entry_path, 'wb') as dst:
                    copyfileobj(src, dst, _BUFFER_SIZE)
        bz2_path.unlink()
        return entry_path

    def _add_metadata(self):
        """Add the metadata file."""
        json_bytes = json.dumps(self.metadata).encode()
        bz2_bytes = bz2.compress(json_bytes)
        meta_path = File.mktemp(parent=self._temp_dir)
        Age.encrypt_bytes(bz2_bytes, meta_path, self._recipients)
        sig_path = SSH.sign(meta_path, self.secret_key)
        self._zipfile.add_metadata(meta_path, sig_path)
        meta_path.unlink()
        sig_path.unlink()

    def _load_metadata(self):
        """Extract and validate the metadata."""
        meta_path, sig_path = self._zipfile.extract_metadata()
        SSH.verify(meta_path, sig_path, self.allowed_signers)
        bz2_bytes = Age.decrypt_bytes(meta_path, self.secret_key)
        json_bytes = bz2.decompress(bz2_bytes)
        metadata = json.loads(json_bytes)
        self._validate_metadata(metadata)
        self.metadata = metadata
        meta_path.unlink()
        sig_path.unlink()

    @staticmethod
    def _archive_name(source, base_path):
        """Return the in-archive filename for source."""
        result = str(source.relative_to(base_path))
        if source.is_dir():
            result += '/'
        return result

    # TODO Use Pydantic or a schema
    @staticmethod
    def _validate_metadata(metadata):
        """Check metadata for validity."""
        if type(metadata) != dict:
            raise InvalidArchiveError('Invalid metadata.')
        if type(metadata.get('archive_name')) != str:
            raise InvalidArchiveError('Invalid metadata.')
        checksum_function = metadata.get('checksum_function')
        if type(checksum_function) != str:
            raise InvalidArchiveError('Invalid metadata.')
        if checksum_function not in _VALID_CHECKSUM:
            raise InvalidArchiveError(f'Unsupported checksum function: {checksum_function}')  # noqa
        encryption = metadata.get('encryption')
        if type(encryption) != str:
            raise InvalidArchiveError('Invalid metadata.')
        if encryption not in _VALID_ENCRYPTION:
            raise InvalidArchiveError(f'Unsupported encryption: {encryption}')  # noqa
        if type(metadata.get('entry_key')) != str:
            raise InvalidArchiveError('Invalid metadata.')
        if type(metadata.get('entries')) != list:
            raise InvalidArchiveError('Invalid metadata.')
        for entry in metadata.get('entries'):
            if type(entry) != dict:
                raise InvalidArchiveError('Invalid metadata.')
            if type(entry.get('key')) != str:
                raise InvalidArchiveError('Invalid metadata.')
            if type(entry.get('name')) != str:
                raise InvalidArchiveError('Invalid metadata.')
            if entry['name'].endswith('/'):
                continue
            compression = entry.get('compression')
            if type(compression) != str:
                raise InvalidArchiveError('Invalid metadata.')
            if compression not in _VALID_COMPRESSION:
                raise InvalidArchiveError(f'Unsupported compression: {compression}')  # noqa
            if type(entry.get('stored_size')) != int:
                raise InvalidArchiveError('Invalid metadata.')
            if type(entry.get('stored_checksum')) != str:
                raise InvalidArchiveError('Invalid metadata.')


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
    archive = Icepack(
        dst_path,
        key_path,
        mode='w',
        extra_recipients=extra_recipients)
    try:
        for source in sources:
            log(source.relative_to(base))
            archive.add_entry(source, base)
    finally:
        archive.close()


def extract_archive(src_path, dst_path, key_path, log=lambda msg: None):
    """Extract the archive at src_path to dst_path."""
    src_path = src_path.resolve()
    dst_path = dst_path.resolve()
    if not dst_path.is_dir():
        raise Exception(f'Invalid destination: {dst_path}')
    archive = Icepack(src_path, key_path)
    try:
        for entry in archive.metadata['entries']:
            log(entry['name'])
            archive.extract_entry(entry, dst_path)
    finally:
        archive.close()


def _source_key(path):
    """Sort key for Paths."""
    key = str(path).casefold()
    if path.is_dir:
        key += '/'
    return key
