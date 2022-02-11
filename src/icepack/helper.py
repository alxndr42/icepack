import hashlib
import os
from pathlib import Path
from shutil import copyfileobj, rmtree
import subprocess
import tempfile

from zipfile import ZIP_STORED, is_zipfile, ZipFile, ZipInfo

from icepack.error import InvalidArchiveError
from icepack.meta import NAME


_BUFFER_SIZE = 64 * 1024
_PUBLIC_KEY_PREFIX = 'age'
_SECRET_KEY_PREFIX = 'AGE-SECRET-KEY-'


class Age():
    """age encryption helpers."""

    @staticmethod
    def keygen():
        """Return a (secret_key, public_key) from age-keygen."""
        secret_key = None
        public_key = None
        result = subprocess.run(
            ['age-keygen'],
            capture_output=True,
            text=True,
            timeout=5,
            check=True)
        for line in result.stdout.split('\n'):
            if line.startswith(_SECRET_KEY_PREFIX):
                secret_key = line.strip()
                break
        else:
            raise Exception('No secret key in age-keygen output.')
        result = subprocess.run(
            ['age-keygen', '-y'],
            input=secret_key,
            capture_output=True,
            text=True,
            timeout=5,
            check=True)
        if result.stdout.startswith(_PUBLIC_KEY_PREFIX):
            public_key = result.stdout.strip()
        else:
            raise Exception('No public key in age-keygen output.')
        return secret_key, public_key

    @staticmethod
    def encrypt(src_path, dst_path, secret_key):
        """Encrypt src_path to dst_path, pass secret_key to age STDIN."""
        subprocess.run(
            ['age', '-e', '-i', '-', '-o', str(dst_path), str(src_path)],
            input=secret_key,
            text=True,
            check=True)

    @staticmethod
    def decrypt(src_path, dst_path, secret_key):
        """Decrypt src_path to dst_path, pass secret_key to age STDIN."""
        subprocess.run(
            ['age', '-d', '-i', '-', '-o', str(dst_path), str(src_path)],
            input=secret_key,
            text=True,
            check=True)


class File():
    """File operation helpers."""

    @staticmethod
    def children(path):
        """Return the Paths of all files and directories under path."""
        for child in path.iterdir():
            if child.is_file():
                yield child
            elif child.is_dir():
                yield child
                yield from File.children(child)

    @staticmethod
    def mktemp(directory=False, parent=None):
        """Return the Path of a new temporary file or directory."""
        if directory:
            tmpfile = tempfile.mkdtemp(prefix=NAME, dir=parent)
        else:
            fd, tmpfile = tempfile.mkstemp(prefix=NAME, dir=parent)
            os.close(fd)
        return Path(tmpfile)

    @staticmethod
    def sha256(path):
        """Return the file's SHA-256 digest."""
        d = hashlib.sha256()
        with open(path, 'rb') as src:
            while True:
                chunk = src.read(_BUFFER_SIZE)
                if not chunk:
                    break
                d.update(chunk)
        return d.hexdigest()


class Zip():
    """Zip archive helper."""

    def __init__(self, path, mode='r'):
        if mode not in ['r', 'w']:
            raise Exception(f'Unsupported mode: {mode}')
        if mode == 'r' and not is_zipfile(path):
            raise InvalidArchiveError(f'{path} is not a Zip file.')
        self.path = path.resolve()
        self._mode = mode
        self._zipfile = ZipFile(path, mode=mode)
        self._temp_dir = File.mktemp(directory=True)
        if mode == 'r':
            infolist = self._zipfile.infolist()
            self._validate_infolist(infolist)
            self._entries = {i.filename: i for i in infolist}
        else:
            self._entries = {}

    def add_entry(self, key, path):
        """Add an entry with the content of path (may be None)."""
        if self._mode != 'w':
            raise Exception('Not in write mode.')
        if key in self._entries:
            raise InvalidArchiveError(f'Duplicate key: {key}')
        if 'metadata' in self._entries:
            raise InvalidArchiveError(f'Metadata file already added.')
        info = ZipInfo(key)
        self._entries[key] = info
        with self._zipfile.open(info, mode='w', force_zip64=True) as dst:
            if path is None:
                return
            with open(path, 'rb') as src:
                copyfileobj(src, dst, _BUFFER_SIZE)

    def add_metadata(self, path):
        """Add the metadata file."""
        if self._mode != 'w':
            raise Exception('Not in write mode.')
        if 'metadata' in self._entries:
            raise InvalidArchiveError(f'Metadata file already added.')
        info = ZipInfo('metadata')
        self._entries['metadata'] = info
        with self._zipfile.open(info, mode='w', force_zip64=True) as dst:
            with open(path, 'rb') as src:
                copyfileobj(src, dst, _BUFFER_SIZE)

    def close(self):
        """Close the Zip archive and delete all temporary files."""
        self._zipfile.close()
        rmtree(self._temp_dir, ignore_errors=True)
        if 'metadata' not in self._entries:
            raise InvalidArchiveError(f'No metadata file added.')

    def extract_entry(self, key):
        """Extract an entry and return its temporary Path."""
        if self._mode != 'r':
            raise Exception('Not in read mode.')
        if key not in self._entries:
            raise Exception(f'Invalid key: {key}')
        info = self._entries[key]
        path = Path(self._zipfile.extract(info, path=self._temp_dir))
        return path

    def extract_metadata(self):
        """Extract the metadata file and return its temporary Path."""
        if self._mode != 'r':
            raise Exception('Not in read mode.')
        info = self._entries['metadata']
        path = Path(self._zipfile.extract(info, path=self._temp_dir))
        return path

    @staticmethod
    def _validate_infolist(infolist):
        """Check the infolist for validity."""
        if len(infolist) == 0:
            raise InvalidArchiveError('Empty Zip.')
        if infolist[-1].filename != 'metadata':
            raise InvalidArchiveError('No metadata file at end of Zip.')
        filenames = {i.filename for i in infolist}
        if len(filenames) != len(infolist):
            raise InvalidArchiveError(f'Duplicate filename in Zip.')
        if any(map(lambda i: i.compress_type != ZIP_STORED, infolist)):
            raise InvalidArchiveError('Non-STORED Zip entry.')
