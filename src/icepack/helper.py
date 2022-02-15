import hashlib
import os
from pathlib import Path
from shutil import copyfileobj, rmtree, which
import subprocess
import tempfile

from zipfile import ZIP_STORED, is_zipfile, ZipFile, ZipInfo

from icepack.error import InvalidArchiveError
from icepack.meta import NAME, SECRET_KEY, PUBLIC_KEY, ALLOWED_SIGNERS


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

    @staticmethod
    def encrypt_bytes(data, dst_path, recipients):
        """Encrypt data via age STDIN."""
        args = ['age', '-e', '-o', str(dst_path)]
        for recipient in recipients:
            args.extend(['-r', recipient])
        subprocess.run(args, input=data, check=True)

    @staticmethod
    def decrypt_bytes(src_path, identity):
        """Decrypt src_path via age STDOUT."""
        result = subprocess.run(
            ['age', '-d', '-i', str(identity), str(src_path)],
            capture_output=True,
            check=True)
        return result.stdout

    @staticmethod
    def version():
        """Return the age version and age-keygen presence as a tuple."""
        age_version = None
        if which('age'):
            result = subprocess.run(
                ['age', '--version'],
                capture_output=True,
                text=True,
                timeout=5)
            if result.returncode == 0:
                age_version = result.stdout.strip()
        age_keygen = bool(which('age-keygen'))
        return age_version, age_keygen


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


class SSH():
    """ssh-keygen helpers."""

    @staticmethod
    def keygen(key_path):
        """Generate the keys and allowed_signers."""
        secret_key = key_path / SECRET_KEY
        if secret_key.is_file():
            raise Exception(f'{secret_key} already exists.')
        subprocess.run(
            [
                'ssh-keygen',
                '-t', 'ed25519',
                '-C', '',
                '-f', secret_key,
                '-q'
            ],
            timeout=5,
            check=True)
        public_key = (key_path / PUBLIC_KEY).read_text()
        allowed_signers = f'{NAME} {public_key}'
        (key_path / ALLOWED_SIGNERS).write_text(allowed_signers)

    @staticmethod
    def sign(data_path, secret_key):
        """Sign data_path with ssh-keygen."""
        subprocess.run(
            [
                'ssh-keygen',
                '-Y', 'sign',
                '-f', secret_key,
                '-n', NAME,
                '-q',
                data_path
            ],
            check=True)
        sig_path = data_path.parent / (data_path.name + '.sig')
        if not sig_path.is_file():
            raise Exception(f'{sig_path} not found.')
        return sig_path

    @staticmethod
    def verify(data_path, sig_path, allowed_signers):
        """Verify the signature with ssh-keygen."""
        subprocess.run(
            [
                'ssh-keygen',
                '-Y', 'verify',
                '-f', allowed_signers,
                '-I', NAME,
                '-n', NAME,
                '-s', sig_path,
                '-q'
            ],
            input=data_path.read_bytes(),
            check=True)

    @staticmethod
    def version():
        """Return the SSH version and ssh-keygen presence as a tuple."""
        ssh_version = None
        if which('ssh'):
            result = subprocess.run(
                ['ssh', '-V'],
                capture_output=True,
                text=True,
                timeout=5)
            if result.returncode == 0:
                ssh_version = result.stderr.strip()
                ssh_version = ssh_version.split(' ')[0]
        ssh_keygen = bool(which('ssh-keygen'))
        return ssh_version, ssh_keygen


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

    def add_metadata(self, data_path, sig_path):
        """Add the metadata and signature files."""
        if self._mode != 'w':
            raise Exception('Not in write mode.')
        if 'metadata' in self._entries:
            raise InvalidArchiveError(f'Metadata file already added.')
        info = ZipInfo('metadata')
        info.comment = sig_path.read_bytes()
        self._entries['metadata'] = info
        with self._zipfile.open(info, mode='w', force_zip64=True) as dst:
            with open(data_path, 'rb') as src:
                copyfileobj(src, dst, _BUFFER_SIZE)

    def close(self, silent=False):
        """Close the Zip archive and delete all temporary files."""
        rmtree(self._temp_dir, ignore_errors=True)
        try:
            self._zipfile.close()
        except Exception:
            if not silent:
                raise
        if 'metadata' not in self._entries and not silent:
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
        """Return a tuple of temporary Paths for metadata and signature."""
        if self._mode != 'r':
            raise Exception('Not in read mode.')
        info = self._entries['metadata']
        meta_path = Path(self._zipfile.extract(info, path=self._temp_dir))
        sig_path = meta_path.parent / (meta_path.name + '.sig')
        sig_path.write_bytes(info.comment)
        return meta_path, sig_path

    @staticmethod
    def _validate_infolist(infolist):
        """Check the infolist for validity."""
        if len(infolist) == 0:
            raise InvalidArchiveError('Empty Zip.')
        if infolist[-1].filename != 'metadata':
            raise InvalidArchiveError('No metadata file at end of Zip.')
        if infolist[-1].comment is None:
            raise InvalidArchiveError('No metadata signature.')
        filenames = {i.filename for i in infolist}
        if len(filenames) != len(infolist):
            raise InvalidArchiveError(f'Duplicate filename in Zip.')
        if any(map(lambda i: i.compress_type != ZIP_STORED, infolist)):
            raise InvalidArchiveError('Non-STORED Zip entry.')
