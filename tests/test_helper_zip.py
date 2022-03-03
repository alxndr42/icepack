from zipfile import ZipFile

import pytest

from icepack.error import InvalidArchiveError
from icepack.helper import File, Zip

from helper import src_path, zip_path


@pytest.fixture
def zip_file(zip_path):
    return Zip(zip_path, mode='w')


class TestWriteMode:
    """Test write operations."""

    def test_write_mode(self, src_path, zip_file):
        zip_file.add_entry('foo', src_path / 'foo')
        zip_file.add_entry('bar', None)
        meta_path = src_path / 'qux' / 'quux'
        zip_file.add_metadata(meta_path, meta_path)
        zip_file.close()
        with ZipFile(zip_file.path) as zip_file:
            assert zip_file.testzip() is None
            infolist = zip_file.infolist()
        names = [i.filename for i in infolist]
        assert names == ['foo', 'bar', 'metadata']
        sizes = [i.file_size for i in infolist]
        assert sizes == [4, 0, 5]

    def test_add_entry_twice(self, src_path, zip_file):
        zip_file.add_entry('foo', src_path / 'foo')
        with pytest.raises(InvalidArchiveError):
            zip_file.add_entry('foo', src_path / 'foo')

    def test_add_metadata_twice(self, src_path, zip_file):
        foo = src_path / 'foo'
        zip_file.add_metadata(foo, foo)
        with pytest.raises(InvalidArchiveError):
            zip_file.add_metadata(foo, foo)

    def test_add_entry_after_metdata(self, src_path, zip_file):
        foo = src_path / 'foo'
        zip_file.add_entry('foo', foo)
        zip_file.add_metadata(foo, foo)
        with pytest.raises(InvalidArchiveError):
            zip_file.add_entry('bar', foo)

    def test_context_manager(self, src_path, zip_path):
        with Zip(zip_path, mode='w') as zip_file:
            zip_file.add_entry('foo', src_path / 'foo')
            meta_path = src_path / 'qux' / 'quux'
            zip_file.add_metadata(meta_path, meta_path)
            temp_dir = zip_file._temp_dir
            assert temp_dir.exists()
        assert not temp_dir.exists()
        assert zip_path.exists()


class TestReadMode:
    """Test read operations."""

    def test_read_mode(self, shared_datadir):
        path = shared_datadir / 'zips' / 'zip-helper.zip'
        zip_file = Zip(path)
        path = zip_file.extract_entry('foo')
        assert File.sha256(path) == 'b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c'  # noqa
        path, sig = zip_file.extract_metadata()
        assert File.sha256(path) == '49ae93732fcf8d63fe1cce759664982dbd5b23161f007dba8561862adc96d063'  # noqa
        assert File.sha256(sig) == '49ae93732fcf8d63fe1cce759664982dbd5b23161f007dba8561862adc96d063'  # noqa
        zip_file.close()

    def test_regular_zip(self, shared_datadir):
        path = shared_datadir / 'zips' / 'infozip.zip'
        with pytest.raises(InvalidArchiveError):
            zip_file = Zip(path)

    def test_context_manager(self, shared_datadir):
        path = shared_datadir / 'zips' / 'zip-helper.zip'
        with Zip(path) as zip_file:
            path = zip_file.extract_entry('foo')
            assert File.sha256(path) == 'b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c'  # noqa
            temp_dir = zip_file._temp_dir
            assert temp_dir.exists()
        assert not temp_dir.exists()
