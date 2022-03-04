from zipfile import ZipFile

import pytest

from icepack.error import InvalidArchiveError
from icepack.helper import File, Zip

from helper import src_path, dst_path, zip_path


@pytest.fixture
def meta_path(dst_path):
    path = dst_path / 'metadata'
    path.write_text('metadata')
    return path


@pytest.fixture
def zip_file(zip_path):
    return Zip(zip_path, mode='w')


class TestWriteMode:
    """Test write operations."""

    def test_write_mode(self, src_path, meta_path, zip_file):
        zip_file.add_entry('foo', src_path / 'foo')
        zip_file.add_entry('bar', None)
        zip_file.add_metadata(meta_path, meta_path)
        zip_file.close()
        with ZipFile(zip_file.path) as zip_file:
            assert zip_file.testzip() is None
            infolist = zip_file.infolist()
        names = [i.filename for i in infolist]
        assert names == ['foo', 'bar', 'metadata']
        sizes = [i.file_size for i in infolist]
        assert sizes == [4, 0, 8]

    def test_no_metadata(self, src_path, zip_file):
        zip_file.add_entry('foo', src_path / 'foo')
        with pytest.raises(InvalidArchiveError):
            zip_file.close()

    def test_add_entry_twice(self, src_path, zip_file):
        zip_file.add_entry('foo', src_path / 'foo')
        with pytest.raises(InvalidArchiveError):
            zip_file.add_entry('foo', src_path / 'foo')

    def test_add_metadata_twice(self, meta_path, zip_file):
        zip_file.add_metadata(meta_path, meta_path)
        with pytest.raises(InvalidArchiveError):
            zip_file.add_metadata(meta_path, meta_path)

    def test_add_entry_after_metdata(self, meta_path, zip_file):
        zip_file.add_entry('foo', meta_path)
        zip_file.add_metadata(meta_path, meta_path)
        with pytest.raises(InvalidArchiveError):
            zip_file.add_entry('bar', meta_path)

    def test_context_manager(self, meta_path, zip_path):
        with Zip(zip_path, mode='w') as zip_file:
            zip_file.add_entry('foo', meta_path)
            zip_file.add_metadata(meta_path, meta_path)
            tempdir = zip_file._tempdir
            assert tempdir.exists()
        assert not tempdir.exists()
        assert zip_path.exists()


class TestReadMode:
    """Test read operations."""

    def test_read_mode(self, shared_datadir):
        path = shared_datadir / 'zips' / 'zip-helper.zip'
        zip_file = Zip(path)
        path = zip_file.extract_entry('foo')
        assert File.sha256(path) == 'b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c'  # noqa
        path, sig = zip_file.extract_metadata()
        assert File.sha256(path) == '45447b7afbd5e544f7d0f1df0fccd26014d9850130abd3f020b89ff96b82079f'  # noqa
        assert File.sha256(sig) == '45447b7afbd5e544f7d0f1df0fccd26014d9850130abd3f020b89ff96b82079f'  # noqa
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
            tempdir = zip_file._tempdir
            assert tempdir.exists()
        assert not tempdir.exists()
