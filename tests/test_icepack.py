import pytest

from icepack import Icepack
from icepack.error import InvalidArchiveError


@pytest.fixture
def src_path(shared_datadir):
    return shared_datadir / 'src'


@pytest.fixture
def archive_w(shared_datadir):
    zip_path = shared_datadir / 'dst' / 'test.zip'
    key_path = shared_datadir / 'keys'
    return Icepack(zip_path, key_path, mode='w')


class TestWriteMode:
    """Test write operations."""

    def test_with_context(self, shared_datadir, src_path):
        zip_path = shared_datadir / 'dst' / 'test.zip'
        key_path = shared_datadir / 'keys'
        with Icepack(zip_path, key_path, mode='w') as archive:
            archive.add_entry(src_path / 'foo', src_path)
            archive.add_metadata()

    def test_without_context(self, archive_w, src_path):
        archive_w.add_entry(src_path / 'foo', src_path)
        archive_w.add_metadata()
        archive_w.close()

    def test_missing_metadata(self, archive_w, src_path):
        archive_w.add_entry(src_path / 'foo', src_path)
        with pytest.raises(InvalidArchiveError):
            archive_w.close()

    def test_double_metadata(self, archive_w, src_path):
        archive_w.add_entry(src_path / 'foo', src_path)
        archive_w.add_metadata()
        with pytest.raises(InvalidArchiveError):
            archive_w.add_metadata()

    def test_late_entry(self, archive_w, src_path):
        archive_w.add_entry(src_path / 'foo', src_path)
        archive_w.add_metadata()
        with pytest.raises(InvalidArchiveError):
            archive_w.add_entry(src_path / 'bar', src_path)
