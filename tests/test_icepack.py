import pytest

from icepack import IcepackWriter
from icepack.error import InvalidArchiveError

from helper import key_path, src_path, zip_path


@pytest.fixture
def archive_w(zip_path, key_path):
    return IcepackWriter(zip_path, key_path)


class TestWriteMode:
    """Test write operations."""

    def test_with_context(self, zip_path, key_path, src_path):
        with IcepackWriter(zip_path, key_path) as archive:
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
