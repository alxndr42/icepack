from icepack import extract_archive

from helper import key_path


def test_v0_1_0(shared_datadir, key_path):
    """Test extracting a v0.1.0 archive."""
    src_path = shared_datadir / 'zips' / 'icepack-v0.1.0.zip'
    dst_path = shared_datadir / 'dst'
    extract_archive(src_path, dst_path, key_path)
    foo_path = dst_path / 'src' / 'foo'
    assert foo_path.read_text().strip() == 'foo'
