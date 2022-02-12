from icepack import create_archive, extract_archive
from icepack.helper import File

from helper import key_path


def test_round_trip_directory(shared_datadir, key_path):
    """Test creation and extraction of a directory."""
    src_path = shared_datadir / 'src'
    dst_path = shared_datadir / 'dst'
    zip_path = shared_datadir / 'dst' / 'test.zip'
    create_archive(src_path, zip_path, key_path)
    extract_archive(zip_path, dst_path, key_path)
    for src in File.children(src_path):
        dst = dst_path / src.relative_to(shared_datadir)
        compare_paths(src, dst)


def test_round_trip_file(shared_datadir, key_path):
    """Test creation and extraction of a file."""
    src_path = shared_datadir / 'src' / 'foo'
    dst_path = shared_datadir / 'dst'
    zip_path = shared_datadir / 'dst' / 'test.zip'
    create_archive(src_path, zip_path, key_path)
    extract_archive(zip_path, dst_path, key_path)
    compare_paths(src_path, dst_path / 'foo')


def compare_paths(src, dst):
    """Assert that src and dst refer to identical objects."""
    assert src.exists()
    assert dst.exists()
    if src.is_file():
        assert dst.is_file()
        assert File.sha256(src) == File.sha256(dst)
    elif src.is_dir():
        assert dst.is_dir()
    else:
        raise Exception(f'Unsupported type: {src}')
