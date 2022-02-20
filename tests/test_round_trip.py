from click.testing import CliRunner

from icepack.cli import icepack
from icepack.helper import File

from helper import dst_path, key_path, src_path, zip_path


def test_round_trip_directory(src_path, dst_path, zip_path, key_path):
    """Test creation and extraction of a directory."""
    # Create archive
    args = ['-c', str(key_path), 'create', str(src_path), str(zip_path)]
    runner = CliRunner()
    result = runner.invoke(icepack, args)
    assert result.exit_code == 0
    # Extract archive
    args = ['-c', str(key_path), 'extract', str(zip_path), str(dst_path)]
    runner = CliRunner()
    result = runner.invoke(icepack, args)
    assert result.exit_code == 0
    # Compare directories
    for src in File.children(src_path):
        dst = dst_path / src.relative_to(src_path.parent)
        compare_paths(src, dst)


def test_round_trip_file(src_path, dst_path, zip_path, key_path):
    """Test creation and extraction of a file."""
    file_path = src_path / 'foo'
    # Create archive
    args = ['-c', str(key_path), 'create', str(file_path), str(zip_path)]
    runner = CliRunner()
    result = runner.invoke(icepack, args)
    assert result.exit_code == 0
    # Extract archive
    args = ['-c', str(key_path), 'extract', str(zip_path), str(dst_path)]
    runner = CliRunner()
    result = runner.invoke(icepack, args)
    assert result.exit_code == 0
    # Compare files
    compare_paths(file_path, dst_path / 'foo')


def test_without_compression(src_path, dst_path, zip_path, key_path):
    """Test with "none" compression."""
    # Create archive
    args = [
        '-c', str(key_path),
        'create', '--compression', 'none',
        str(src_path), str(zip_path)]
    runner = CliRunner()
    result = runner.invoke(icepack, args)
    assert result.exit_code == 0
    # Extract archive
    args = ['-c', str(key_path), 'extract', str(zip_path), str(dst_path)]
    runner = CliRunner()
    result = runner.invoke(icepack, args)
    assert result.exit_code == 0
    # Compare directories
    for src in File.children(src_path):
        dst = dst_path / src.relative_to(src_path.parent)
        compare_paths(src, dst)


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
