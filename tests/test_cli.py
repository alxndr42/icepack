import os

from click.testing import CliRunner

from icepack.cli import icepack
from icepack.helper import File
from icepack.meta import NAME, VERSION, SECRET_KEY, PUBLIC_KEY

from helper import dst_path, key_path, src_path, zip_path


def test_init(dst_path):
    """Test init command."""
    secret_key = dst_path / SECRET_KEY
    assert not secret_key.is_file()
    args = ['-c', str(dst_path), 'init']
    run_cli(args)
    assert secret_key.is_file()


def test_init_existing_keys(key_path):
    """Test init command on existing keys."""
    secret_path = key_path / SECRET_KEY
    secret_key = secret_path.read_text()
    args = ['-c', str(key_path), 'init']
    run_cli(args, exit_code=1)
    assert secret_path.read_text() == secret_key


def test_bz2_compression(src_path, dst_path, zip_path, key_path):
    """Test round-trip with "bz2" compression."""
    # Create archive
    args = [
        '-c', str(key_path),
        'create',
        '--compression', 'bz2',
        str(src_path), str(zip_path)]
    run_cli(args)
    # Extract archive
    args = ['-c', str(key_path), 'extract', str(zip_path), str(dst_path)]
    run_cli(args)
    # Compare directories
    for src in File.children(src_path):
        dst = dst_path / src.relative_to(src_path.parent)
        compare_paths(src, dst)


def test_gz_compression(src_path, dst_path, zip_path, key_path):
    """Test round-trip with "gz" compression."""
    # Create archive
    args = [
        '-c', str(key_path),
        'create',
        '--compression', 'gz',
        str(src_path), str(zip_path)]
    run_cli(args)
    # Extract archive
    args = ['-c', str(key_path), 'extract', str(zip_path), str(dst_path)]
    run_cli(args)
    # Compare directories
    for src in File.children(src_path):
        dst = dst_path / src.relative_to(src_path.parent)
        compare_paths(src, dst)


def test_none_compression(src_path, dst_path, zip_path, key_path):
    """Test round-trip with "none" compression."""
    # Create archive
    args = [
        '-c', str(key_path),
        'create',
        '--compression', 'none',
        str(src_path), str(zip_path)]
    run_cli(args)
    # Extract archive
    args = ['-c', str(key_path), 'extract', str(zip_path), str(dst_path)]
    run_cli(args)
    # Compare directories
    for src in File.children(src_path):
        dst = dst_path / src.relative_to(src_path.parent)
        compare_paths(src, dst)


def test_round_trip_file(src_path, dst_path, zip_path, key_path):
    """Test creation and extraction of a file."""
    file_path = src_path / 'foo'
    # Create archive
    args = ['-c', str(key_path), 'create', str(file_path), str(zip_path)]
    run_cli(args)
    # Extract archive
    args = ['-c', str(key_path), 'extract', str(zip_path), str(dst_path)]
    run_cli(args)
    # Compare files
    compare_paths(file_path, dst_path / 'foo')


def test_comment(src_path, dst_path, zip_path, key_path):
    """Test creation and extraction with --comment."""
    # Create archive
    args = [
        '-c', str(key_path),
        'create',
        str(src_path),
        str(zip_path),
        '--comment', 'Hello, World!'
    ]
    run_cli(args)
    # Extract archive
    args = [
        '-c', str(key_path),
        'extract',
        str(zip_path),
        str(dst_path)
    ]
    result = run_cli(args)
    # Check for comment
    assert 'Hello, World!' in result.stdout


def test_mode_flag(src_path, dst_path, zip_path, key_path):
    """Test creation and extraction with --mode."""
    (src_path / 'foo').chmod(0o755)
    (src_path / 'qux').chmod(0o700)
    # Create archive
    args = [
        '-c', str(key_path),
        'create',
        str(src_path),
        str(zip_path),
        '--mode'
    ]
    run_cli(args)
    # Extract archive
    args = [
        '-c', str(key_path),
        'extract',
        str(zip_path),
        str(dst_path),
        '--mode'
    ]
    run_cli(args)
    # Check modes
    assert (dst_path / 'src' / 'foo').stat().st_mode & 0o777 == 0o755
    assert (dst_path / 'src' / 'qux').stat().st_mode & 0o777 == 0o700


def test_mtime_flag(src_path, dst_path, zip_path, key_path):
    """Test creation and extraction with --mtime."""
    os.utime((src_path / 'foo'), times=(0, 0))
    os.utime((src_path / 'qux'), times=(1640995200, 1640995200))
    # Create archive
    args = [
        '-c', str(key_path),
        'create',
        str(src_path),
        str(zip_path),
        '--mtime'
    ]
    run_cli(args)
    # Extract archive
    args = [
        '-c', str(key_path),
        'extract',
        str(zip_path),
        str(dst_path),
        '--mtime'
    ]
    run_cli(args)
    # Check mtimes
    assert (dst_path / 'src' / 'foo').stat().st_mtime == 0
    assert (dst_path / 'src' / 'qux').stat().st_mtime == 1640995200


def test_list(src_path, dst_path, zip_path, key_path):
    """Test list command."""
    file_path = src_path / 'foo'
    # Create archive
    args = ['-c', str(key_path), 'create', str(file_path), str(zip_path)]
    run_cli(args)
    # List archive
    args = ['-c', str(key_path), 'list', str(zip_path)]
    result = run_cli(args)
    assert result.output == 'foo\n'


def test_version(key_path):
    """Test version command."""
    args = ['-c', str(key_path), 'version']
    result = run_cli(args)
    assert result.output == f'{NAME} {VERSION}\n'


def test_signer_list(key_path):
    """Test signer list command."""
    own_key = (key_path / PUBLIC_KEY).read_text().strip()
    args = ['-c', str(key_path), 'signer', 'list']
    result = run_cli(args)
    assert result.output.startswith(own_key)


def test_signer_add(key_path):
    """Test signer add command."""
    own_key = (key_path / PUBLIC_KEY).read_text().strip()
    foo_key = own_key[:-3] + 'FOO'
    args = ['-c', str(key_path), 'signer', 'add', foo_key, '-a', 'foo']
    run_cli(args)
    args = ['-c', str(key_path), 'signer', 'list']
    result = run_cli(args)
    assert own_key in result.output
    assert foo_key in result.output
    assert '(foo)' in result.output


def test_signer_remove(key_path):
    """Test signer remove command."""
    own_key = (key_path / PUBLIC_KEY).read_text().strip()
    foo_key = own_key[:-3] + 'FOO'
    bar_key = own_key[:-3] + 'BAR'
    args = ['-c', str(key_path), 'signer', 'add', foo_key, '-a', 'foo']
    run_cli(args)
    args = ['-c', str(key_path), 'signer', 'add', bar_key, '-a', 'bar']
    run_cli(args)
    args = ['-c', str(key_path), 'signer', 'remove', foo_key]
    run_cli(args)
    args = ['-c', str(key_path), 'signer', 'remove', 'bar']
    run_cli(args)
    args = ['-c', str(key_path), 'signer', 'list']
    result = run_cli(args)
    assert own_key in result.output
    assert foo_key not in result.output
    assert bar_key not in result.output


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


def run_cli(args, exit_code=0):
    """Run the CLI and return the result."""
    runner = CliRunner()
    result = runner.invoke(icepack, args)
    assert result.exit_code == exit_code
    return result
