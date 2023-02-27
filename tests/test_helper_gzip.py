import os

import pytest

from icepack.helper import PIGZ_ENV, File, GZip

from helper import src_path, dst_path


@pytest.fixture
def pigz_env():
    """Preserve the existing PIGZ_ENV value, if any."""
    old_value = os.environ.get(PIGZ_ENV)
    yield
    if old_value is not None:
        os.environ[PIGZ_ENV] = old_value
    elif PIGZ_ENV in os.environ:
        del os.environ[PIGZ_ENV]


def test_ensure_pigz():
    """Ensure that pigz is available."""
    assert GZip.has_pigz() is True
    assert GZip.pigz_version is not None


def test_without_pigz(src_path, dst_path, pigz_env):
    """Test compression without pigz."""
    os.environ[PIGZ_ENV] = 'false'
    GZip.compress(src_path / 'foo', dst_path / 'foo.gz')
    GZip.decompress(dst_path / 'foo.gz', dst_path / 'foo')
    assert File.sha256(dst_path / 'foo') == 'b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c'  # noqa


def test_with_pigz(src_path, dst_path, pigz_env):
    """Test compression with pigz."""
    os.environ[PIGZ_ENV] = 'true'
    GZip.compress(src_path / 'foo', dst_path / 'foo.gz')
    GZip.decompress(dst_path / 'foo.gz', dst_path / 'foo')
    assert File.sha256(dst_path / 'foo') == 'b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c'  # noqa
