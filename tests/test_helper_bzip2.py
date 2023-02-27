import os

import pytest

from icepack.helper import PBZIP2_ENV, BZip2, File

from helper import src_path, dst_path


@pytest.fixture
def pbzip2_env():
    """Preserve the existing PBZIP2_ENV value, if any."""
    old_value = os.environ.get(PBZIP2_ENV)
    yield
    if old_value is not None:
        os.environ[PBZIP2_ENV] = old_value
    elif PBZIP2_ENV in os.environ:
        del os.environ[PBZIP2_ENV]


def test_ensure_pbzip2():
    """Ensure that pbzip2 is available."""
    assert BZip2.has_pbzip2() is True
    assert BZip2.pbzip2_version() is not None


def test_without_pbzip2(src_path, dst_path, pbzip2_env):
    """Test compression without pbzip2."""
    os.environ[PBZIP2_ENV] = 'false'
    BZip2.compress(src_path / 'foo', dst_path / 'foo.bz2')
    BZip2.decompress(dst_path / 'foo.bz2', dst_path / 'foo')
    assert File.sha256(dst_path / 'foo') == 'b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c'  # noqa


def test_with_pbzip2(src_path, dst_path, pbzip2_env):
    """Test compression with pbzip2."""
    os.environ[PBZIP2_ENV] = 'true'
    BZip2.compress(src_path / 'foo', dst_path / 'foo.bz2')
    BZip2.decompress(dst_path / 'foo.bz2', dst_path / 'foo')
    assert File.sha256(dst_path / 'foo') == 'b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c'  # noqa
