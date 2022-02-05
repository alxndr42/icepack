from icepack.helper import File


def test_children(shared_datadir):
    """Test File.children()."""
    src_path = shared_datadir / 'src'
    children = list(File.children(src_path))
    relative = [str(c.relative_to(src_path)) for c in children]
    assert sorted(relative) == ['bar', 'foo', 'qux', 'qux/quux']


def test_sha256(shared_datadir):
    """Test File.sha256()."""
    assert File.sha256(shared_datadir / 'src' / 'foo') == 'b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c'  # noqa
