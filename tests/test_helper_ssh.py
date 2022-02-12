from subprocess import CalledProcessError

import pytest

from icepack.helper import SSH

from helper import key_path


def test_sign_and_verify(shared_datadir, key_path):
    """Test SSH.sign() and SSH.verify()."""
    foo = shared_datadir / 'dst' / 'foo'
    foo.write_text('foo')
    secret_key = key_path / 'identity'
    SSH.sign(foo, secret_key)
    foo_sig = foo.parent / (foo.name + '.sig')
    assert foo_sig.is_file()
    allowed_signers = key_path / 'allowed_signers'
    SSH.verify(foo, foo_sig, allowed_signers)


def test_invalid_signature(shared_datadir, key_path):
    """Test verifying an invalid signature."""
    foo = shared_datadir / 'dst' / 'foo'
    foo.write_text('foo')
    bar = shared_datadir / 'dst' / 'bar'
    bar.write_text('bar')
    secret_key = key_path / 'identity'
    SSH.sign(foo, secret_key)
    SSH.sign(bar, secret_key)
    foo_sig = foo.parent / (foo.name + '.sig')
    bar_sig = bar.parent / (bar.name + '.sig')
    allowed_signers = key_path / 'allowed_signers'
    with pytest.raises(CalledProcessError):
        SSH.verify(foo, bar_sig, allowed_signers)
