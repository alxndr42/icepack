from subprocess import CalledProcessError

import pytest

from icepack.helper import SSH
from icepack.meta import SECRET_KEY, PUBLIC_KEY, ALLOWED_SIGNERS

from helper import key_path


def test_keygen(shared_datadir):
    """Test SSH.keygen()."""
    key_path = shared_datadir / 'dst'
    SSH.keygen(key_path)
    assert (key_path / SECRET_KEY).is_file()
    assert (key_path / PUBLIC_KEY).is_file()
    assert (key_path / ALLOWED_SIGNERS).is_file()


def test_keygen_twice(shared_datadir):
    """Test SSH.keygen() on existing keys."""
    key_path = shared_datadir / 'dst'
    SSH.keygen(key_path)
    secret_key = (key_path / SECRET_KEY).read_text()
    with pytest.raises(Exception):
        SSH.keygen(key_path)
    assert (key_path / SECRET_KEY).read_text() == secret_key


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
