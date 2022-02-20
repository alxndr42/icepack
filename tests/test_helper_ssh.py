from subprocess import CalledProcessError

import pytest

from icepack.helper import SSH
from icepack.meta import SECRET_KEY, PUBLIC_KEY, ALLOWED_SIGNERS

from helper import dst_path, key_path


def test_keygen(dst_path):
    """Test SSH.keygen()."""
    SSH.keygen(dst_path)
    assert (dst_path / SECRET_KEY).is_file()
    assert (dst_path / PUBLIC_KEY).is_file()
    assert (dst_path / ALLOWED_SIGNERS).is_file()


def test_keygen_twice(dst_path):
    """Test SSH.keygen() on existing keys."""
    SSH.keygen(dst_path)
    secret_key = (dst_path / SECRET_KEY).read_text()
    with pytest.raises(Exception):
        SSH.keygen(dst_path)
    assert (dst_path / SECRET_KEY).read_text() == secret_key


def test_sign_and_verify(dst_path, key_path):
    """Test SSH.sign() and SSH.verify()."""
    foo = dst_path / 'foo'
    foo.write_text('foo')
    secret_key = key_path / SECRET_KEY
    SSH.sign(foo, secret_key)
    foo_sig = foo.parent / (foo.name + '.sig')
    assert foo_sig.is_file()
    allowed_signers = key_path / ALLOWED_SIGNERS
    SSH.verify(foo, foo_sig, allowed_signers)


def test_invalid_signature(dst_path, key_path):
    """Test verifying an invalid signature."""
    foo = dst_path / 'foo'
    foo.write_text('foo')
    bar = dst_path / 'bar'
    bar.write_text('bar')
    secret_key = key_path / SECRET_KEY
    SSH.sign(foo, secret_key)
    SSH.sign(bar, secret_key)
    foo_sig = foo.parent / (foo.name + '.sig')
    bar_sig = bar.parent / (bar.name + '.sig')
    allowed_signers = key_path / ALLOWED_SIGNERS
    with pytest.raises(CalledProcessError):
        SSH.verify(foo, bar_sig, allowed_signers)


def test_get_signers(key_path):
    """Test SSH.get_signers()."""
    own_path = key_path / PUBLIC_KEY
    own_key = own_path.read_text().strip()
    signers = SSH.get_signers(key_path)
    assert len(signers) == 1
    key, alias = signers[0]
    assert key == own_key
    assert alias is None


def test_update_signers(key_path):
    """Test SSH.update_signers()."""
    own_path = key_path / PUBLIC_KEY
    own_key = own_path.read_text().strip()
    foo_key = own_key[:-3] + 'FOO'
    bar_key = own_key[:-3] + 'BAR'
    SSH.update_signers(key_path, append=(foo_key, 'foo'))
    SSH.update_signers(key_path, append=(bar_key, 'bar'))
    signers = SSH.get_signers(key_path)
    assert len(signers) == 3
    assert signers[1][0] == foo_key
    assert signers[1][1] == 'foo'
    assert signers[2][0] == bar_key
    assert signers[2][1] == 'bar'
    SSH.update_signers(key_path, remove='foo')
    signers = SSH.get_signers(key_path)
    assert len(signers) == 2
    assert signers[0][0] == own_key
    assert signers[1][0] == bar_key
    SSH.update_signers(key_path, remove=bar_key)
    signers = SSH.get_signers(key_path)
    assert len(signers) == 1
    assert signers[0][0] == own_key
