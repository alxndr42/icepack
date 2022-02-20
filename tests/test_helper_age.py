from icepack.helper import Age

from helper import dst_path, src_path


def test_keygen():
    """Test Age.keygen()."""
    secret_key, public_key = Age.keygen()
    assert type(secret_key) == str
    assert type(public_key) == str
    assert secret_key.startswith('AGE-SECRET-KEY-')
    assert public_key.startswith('age')


def test_encrypt_decrypt(src_path, dst_path):
    """Test Age.encrypt() and Age.decrypt()."""
    secret_key = Age.keygen()[0]
    src = src_path / 'foo'
    dst = dst_path / 'foo.age'
    Age.encrypt(src, dst, secret_key)
    assert dst.read_bytes()[:3] == 'age'.encode()
    src = dst_path / 'foo.age'
    dst = dst_path / 'foo'
    Age.decrypt(src, dst, secret_key)
    assert dst.read_text().strip() == 'foo'


def test_encrypt_decrypt_bytes(dst_path):
    """Test Age.encrypt_bytes() and Age.decrypt_bytes()."""
    secret_key, public_key = Age.keygen()
    foo_bytes = 'foo'.encode()
    age_path = dst_path / 'foo.age'
    Age.encrypt_bytes(foo_bytes, age_path, [public_key])
    key_path = dst_path / 'age.key'
    key_path.write_text(secret_key)
    result = Age.decrypt_bytes(age_path, key_path)
    assert result == foo_bytes


def test_encrypt_decrypt_bytes_multiple_recipients(dst_path):
    """Test encrypt_bytes() and decrypt_bytes() with multiple recipients."""
    secret_foo, public_foo = Age.keygen()
    secret_bar, public_bar = Age.keygen()
    foo_bytes = 'foo'.encode()
    age_path = dst_path / 'foo.age'
    Age.encrypt_bytes(foo_bytes, age_path, [public_foo, public_bar])
    key_path = dst_path / 'age.key'
    key_path.write_text(secret_bar)
    result = Age.decrypt_bytes(age_path, key_path)
    assert result == foo_bytes
