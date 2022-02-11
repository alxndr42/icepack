from icepack.helper import Age


def test_keygen():
    """Test Age.keygen()."""
    secret_key, public_key = Age.keygen()
    assert type(secret_key) == str
    assert type(public_key) == str
    assert secret_key.startswith('AGE-SECRET-KEY-')
    assert public_key.startswith('age')


def test_encrypt_decrypt(shared_datadir):
    """Test Age.encrypt() and Age.decrypt()."""
    secret_key = Age.keygen()[0]
    src = shared_datadir / 'src' / 'foo'
    dst = shared_datadir / 'dst' / 'foo.age'
    Age.encrypt(src, dst, secret_key)
    assert dst.read_bytes()[:3] == 'age'.encode()
    src = shared_datadir / 'dst' / 'foo.age'
    dst = shared_datadir / 'dst' / 'foo'
    Age.decrypt(src, dst, secret_key)
    assert dst.read_text().strip() == 'foo'
