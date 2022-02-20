import base64
import stat

import pytest


SECRET_KEY = 'LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFBQUFBQkc1dmJtVUFBQUFFYm05dVpRQUFBQUFBQUFBQkFBQUFNd0FBQUF0emMyZ3RaVwpReU5UVXhPUUFBQUNCUk9hVVVvM1dlTklFdGdSVGNyTGdldGR0RllzQ09IUjVPeHdUUGdOeTBtQUFBQUlqS0h6K0F5aDgvCmdBQUFBQXR6YzJndFpXUXlOVFV4T1FBQUFDQlJPYVVVbzNXZU5JRXRnUlRjckxnZXRkdEZZc0NPSFI1T3h3VFBnTnkwbUEKQUFBRUM0UVVIdlQ5Unc2Yk51OHZ0UnJvL1diUzBqazlhb3NZNDdqeWdFK3o5eHNWRTVwUlNqZFo0MGdTMkJGTnlzdUI2MQoyMFZpd0k0ZEhrN0hCTStBM0xTWUFBQUFBQUVDQXdRRgotLS0tLUVORCBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0K'  # noqa


@pytest.fixture
def src_path(shared_datadir):
    return shared_datadir / 'src'


@pytest.fixture
def dst_path(shared_datadir):
    return shared_datadir / 'dst'


@pytest.fixture
def zip_path(shared_datadir):
    return shared_datadir / 'dst' / 'test.zip'


@pytest.fixture
def key_path(shared_datadir):
    """Deobfuscate the secret key and return the key directory Path."""
    path = shared_datadir / 'keys'
    secret_key = path / 'identity'
    secret_key.write_bytes(base64.standard_b64decode(SECRET_KEY))
    secret_key.chmod(stat.S_IRUSR | stat.S_IRUSR)
    return path
