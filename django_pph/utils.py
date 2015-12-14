from base64 import b64encode, b64decode
from distutils.version import StrictVersion

import django
if StrictVersion(django.get_version()) < StrictVersion('1.9.0'):
    from django.core.cache import get_cache
else:
    from django.core.cache import caches

from django.utils import six
from django.utils import crypto

from .settings import SETTINGS


class LockedException(Exception):
    def __str__(self):
        return "Context is locked right now, we cannot provide authentication!"


def do_bytearray_xor(a, b):
    a = bytearray(a)
    b = bytearray(b)

    assert len(a) == len(b)
    result = bytearray()

    for pos in range(len(a)):
        result.append(a[pos] ^ b[pos])

    return result


def binary_type(s):
    if isinstance(s, six.binary_type):
        return s
    if six.PY2 or isinstance(s, bytearray):
        return six.binary_type(s)
    return six.binary_type(s, 'utf8')


def constant_time_compare(val1, val2):
    """Performs constant_time_compare with consistent typing"""
    return crypto.constant_time_compare(binary_type(val1), binary_type(val2))


b64enc = lambda s: b64encode(s).decode('ascii').strip()
bin64enc = lambda s: b64enc(binary_type(s))
bin64dec = lambda s: binary_type(b64decode(s))

if StrictVersion(django.get_version()) < StrictVersion('1.9'):
    cache = get_cache(SETTINGS['CACHE_ALIAS'])
    share_cache = get_cache('share_cache')
else:
    cache = caches[SETTINGS['CACHE_ALIAS']]
    share_cache = caches['share_cache']
