import os
import sys

import django
from django.conf import settings


DIRNAME = os.path.dirname(__file__)

settings.configure(
    DEBUG=True,
    DATABASES={
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': 'test.db'
        }
    },
    MIDDLEWARE_CLASSES=(),
    INSTALLED_APPS=(
        'django.contrib.auth',
        'django.contrib.contenttypes',
        'django.contrib.sessions',
        'django.contrib.admin',
        'django_pph',
    ),
    ROOT_URLCONF='runtests',
    PASSWORD_HASHERS=(
        'django_pph.hashers.PolyPassHasher',
    ),
    CACHES={
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            'TIMEOUT': None,
        }
    },
)


if hasattr(django, 'setup'):
    django.setup()


if __name__ == '__main__':
    from django.core.management import execute_from_command_line
    if not sys.argv[1:]:
        sys.argv.extend(['test', 'django_pph'])
    execute_from_command_line(sys.argv)
