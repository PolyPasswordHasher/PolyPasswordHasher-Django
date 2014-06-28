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

from django.test.utils import get_runner

sys.exit(get_runner(settings)().run_tests(['django_pph']))
