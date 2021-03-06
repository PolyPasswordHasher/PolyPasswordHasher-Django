import os
import sys

import django
from django.conf import settings

urlpatterns = []


DIRNAME = os.path.dirname(__file__)

if not settings.configured:
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
            'django_pph.hashers.PolyPasswordHasher',
        ),
        CACHES={
            'default': {
                'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            },
            'pph': {
                'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache',
                'LOCATION': 'pph_cache',
                'TIMEOUT': None,
            },
            'share_cache': {
                'BACKEND': 'django.core.cache.backends.db.DatabaseCache',
                'LOCATION': 'share_table',
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
