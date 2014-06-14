import os
import sys

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
    )
)

from django.test.utils import get_runner

sys.exit(get_runner(settings)().run_tests(['django_pph']))