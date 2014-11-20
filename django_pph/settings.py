from django.conf import settings


SETTINGS = {
    'THRESHOLD': 3,
    'PARTIALBYTES': 2,
    'SECRET_VERIFICATION_BYTES': 4,
    'SECRET_LENGTH': 32,
    'CACHE_ALIAS': 'pph',
    'SECRET_ITERATIONS': 1000,
}


SETTINGS.update(getattr(settings, 'PPH_SETTINGS', {}))
