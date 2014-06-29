from django.conf import settings


SETTINGS = {
    'THRESHOLD': 5,
    'PARTIALBYTES': 2,
    'SECRET_VERIFICATION_BYTES': 4,
    'SECRET_LENGTH': 32,
    'CACHE_ALIAS': 'pph'
}


SETTINGS.update(getattr(settings, 'PPH_SETTINGS', {}))
