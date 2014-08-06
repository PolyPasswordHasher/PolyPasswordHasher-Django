from django.core.management.base import BaseCommand
from django.contrib.auth.hashers import get_hasher
from django.utils.crypto import get_random_string

from django_pph.shamirsecret import ShamirSecret
from django_pph.settings import SETTINGS
from django_pph.utils import cache, bin64enc, binary_type


class Command(BaseCommand):

    help = 'Forcefully locks the pph store'
    hasher = get_hasher('pph')

    def handle(self, *args, **options):

        self.lock_store()


    def lock_store(self):
        """
        Locks a the store for the hasher.
        """
        self.hasher.load()
        data = {
            'is_unlocked': False,
            'secret': None,
            'shamirsecretobj': None,
            'thresholdlesskey': None,
        }
        self.hasher.update(data)
        cache.set('hasher', data)
