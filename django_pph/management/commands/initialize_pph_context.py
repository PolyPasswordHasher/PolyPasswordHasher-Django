#!/usr/bin/env python

from base64 import b64encode

from django.core.management.base import BaseCommand
from django.contrib.auth.hashers import get_hasher
from django.utils.crypto import get_random_string

from django_pph.shamirsecret import ShamirSecret
from django_pph.settings import SETTINGS


class Command(BaseCommand):

    help = 'Initializes a pph store'

    def handle(self, *args, **options):

        hasher = get_hasher('pph')

        # We load the hasher's digest instead of assigning ours to match the
        # hash algorithm that will be used to verify
        self.digest = hasher.digest

        # intialize the whole store, basically generate the secret, create
        # a shamir secret object and assign the secret to the thresholdlesskey
        self.initialize(hasher)

    def initialize(self, hasher):
        hasher.secret = self.create_secret()
        assert hasher.verify_secret(hasher.secret) is True
        hasher.shamirsecretobj = ShamirSecret(hasher.threshold, hasher.secret)
        hasher.thresholdlesskey = hasher.secret
        hasher.nextavailableshare = 1
        hasher.is_unlocked = True

    # create_secret method:
    #   returns a random string consisting of 28 bytes of random data
    #   and 4 bytes of hash to verify the secret upon recombination
    def create_secret(self):
        secret = get_random_string(SETTINGS['SECRET_LENGTH']
                                   - SETTINGS['SECRET_VERIFICATION_BYTES'])
        secret_digest = self.digest(secret).digest()
        secret_digest = b64encode(secret_digest).decode('ascii').strip()
        secret += secret_digest[:SETTINGS['SECRET_VERIFICATION_BYTES']]
        return bytes(secret)
