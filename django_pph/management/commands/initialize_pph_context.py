#!/usr/bin/env python

from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth.hashers import get_hasher
from django.utils.crypto import get_random_string

from base64 import b64encode


from django_pph.shamirsecret import ShamirSecret



class Command(BaseCommand):

    help='Initializes a pph store'

    def handle(self, *args, **options):

        hasher = get_hasher('pph')

        # We load the hasher's digest instead of assigning ours to match the 
        # hash algorithm that will be used to verify
        self.digest = hasher.digest

        # intialize the whole store, basically generate the secret, create
        # a shamir secret object and assign the secret to the thresholdlesskey
        self.initialize(hasher)

        # TODO: are we missing anything else here?
        #

        # return


    def initialize(self, hasher):
      hasher.secret = self.create_secret()
      assert hasher.verify_secret(hasher.secret) == True
      hasher.shamirsecretobj = ShamirSecret(hasher.threshold, hasher.secret)
      hasher.thresholdlesskey = hasher.secret
      hasher.is_unlocked = True

    # create_secret method:
    #   returns a random string consisting of 28 bytes of random data
    #   and 4 bytes of hash to verify the secret upon recombination
    def create_secret(self):
        secret = get_random_string(28)
        secret_digest = self.digest(secret).digest()
        secret_digest = b64encode(secret_digest).decode('ascii').strip()[:4]
        secret += secret_digest
        return bytes(secret)


