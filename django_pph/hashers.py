import hashlib
from base64 import b64encode

from Crypto.Cipher import AES

from django.contrib.auth.hashers import BasePasswordHasher
from django.utils.crypto import get_random_string, constant_time_compare
from django.utils.translation import ugettext_noop as _

from .shamirsecret import ShamirSecret

# create_secret method:
#   returns a random string consisting of 28 bytes of random data
#   and 4 bytes of hash to verify the secret upon recombination
def create_secret(digest):
    secret = get_random_string(28)
    secret_digest = digest(secret).digest()
    secret_digest = b64encode(secret_digest).decode('ascii').strip()[:4]
    secret += secret_digest
    return bytes(secret)


# verify_secret function
#   checks wether the secret given contains a proper fingerprint with the
#   following form:
#       [28 bytes random data][4 bytes hash of random data]
# 
#   the boolean returned indicates wether it falls under the fingerprint or
#   not
def verify_secret(digest, secret):
    random_data = secret[:28]
    secret_hash = digest(random_data).digest()
    secret_hash_text = b64encode(secret_hash).decode('ascii').strip()[:4]
    return constant_time_compare(secret[28:],secret_hash_text)


def do_bytearray_xor(a, b):
    a = bytearray(a)
    b = bytearray(b)

    # should always be true in our case...
    if len(a) != len(b):
        print((len(a), len(b), a, b))
    assert len(a) == len(b)
    result = bytearray()

    for pos in range(len(a)):
        result.append(a[pos] ^ b[pos])

    return result


class PolyPassHasher(BasePasswordHasher):
    algorithm = 'pph'
    iterations = 12000
    threshold = 5
    nextavailableshare = 1
    partialbytes = 2
    digest = hashlib.sha256

    is_unlocked = True
    secret = create_secret(digest)
    shamirsecretobj = ShamirSecret(5, secret)
    thresholdlesskey = secret


    def encode(self, password, salt, iterations=None):

        if self.is_unlocked == False or self.thresholdlesskey is None:
            raise Excetption("Context is locked")

        assert salt is not None
        assert password is not None

        # we preparse the input string to verify which kind of entry this 
        # belongs to
        if '$' in salt:
            sharenumber = self.nextavailableshare
            self.nextavailableshare += 1
            salt = salt.strip('$')
        else:
            sharenumber = 0

        if iterations is None:
            iterations = self.iterations

        # create_account(password, salt)
        # shareN + ^ + salt = a share
        # shareN is from nextavailableshare
        # when running encode w/ ^, nextavailableshare += 1
        # iterations => pbkdf2
        # pbkdf2 is hash function

        # we verify whether the entry is to be a threshold or thresholdless 
        # account. We account threhsold accounts f
        if sharenumber == 0 or sharenumber == None:

            passhash = self._encrypt_entry(password, salt)
        else:

            passhash = self._polyhash_entry(password, salt, sharenumber)

        return "%s$%d$%d$%s$%s" % (self.algorithm, sharenumber, iterations,
                salt, passhash)


    def verify(self, password, encoded):
        # check share number w/ '^'

        algorithm, sharenumber, iterations, salt, original_hash = \
                encoded.split('$', 4)

        assert algorithm == self.algorithm

        sharenumber = int(sharenumber)
        if self.secret is not None:
            if sharenumber != 0:
                proposed_hash= self._polyhash_entry(password, salt, sharenumber)
            else:
                proposed_hash = self._encrypt_entry(password, salt)

            return constant_time_compare(original_hash, proposed_hash)

        elif self.partialbytes > 0:
            # TODO: provide partial verification and do the caching
            pass

        raise Exception("Context is locked right now, we cannot provide authentication!")


    def safe_summary(self, encoded):
        algorithm, sharenumber, iterations, salt, hash = encoded.split('$', 4)
        assert algorithm == self.algorithm
        return OrderedDict([
            (_('algorithm'), algorithm),
            (_('sharenumber'), sharenumber),
            (_('iterations'), iterations),
            (_('salt'), mask_hash(salt)),
            (_('hash'), mask_hash(hash)),
        ])


    def must_update(self, encoded):
        algorithm, sharenumber, iterations, salt, hash = encoded.split('$', 4)
        return int(iterations) != self.iterations


    # private helper that computes a polyhashed entry with a given sharenumber,
    # password and salt. Used in hash creation and verification.
    # TODO: What's with the iterations?
    def _polyhash_entry(self, password, salt, sharenumber):

        assert self.shamirsecretobj is not None

        saltedpasswordhash = self.digest(salt + password).digest()
        shamirsecretdata = self.shamirsecretobj.compute_share(sharenumber)[1]
        passhash = do_bytearray_xor(saltedpasswordhash, shamirsecretdata)
        passhash += saltedpasswordhash[len(saltedpasswordhash) - self.partialbytes:]
        passhash = b64encode(passhash).decode('ascii').strip()
        return passhash


    # private helper that decrypts a given password
    def _encrypt_entry(self, password, salt):

        assert self.thresholdlesskey is not None

        saltedpasswordhash = self.digest(salt + password).digest()
        passhash = AES.new(self.thresholdlesskey).encrypt(saltedpasswordhash)
        passhash += saltedpasswordhash[len(saltedpasswordhash) - self.partialbytes:]
        passhash = b64encode(passhash).decode('ascii').strip()
        return passhash

    # FIXME: this needs to be moved somewhere else, to the admin command
    def initialize(self):
      self.secret = self.create_secret()
      assert self.verify_secret(self.secret) == True
      self.shamirsecretobj = ShamirSecret(5, self.secret)
      self.thresholdlesskey = self.secret
      self.is_unlocked = True
