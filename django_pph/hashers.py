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
    secret_digest = b64encode(secret).decode('ascii').strip()[:4]
    secret += secret_digest
    return bytes(secret)

# verify_secret function
#   checks wether the secret given contains a proper fingerprint with the
#   following form:
#       [28 bytes random data][4 bytes hash of random data]
# 
#   the boolean returned indicates wether it falls under the fingerprint or
#   not
def _verify_secret(digest, secret):
    
    random_data = secret[:28]
    secret_hash = digest(random_data).digest()
    secret_hash_text = b64encode(secret_hash).decode('ascii').strip()[:4]
    return constant_time_compare(secret[28:],secret_hash)



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
    nextavailableshare = 0
    partialbytes = 2
    digest = hashlib.sha256
    thresholdlesskey = create_secret(digest)
#    thresholdlesskey = bytes(get_random_string(32))
    shamirsecretobj = ShamirSecret(5 , thresholdlesskey)

    def encode(self, password, salt, sharenumber=None, iterations=None):
        assert password is not None
        assert salt and '$' not in salt
        if iterations is None:
            iterations = self.iterations
        if sharenumber is None:
            sharenumber = self.nextavailableshare
            self.nextavailableshare += 1
        # create_account(password, salt)
        # shareN + ^ + salt = a share
        # shareN is from nextavailableshare
        # when running encode w/ ^, nextavailableshare += 1
        # iterations => pbkdf2
        # pbkdf2 is hash function


        saltedpasswordhash = self.digest(salt + password).digest()
        if sharenumber == 0:
            # Encrypt the salted secure hash.   The salt should make all entries
            # unique when encrypted.
            passhash = AES.new(self.thresholdlesskey).encrypt(saltedpasswordhash)
        else:
            # take the bytearray part of this
            shamirsecretdata = self.shamirsecretobj.compute_share(sharenumber)[1]
            # XOR the two and keep this.   This effectively hides the hash unless
            # threshold hashes can be simultaneously decoded
            passhash = do_bytearray_xor(saltedpasswordhash, shamirsecretdata)

        # append the partial verification data...
        passhash += saltedpasswordhash[len(saltedpasswordhash) - self.partialbytes:]
        passhash = b64encode(passhash).decode('ascii').strip()
        return "%s$%d$%d$%s$%s" % (self.algorithm, sharenumber, iterations, salt, passhash)

    def verify(self, password, encoded):
        # check share number w/ '^'
        algorithm, sharenumber, iterations, salt, hash = encoded.split('$', 4)
        assert algorithm == self.algorithm
        encoded_2 = self.encode(password, salt, int(sharenumber), int(iterations))
        return constant_time_compare(encoded, encoded_2)

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

