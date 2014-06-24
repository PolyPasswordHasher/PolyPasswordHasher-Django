import hashlib
from base64 import b64encode, b64decode

from Crypto.Cipher import AES

from django.contrib.auth.hashers import BasePasswordHasher
from django.utils.crypto import get_random_string, constant_time_compare
from django.utils.translation import ugettext_noop as _

from .shamirsecret import ShamirSecret

from django.core.cache import cache
from django.conf import settings


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
    threshold = settings.PPH_THRESHOLD
    nextavailableshare = 1
    partialbytes = settings.PPH_PARTIALBYTES
    digest = hashlib.sha256

    is_unlocked = True
    secret = None
    shamirsecretobj = None
    thresholdlesskey = secret


    def encode(self, password, salt, iterations=None):

        if self.is_unlocked == False or self.thresholdlesskey is None:
            raise Exception("Context is locked")

        assert salt is not None
        assert password is not None

        # we pre-parse the input string to verify which kind of entry this 
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
        # account. We account threshold accounts f
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
    
        if self.secret is not None and self.thresholdlesskey is not None:
            if sharenumber != 0:
                proposed_hash= self._polyhash_entry(password, salt, sharenumber)
            else:
                proposed_hash = self._encrypt_entry(password, salt)

            return constant_time_compare(original_hash, proposed_hash)

        else:
            # try to infer the share from the information given
            # TODO: this could be optimized by merging the functionality from
            # _get_share... with _partial_verify...
            if sharenumber != 0:
                share = self._get_share_from_hash(password, salt, original_hash)
                
                # we check for conflicts before inserting this into our cache
                if cache.get(sharenumber):
                    original_share = b64encode(
                            cache.get(sharenumber)).decode('ascii').strip()

                    new_share = b64encode(share).decode('ascii').strip()
                    # if they are not the same
                    if not constant_time_compare(original_share, new_share):
                        raise Exception("Cached share does not match the new" +
                                " share value!")
                else:
                    # this is a new share, add it to the cache and recombine if
                    # possible
                    cache.set(sharenumber, share)
                    sharenumbers = cache.get("sharenumbers")

                    if not sharenumbers:
                        sharenumbers = set()

                    sharenumbers.add(sharenumber)
                    cache.set("sharenumbers", sharenumbers)

                    if len(sharenumbers) >= self.threshold:
                        self._recombine()

       
            # partial verification step, if we are locked, let's try to log the
            # user in
            if self.partialbytes > 0:

                partial_verification_result = self._partial_verify(password,
                        salt, original_hash)
                return partial_verification_result

        
        raise Exception("Context is locked right now, " + 
                "we cannot provide authentication!")


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
    def _polyhash_entry(self, password, salt, sharenumber):

        assert self.shamirsecretobj is not None

        saltedpasswordhash = self.digest(password + salt).digest()
        shamirsecretdata = self.shamirsecretobj.compute_share(sharenumber)[1]
        passhash = do_bytearray_xor(saltedpasswordhash, shamirsecretdata)
        passhash = b64encode(passhash).decode('ascii').strip()
        passhash += b64encode(saltedpasswordhash[len(saltedpasswordhash) -
            self.partialbytes:]).decode('ascii').strip()

        return passhash


    # private helper that decrypts a given password
    def _encrypt_entry(self, password, salt):

        assert self.thresholdlesskey is not None

        saltedpasswordhash = self.digest(password + salt).digest()
        passhash = AES.new(self.thresholdlesskey).encrypt(saltedpasswordhash)
        passhash = b64encode(passhash).decode('ascii').strip()
        passhash += b64encode(saltedpasswordhash[len(saltedpasswordhash) -
            self.partialbytes:]).decode('ascii').strip()
        return passhash

    # private helper to provide partial verification.
    def _partial_verify(self, password, salt, passhash):

        saltedpasswordhash = b64encode(self.digest(password +
            salt).digest()).decode('ascii').strip()
        partial_bytes = saltedpasswordhash[len(saltedpasswordhash) -
                self.partialbytes:]
        original_partial_bytes = passhash[len(passhash) - self.partialbytes:]
        return constant_time_compare(partial_bytes, original_partial_bytes)

    # private helper to provide shares from hash ^ passhash
    def _get_share_from_hash(self, password, salt, passhash):

        saltedpasswordhash = self.digest(password + salt).digest()
        byte_passhash = b64decode(passhash[:len(passhash) - self.partialbytes])
        shamirsecretdata = do_bytearray_xor(byte_passhash, saltedpasswordhash)
        return shamirsecretdata

    # verify_secret function checks whether the secret given contains a
    # proper fingerprint with the following form: [28 bytes random data][4
    # bytes hash of random data]
    # 
    #   the boolean returned indicates whether it falls under the
    #   fingerprint or not
    def verify_secret(self, secret):

        secret_length = settings.PPH_SECRET_LENGTH
        verification_len = settings.PPH_SECRET_VERIFICATION_BYTES
        random_data = secret[:secret_length - verification_len]
        secret_hash = self.digest(random_data).digest()
        secret_hash_text = \
            b64encode(secret_hash).decode('ascii').strip()[:verification_len]
        return constant_time_compare(secret[secret_length - verification_len:],
                secret_hash_text)
   
    # this private helper will attempt to restore the secret when a threshold 
    # of shares has been met.
    def _recombine(self):

        sharenumbers = cache.get("sharenumbers")
        assert(sharenumbers is not None)
       
        recombination_shares = []
        for share in sharenumbers:
            share_value = cache.get(share)  
            assert(share_value is not None)
            current_share = (int(share), share_value)
            recombination_shares.append(current_share)

        self.shamirsecretobj = ShamirSecret(self.threshold)
        self.shamirsecretobj.recover_secretdata(recombination_shares)
        self.secret = self.shamirsecretobj.secretdata

        if not self.verify_secret(self.secret):
            raise Exception("Couldn't recombine store!")

        self.thresholdlesskey = self.secret
        
