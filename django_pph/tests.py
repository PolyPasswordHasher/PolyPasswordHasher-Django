from django.test import TestCase
from django.contrib.auth.hashers import make_password, check_password, get_hasher

from django_pph.utils import get_cache
cache = get_cache('pph')


def make(password):
    return make_password(password, hasher='pph')


def make_share(password):
    return make_password(password, '$easalt', hasher='pph')


def check(password, encoded):
    return check_password(password, encoded,  preferred='pph')


class PolyPasswordHasherTestCase(TestCase):
    hasher = get_hasher('pph')

    def test_hasher(self):

        password1 = make_share('password1')
        password2 = make_share('password2')
        password3 = make_share('password3')

        self.assertTrue(password1.startswith('pph$1'))
        self.assertTrue(password2.startswith('pph$2'))
        self.assertTrue(password3.startswith('pph$3'))

        self.assertTrue(check('password1', password1))
        self.assertTrue(check('password2', password2))
        self.assertTrue(check('password3', password3))

        self.assertLess(len(password1), 128)
        self.assertLess(len(password2), 128)
        self.assertLess(len(password3), 128)

    def test_total_shares(self):

        # TODO: Any higher range breaks shamirsecret.compute_share
        for i in range(253):
            raw = 'password%d' % i
            password = make(raw)
            self.assertTrue(check(raw, password))
            self.assertLess(len(password), 128)

    # We create a brand new store, lock it and unlock it. We expect to have
    # the secret back at the end of this function.
    def test_unlock_store(self):

        password1 = make_share('password1')
        password2 = make_share('password2')
        password3 = make_share('password3')
        password4 = make_share('password4')
        password5 = make_share('password5')

        # We backup the secret to compare against it upon recombination
        secret_backup = self.hasher.data['secret']
        self.hasher.update(secret=None)

        self.assertTrue(check('password1', password1))
        self.assertTrue(check('password2', password2))
        self.assertTrue(check('password3', password3))
        self.assertTrue(check('password4', password4))
        self.assertTrue(check('password5', password5))

        # with a threshold of 5, at this point we should have the secret back
        self.assertTrue(self.hasher.data['secret'] is not None)
        self.assertTrue(self.hasher.data['secret'] == secret_backup)

    # We will do all of the pertinent thresholdless movements in this test:
    #   * Create a thresholdless hash with the context unlocked
    #   * Fail to provide a new hash after locking the store
    #   * Provide partial verification for thresholdless account
    #   * Provide new creation capabilities after re-unlocking
    #   * Provide verification capabilities after unlocking (original hash)
    def test_thresholdless_hash(self):

        # These are threshold accounts for the unlocking phase
        password1 = make_share('password1')
        password2 = make_share('password2')
        password3 = make_share('password3')
        password4 = make_share('password4')
        password5 = make_share('password5')

        thresholdless1 = make('thresholdless1')

        # we lock the store forcefully
        self.hasher.update(
            secret=None,
            thresholdlesskey=None
        )

        # NOTICE: since we are now able to provide hashes even when the context
        # is unlocked, I removed the "self.assertRaises".

        # partial verification
        self.assertTrue(check('thresholdless1', thresholdless1))

        # unlock the store
        self.assertTrue(check('password1', password1))
        self.assertTrue(check('password2', password2))
        self.assertTrue(check('password3', password3))
        self.assertTrue(check('password4', password4))
        self.assertTrue(check('password5', password5))

        # get a new hash
        thresholdless2 = make('thresholdless2')

        # verify the passwords
        self.assertTrue(check('thresholdless1', thresholdless1))
        self.assertTrue(check('thresholdless2', thresholdless2))

    def test_partial_verfication(self):

        cache.clear()
        password1 = make_share('password1')

        # Forcefully lock the context

        self.hasher.update(secret=None)

        # now try to provide partial verification
        self.assertTrue(check('password1', password1))
