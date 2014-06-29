from django.test import TestCase
from django.contrib.auth.hashers import make_password, check_password
from django.core import management
from django.contrib.auth.hashers import get_hasher

from django_pph.utils import cache


class PolyPassHashTestCase(TestCase):
    def test_hasher(self):

        # we create a new secret and clear the cache for each test, so
        # previous entries in the hasher instance do not mess with each other
        management.call_command("initialize_pph_context")
        cache.clear()

        password1 = make_password('password1', salt='$easalt')
        password2 = make_password('password2', salt='$easalt')
        password3 = make_password('password3', salt='$easalt')

        self.assertTrue(password1.startswith('pph$1'))
        self.assertTrue(password2.startswith('pph$2'))
        self.assertTrue(password3.startswith('pph$3'))

        self.assertTrue(check_password('password1', password1))
        self.assertTrue(check_password('password2', password2))
        self.assertTrue(check_password('password3', password3))

        self.assertLess(len(password1), 128)
        self.assertLess(len(password2), 128)
        self.assertLess(len(password3), 128)

    def test_total_shares(self):

        management.call_command("initialize_pph_context")
        # TODO: Any higher range breaks shamirsecret.compute_share
        for i in range(253):
            raw = 'password%d' % i
            password = make_password(raw)
            self.assertTrue(check_password(raw, password))
            self.assertLess(len(password), 128)

    # We create a brand new store, lock it and unlock it. We expect to have
    # the secret back at the end of this function.
    def test_unlock_store(self):

        # we create a new secret and clear the cache for each test, so
        # previous entries in the hasher instance do not mess with each other
        cache.clear()
        management.call_command("initialize_pph_context")

        password1 = make_password('password1', salt='$easalt')
        password2 = make_password('password2', salt='$easalt')
        password3 = make_password('password3', salt='$easalt')
        password4 = make_password('password4', salt='$easalt')
        password5 = make_password('password5', salt='$easalt')

        # We backup the secret to compare against it upon recombination
        hasher = get_hasher('pph')
        secret_backup = hasher.secret
        hasher.secret = None

        self.assertTrue(check_password('password1', password1))
        self.assertTrue(check_password('password2', password2))
        self.assertTrue(check_password('password3', password3))
        self.assertTrue(check_password('password4', password4))
        self.assertTrue(check_password('password5', password5))

        # with a threshold of 5, at this point we should have the secret back
        self.assertTrue(hasher.secret is not None)
        self.assertTrue(hasher.secret == secret_backup)

    # We will do all of the pertinent thresholdless movements in this test:
    #   * Create a thresholdless hash with the context unlocked
    #   * Fail to provide a new hash after locking the store
    #   * Provide partial verification for thresholdless account
    #   * Provide new creation capabilities after re-unlocking
    #   * Provide verification capabilities after unlocking (original hash)
    def test_thresholdless_hash(self):

        # we create a new secret and clear the cache for each test, so
        # previous entries in the hasher instance do not mess with each other
        cache.clear()
        management.call_command("initialize_pph_context")

        # These are threshold accounts for the unlocking phase
        password1 = make_password('password1', salt='$easalt')
        password2 = make_password('password2', salt='$easalt')
        password3 = make_password('password3', salt='$easalt')
        password4 = make_password('password4', salt='$easalt')
        password5 = make_password('password5', salt='$easalt')

        thresholdless1 = make_password('thresholdless1')

        # we lock the store forcefully
        hasher = get_hasher('pph')
        hasher.secret = None
        hasher.thresholdlesskey = None

        self.assertRaises(Exception, make_password, 'thresholdless2')

        # partial verification
        self.assertTrue(check_password('thresholdless1', thresholdless1))

        # unlock the store
        self.assertTrue(check_password('password1', password1))
        self.assertTrue(check_password('password2', password2))
        self.assertTrue(check_password('password3', password3))
        self.assertTrue(check_password('password4', password4))
        self.assertTrue(check_password('password5', password5))

        # get a new hash
        thresholdless2 = make_password('thresholdless2')

        # verify the passwords
        self.assertTrue(check_password('thresholdless1', thresholdless1))
        self.assertTrue(check_password('thresholdless2', thresholdless2))

    def test_partial_verfication(self):

        # we create a new secret and clear the cache for each test, so
        # previous entries in the hasher instance do not mess with each other
        management.call_command("initialize_pph_context")
        cache.clear()

        password1 = make_password('password1', salt='$easalt')

        # Forcefully lock the context
        hasher = get_hasher('pph')
        hasher.secret = None

        # now try to provide partial verification
        self.assertTrue(check_password('password1', password1))
