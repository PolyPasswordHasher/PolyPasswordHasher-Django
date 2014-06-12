from django.test import TestCase
from django.contrib.auth.hashers import make_password, check_password


class PolyPassHashTestCase(TestCase):
    def test_hasher(self):
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
        # TODO: Any higher range breaks shamirsecret.compute_share
        for i in range(253):
            raw = 'password%d' % i
            password = make_password(raw)
            self.assertTrue(check_password(raw, password))
            self.assertLess(len(password), 128)

    def test_unlock_store(self):
        # TODO;
        pass

    def test_thresholdless_hash(self):
        # TODO:
        pass
    
