from django.core.management.base import BaseCommand
from django.contrib.auth.hashers import get_hasher
from django.contrib.auth.models import User

from base64 import b64decode, b64encode

from django.utils.crypto import get_random_string

try:
    from Crypto.Cipher import AES
except ImportError:
    raise ImproperlyConfigured('You must have PyCrypto installed in order to use the PolyPasswordHasher')



from django_pph.shamirsecret import ShamirSecret
from django_pph.settings import SETTINGS
from django_pph.utils import cache, bin64enc, binary_type, do_bytearray_xor


# given a username, we search for a user in a database and remove him from the
# threshold-pool of users.
def demote_user(username):

    hasher = get_hasher('pph')
    target_user = User.objects.filter(username=username)
    assert len(target_user)==1
    hasher.load()

    # for safety purposes, we will scan the database to guarantee that there
    # is already a threshold of users in order to recover the secert after
    # unlocking.
    target_threshold = hasher.threshold
    number_of_threshold_accounts = 0
    all_users = User.objects.all()
    for user in all_users:
        sharenumber = user.password.split('$')[1]
        sharenumber = int(sharenumber)
        if sharenumber > 0:
            number_of_threshold_accounts += 1


    assert number_of_threshold_accounts > target_threshold

    # now, perform the demotion
    for user in target_user:
        print("should update {}".format(user.password)) 
        encoded = user.password
        algorithm, sharenumber, iterations, salt, original_hash = \
                encoded.split('$', 4)
        assert algorithm == 'pph'
        sharenumber = int(sharenumber)
        assert sharenumber > 0
        assert hasher.data['is_unlocked'] == 1
        
        partial_bytes = hasher.partialbytes
        byte_hash = b64decode(
                original_hash[:len(original_hash) - partial_bytes])
        share = hasher.data['shamirsecretobj'].compute_share(
                sharenumber)[1]
        byte_hash = do_bytearray_xor(share, byte_hash)
        import pdb; pdb.set_trace()  
        passhash = AES.new(hasher.data['thresholdlesskey']).encrypt(
            buffer(byte_hash))
        passhash = b64encode(passhash)
        passhash += b64encode(
                byte_hash[len(byte_hash) - hasher.partialbytes:])

        password = "%s$%d$%s$%s$%s" % (hasher.algorithm,
                0, iterations, salt, passhash)

        user.password = password
        user.save()


class Command(BaseCommand):

    help = 'Remove a user from the thresholdless-account pool'

    def add_arguments(self, parser):
        parser.add_argument('user_id', nargs='+', type=int,
                help='the target username to add to thresholdless accounts')
        

    def handle(self, *args, **options):

        # FIXME: we should support the options arguments or detect different
        # django versions for it.
        demote_user(args[0])

               




            
        
    
