from django.core.management.base import BaseCommand
from django.contrib.auth.hashers import get_hasher
from django.contrib.auth.models import User

from django_pph.shamirsecret import ShamirSecret
from django_pph.settings import SETTINGS


# This will be more elaborate once we have multi-hasher support.
SUPPORTED_HASHES = set(['pkbdf2_sha256'])


# For a given user, turn his passhash into a thresholdless polypasswordhash
def migrate_user(username):

    target_user = User.objects.filter(username=username)
    assert len(target_user) == 1, \
            "there is no such user or the database is corrupted"

    hasher = get_hasher('pph')
    hasher.load()

    user = target_user[0]

    encoded = user.password
    algorithm = encoded.split('$')[0]

    if algorithm == 'pph':
        # TODO: wiould be nice to report somehow
        return
    elif algorithm in SUPPORTED_HASHES:
        # TODO: with multi-hasher support, we should set the information 
        # regarding the original hash somewhere
        algorithm, iterations, salt, passhash = encoded.split('$')
        
        if hasher.data['is_unlocked']:
            sharenumber = '0'
            encrypted_entry = hasher.update_hash_thresholdless(passhash)
        else:
            sharenubmer = '-0' 
            encrypted_entry = passhash
        
        password = "{}${}${}${}${}".format('pph', sharenumber, iterations,
                salt, encrypted_entry)

        user.password = password
        user.save()

    else:

        raise Exception('impossible to migrate form this type of hash')
   

class Command(BaseCommand):

    help = 'Adds a non-pph-encoded user to the list of thresholdless accounts.'

    def add_arguments(self, parser):
        parser.add_argument('user_id', nargs='+', type=int,
                help='the target username to add to pph.')

    def handle(self, *args, **options):

        migrate_user(args[0])
                        

                




            
        
    
