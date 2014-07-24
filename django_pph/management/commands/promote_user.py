from django.core.management.base import BaseCommand
from django.contrib.auth.hashers import get_hasher
from django.contrib.auth.models import User

from django_pph.shamirsecret import ShamirSecret
from django_pph.settings import SETTINGS
from django_pph.utils import cache, bin64enc, binary_type

# given a username, search for a user entry in the database and update its hash
# to make it count towards the threshold for secret recovery
def promote_user(username):

    target_user = User.objects.filter(username=username)
    assert len(target_user)==1

    hasher = get_hasher('pph')
    hasher.load()
    print(hasher.data['nextavailableshare'])

    for user in target_user:
        print("should update {}".format(user.password)) 
        encoded = user.password
        algorithm, sharenumber, iterations, salt, original_hash = encoded.split('$', 4)
        assert algorithm == 'pph'

        if hasher.data['is_unlocked'] == 1:

            if sharenumber.startswith('-'):
                sharenumber.strip('-')
            sharenumber = int(sharenumber)
            assert sharenumber == 0
            passhash, sharenumber = hasher.update_hash_threshold(
                    original_hash)
            password = "%s$%d$%s$%s$%s" % (hasher.algorithm,
                    sharenumber, iterations, salt, passhash)

            user.password = password
            user.save()

        else:

            sharenumber.strip('-')
            sharenumber = int(sharenumber)

            assert sharenumber == 0
            new_sharenumber = int(hasher.data['nextavailableshare'])
            hasher.data['nextavailableshare'] += 1
            hasher.update()
            password = "%s$-%d$%s$%s$%s" % (hasher.algorithm,
                    new_sharenumber, iterations, salt, original_hash)

            user.password = password
            user.save()



class Command(BaseCommand):

    help = 'Adds a thresholdless user to the threshold accounts'

    def add_arguments(self, parser):
        parser.add_argument('user_id', nargs='+', type=int,
                help='the target username to add to thresholdless accounts')

    def handle(self, *args, **options):

        promote_user(args[0])
                        

                




            
        
    
