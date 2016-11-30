from django.core.management.base import BaseCommand
from django.contrib.auth.hashers import get_hasher
from django.utils.crypto import get_random_string
from django.contrib.auth.models import User
from django.core.management import call_command

from django_pph.shamirsecret import ShamirSecret
from django_pph.settings import SETTINGS
from django_pph.utils import cache, bin64enc, binary_type, share_cache


class Command(BaseCommand):

    help = 'Initializes the polypasswordhasher store with a new secret and ' +\
        'updates the database.\n\n' +\
        "This command requires a list of trusted users to be initialized " +\
        "as threshold accounts"

    hasher = get_hasher('pph')

    def add_arguments(self, parser):
        parser.add_argument("usernames", nargs="+")

    def handle(self, *args, **options):

        
        # TODO: require confirmation
        is_initialized = share_cache.get("is_initialized")
        if is_initialized:
            raise Exception("This database has been initialized already!")

        call_command("initialize_pph_context", verbosity=0)

        threshold = self.hasher.threshold
       
        assert len(options['usernames']) >= threshold, "Not enough users provided to " +\
            "create a store with the current settings.\n\t" +\
            "Usage: ./manage.py setup_store [user1] [user2] ... [usern]"

        users = []
        for username in options['usernames']:
            target_user = User.objects.filter(username=username)
            assert len(target_user) == 1, \
            "there is no {0} user or the database is corrupted".format(username)
            users.append(target_user[0])

        assert len(users) >= threshold, \
            "Coudldn't gather enough accounts for store creation" 


        print("Creating threshold accounts...")
        for user in users:

            # we try to decompose, if it's a pph locked entry, we treat it
            # as a pbkdf2 entry
            try:
                algorithm, iterations, salt, passhash = user.password.split('$')
            except:
                if user.password.startswith("pph$-0$"):
                    algoritm = 'pbkdf2_sha256'
                    user_info = user.password.split("$")
                    iterations = user_info[2]
                    salt = user_info[3]
                    passhash = user_info[4]
                else:
                    raise ValueError("This account ({}) already has "
                        "a shielded/protector value!".format(user.username))

            assert algorithm == 'pbkdf2_sha256', \
                "Cannot update hash for user {0}, hasher ({1}) not supported.".format(
                            user.username, algorithm)


            new_passhash, sharenumber = self.hasher.update_hash_threshold(
                    passhash)

            new_password = "pph${0}${1}${2}${3}".format(sharenumber, iterations,
                    salt, new_passhash)

            user.password = new_password

        # I separate the loops so I don't save users unless the information
        # actually works
        print("Saving threshold accounts....")
        for user in users:
            user.save() 


        # now update the rest of the existing accounts:
        print("Updating thresholdless accounts...")
        target_users = User.objects.all()

        for user in target_users:

            # check that we don't reupdate hashes
            if user.password.startswith('pph'):
                continue

            if not user.password.startswith('pbkdf2_sha256'):
                print("Unsupported hashing format for username {0}, skipping.".format(
                    user.username))
                continue

            algorithm, iterations, salt, passhash = user.password.split("$")

            new_passhash = self.hasher.update_hash_thresholdless(passhash)

            new_password = "pph$0${0}${1}${2}".format(iterations, salt,
                    new_passhash)

            user.password = new_password
            user.save()

        print("Database initialized")
        share_cache.set("is_initialized", True)


    
