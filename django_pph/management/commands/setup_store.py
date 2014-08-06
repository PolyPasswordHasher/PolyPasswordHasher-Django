from django.core.management.base import BaseCommand
from django.contrib.auth.hashers import get_hasher
from django.utils.crypto import get_random_string
from django.contrib.auth.models import User
from django.core.management import call_command

from django_pph.shamirsecret import ShamirSecret
from django_pph.settings import SETTINGS
from django_pph.utils import cache, bin64enc, binary_type
from django_pph.management.commands import initialize_pph_context, promote_user


class Command(BaseCommand):

    help = 'Initializes the polypasswordhasher store with a new secret and ' +\
        'updates the database'

    hasher = get_hasher('pph')

    def handle(self, *args, **options):
        
        # TODO: require confirmation
       
        call_command("initialize_pph_context", None, None)

        threshold = self.hasher.threshold
       
        assert len(args) >= threshold, "Not enough user to create a store " + \
        "with the current settings."

        users = []
        for username in args:
            target_user = User.objects.filter(username=username)
            assert len(target_user) == 1, \
            "there is no {0} user or the database is corrupted".format(username)
            users.append(target_user[0])

        assert len(users) >= threshold, \
            "Coudldn't gather enough accounts for store creation" 


        print("Creating threshold accounts...")
        for user in users:
            algorithm, iterations, salt, passhash = user.password.split('$')

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
                print("Unsupported hashing format for username {0}, skipping.".format(user.username))
                continue

            algorithm, iterations, salt, passhash = user.password.split("$")

            new_passhash = self.hasher.update_hash_thresholdless(passhash)

            new_password = "pph$0${0}${1}${2}".format(iterations, salt,
                    new_passhash)

            user.password = new_password
            user.save()



    
