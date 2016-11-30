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
    assert len(target_user) == 1, \
        "there is no such user or the database is corrupted"

    hasher = get_hasher('pph')
    hasher.load()

    for user in target_user:
        encoded = user.password
        new_password = hasher.promote_hash(encoded)
        user.password = new_password
        user.save()

class Command(BaseCommand):

    help = 'Adds a thresholdless user to the threshold accounts'

    def add_arguments(self, parser):
        parser.add_argument('user_id', nargs='+',
                            help=("the target username to add to "
                                  "thresholdless accounts"))

    def handle(self, *args, **options):

        for username in options['user_id']:
            promote_user(username)
