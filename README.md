PolyPasswordHasher-Django
===================

Django password hasher using the PolyPasswordHasher algo

For installation and usage instructions, visit (this wikipage)[https://github.com/PolyPasswordHasher/PolyPasswordHasher-Django/wiki/Installing-and-Using-the-PolyPasswordHasher-for-Django].

Installation and Usage
======================

* [Installation](#installation)
  * [Getting the sources](#getting_sources)
  * [Installing django_pph in a new server](#new_server)
    * [Configuring the settings file](#settings file)
    * [Running the server and assigning a secret](#set_secret)
    * [Adding threshold accounts](#set_threshold)
  * [Django_pph in an existing application (migration using south)](#south)
* [Using Django_pph](#usage)
  * [Configuring the logger for break-in alerts](#configure_logger")
  * [Management commands](#management_commands)
    * [promote_user](#promote_user)
    * [demote_user](#demote_user)
    * [Initialize_pph_context](#intialize_pph_context)

<a name="installation"/>
# Installation

Django_pph can be installed in both, new servers and existing servers. Here, we describe how to setup the hasher for either case. 

<a name="getting_sources" />
## Getting the sources
The sources can be downloaded [here](https://github.com/PolyPasswordHasher/PolyPasswordHasher-Django/archive/master.zip). After downloading, uncompress and copy the django_pph folder to the root of
your application.

<a name="new_server"/>
## Installing django_pph New server.

To install and run django_pph in a new server you must do three basic steps:

1. Edit the settings.py file inside your configuration script
2. Run the server
3. Create a secret and add administrative accounts.

The upcoming subsections will describe these steps in depth.

<a name="settings file" />
### Configuring the settings file.

The settings file will contain the elements for every application that's installed. Django_pph specific settings are also set there. 

First, we will describe the basic setup to have a vanilla django_pph application running. Afterwards, we will focus on setting polypasswordhasher-specific settings to taylor the hasher to our needs. 

#### Basic setup.

In order to work, a Django PPH server must at least contain the following elements in the settings.py file:

```python
INSTALLED_APPS = (
    'django.contrib.auth',
     ...
    'django_pph',
)

PASSWORD_HASHERS = (
    'django_pph.hashers.PolyPasswordHasher',
    ...
)

CACHES={
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
    },
    'pph': {
        'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache',
        'LOCATION': 'pph_cache',
        'TIMEOUT': None,
    }
}

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '%(levelname)s %(asctime)s %(module)s %(process)d %(thread)d %(message)s',
        },
        'simple': {
            'format': '%(levelname)s %(message)s',
        },
    },
    'handlers': {
        'file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': '/path/to/log.log',
            'formatter':'verbose',
        },
    },
    'loggers': {
        'django.security.PPH': {
            'handlers': ['file'],
            'level': 'DEBUG',
            'propagate': True,
        },
    },
}

```

#### Customization
After setting django pph, you can also modify some hasher-specific settings to meet your server's configuration. The following list displays the possible parameters 
* THRESHOLD: sets the minimum number of threshold accounts to unlock the store.
* PARTIALBYTES: sets the amount of bytes to leak from the hash in order to provide partial verification.
* SECRET_VERIFICATION_BYTES: this sets the number of bytes for the checksum to verify upon recombination. 
* SECRET_LENGTH: The length of the secret, this should match the length of the hash.

To set any of these values, you should overwrite them in your settings.py inside the PPH_SETTINGS variable. The following code listing shows an example of this:

```python
PPH_SETTINGS = (
    THRESHOLD = 2,
    PARTIAL_BYTES = 6,
)
```

Out of these fields, threshold and partial bytes are the ones that leave the most space for configuration. secret length and secret verification bytes offer little space to play and we advise to leave them in their default setup. Having said this, we will describe threshold and partial_bytes next.

**Setting the threshold**

The threshold is a value that directly maps to the number of administrative users you want to consider in your server's configuration. 

For the PolyPasswordHasher, there exists two types of hashes: threshold and thresholdless. Threshold accounts are the ones that are able to unlock the store after a reboot. Because of this, it is important to only allow this capability to active and trusted users/administrators. 

If, for example, there are 5 administrators inside your server, a good idea is to set the threshold to 3 or 4, to ensure that after a reboot it is possible to unlock the store right away. You can look at [broken_link](broken) for more explanation about how to pick this value. Do not choose a threshold value higher than the number of trusted administrators of users or else it will be impossible to unlock the store after that.

**Setting the number of partial bytes**

Partial bytes provide partial verification. In essence, we leak a part of the hash to allow users to log-in in case the threshold accounts take a while to respond upon a server reboot. The higher this number is set, the more information about the original hash is leaked, so try not to leak more information. However, if you set this value too low, it would be possible that someone can login with wrong credentials. A safe value for this is four to six bytes. 

You can learn more about partial bytes in this [broken_link](broken_link)

<a name="set_secret" />
### Running the server and assigning a secret.

After the settings file is properly configured, we are able to use the server right away. In order to start the server we run the following administrator command:

```bash
$ ./manage.py runserver
```

Once the server is running, we need to create the secret for the polypasswordhasher store. We create a secret and unlock the store for the first time by issuing the following command:

```bash
$ ./manage.py initialize_pph_context
```

Now we have a secret and the context is initialized. We can proceed to the last step. 

> **Warning, using this command with an already running application could overwrite the secret and yield an inconsistent store**

<a name="set_threshold" />
### Adding threshold accounts.

Lastly, we want to create a number of threshold accounts higher than the threshold we configured in step one. We must issue the following commands for each user:

```bash
$ ./manage.py createsuperuser [username]
$ ./manage.py promote_user [username]
```

The first command creates an account and second command makes the account count towards the threshold. This should be repeated threshold-number of times. Notice that you could create non-superuser accounts with another command (e.g. the administrator console) and then promote them in the same way.

Congratulations! Now we have a django_pph enabled application from scratch.

<a name="south" />
## Django_pph in an existing application (migration using south)

In case we already have a server running our Django application, we must first migrate all of the information using south. In order to do this we must first install south:

```bash
$ pip install south
```

After a successful installation of south, we must add the following line to the settings.py file:

```python
INSTALLED_APPS = (
    'django.contrib.auth',
    ...
    'django_pph',
    'south',
)

SOUTH_MIGRATION_MODULES = {
    'auth' : 'django_pph.migrations'
}
```

This instructs south to search for the migration procedures for the authentication backend in the django_pph folder and installs both: django_pph and south to our server's applications. Remember that you must also add the config settings displayed in the previous section in order to have django_pph working.

Finally, in order to run the migration, we issue the following command

```bash
$ ./manage.py migrate auth
```

This will run our south migration script and leave the database in a consistent state. Threshold accounts in here are selected as the administrative accounts. 

> **WARNING, consider backing up your database before running the migration script**

Congratulations! Now you have a complete setup of django_pph in your application.

<a name="usage" />
# Using Django_pph.

In this section you can find extensions to the bare-bones installation of django_pph as well as description of some administration commands that make it useful for maintaining your system. 

<a name="configure_logger" />
## Configuring the logger for break-in alerts

The django_pph application uses the default django logger in order to notify the administrator of certain errors and break-in attempts. One feature of this is the ability to plug the logger messages of certain level (e.g. error) to an e-mail handler. By doing this, we are able to be notified when events such as a possible database-leak has ocurred. 

In this section we will provide an example configuration of the django_pph logger that notifies administrators of break-in scenarios by sending an email. The following code snipped is to be modified in the original settings.py and inside the logger variable:

```python
    'handlers': {
        'file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': '/path/to/log.log',
            'formatter':'verbose',
        },
        'mail_admins': {
             'level': 'ERROR',
             'class': 'django.utils.log.AdminEmailHandler'
    },
    'loggers': {
        'django.security.PPH': {
            'handlers': ['mail_admins'],
            'level': 'DEBUG',
            'propagate': True,
        },
    },
```

Also, you might want to set the following variable:

```python
SERVER_EMAIL = '[application]@[domain].com'
```
So you know where it comes from.

 Some versions of Django require that you unset the DEBUG variable in order to work.

<a name="management_commands" />
## Management commands

Django_pph comes with three management commands. Two of them, promote_ and demote_user, provide the ability to manage which accounts count towards the threshold to unlock a store. The third one, initialize_pph_context, should be only called when the application is first launched. 

The following sections contain a detailed description of the management commands.

<a name="promote_user" />
### promote_user

```bash
$ ./manage.py promote_user [username]
```

#### Arguments
Promote user only takes the desired username to promote as its first argument; further arguments will be ignored by the command.

The context doesn't need to be unlocked in order for the command to succeed.

#### Errors
This command will fail under the following scenarios:
* The username does not exist.
* There are repeated usernames (this means your database is malformed).
* The username is already part of the threshold accounts.

<a name="demote_user" />
### demote_user

```python
./manage.py demote_user [username]
```

This command removes a user from the accounts that count towards the threshold in the secret-recombination phase. In case a user becomes inactive or shouldn't be trusted, we advise to run this command right away. 

In contrast to promote_user, this command needs an unlocked store in order to demote a user.

#### Arguments 
Promote user only takes the desired username to promote as its first argument; further arguments will be ignored by the command.

#### Errors
Demote user will fail in the following scenarios
* There are not enough threshold accounts to unlock the store after demoting the target user
* There are more than one usernames (the database is inconsistent)
* The username didn't belong to a threshold account
* The store is not unlocked.

<a name="intialize_pph_context" />
### Initialize_pph_context

```bash
$ ./manage.py initialize_pph_context
```

This command is only meant to be ran during the first run of the django_pph application. When using migrations, this command is already run by the migration script and it is, therefore, unnecessary to run it afterwards.

Be careful when running this command, since it might yield the authentication database useless. Remember always to have backups of your database.

#### Arguments
None

#### Errors
If the application is properly configured, this command shouldn't fail.
