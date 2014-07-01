from setuptools import setup, find_packages

setup(
    name='django-polypasshash',
    version='0.1.0',
    packages=find_packages(),
    zip_safe=False,
    author="Justin Cappos",
    author_email="jcappos@poly.edu",
    install_requires=[
        "pycrypto"
    ],
    classifiers=['Development Status :: 3 - Alpha',
                 'Intended Audience :: Developers',
                 'Intended Audience :: Science/Research',
                 'Intended Audience :: System Administrators',
                 'Environment :: Web Environment',
                 'Framework :: Django',
                 'License :: OSI Approved :: MIT License',
                 'Operating System :: OS Independent',
                 'Programming Language :: Python :: 2',
                 'Programming Language :: Python :: 3',
                 'Topic :: Security :: Cryptography',
                 'Topic :: Utilities'],
)
