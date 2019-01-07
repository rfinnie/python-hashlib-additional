#!/usr/bin/env python3

import os
import sys
from setuptools import setup, find_packages

assert(sys.version_info > (3, 4))


def read(filename):
    return open(os.path.join(os.path.dirname(__file__), filename)).read()


setup(
    name='hashlib_additional',
    description='Additional hashlib-compatible hashing digests',
    long_description=read('README'),
    version='1.0',
    license='BSD',
    platforms=['Unix'],
    author='Ryan Finnie',
    author_email='ryan@finnie.org',
    url='https://github.com/rfinnie/python-hashlib_additional',
    download_url='https://github.com/rfinnie/python-hashlib_additional',
    packages=find_packages(),
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    test_suite='tests',
)

