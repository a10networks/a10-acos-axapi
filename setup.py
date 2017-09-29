#!/usr/bin/env python
# flake8: noqa

from setuptools import setup, find_packages

setup(
    name = "a10-ansible",
    version = "0.0.1",
    packages = find_packages(),

    author = "A10 Networks",
    author_email = "mdurrant@a10networks.com",
    description = "A10 Networks Ansible Module",
    license = "Apache",
    keywords = "a10 axapi ansible acos adc slb load balancer",
    url = "https://github.com/a10networks/a10-ansible",

    long_description = open('README.md').read(),

    classifiers = [
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: POSIX',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Topic :: Internet',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],

    install_requires = ['paramiko', 'PyYAML', 'jinja2', 'httplib2', 'passlib', 'six']

)
