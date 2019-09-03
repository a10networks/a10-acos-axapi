
from setuptools import setup
setup(name='a10_ansible',
      version='0.0.1',
      description='Ansible support for A10 AXAPI',
      url='http://github.com/a10networks/a10-ansible',
      author='A10 Networks',
      author_email='mdurrant@a10networks.com',
      license='MIT',
      packages=['a10_ansible'],
      zip_safe=False,
      install_requires=['requests']
      # Install scripts for calling this easily.
      # Need to figure out an easy way of making this a script.
     )
