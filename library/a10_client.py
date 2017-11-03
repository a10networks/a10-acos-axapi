#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2017 A10 Networks
#


# ANSIBLE_METADATA = {'status': ['preview'],
#                     'supported_by': 'community',
#                     'version': '1.0'}

DOCUMENTATION = '''
---
module: a10_base
short_description: Base module for a10 actions
description:
  - Provide base client functionality for a10 devices.
# TODO(mdurrant) - Check if this is necessary.
# version_added: "2.2"
options:
  host:
    description:
      - Specifies the admin host/IP address of A10 ADC
    required: true
  version:
    description:
      - Specifies the API version of the A10 ADC
    required: true
    choices:
       - 2.1
       - 3.0
  username:
    description:
      - The username to authenticate to the admin interface for the A10 ADC
    required: true
  password:
    description:
      - The password to authenticate to the admin interface for the A10 ADC
    required: true
  port:
    description:
      - The TCP port of the admin interface for the A10 ADC
    required: False 
    default: 443

notes:
  - Requires the acos-client Python package on the host. This should be installed
        with this package.

# extends_documentation_fragment: a10
requirements:
  - acos-client
author:
# TODO(documentation) - Put in a better email address for support.
  - A10 Networks (support@a10networks.com)
'''

EXAMPLES = '''
- name: Set the client settings
  a10_base:
      host: 10.10.10.10
      version: 2.1
      username="admin"
      password: "a10"
      port: 443
'''

RETURN = '''
retval:
    description: Return value
    returned: changed
    type: string
    sample: "retval"
'''

from ansible.module_utils.basic import *
from a10_base import a10_module,a10_argument_spec,REQUIRED_DEFAULT


def main():
    argument_spec = a10_argument_spec()
    module = a10_module(
        argument_spec=argument_spec,
        required_one_of=[REQUIRED],
        supports_check_mode=True
    )

if __name__ == '__main__':
    main()
