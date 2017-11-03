#/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2017 A10 Networks
#


# ANSIBLE_METADATA = {'status': ['preview'],
#                     'supported_by': 'community',
#                     'version': '1.0'}
from ansible.module_utils.basic import AnsibleModule

from acos_client import errors as acos_errors
from acos_client.client import Client

REQUIRED_DEFAULT = ['host', 'version', 'username', 'password']
AXAPI_VERSIONS = [2.1, 3.0]
AXAPI_PORT_PROTOCOLS = {
    'tcp': 2,
    'udp': 3,
}

AXAPI_VPORT_PROTOCOLS = {
    'tcp': 2,
    'udp': 3,
    'fast-http': 9,
    'http': 11,
    'https': 12,
}

DEFAULT_ARGUMENT_SPEC = dict( 
    a10_host=dict(type='str', required=True),
    a10_version=dict(type='float', default=None),
    a10_username=dict(type='str', required=True),
    a10_password=dict(type='str', required=True, no_log=True),
    a10_port=dict(type='int', default=443, required=False),
    a10_partition=dict(type="str", required=False),
    a10_protocol=dict(type="str", required=False, default="https", choices=["http", "https"])
)


def a10_argument_spec():
    return DEFAULT_ARGUMENT_SPEC

def axapi_enabled_disabled(flag):
    '''
    The axapi uses 0/1 integer values for flags, rather than strings
    or booleans, so convert the given flag to a 0 or 1. For now, params
    are specified as strings only so thats what we check.
    '''
    if flag == 'enabled':
        return 1
    else:
        return 0


def axapi_get_port_protocol(protocol):
    return AXAPI_PORT_PROTOCOLS.get(protocol.lower(), None)


def axapi_get_vport_protocol(protocol):
    return AXAPI_VPORT_PROTOCOLS.get(protocol.lower(), None)


def axapi_failure(result):
    if result is None:
        return True 
    if 'response' in result and result['response'].get('status') == 'fail':
        return True
    return False



def test_a10_argument_spec():
    actual = a10_argument_spec()
    assert actual.get("a10_host", None) is not None, "host was none"
    assert actual.get("a10_username", None) is not None, "username was none"
    assert actual.get("a10_password", None) is not None, "password was none"
    assert actual.get("a10_version", None) is not None, "version was none"
    assert actual.get("a10_port", None) is not None, "port was none"
    assert actual.get("a10_protocol", None) is not None, "protocol was none"


def client_factory(params):
    return Client(params["a10_host"],
                  params["a10_version"],
                  params["a10_username"],
                  params["a10_password"],
                  params["a10_port"],
                  params["a10_protocol"])


def a10_module(*args, **kwargs):
    module = AnsibleModule(*args, **kwargs)
    module.client = kwargs.get("client") or client_factory(module.params)
    partition = module.params["a10_partition"]
    if partition:
        module.client.system.partition.active(partition)
    return module


def main():
    test_a10_argument_spec()


if __name__ == "__main__":
    main()
