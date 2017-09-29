#/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2017 A10 Networks
#


# ANSIBLE_METADATA = {'status': ['preview'],
#                     'supported_by': 'community',
#                     'version': '1.0'}

def a10_argument_spec():
    return dict(
        host=dict(type='str', required=True),
        version=dict(type='float', default=None),
        username=dict(type='str', required=True),
        password=dict(type='str', required=True, no_log=True),
        port=dict(type='int', default=443, required=False),
    )


def test_a10_argument_spec():
    actual = a10_argument_spec()
    assert actual.get("host", None) is not None, "host was none"
    assert actual.get("username", None) is not None, "username was none"
    assert actual.get("password", None) is not None, "password was none"
    assert actual.get("version", None) is not None, "version was none"
    assert actual.get("port", None) is not None, "port was none"


def main():
    test_a10_argument_spec()


if __name__ == "__main__":
    main()
