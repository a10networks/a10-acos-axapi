#/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2017 A10 Networks
#


# ANSIBLE_METADATA = {'status': ['preview'],
#                     'supported_by': 'community',
#                     'version': '1.0'}
from acos_client import errors as acos_errors
from acos_client.client import Client
from a10_base import * 

STATE_PRESENT = "present"
STATE_ABSENT = "absent"

DEFAULT_CREATE = "create"
DEFAULT_DELETE = "delete"
DEFAULT_UPDATE = "update"
DEFAULT_GET = "get"

DEFAULT_KEY_MAP = {
    "a10_host": "host",
    "a10_username": "username",
    "a10_password": "password",
    "a10_port": "port",
    "a10_protocol": "protocol",
    "a10_partition": "partition",
} 

ACTION_KEY_MAP = {
    DEFAULT_CREATE: DEFAULT_KEY_MAP,
    DEFAULT_DELETE: DEFAULT_KEY_MAP,
    DEFAULT_UPDATE: DEFAULT_KEY_MAP,
    DEFAULT_GET: DEFAULT_KEY_MAP 
} 

def get_default_argspec(other_argset={}):
    other_argset.update(DEFAULT_ARGUMENT_SPEC)
    return other_argset

def _get_keymap(action, action_args={}):
   return ACTION_KEY_MAP.get(action, {}).update(action_args) 

def _get_args(action, params):
    rv = {}
    key_map = ACTION_KEY_MAP[action]
    for k in key_map:
        rv[key_map[k]] = params[k]
    return rv


def _get_call(module, action):
    return getattr(module.mod_path, action)


def _write(module, action, params):
    if params and action and module and module.client and module.mod_path:
        func = _get_call(module, action)
        args = _get_args(action, params)
        return func(**args)


def _create(module, params):
    return _write(module, DEFAULT_CREATE, params)

def _update(module, params):
    return _write(module, DEFAULT_UPDATE, params)

def _delete(module, params):
    return _write(module, DEFAULT_DELETE, params)

def _get(module, params):
    return _write(module, DEFAULT_GET, params) 

def create(module, params):
    try:
        return _create(module, params)
    except acos_errors.Exists:
        return None

def update(module, params):
    return _update(module, params)

def delete(module, params):
    return _delete(module, params)

def get(module, params):
    try:
        return _get(module, params)
    except acos_errors.NotFound:
        return None
         

def run_command(module):
    # Ensures commands are fully defined
    if not ACOS_PATH:
        raise NotImplementedError()

    if "state" in module.params:
        if module.params["state"] == STATE_PRESENT:
            return update(module, module.params)
        if module.params["state"] == STATE_ABSENT:
            return delete(module, module.params)
    else:
        return create(module, module.params)
        
