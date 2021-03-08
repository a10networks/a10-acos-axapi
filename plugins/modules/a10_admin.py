#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_admin
description:
    - System admin user configuration
author: A10 Networks 2021
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - noop
          - present
          - absent
        type: str
        required: True
    ansible_host:
        description:
        - Host for AXAPI authentication
        type: str
        required: True
    ansible_username:
        description:
        - Username for AXAPI authentication
        type: str
        required: True
    ansible_password:
        description:
        - Password for AXAPI authentication
        type: str
        required: True
    ansible_port:
        description:
        - Port for AXAPI authentication
        type: int
        required: True
    a10_device_context_id:
        description:
        - Device ID for aVCS configuration
        choices: [1-8]
        type: int
        required: False
    a10_partition:
        description:
        - Destination/target partition for object/command
        type: str
        required: False
    user:
        description:
        - "System admin user name"
        type: str
        required: True
    password_key:
        description:
        - "Config admin user password"
        type: bool
        required: False
    passwd_string:
        description:
        - "Config admin user password"
        type: str
        required: False
    action:
        description:
        - "'enable'= Enable user; 'disable'= Disable user;"
        type: str
        required: False
    unlock:
        description:
        - "Unlock admin user"
        type: bool
        required: False
    trusted_host:
        description:
        - "Set trusted network administrator can login in"
        type: bool
        required: False
    trusted_host_cidr:
        description:
        - "Trusted IP Address with network mask"
        type: str
        required: False
    access_list:
        description:
        - "Specify an ACL to classify a trusted host"
        type: bool
        required: False
    trusted_host_acl_id:
        description:
        - "ACL ID"
        type: int
        required: False
    privilege_global:
        description:
        - "'read'= Set read privilege; 'write'= Set write privilege; 'hm'= Set external
          health monitor script content operations privilege;"
        type: str
        required: False
    privilege_list:
        description:
        - "Field privilege_list"
        type: list
        required: False
        suboptions:
            privilege_partition:
                description:
                - "'partition-enable-disable'= Set per-partition enable/disable privilege;
          'partition-read'= Set per-partition read privilege; 'partition-write'= Set per-
          partition write privilege;"
                type: str
            partition_name:
                description:
                - "Partition Name"
                type: str
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    user_tag:
        description:
        - "Customized tag"
        type: str
        required: False
    aws_accesskey:
        description:
        - "Field aws_accesskey"
        type: dict
        required: False
        suboptions:
            nimport:
                description:
                - "Import an aws-accesskey"
                type: bool
            use_mgmt_port:
                description:
                - "Use management port as source port"
                type: bool
            file_url:
                description:
                - "File URL"
                type: str
            delete:
                description:
                - "Delete an authorized aws accesskey"
                type: bool
            show:
                description:
                - "Show authorized aws accesskey"
                type: bool
    ssh_pubkey:
        description:
        - "Field ssh_pubkey"
        type: dict
        required: False
        suboptions:
            nimport:
                description:
                - "Import an authorized public key"
                type: bool
            use_mgmt_port:
                description:
                - "Use management port as source port"
                type: bool
            file_url:
                description:
                - "File URL"
                type: str
            delete:
                description:
                - "Delete an authorized public key (SSH key index)"
                type: int
            list:
                description:
                - "List all authorized public keys"
                type: bool
    access:
        description:
        - "Field access"
        type: dict
        required: False
        suboptions:
            access_type:
                description:
                - "Field access_type"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    password:
        description:
        - "Field password"
        type: dict
        required: False
        suboptions:
            password_in_module:
                description:
                - "Config admin user password"
                type: str
            encrypted_in_module:
                description:
                - "Specify an ENCRYPTED password string (System admin user password)"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str

'''

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "access",
    "access_list",
    "action",
    "aws_accesskey",
    "passwd_string",
    "password",
    "password_key",
    "privilege_global",
    "privilege_list",
    "ssh_pubkey",
    "trusted_host",
    "trusted_host_acl_id",
    "trusted_host_cidr",
    "unlock",
    "user",
    "user_tag",
    "uuid",
]

from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str',
                   default="present",
                   choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(
            type='dict',
            name=dict(type='str', ),
            shared=dict(type='str', ),
            required=False,
        ),
        a10_device_context_id=dict(
            type='int',
            choices=[1, 2, 3, 4, 5, 6, 7, 8],
            required=False,
        ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )


def get_argspec():
    rv = get_default_argspec()
    rv.update({
        'user': {
            'type': 'str',
            'required': True,
        },
        'password_key': {
            'type': 'bool',
        },
        'passwd_string': {
            'type': 'str',
        },
        'action': {
            'type': 'str',
            'choices': ['enable', 'disable']
        },
        'unlock': {
            'type': 'bool',
        },
        'trusted_host': {
            'type': 'bool',
        },
        'trusted_host_cidr': {
            'type': 'str',
        },
        'access_list': {
            'type': 'bool',
        },
        'trusted_host_acl_id': {
            'type': 'int',
        },
        'privilege_global': {
            'type': 'str',
            'choices': ['read', 'write', 'hm']
        },
        'privilege_list': {
            'type': 'list',
            'privilege_partition': {
                'type':
                'str',
                'choices': [
                    'partition-enable-disable', 'partition-read',
                    'partition-write'
                ]
            },
            'partition_name': {
                'type': 'str',
            }
        },
        'uuid': {
            'type': 'str',
        },
        'user_tag': {
            'type': 'str',
        },
        'aws_accesskey': {
            'type': 'dict',
            'nimport': {
                'type': 'bool',
            },
            'use_mgmt_port': {
                'type': 'bool',
            },
            'file_url': {
                'type': 'str',
            },
            'delete': {
                'type': 'bool',
            },
            'show': {
                'type': 'bool',
            }
        },
        'ssh_pubkey': {
            'type': 'dict',
            'nimport': {
                'type': 'bool',
            },
            'use_mgmt_port': {
                'type': 'bool',
            },
            'file_url': {
                'type': 'str',
            },
            'delete': {
                'type': 'int',
            },
            'list': {
                'type': 'bool',
            }
        },
        'access': {
            'type': 'dict',
            'access_type': {
                'type': 'str',
                'choices': ['axapi', 'cli', 'web']
            },
            'uuid': {
                'type': 'str',
            }
        },
        'password': {
            'type': 'dict',
            'password_in_module': {
                'type': 'str',
            },
            'encrypted_in_module': {
                'type': 'str',
            },
            'uuid': {
                'type': 'str',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/admin/{user}"

    f_dict = {}
    f_dict["user"] = module.params["user"]

    return url_base.format(**f_dict)


def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]


def get(module):
    return module.client.get(existing_url(module))


def get_list(module):
    return module.client.get(list_url(module))


def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None


def _to_axapi(key):
    return translateBlacklist(key, KW_OUT).replace("_", "-")


def _build_dict_from_param(param):
    rv = {}

    for k, v in param.items():
        hk = _to_axapi(k)
        if isinstance(v, dict):
            v_dict = _build_dict_from_param(v)
            rv[hk] = v_dict
        elif isinstance(v, list):
            nv = [_build_dict_from_param(x) for x in v]
            rv[hk] = nv
        else:
            rv[hk] = v

    return rv


def build_envelope(title, data):
    return {title: data}


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/admin/{user}"

    f_dict = {}
    f_dict["user"] = ""

    return url_base.format(**f_dict)


def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([
        x for x in requires_one_of if x in params and params.get(x) is not None
    ])

    errors = []
    marg = []

    if not len(requires_one_of):
        return REQUIRED_VALID

    if len(present_keys) == 0:
        rc, msg = REQUIRED_NOT_SET
        marg = requires_one_of
    elif requires_one_of == present_keys:
        rc, msg = REQUIRED_MUTEX
        marg = present_keys
    else:
        rc, msg = REQUIRED_VALID

    if not rc:
        errors.append(msg.format(", ".join(marg)))

    return rc, errors


def build_json(title, module):
    rv = {}

    for x in AVAILABLE_PROPERTIES:
        v = module.params.get(x)
        if v is not None:
            rx = _to_axapi(x)

            if isinstance(v, dict):
                nv = _build_dict_from_param(v)
                rv[rx] = nv
            elif isinstance(v, list):
                nv = [_build_dict_from_param(x) for x in v]
                rv[rx] = nv
            else:
                rv[rx] = module.params[x]

    return build_envelope(title, rv)


def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["admin"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["admin"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["admin"][k] = v
            result.update(**existing_config)
    else:
        result.update(**payload)
    return result


def create(module, result, payload):
    try:
        post_result = module.client.post(new_url(module), payload)
        if post_result:
            result.update(**post_result)
        result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def update(module, result, existing_config, payload):
    try:
        post_result = module.client.post(existing_url(module), payload)
        if post_result:
            result.update(**post_result)
        if post_result == existing_config:
            result["changed"] = False
        else:
            result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def present(module, result, existing_config):
    payload = build_json("admin", module)
    changed_config = report_changes(module, result, existing_config, payload)
    if module.check_mode:
        return changed_config
    elif not existing_config:
        return create(module, result, payload)
    elif existing_config and not changed_config.get('changed'):
        return update(module, result, existing_config, payload)
    else:
        result["changed"] = True
        return result


def delete(module, result):
    try:
        module.client.delete(existing_url(module))
        result["changed"] = True
    except a10_ex.NotFound:
        result["changed"] = False
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def absent(module, result, existing_config):
    if module.check_mode:
        if existing_config:
            result["changed"] = True
            return result
        else:
            result["changed"] = False
            return result
    else:
        return delete(module, result)


def replace(module, result, existing_config, payload):
    try:
        post_result = module.client.put(existing_url(module), payload)
        if post_result:
            result.update(**post_result)
        if post_result == existing_config:
            result["changed"] = False
        else:
            result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def run_command(module):
    run_errors = []

    result = dict(changed=False, original_message="", message="", result={})

    state = module.params["state"]
    ansible_host = module.params["ansible_host"]
    ansible_username = module.params["ansible_username"]
    ansible_password = module.params["ansible_password"]
    ansible_port = module.params["ansible_port"]
    a10_partition = module.params["a10_partition"]
    a10_device_context_id = module.params["a10_device_context_id"]

    if ansible_port == 80:
        protocol = "http"
    elif ansible_port == 443:
        protocol = "https"

    valid = True

    if state == 'present':
        valid, validation_errors = validate(module.params)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(ansible_host, ansible_port, protocol,
                                   ansible_username, ansible_password)

    if a10_partition:
        module.client.activate_partition(a10_partition)

    if a10_device_context_id:
        module.client.change_context(a10_device_context_id)

    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)

    if state == 'absent':
        result = absent(module, result, existing_config)

    if state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
    module.client.session.close()
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


# standard ansible module imports
from ansible.module_utils.basic import AnsibleModule

if __name__ == '__main__':
    main()
