#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_cgnv6_fixed_nat_inside_ipv4address
description:
    - Configure Fixed NAT
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
    inside_start_address:
        description:
        - "IPv4 Inside User Start Address"
        type: str
        required: True
    inside_end_address:
        description:
        - "IPv4 Inside User End Address"
        type: str
        required: True
    inside_netmask:
        description:
        - "IPv4 Netmask"
        type: str
        required: True
    partition:
        description:
        - "Inside User Partition (Partition Name)"
        type: str
        required: True
    nat_ip_list:
        description:
        - "Name of IP List used to specify NAT addresses"
        type: str
        required: False
    nat_start_address:
        description:
        - "Start NAT Address"
        type: str
        required: False
    nat_end_address:
        description:
        - "IPv4 End NAT Address"
        type: str
        required: False
    nat_netmask:
        description:
        - "NAT Addresses IP Netmask"
        type: str
        required: False
    vrid:
        description:
        - "VRRP-A vrid (Specify ha VRRP-A vrid)"
        type: int
        required: False
    dest_rule_list:
        description:
        - "Bind destination based Rule-List (Fixed NAT Rule-List Name)"
        type: str
        required: False
    dynamic_pool_size:
        description:
        - "Configure size of Dynamic pool (Default= 0)"
        type: int
        required: False
    method:
        description:
        - "'use-all-nat-ips'= Use all the NAT IP addresses configured; 'use-least-nat-
          ips'= Use the least number of NAT IP addresses required (default);"
        type: str
        required: False
    offset:
        description:
        - "Field offset"
        type: dict
        required: False
        suboptions:
            random:
                description:
                - "Randomly choose the first NAT IP address"
                type: bool
            numeric_offset:
                description:
                - "Configure a numeric offset to the first NAT IP address"
                type: int
    ports_per_user:
        description:
        - "Configure Ports per Inside User (ports-per-user)"
        type: int
        required: False
    respond_to_user_mac:
        description:
        - "Use the user's source MAC for the next hop rather than the routing table
          (Default= off)"
        type: bool
        required: False
    session_quota:
        description:
        - "Configure per user quota on sessions"
        type: int
        required: False
    usable_nat_ports:
        description:
        - "Field usable_nat_ports"
        type: dict
        required: False
        suboptions:
            usable_start_port:
                description:
                - "Start Port of Usable NAT Ports"
                type: int
            usable_end_port:
                description:
                - "End Port of Usable NAT Ports"
                type: int
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False

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
    "dest_rule_list",
    "dynamic_pool_size",
    "inside_end_address",
    "inside_netmask",
    "inside_start_address",
    "method",
    "nat_end_address",
    "nat_ip_list",
    "nat_netmask",
    "nat_start_address",
    "offset",
    "partition",
    "ports_per_user",
    "respond_to_user_mac",
    "session_quota",
    "usable_nat_ports",
    "uuid",
    "vrid",
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
        'inside_start_address': {
            'type': 'str',
            'required': True,
        },
        'inside_end_address': {
            'type': 'str',
            'required': True,
        },
        'inside_netmask': {
            'type': 'str',
            'required': True,
        },
        'partition': {
            'type': 'str',
            'required': True,
        },
        'nat_ip_list': {
            'type': 'str',
        },
        'nat_start_address': {
            'type': 'str',
        },
        'nat_end_address': {
            'type': 'str',
        },
        'nat_netmask': {
            'type': 'str',
        },
        'vrid': {
            'type': 'int',
        },
        'dest_rule_list': {
            'type': 'str',
        },
        'dynamic_pool_size': {
            'type': 'int',
        },
        'method': {
            'type': 'str',
            'choices': ['use-all-nat-ips', 'use-least-nat-ips']
        },
        'offset': {
            'type': 'dict',
            'random': {
                'type': 'bool',
            },
            'numeric_offset': {
                'type': 'int',
            }
        },
        'ports_per_user': {
            'type': 'int',
        },
        'respond_to_user_mac': {
            'type': 'bool',
        },
        'session_quota': {
            'type': 'int',
        },
        'usable_nat_ports': {
            'type': 'dict',
            'usable_start_port': {
                'type': 'int',
            },
            'usable_end_port': {
                'type': 'int',
            }
        },
        'uuid': {
            'type': 'str',
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/fixed-nat/inside/ipv4address/{inside-start-address}+{inside-end-address}+{inside-netmask}+{partition}"

    f_dict = {}
    f_dict["inside-start-address"] = module.params["inside_start_address"]
    f_dict["inside-end-address"] = module.params["inside_end_address"]
    f_dict["inside-netmask"] = module.params["inside_netmask"]
    f_dict["partition"] = module.params["partition"]

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
    url_base = "/axapi/v3/cgnv6/fixed-nat/inside/ipv4address/{inside-start-address}+{inside-end-address}+{inside-netmask}+{partition}"

    f_dict = {}
    f_dict["inside-start-address"] = ""
    f_dict["inside-end-address"] = ""
    f_dict["inside-netmask"] = ""
    f_dict["partition"] = ""

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
        for k, v in payload["ipv4address"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["ipv4address"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["ipv4address"][k] = v
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
    payload = build_json("ipv4address", module)
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
