#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_axdebug_filter_config
description:
    - Global debug filter
short_description: Configures A10 axdebug.filter-config
author: A10 Networks 2018
version_added: 2.4
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - noop
          - present
          - absent
        required: True
    ansible_host:
        description:
        - Host for AXAPI authentication
        required: True
    ansible_username:
        description:
        - Username for AXAPI authentication
        required: True
    ansible_password:
        description:
        - Password for AXAPI authentication
        required: True
    ansible_port:
        description:
        - Port for AXAPI authentication
        required: True
    a10_device_context_id:
        description:
        - Device ID for aVCS configuration
        choices: [1-8]
        required: False
    a10_partition:
        description:
        - Destination/target partition for object/command
        required: False
    arp:
        description:
        - "ARP"
        required: False
    ip:
        description:
        - "IP"
        required: False
    offset:
        description:
        - "byte offset"
        required: False
    number:
        description:
        - "Specify filter id"
        required: True
    tcp:
        description:
        - "Field tcp"
        required: False
    l3_proto:
        description:
        - "Layer 3 protocol"
        required: False
    ipv4_address:
        description:
        - "ip address"
        required: False
    port:
        description:
        - "port number"
        required: False
    port_num_min:
        description:
        - "min port number"
        required: False
    oper_range:
        description:
        - "'gt'= greater than; 'gte'= greater than or equal to; 'se'= smaller than or
          equal to; 'st'= smaller than; 'eq'= equal to;"
        required: False
    ipv6_adddress:
        description:
        - "ipv6 address"
        required: False
    WORD:
        description:
        - "WORD to compare"
        required: False
    comp_hex:
        description:
        - "value to compare"
        required: False
    proto:
        description:
        - "ip protocol number"
        required: False
    dst:
        description:
        - "Destination"
        required: False
    hex:
        description:
        - "Define hex value"
        required: False
    integer_comp:
        description:
        - "value to compare"
        required: False
    port_num_max:
        description:
        - "max port number"
        required: False
    exit:
        description:
        - "Exit from axdebug mode"
        required: False
    ipv6:
        description:
        - "IPV6"
        required: False
    length:
        description:
        - "byte length"
        required: False
    udp:
        description:
        - "Field udp"
        required: False
    neighbor:
        description:
        - "IPv6 Neighbor/Router"
        required: False
    port_num:
        description:
        - "Port number"
        required: False
    max_hex:
        description:
        - "max value"
        required: False
    mac:
        description:
        - "mac address"
        required: False
    min_hex:
        description:
        - "min value"
        required: False
    WORD1:
        description:
        - "WORD min value"
        required: False
    WORD2:
        description:
        - "WORD max value"
        required: False
    integer_max:
        description:
        - "max value"
        required: False
    integer:
        description:
        - "Define decimal value"
        required: False
    icmp:
        description:
        - "Field icmp"
        required: False
    src:
        description:
        - "Source"
        required: False
    mac_addr:
        description:
        - "mac address"
        required: False
    ipv4_netmask:
        description:
        - "IP subnet mask"
        required: False
    icmpv6:
        description:
        - "Field icmpv6"
        required: False
    range:
        description:
        - "select a range"
        required: False
    integer_min:
        description:
        - "min value"
        required: False
    prot_num:
        description:
        - "protocol number"
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
    "arp",
    "comp_hex",
    "dst",
    "exit",
    "hex",
    "icmp",
    "icmpv6",
    "integer",
    "integer_comp",
    "integer_max",
    "integer_min",
    "ip",
    "ipv4_address",
    "ipv4_netmask",
    "ipv6",
    "ipv6_adddress",
    "l3_proto",
    "length",
    "mac",
    "mac_addr",
    "max_hex",
    "min_hex",
    "neighbor",
    "number",
    "offset",
    "oper_range",
    "port",
    "port_num",
    "port_num_max",
    "port_num_min",
    "prot_num",
    "proto",
    "range",
    "src",
    "tcp",
    "udp",
    "WORD",
    "WORD1",
    "WORD2",
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
        'arp': {
            'type': 'bool',
        },
        'ip': {
            'type': 'bool',
        },
        'offset': {
            'type': 'int',
        },
        'number': {
            'type': 'int',
            'required': True,
        },
        'tcp': {
            'type': 'bool',
        },
        'l3_proto': {
            'type': 'bool',
        },
        'ipv4_address': {
            'type': 'str',
        },
        'port': {
            'type': 'bool',
        },
        'port_num_min': {
            'type': 'int',
        },
        'oper_range': {
            'type': 'str',
            'choices': ['gt', 'gte', 'se', 'st', 'eq']
        },
        'ipv6_adddress': {
            'type': 'str',
        },
        'WORD': {
            'type': 'str',
        },
        'comp_hex': {
            'type': 'str',
        },
        'proto': {
            'type': 'bool',
        },
        'dst': {
            'type': 'bool',
        },
        'hex': {
            'type': 'bool',
        },
        'integer_comp': {
            'type': 'int',
        },
        'port_num_max': {
            'type': 'int',
        },
        'exit': {
            'type': 'bool',
        },
        'ipv6': {
            'type': 'bool',
        },
        'length': {
            'type': 'int',
        },
        'udp': {
            'type': 'bool',
        },
        'neighbor': {
            'type': 'bool',
        },
        'port_num': {
            'type': 'int',
        },
        'max_hex': {
            'type': 'str',
        },
        'mac': {
            'type': 'bool',
        },
        'min_hex': {
            'type': 'str',
        },
        'WORD1': {
            'type': 'str',
        },
        'WORD2': {
            'type': 'str',
        },
        'integer_max': {
            'type': 'int',
        },
        'integer': {
            'type': 'bool',
        },
        'icmp': {
            'type': 'bool',
        },
        'src': {
            'type': 'bool',
        },
        'mac_addr': {
            'type': 'str',
        },
        'ipv4_netmask': {
            'type': 'str',
        },
        'icmpv6': {
            'type': 'bool',
        },
        'range': {
            'type': 'bool',
        },
        'integer_min': {
            'type': 'int',
        },
        'prot_num': {
            'type': 'int',
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/axdebug/filter-config"

    f_dict = {}

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
    url_base = "/axapi/v3/axdebug/filter-config"

    f_dict = {}

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
        for k, v in payload["filter-config"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["filter-config"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["filter-config"][k] = v
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
    payload = build_json("filter-config", module)
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
