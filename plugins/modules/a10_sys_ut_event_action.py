#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_sys_ut_event_action
description:
    - Specify event parameters
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
    event_number:
        description:
        - Key to identify parent object
        type: str
        required: True
    direction:
        description:
        - "'send'= Test event; 'expect'= Expected result; 'wait'= Introduce a delay;"
        type: str
        required: True
    template:
        description:
        - "Packet template"
        type: str
        required: False
    drop:
        description:
        - "Packet drop. Only allowed for output spec"
        type: bool
        required: False
    delay:
        description:
        - "Delay in seconds"
        type: int
        required: False
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    l1:
        description:
        - "Field l1"
        type: dict
        required: False
        suboptions:
            eth_list:
                description:
                - "Field eth_list"
                type: list
            trunk_list:
                description:
                - "Field trunk_list"
                type: list
            length:
                description:
                - "packet length"
                type: bool
            value:
                description:
                - "Total packet length starting at L2 header"
                type: int
            auto:
                description:
                - "Auto calculate pkt len"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
    l2:
        description:
        - "Field l2"
        type: dict
        required: False
        suboptions:
            ethertype:
                description:
                - "L2 frame type"
                type: bool
            protocol:
                description:
                - "'arp'= arp; 'ipv4'= ipv4; 'ipv6'= ipv6;"
                type: str
            value:
                description:
                - "ethertype number"
                type: int
            vlan:
                description:
                - "Vlan ID on the packet. 0 is untagged"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
            mac_list:
                description:
                - "Field mac_list"
                type: list
    l3:
        description:
        - "Field l3"
        type: dict
        required: False
        suboptions:
            protocol:
                description:
                - "L4 Protocol"
                type: bool
            ntype:
                description:
                - "'tcp'= tcp; 'udp'= udp; 'icmp'= icmp;"
                type: str
            value:
                description:
                - "protocol number"
                type: int
            checksum:
                description:
                - "'valid'= valid; 'invalid'= invalid;"
                type: str
            ttl:
                description:
                - "Field ttl"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
            ip_list:
                description:
                - "Field ip_list"
                type: list
    tcp:
        description:
        - "Field tcp"
        type: dict
        required: False
        suboptions:
            src_port:
                description:
                - "Source port value"
                type: int
            dest_port:
                description:
                - "Dest port"
                type: bool
            dest_port_value:
                description:
                - "Dest port value"
                type: int
            nat_pool:
                description:
                - "Nat pool port"
                type: str
            seq_number:
                description:
                - "'valid'= valid; 'invalid'= invalid;"
                type: str
            ack_seq_number:
                description:
                - "'valid'= valid; 'invalid'= invalid;"
                type: str
            checksum:
                description:
                - "'valid'= valid; 'invalid'= invalid;"
                type: str
            urgent:
                description:
                - "'valid'= valid; 'invalid'= invalid;"
                type: str
            window:
                description:
                - "'valid'= valid; 'invalid'= invalid;"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            flags:
                description:
                - "Field flags"
                type: dict
            options:
                description:
                - "Field options"
                type: dict
    udp:
        description:
        - "Field udp"
        type: dict
        required: False
        suboptions:
            src_port:
                description:
                - "Source port value"
                type: int
            dest_port:
                description:
                - "Dest port"
                type: bool
            dest_port_value:
                description:
                - "Dest port value"
                type: int
            nat_pool:
                description:
                - "Nat pool port"
                type: str
            length:
                description:
                - "Total packet length starting at UDP header"
                type: int
            checksum:
                description:
                - "'valid'= valid; 'invalid'= invalid;"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    ignore_validation:
        description:
        - "Field ignore_validation"
        type: dict
        required: False
        suboptions:
            l1:
                description:
                - "Dont validate TX descriptor. This includes Tx port, Len & vlan"
                type: bool
            l2:
                description:
                - "Dont validate L2 header"
                type: bool
            l3:
                description:
                - "Dont validate L3 header"
                type: bool
            l4:
                description:
                - "Dont validate L4 header"
                type: bool
            all:
                description:
                - "Skip validation"
                type: bool
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
    "delay",
    "direction",
    "drop",
    "ignore_validation",
    "l1",
    "l2",
    "l3",
    "tcp",
    "template",
    "udp",
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
        'direction': {
            'type': 'str',
            'required': True,
            'choices': ['send', 'expect', 'wait']
        },
        'template': {
            'type': 'str',
        },
        'drop': {
            'type': 'bool',
        },
        'delay': {
            'type': 'int',
        },
        'uuid': {
            'type': 'str',
        },
        'l1': {
            'type': 'dict',
            'eth_list': {
                'type': 'list',
                'ethernet_start': {
                    'type': 'str',
                },
                'ethernet_end': {
                    'type': 'str',
                }
            },
            'trunk_list': {
                'type': 'list',
                'trunk_start': {
                    'type': 'int',
                },
                'trunk_end': {
                    'type': 'int',
                }
            },
            'length': {
                'type': 'bool',
            },
            'value': {
                'type': 'int',
            },
            'auto': {
                'type': 'bool',
            },
            'uuid': {
                'type': 'str',
            }
        },
        'l2': {
            'type': 'dict',
            'ethertype': {
                'type': 'bool',
            },
            'protocol': {
                'type': 'str',
                'choices': ['arp', 'ipv4', 'ipv6']
            },
            'value': {
                'type': 'int',
            },
            'vlan': {
                'type': 'int',
            },
            'uuid': {
                'type': 'str',
            },
            'mac_list': {
                'type': 'list',
                'src_dst': {
                    'type': 'str',
                    'required': True,
                    'choices': ['dest', 'src']
                },
                'address_type': {
                    'type': 'str',
                    'choices': ['broadcast', 'multicast']
                },
                'virtual_server': {
                    'type': 'str',
                },
                'nat_pool': {
                    'type': 'str',
                },
                'ethernet': {
                    'type': 'str',
                },
                've': {
                    'type': 'str',
                },
                'trunk': {
                    'type': 'str',
                },
                'value': {
                    'type': 'str',
                },
                'uuid': {
                    'type': 'str',
                }
            }
        },
        'l3': {
            'type': 'dict',
            'protocol': {
                'type': 'bool',
            },
            'ntype': {
                'type': 'str',
                'choices': ['tcp', 'udp', 'icmp']
            },
            'value': {
                'type': 'int',
            },
            'checksum': {
                'type': 'str',
                'choices': ['valid', 'invalid']
            },
            'ttl': {
                'type': 'int',
            },
            'uuid': {
                'type': 'str',
            },
            'ip_list': {
                'type': 'list',
                'src_dst': {
                    'type': 'str',
                    'required': True,
                    'choices': ['dest', 'src']
                },
                'ipv4_address': {
                    'type': 'str',
                },
                'ipv6_address': {
                    'type': 'str',
                },
                'nat_pool': {
                    'type': 'str',
                },
                'virtual_server': {
                    'type': 'str',
                },
                'ethernet': {
                    'type': 'str',
                },
                've': {
                    'type': 'str',
                },
                'trunk': {
                    'type': 'str',
                },
                'uuid': {
                    'type': 'str',
                }
            }
        },
        'tcp': {
            'type': 'dict',
            'src_port': {
                'type': 'int',
            },
            'dest_port': {
                'type': 'bool',
            },
            'dest_port_value': {
                'type': 'int',
            },
            'nat_pool': {
                'type': 'str',
            },
            'seq_number': {
                'type': 'str',
                'choices': ['valid', 'invalid']
            },
            'ack_seq_number': {
                'type': 'str',
                'choices': ['valid', 'invalid']
            },
            'checksum': {
                'type': 'str',
                'choices': ['valid', 'invalid']
            },
            'urgent': {
                'type': 'str',
                'choices': ['valid', 'invalid']
            },
            'window': {
                'type': 'str',
                'choices': ['valid', 'invalid']
            },
            'uuid': {
                'type': 'str',
            },
            'flags': {
                'type': 'dict',
                'syn': {
                    'type': 'bool',
                },
                'ack': {
                    'type': 'bool',
                },
                'fin': {
                    'type': 'bool',
                },
                'rst': {
                    'type': 'bool',
                },
                'psh': {
                    'type': 'bool',
                },
                'ece': {
                    'type': 'bool',
                },
                'urg': {
                    'type': 'bool',
                },
                'cwr': {
                    'type': 'bool',
                },
                'uuid': {
                    'type': 'str',
                }
            },
            'options': {
                'type': 'dict',
                'mss': {
                    'type': 'int',
                },
                'wscale': {
                    'type': 'int',
                },
                'sack_type': {
                    'type': 'str',
                    'choices': ['permitted', 'block']
                },
                'time_stamp_enable': {
                    'type': 'bool',
                },
                'nop': {
                    'type': 'bool',
                },
                'uuid': {
                    'type': 'str',
                }
            }
        },
        'udp': {
            'type': 'dict',
            'src_port': {
                'type': 'int',
            },
            'dest_port': {
                'type': 'bool',
            },
            'dest_port_value': {
                'type': 'int',
            },
            'nat_pool': {
                'type': 'str',
            },
            'length': {
                'type': 'int',
            },
            'checksum': {
                'type': 'str',
                'choices': ['valid', 'invalid']
            },
            'uuid': {
                'type': 'str',
            }
        },
        'ignore_validation': {
            'type': 'dict',
            'l1': {
                'type': 'bool',
            },
            'l2': {
                'type': 'bool',
            },
            'l3': {
                'type': 'bool',
            },
            'l4': {
                'type': 'bool',
            },
            'all': {
                'type': 'bool',
            },
            'uuid': {
                'type': 'str',
            }
        }
    })
    # Parent keys
    rv.update(dict(event_number=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/sys-ut/event/{event_number}/action/{direction}"

    f_dict = {}
    f_dict["direction"] = module.params["direction"]
    f_dict["event_number"] = module.params["event_number"]

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
    url_base = "/axapi/v3/sys-ut/event/{event_number}/action/{direction}"

    f_dict = {}
    f_dict["direction"] = ""
    f_dict["event_number"] = module.params["event_number"]

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
        for k, v in payload["action"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["action"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["action"][k] = v
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
    payload = build_json("action", module)
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
