#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_interface_management
description:
    - Management interface
author: A10 Networks 2021
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - noop
          - present
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
    access_list:
        description:
        - "Field access_list"
        type: dict
        required: False
        suboptions:
            acl_id:
                description:
                - "ACL id"
                type: int
            acl_name:
                description:
                - "Apply an access list (Named Access List)"
                type: str
    duplexity:
        description:
        - "'Full'= Full; 'Half'= Half; 'auto'= Auto;"
        type: str
        required: False
    speed:
        description:
        - "'10'= 10 Mbs/sec; '100'= 100 Mbs/sec; '1000'= 1 Gb/sec; 'auto'= Auto Negotiate
          Speed;  (Interface Speed)"
        type: str
        required: False
    flow_control:
        description:
        - "Enable 802.3x flow control on full duplex port"
        type: bool
        required: False
    broadcast_rate_limit:
        description:
        - "Field broadcast_rate_limit"
        type: dict
        required: False
        suboptions:
            bcast_rate_limit_enable:
                description:
                - "Rate limit the l2 broadcast packet on mgmt port"
                type: bool
            rate:
                description:
                - "packets per second. Default is 500. (packets per second. Please specify an even
          number. Default is 500)"
                type: int
    ip:
        description:
        - "Field ip"
        type: dict
        required: False
        suboptions:
            ipv4_address:
                description:
                - "IP address"
                type: str
            ipv4_netmask:
                description:
                - "IP subnet mask"
                type: str
            dhcp:
                description:
                - "Use DHCP to configure IP address"
                type: bool
            control_apps_use_mgmt_port:
                description:
                - "Control applications use management port"
                type: bool
            default_gateway:
                description:
                - "Set default gateway (Default gateway address)"
                type: str
    secondary_ip:
        description:
        - "Field secondary_ip"
        type: dict
        required: False
        suboptions:
            secondary_ip:
                description:
                - "Global IP configuration subcommands"
                type: bool
            ipv4_address:
                description:
                - "IP address"
                type: str
            ipv4_netmask:
                description:
                - "IP subnet mask"
                type: str
            dhcp:
                description:
                - "Use DHCP to configure IP address"
                type: bool
            control_apps_use_mgmt_port:
                description:
                - "Control applications use management port"
                type: bool
            default_gateway:
                description:
                - "Set default gateway (Default gateway address)"
                type: str
    ipv6:
        description:
        - "Field ipv6"
        type: list
        required: False
        suboptions:
            ipv6_addr:
                description:
                - "Set the IPv6 address of an interface"
                type: str
            address_type:
                description:
                - "'link-local'= Configure an IPv6 link local address;"
                type: str
            v6_acl_name:
                description:
                - "Apply ACL rules to incoming packets on this interface (Named Access List)"
                type: str
            inbound:
                description:
                - "ACL applied on incoming packets to this interface"
                type: bool
            default_ipv6_gateway:
                description:
                - "Set default gateway (Default gateway address)"
                type: str
    action:
        description:
        - "'enable'= Enable Management Port; 'disable'= Disable Management Port;"
        type: str
        required: False
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        type: list
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'packets_input'= Input packets; 'bytes_input'= Input bytes;
          'received_broadcasts'= Received broadcasts; 'received_multicasts'= Received
          multicasts; 'received_unicasts'= Received unicasts; 'input_errors'= Input
          errors; 'crc'= CRC; 'frame'= Frames; 'input_err_short'= Runts;
          'input_err_long'= Giants; 'packets_output'= Output packets; 'bytes_output'=
          Output bytes; 'transmitted_broadcasts'= Transmitted broadcasts;
          'transmitted_multicasts'= Transmitted multicasts; 'transmitted_unicasts'=
          Transmitted unicasts; 'output_errors'= Output errors; 'collisions'= Collisions;"
                type: str
    lldp:
        description:
        - "Field lldp"
        type: dict
        required: False
        suboptions:
            enable_cfg:
                description:
                - "Field enable_cfg"
                type: dict
            notification_cfg:
                description:
                - "Field notification_cfg"
                type: dict
            tx_dot1_cfg:
                description:
                - "Field tx_dot1_cfg"
                type: dict
            tx_tlvs_cfg:
                description:
                - "Field tx_tlvs_cfg"
                type: dict
            uuid:
                description:
                - "uuid of the object"
                type: str
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            interface:
                description:
                - "Field interface"
                type: str
            state:
                description:
                - "Field state"
                type: int
            line_protocol:
                description:
                - "Field line_protocol"
                type: str
            link_type:
                description:
                - "Field link_type"
                type: str
            mac:
                description:
                - "Field mac"
                type: str
            ipv4_addr:
                description:
                - "IP address"
                type: str
            ipv4_mask:
                description:
                - "IP subnet mask"
                type: str
            ipv4_default_gateway:
                description:
                - "IP gateway address"
                type: str
            ipv6_addr:
                description:
                - "Field ipv6_addr"
                type: str
            ipv6_prefix:
                description:
                - "Field ipv6_prefix"
                type: str
            ipv6_link_local:
                description:
                - "Field ipv6_link_local"
                type: str
            ipv6_link_local_prefix:
                description:
                - "Field ipv6_link_local_prefix"
                type: str
            ipv6_default_gateway:
                description:
                - "Field ipv6_default_gateway"
                type: str
            speed:
                description:
                - "Field speed"
                type: str
            duplexity:
                description:
                - "Field duplexity"
                type: str
            mtu:
                description:
                - "Field mtu"
                type: int
            flow_control:
                description:
                - "Field flow_control"
                type: int
            ipv4_acl:
                description:
                - "Field ipv4_acl"
                type: str
            ipv6_acl:
                description:
                - "Field ipv6_acl"
                type: str
            dhcp_enabled:
                description:
                - "Field dhcp_enabled"
                type: int
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            packets_input:
                description:
                - "Input packets"
                type: str
            bytes_input:
                description:
                - "Input bytes"
                type: str
            received_broadcasts:
                description:
                - "Received broadcasts"
                type: str
            received_multicasts:
                description:
                - "Received multicasts"
                type: str
            received_unicasts:
                description:
                - "Received unicasts"
                type: str
            input_errors:
                description:
                - "Input errors"
                type: str
            crc:
                description:
                - "CRC"
                type: str
            frame:
                description:
                - "Frames"
                type: str
            input_err_short:
                description:
                - "Runts"
                type: str
            input_err_long:
                description:
                - "Giants"
                type: str
            packets_output:
                description:
                - "Output packets"
                type: str
            bytes_output:
                description:
                - "Output bytes"
                type: str
            transmitted_broadcasts:
                description:
                - "Transmitted broadcasts"
                type: str
            transmitted_multicasts:
                description:
                - "Transmitted multicasts"
                type: str
            transmitted_unicasts:
                description:
                - "Transmitted unicasts"
                type: str
            output_errors:
                description:
                - "Output errors"
                type: str
            collisions:
                description:
                - "Collisions"
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
    "access_list",
    "action",
    "broadcast_rate_limit",
    "duplexity",
    "flow_control",
    "ip",
    "ipv6",
    "lldp",
    "oper",
    "sampling_enable",
    "secondary_ip",
    "speed",
    "stats",
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
        state=dict(type='str', default="present", choices=['noop', 'present']),
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
        'access_list': {
            'type': 'dict',
            'acl_id': {
                'type': 'int',
            },
            'acl_name': {
                'type': 'str',
            }
        },
        'duplexity': {
            'type': 'str',
            'choices': ['Full', 'Half', 'auto']
        },
        'speed': {
            'type': 'str',
            'choices': ['10', '100', '1000', 'auto']
        },
        'flow_control': {
            'type': 'bool',
        },
        'broadcast_rate_limit': {
            'type': 'dict',
            'bcast_rate_limit_enable': {
                'type': 'bool',
            },
            'rate': {
                'type': 'int',
            }
        },
        'ip': {
            'type': 'dict',
            'ipv4_address': {
                'type': 'str',
            },
            'ipv4_netmask': {
                'type': 'str',
            },
            'dhcp': {
                'type': 'bool',
            },
            'control_apps_use_mgmt_port': {
                'type': 'bool',
            },
            'default_gateway': {
                'type': 'str',
            }
        },
        'secondary_ip': {
            'type': 'dict',
            'secondary_ip': {
                'type': 'bool',
            },
            'ipv4_address': {
                'type': 'str',
            },
            'ipv4_netmask': {
                'type': 'str',
            },
            'dhcp': {
                'type': 'bool',
            },
            'control_apps_use_mgmt_port': {
                'type': 'bool',
            },
            'default_gateway': {
                'type': 'str',
            }
        },
        'ipv6': {
            'type': 'list',
            'ipv6_addr': {
                'type': 'str',
            },
            'address_type': {
                'type': 'str',
                'choices': ['link-local']
            },
            'v6_acl_name': {
                'type': 'str',
            },
            'inbound': {
                'type': 'bool',
            },
            'default_ipv6_gateway': {
                'type': 'str',
            }
        },
        'action': {
            'type': 'str',
            'choices': ['enable', 'disable']
        },
        'uuid': {
            'type': 'str',
        },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'packets_input', 'bytes_input',
                    'received_broadcasts', 'received_multicasts',
                    'received_unicasts', 'input_errors', 'crc', 'frame',
                    'input_err_short', 'input_err_long', 'packets_output',
                    'bytes_output', 'transmitted_broadcasts',
                    'transmitted_multicasts', 'transmitted_unicasts',
                    'output_errors', 'collisions'
                ]
            }
        },
        'lldp': {
            'type': 'dict',
            'enable_cfg': {
                'type': 'dict',
                'rt_enable': {
                    'type': 'bool',
                },
                'rx': {
                    'type': 'bool',
                },
                'tx': {
                    'type': 'bool',
                }
            },
            'notification_cfg': {
                'type': 'dict',
                'notification': {
                    'type': 'bool',
                },
                'notif_enable': {
                    'type': 'bool',
                }
            },
            'tx_dot1_cfg': {
                'type': 'dict',
                'tx_dot1_tlvs': {
                    'type': 'bool',
                },
                'link_aggregation': {
                    'type': 'bool',
                },
                'vlan': {
                    'type': 'bool',
                }
            },
            'tx_tlvs_cfg': {
                'type': 'dict',
                'tx_tlvs': {
                    'type': 'bool',
                },
                'exclude': {
                    'type': 'bool',
                },
                'management_address': {
                    'type': 'bool',
                },
                'port_description': {
                    'type': 'bool',
                },
                'system_capabilities': {
                    'type': 'bool',
                },
                'system_description': {
                    'type': 'bool',
                },
                'system_name': {
                    'type': 'bool',
                }
            },
            'uuid': {
                'type': 'str',
            }
        },
        'oper': {
            'type': 'dict',
            'interface': {
                'type': 'str',
            },
            'state': {
                'type': 'int',
            },
            'line_protocol': {
                'type': 'str',
            },
            'link_type': {
                'type': 'str',
                'choices': ['GigabitEthernet', '10Gig', '40Gig']
            },
            'mac': {
                'type': 'str',
            },
            'ipv4_addr': {
                'type': 'str',
            },
            'ipv4_mask': {
                'type': 'str',
            },
            'ipv4_default_gateway': {
                'type': 'str',
            },
            'ipv6_addr': {
                'type': 'str',
            },
            'ipv6_prefix': {
                'type': 'str',
            },
            'ipv6_link_local': {
                'type': 'str',
            },
            'ipv6_link_local_prefix': {
                'type': 'str',
            },
            'ipv6_default_gateway': {
                'type': 'str',
            },
            'speed': {
                'type': 'str',
            },
            'duplexity': {
                'type': 'str',
            },
            'mtu': {
                'type': 'int',
            },
            'flow_control': {
                'type': 'int',
            },
            'ipv4_acl': {
                'type': 'str',
            },
            'ipv6_acl': {
                'type': 'str',
            },
            'dhcp_enabled': {
                'type': 'int',
            }
        },
        'stats': {
            'type': 'dict',
            'packets_input': {
                'type': 'str',
            },
            'bytes_input': {
                'type': 'str',
            },
            'received_broadcasts': {
                'type': 'str',
            },
            'received_multicasts': {
                'type': 'str',
            },
            'received_unicasts': {
                'type': 'str',
            },
            'input_errors': {
                'type': 'str',
            },
            'crc': {
                'type': 'str',
            },
            'frame': {
                'type': 'str',
            },
            'input_err_short': {
                'type': 'str',
            },
            'input_err_long': {
                'type': 'str',
            },
            'packets_output': {
                'type': 'str',
            },
            'bytes_output': {
                'type': 'str',
            },
            'transmitted_broadcasts': {
                'type': 'str',
            },
            'transmitted_multicasts': {
                'type': 'str',
            },
            'transmitted_unicasts': {
                'type': 'str',
            },
            'output_errors': {
                'type': 'str',
            },
            'collisions': {
                'type': 'str',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/interface/management"

    f_dict = {}

    return url_base.format(**f_dict)


def oper_url(module):
    """Return the URL for operational data of an existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/oper"


def stats_url(module):
    """Return the URL for statistical data of and existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/stats"


def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]


def get(module):
    return module.client.get(existing_url(module))


def get_list(module):
    return module.client.get(list_url(module))


def get_oper(module):
    if module.params.get("oper"):
        query_params = {}
        for k, v in module.params["oper"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(oper_url(module), params=query_params)
    return module.client.get(oper_url(module))


def get_stats(module):
    if module.params.get("stats"):
        query_params = {}
        for k, v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(stats_url(module), params=query_params)
    return module.client.get(stats_url(module))


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
    url_base = "/axapi/v3/interface/management"

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
        for k, v in payload["management"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["management"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["management"][k] = v
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
    payload = build_json("management", module)
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

    if state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
        elif module.params.get("get_type") == "oper":
            result["result"] = get_oper(module)
        elif module.params.get("get_type") == "stats":
            result["result"] = get_stats(module)
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
