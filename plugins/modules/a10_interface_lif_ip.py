#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_interface_lif_ip
description:
    - Global IP configuration subcommands
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
    lif_ifnum:
        description:
        - Key to identify parent object
        type: str
        required: True
    dhcp:
        description:
        - "Use DHCP to configure IP address"
        type: bool
        required: False
    address_list:
        description:
        - "Field address_list"
        type: list
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
    allow_promiscuous_vip:
        description:
        - "Allow traffic to be associated with promiscuous VIP"
        type: bool
        required: False
    cache_spoofing_port:
        description:
        - "This interface connects to spoofing cache"
        type: bool
        required: False
    inside:
        description:
        - "Configure interface as inside"
        type: bool
        required: False
    outside:
        description:
        - "Configure interface as outside"
        type: bool
        required: False
    generate_membership_query:
        description:
        - "Enable Membership Query"
        type: bool
        required: False
    query_interval:
        description:
        - "1 - 255 (Default is 125)"
        type: int
        required: False
    max_resp_time:
        description:
        - "Maximum Response Time (Max Response Time (Default is 100))"
        type: int
        required: False
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    router:
        description:
        - "Field router"
        type: dict
        required: False
        suboptions:
            isis:
                description:
                - "Field isis"
                type: dict
    rip:
        description:
        - "Field rip"
        type: dict
        required: False
        suboptions:
            authentication:
                description:
                - "Field authentication"
                type: dict
            send_packet:
                description:
                - "Enable sending packets through the specified interface"
                type: bool
            receive_packet:
                description:
                - "Enable receiving packet through the specified interface"
                type: bool
            send_cfg:
                description:
                - "Field send_cfg"
                type: dict
            receive_cfg:
                description:
                - "Field receive_cfg"
                type: dict
            split_horizon_cfg:
                description:
                - "Field split_horizon_cfg"
                type: dict
            uuid:
                description:
                - "uuid of the object"
                type: str
    ospf:
        description:
        - "Field ospf"
        type: dict
        required: False
        suboptions:
            ospf_global:
                description:
                - "Field ospf_global"
                type: dict
            ospf_ip_list:
                description:
                - "Field ospf_ip_list"
                type: list

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
    "address_list",
    "allow_promiscuous_vip",
    "cache_spoofing_port",
    "dhcp",
    "generate_membership_query",
    "inside",
    "max_resp_time",
    "ospf",
    "outside",
    "query_interval",
    "rip",
    "router",
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
        'dhcp': {
            'type': 'bool',
        },
        'address_list': {
            'type': 'list',
            'ipv4_address': {
                'type': 'str',
            },
            'ipv4_netmask': {
                'type': 'str',
            }
        },
        'allow_promiscuous_vip': {
            'type': 'bool',
        },
        'cache_spoofing_port': {
            'type': 'bool',
        },
        'inside': {
            'type': 'bool',
        },
        'outside': {
            'type': 'bool',
        },
        'generate_membership_query': {
            'type': 'bool',
        },
        'query_interval': {
            'type': 'int',
        },
        'max_resp_time': {
            'type': 'int',
        },
        'uuid': {
            'type': 'str',
        },
        'router': {
            'type': 'dict',
            'isis': {
                'type': 'dict',
                'tag': {
                    'type': 'str',
                },
                'uuid': {
                    'type': 'str',
                }
            }
        },
        'rip': {
            'type': 'dict',
            'authentication': {
                'type': 'dict',
                'str': {
                    'type': 'dict',
                    'string': {
                        'type': 'str',
                    }
                },
                'mode': {
                    'type': 'dict',
                    'mode': {
                        'type': 'str',
                        'choices': ['md5', 'text']
                    }
                },
                'key_chain': {
                    'type': 'dict',
                    'key_chain': {
                        'type': 'str',
                    }
                }
            },
            'send_packet': {
                'type': 'bool',
            },
            'receive_packet': {
                'type': 'bool',
            },
            'send_cfg': {
                'type': 'dict',
                'send': {
                    'type': 'bool',
                },
                'version': {
                    'type': 'str',
                    'choices': ['1', '2', '1-compatible', '1-2']
                }
            },
            'receive_cfg': {
                'type': 'dict',
                'receive': {
                    'type': 'bool',
                },
                'version': {
                    'type': 'str',
                    'choices': ['1', '2', '1-2']
                }
            },
            'split_horizon_cfg': {
                'type': 'dict',
                'state': {
                    'type': 'str',
                    'choices': ['poisoned', 'disable', 'enable']
                }
            },
            'uuid': {
                'type': 'str',
            }
        },
        'ospf': {
            'type': 'dict',
            'ospf_global': {
                'type': 'dict',
                'authentication_cfg': {
                    'type': 'dict',
                    'authentication': {
                        'type': 'bool',
                    },
                    'value': {
                        'type': 'str',
                        'choices': ['message-digest', 'null']
                    }
                },
                'authentication_key': {
                    'type': 'str',
                },
                'bfd_cfg': {
                    'type': 'dict',
                    'bfd': {
                        'type': 'bool',
                    },
                    'disable': {
                        'type': 'bool',
                    }
                },
                'cost': {
                    'type': 'int',
                },
                'database_filter_cfg': {
                    'type': 'dict',
                    'database_filter': {
                        'type': 'str',
                        'choices': ['all']
                    },
                    'out': {
                        'type': 'bool',
                    }
                },
                'dead_interval': {
                    'type': 'int',
                },
                'disable': {
                    'type': 'str',
                    'choices': ['all']
                },
                'hello_interval': {
                    'type': 'int',
                },
                'message_digest_cfg': {
                    'type': 'list',
                    'message_digest_key': {
                        'type': 'int',
                    },
                    'md5': {
                        'type': 'dict',
                        'md5_value': {
                            'type': 'str',
                        },
                        'encrypted': {
                            'type': 'str',
                        }
                    }
                },
                'mtu': {
                    'type': 'int',
                },
                'mtu_ignore': {
                    'type': 'bool',
                },
                'network': {
                    'type': 'dict',
                    'broadcast': {
                        'type': 'bool',
                    },
                    'non_broadcast': {
                        'type': 'bool',
                    },
                    'point_to_point': {
                        'type': 'bool',
                    },
                    'point_to_multipoint': {
                        'type': 'bool',
                    },
                    'p2mp_nbma': {
                        'type': 'bool',
                    }
                },
                'priority': {
                    'type': 'int',
                },
                'retransmit_interval': {
                    'type': 'int',
                },
                'transmit_delay': {
                    'type': 'int',
                },
                'uuid': {
                    'type': 'str',
                }
            },
            'ospf_ip_list': {
                'type': 'list',
                'ip_addr': {
                    'type': 'str',
                    'required': True,
                },
                'authentication': {
                    'type': 'bool',
                },
                'value': {
                    'type': 'str',
                    'choices': ['message-digest', 'null']
                },
                'authentication_key': {
                    'type': 'str',
                },
                'cost': {
                    'type': 'int',
                },
                'database_filter': {
                    'type': 'str',
                    'choices': ['all']
                },
                'out': {
                    'type': 'bool',
                },
                'dead_interval': {
                    'type': 'int',
                },
                'hello_interval': {
                    'type': 'int',
                },
                'message_digest_cfg': {
                    'type': 'list',
                    'message_digest_key': {
                        'type': 'int',
                    },
                    'md5_value': {
                        'type': 'str',
                    },
                    'encrypted': {
                        'type': 'str',
                    }
                },
                'mtu_ignore': {
                    'type': 'bool',
                },
                'priority': {
                    'type': 'int',
                },
                'retransmit_interval': {
                    'type': 'int',
                },
                'transmit_delay': {
                    'type': 'int',
                },
                'uuid': {
                    'type': 'str',
                }
            }
        }
    })
    # Parent keys
    rv.update(dict(lif_ifnum=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/interface/lif/{lif_ifnum}/ip"

    f_dict = {}
    f_dict["lif_ifnum"] = module.params["lif_ifnum"]

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
    url_base = "/axapi/v3/interface/lif/{lif_ifnum}/ip"

    f_dict = {}
    f_dict["lif_ifnum"] = module.params["lif_ifnum"]

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
        for k, v in payload["ip"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["ip"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["ip"][k] = v
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
    payload = build_json("ip", module)
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
