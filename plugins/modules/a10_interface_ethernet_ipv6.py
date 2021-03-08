#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_interface_ethernet_ipv6
description:
    - Global IPv6 configuration subcommands
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
    ethernet_ifnum:
        description:
        - Key to identify parent object
        type: str
        required: True
    address_list:
        description:
        - "Field address_list"
        type: list
        required: False
        suboptions:
            ipv6_addr:
                description:
                - "Set the IPv6 address of an interface"
                type: str
            address_type:
                description:
                - "'anycast'= Configure an IPv6 anycast address; 'link-local'= Configure an IPv6
          link local address;"
                type: str
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
    ipv6_enable:
        description:
        - "Enable IPv6 processing"
        type: bool
        required: False
    ttl_ignore:
        description:
        - "Ignore TTL decrement for a received packet before sending out"
        type: bool
        required: False
    access_list_cfg:
        description:
        - "Field access_list_cfg"
        type: dict
        required: False
        suboptions:
            v6_acl_name:
                description:
                - "Apply ACL rules to incoming packets on this interface (Named Access List)"
                type: str
            inbound:
                description:
                - "ACL applied on incoming packets to this interface"
                type: bool
    router_adver:
        description:
        - "Field router_adver"
        type: dict
        required: False
        suboptions:
            action:
                description:
                - "'enable'= Enable Router Advertisements on this interface; 'disable'= Disable
          Router Advertisements on this interface;"
                type: str
            hop_limit:
                description:
                - "Set Router Advertisement Hop Limit (default= 255)"
                type: int
            max_interval:
                description:
                - "Set Router Advertisement Max Interval (default= 600) (Max Router Advertisement
          Interval (seconds))"
                type: int
            min_interval:
                description:
                - "Set Router Advertisement Min Interval (default= 200) (Min Router Advertisement
          Interval (seconds))"
                type: int
            default_lifetime:
                description:
                - "Set Router Advertisement Default Lifetime (default= 1800) (Default Lifetime
          (seconds))"
                type: int
            rate_limit:
                description:
                - "Rate Limit the processing of incoming Router Solicitations (Max Number of
          Router Solicitations to process per second)"
                type: int
            reachable_time:
                description:
                - "Set Router Advertisement Reachable ime (default= 0) (Reachable Time
          (milliseconds))"
                type: int
            retransmit_timer:
                description:
                - "Set Router Advertisement Retransmit Timer (default= 0)"
                type: int
            adver_mtu_disable:
                description:
                - "Disable Router Advertisement MTU Option"
                type: bool
            adver_mtu:
                description:
                - "Set Router Advertisement MTU Option"
                type: int
            prefix_list:
                description:
                - "Field prefix_list"
                type: list
            managed_config_action:
                description:
                - "'enable'= Enable the Managed Address Configuration flag; 'disable'= Disable the
          Managed Address Configuration flag (default);"
                type: str
            other_config_action:
                description:
                - "'enable'= Enable the Other Stateful Configuration flag; 'disable'= Disable the
          Other Stateful Configuration flag (default);"
                type: str
            adver_vrid:
                description:
                - "Specify ha VRRP-A vrid"
                type: int
            use_floating_ip:
                description:
                - "Use a floating IP as the source address for Router advertisements"
                type: bool
            floating_ip:
                description:
                - "Use a floating IP as the source address for Router advertisements"
                type: str
            adver_vrid_default:
                description:
                - "Default VRRP-A vrid"
                type: bool
            use_floating_ip_default_vrid:
                description:
                - "Use a floating IP as the source address for Router advertisements"
                type: bool
            floating_ip_default_vrid:
                description:
                - "Use a floating IP as the source address for Router advertisements"
                type: str
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    stateful_firewall:
        description:
        - "Field stateful_firewall"
        type: dict
        required: False
        suboptions:
            inside:
                description:
                - "Inside (private) interface for stateful firewall"
                type: bool
            class_list:
                description:
                - "Class List (Class List Name)"
                type: str
            outside:
                description:
                - "Outside (public) interface for stateful firewall"
                type: bool
            access_list:
                description:
                - "Access-list for traffic from the outside"
                type: bool
            acl_name:
                description:
                - "Access-list Name"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    router:
        description:
        - "Field router"
        type: dict
        required: False
        suboptions:
            ripng:
                description:
                - "Field ripng"
                type: dict
            ospf:
                description:
                - "Field ospf"
                type: dict
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
            network_list:
                description:
                - "Field network_list"
                type: list
            bfd:
                description:
                - "Bidirectional Forwarding Detection (BFD)"
                type: bool
            disable:
                description:
                - "Disable BFD"
                type: bool
            cost_cfg:
                description:
                - "Field cost_cfg"
                type: list
            dead_interval_cfg:
                description:
                - "Field dead_interval_cfg"
                type: list
            hello_interval_cfg:
                description:
                - "Field hello_interval_cfg"
                type: list
            mtu_ignore_cfg:
                description:
                - "Field mtu_ignore_cfg"
                type: list
            neighbor_cfg:
                description:
                - "Field neighbor_cfg"
                type: list
            priority_cfg:
                description:
                - "Field priority_cfg"
                type: list
            retransmit_interval_cfg:
                description:
                - "Field retransmit_interval_cfg"
                type: list
            transmit_delay_cfg:
                description:
                - "Field transmit_delay_cfg"
                type: list
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
    "access_list_cfg",
    "address_list",
    "inside",
    "ipv6_enable",
    "ospf",
    "outside",
    "rip",
    "router",
    "router_adver",
    "stateful_firewall",
    "ttl_ignore",
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
        'address_list': {
            'type': 'list',
            'ipv6_addr': {
                'type': 'str',
            },
            'address_type': {
                'type': 'str',
                'choices': ['anycast', 'link-local']
            }
        },
        'inside': {
            'type': 'bool',
        },
        'outside': {
            'type': 'bool',
        },
        'ipv6_enable': {
            'type': 'bool',
        },
        'ttl_ignore': {
            'type': 'bool',
        },
        'access_list_cfg': {
            'type': 'dict',
            'v6_acl_name': {
                'type': 'str',
            },
            'inbound': {
                'type': 'bool',
            }
        },
        'router_adver': {
            'type': 'dict',
            'action': {
                'type': 'str',
                'choices': ['enable', 'disable']
            },
            'hop_limit': {
                'type': 'int',
            },
            'max_interval': {
                'type': 'int',
            },
            'min_interval': {
                'type': 'int',
            },
            'default_lifetime': {
                'type': 'int',
            },
            'rate_limit': {
                'type': 'int',
            },
            'reachable_time': {
                'type': 'int',
            },
            'retransmit_timer': {
                'type': 'int',
            },
            'adver_mtu_disable': {
                'type': 'bool',
            },
            'adver_mtu': {
                'type': 'int',
            },
            'prefix_list': {
                'type': 'list',
                'prefix': {
                    'type': 'str',
                },
                'not_autonomous': {
                    'type': 'bool',
                },
                'not_on_link': {
                    'type': 'bool',
                },
                'preferred_lifetime': {
                    'type': 'int',
                },
                'valid_lifetime': {
                    'type': 'int',
                }
            },
            'managed_config_action': {
                'type': 'str',
                'choices': ['enable', 'disable']
            },
            'other_config_action': {
                'type': 'str',
                'choices': ['enable', 'disable']
            },
            'adver_vrid': {
                'type': 'int',
            },
            'use_floating_ip': {
                'type': 'bool',
            },
            'floating_ip': {
                'type': 'str',
            },
            'adver_vrid_default': {
                'type': 'bool',
            },
            'use_floating_ip_default_vrid': {
                'type': 'bool',
            },
            'floating_ip_default_vrid': {
                'type': 'str',
            }
        },
        'uuid': {
            'type': 'str',
        },
        'stateful_firewall': {
            'type': 'dict',
            'inside': {
                'type': 'bool',
            },
            'class_list': {
                'type': 'str',
            },
            'outside': {
                'type': 'bool',
            },
            'access_list': {
                'type': 'bool',
            },
            'acl_name': {
                'type': 'str',
            },
            'uuid': {
                'type': 'str',
            }
        },
        'router': {
            'type': 'dict',
            'ripng': {
                'type': 'dict',
                'rip': {
                    'type': 'bool',
                },
                'uuid': {
                    'type': 'str',
                }
            },
            'ospf': {
                'type': 'dict',
                'area_list': {
                    'type': 'list',
                    'area_id_num': {
                        'type': 'int',
                    },
                    'area_id_addr': {
                        'type': 'str',
                    },
                    'tag': {
                        'type': 'str',
                    },
                    'instance_id': {
                        'type': 'int',
                    }
                },
                'uuid': {
                    'type': 'str',
                }
            },
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
            'network_list': {
                'type': 'list',
                'broadcast_type': {
                    'type':
                    'str',
                    'choices': [
                        'broadcast', 'non-broadcast', 'point-to-point',
                        'point-to-multipoint'
                    ]
                },
                'p2mp_nbma': {
                    'type': 'bool',
                },
                'network_instance_id': {
                    'type': 'int',
                }
            },
            'bfd': {
                'type': 'bool',
            },
            'disable': {
                'type': 'bool',
            },
            'cost_cfg': {
                'type': 'list',
                'cost': {
                    'type': 'int',
                },
                'instance_id': {
                    'type': 'int',
                }
            },
            'dead_interval_cfg': {
                'type': 'list',
                'dead_interval': {
                    'type': 'int',
                },
                'instance_id': {
                    'type': 'int',
                }
            },
            'hello_interval_cfg': {
                'type': 'list',
                'hello_interval': {
                    'type': 'int',
                },
                'instance_id': {
                    'type': 'int',
                }
            },
            'mtu_ignore_cfg': {
                'type': 'list',
                'mtu_ignore': {
                    'type': 'bool',
                },
                'instance_id': {
                    'type': 'int',
                }
            },
            'neighbor_cfg': {
                'type': 'list',
                'neighbor': {
                    'type': 'str',
                },
                'neig_inst': {
                    'type': 'int',
                },
                'neighbor_cost': {
                    'type': 'int',
                },
                'neighbor_poll_interval': {
                    'type': 'int',
                },
                'neighbor_priority': {
                    'type': 'int',
                }
            },
            'priority_cfg': {
                'type': 'list',
                'priority': {
                    'type': 'int',
                },
                'instance_id': {
                    'type': 'int',
                }
            },
            'retransmit_interval_cfg': {
                'type': 'list',
                'retransmit_interval': {
                    'type': 'int',
                },
                'instance_id': {
                    'type': 'int',
                }
            },
            'transmit_delay_cfg': {
                'type': 'list',
                'transmit_delay': {
                    'type': 'int',
                },
                'instance_id': {
                    'type': 'int',
                }
            },
            'uuid': {
                'type': 'str',
            }
        }
    })
    # Parent keys
    rv.update(dict(ethernet_ifnum=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/interface/ethernet/{ethernet_ifnum}/ipv6"

    f_dict = {}
    f_dict["ethernet_ifnum"] = module.params["ethernet_ifnum"]

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
    url_base = "/axapi/v3/interface/ethernet/{ethernet_ifnum}/ipv6"

    f_dict = {}
    f_dict["ethernet_ifnum"] = module.params["ethernet_ifnum"]

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
        for k, v in payload["ipv6"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["ipv6"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["ipv6"][k] = v
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
    payload = build_json("ipv6", module)
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
