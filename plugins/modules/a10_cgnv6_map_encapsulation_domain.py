#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_cgnv6_map_encapsulation_domain
description:
    - MAP Encapsulation domain
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
    name:
        description:
        - "MAP-E domain name"
        type: str
        required: True
    description:
        description:
        - "MAP-E domain description"
        type: str
        required: False
    format:
        description:
        - "'draft-03'= Construct IPv6 Interface Identifier according to draft-03;"
        type: str
        required: False
    tunnel_endpoint_address:
        description:
        - "Tunnel Endpoint Address for MAP-E domain"
        type: str
        required: False
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
    sampling_enable:
        description:
        - "Field sampling_enable"
        type: list
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'inbound_packet_received'= Inbound IPv4 Packets Received;
          'inbound_frag_packet_received'= Inbound IPv4 Fragment Packets Received;
          'inbound_addr_port_validation_failed'= Inbound IPv4 Destination Address Port
          Validation Failed; 'inbound_rev_lookup_failed'= Inbound IPv4 Reverse Route
          Lookup Failed; 'inbound_dest_unreachable'= Inbound IPv6 Destination Address
          Unreachable; 'outbound_packet_received'= Outbound IPv6 Packets Received;
          'outbound_frag_packet_received'= Outbound IPv6 Fragment Packets Received;
          'outbound_addr_validation_failed'= Outbound IPv6 Source Address Validation
          Failed; 'outbound_rev_lookup_failed'= Outbound IPv6 Reverse Route Lookup
          Failed; 'outbound_dest_unreachable'= Outbound IPv4 Destination Address
          Unreachable; 'packet_mtu_exceeded'= Packet Exceeded MTU; 'frag_icmp_sent'= ICMP
          Packet Too Big Sent; 'interface_not_configured'= Interfaces not Configured
          Dropped; 'bmr_prefixrules_configured'= BMR prefix rules configured;
          'helper_count'= Helper Count; 'active_dhcpv6_leases'= Active DHCPv6 leases;"
                type: str
    health_check_gateway:
        description:
        - "Field health_check_gateway"
        type: dict
        required: False
        suboptions:
            address_list:
                description:
                - "Field address_list"
                type: list
            ipv6_address_list:
                description:
                - "Field ipv6_address_list"
                type: list
            withdraw_route:
                description:
                - "'all-link-failure'= Withdraw routes on health-check failure of all IPv4
          gateways or all IPv6 gateways; 'any-link-failure'= Withdraw routes on health-
          check failure of any gateway (default);"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    basic_mapping_rule:
        description:
        - "Field basic_mapping_rule"
        type: dict
        required: False
        suboptions:
            rule_ipv4_address_port_settings:
                description:
                - "'prefix-addr'= Each CE is assigned an IPv4 prefix; 'single-addr'= Each CE is
          assigned an IPv4 address; 'shared-addr'= Each CE is assigned a shared IPv4
          address;"
                type: str
            ea_length:
                description:
                - "Length of Embedded Address (EA) bits"
                type: int
            share_ratio:
                description:
                - "Port sharing ratio for each NAT IP. Must be Power of 2 value"
                type: int
            port_start:
                description:
                - "Starting Port, Must be Power of 2 value"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
            prefix_rule_list:
                description:
                - "Field prefix_rule_list"
                type: list
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            inbound_packet_received:
                description:
                - "Inbound IPv4 Packets Received"
                type: str
            inbound_frag_packet_received:
                description:
                - "Inbound IPv4 Fragment Packets Received"
                type: str
            inbound_addr_port_validation_failed:
                description:
                - "Inbound IPv4 Destination Address Port Validation Failed"
                type: str
            inbound_rev_lookup_failed:
                description:
                - "Inbound IPv4 Reverse Route Lookup Failed"
                type: str
            inbound_dest_unreachable:
                description:
                - "Inbound IPv6 Destination Address Unreachable"
                type: str
            outbound_packet_received:
                description:
                - "Outbound IPv6 Packets Received"
                type: str
            outbound_frag_packet_received:
                description:
                - "Outbound IPv6 Fragment Packets Received"
                type: str
            outbound_addr_validation_failed:
                description:
                - "Outbound IPv6 Source Address Validation Failed"
                type: str
            outbound_rev_lookup_failed:
                description:
                - "Outbound IPv6 Reverse Route Lookup Failed"
                type: str
            outbound_dest_unreachable:
                description:
                - "Outbound IPv4 Destination Address Unreachable"
                type: str
            packet_mtu_exceeded:
                description:
                - "Packet Exceeded MTU"
                type: str
            frag_icmp_sent:
                description:
                - "ICMP Packet Too Big Sent"
                type: str
            interface_not_configured:
                description:
                - "Interfaces not Configured Dropped"
                type: str
            bmr_prefixrules_configured:
                description:
                - "BMR prefix rules configured"
                type: str
            name:
                description:
                - "MAP-E domain name"
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
    "basic_mapping_rule",
    "description",
    "format",
    "health_check_gateway",
    "name",
    "sampling_enable",
    "stats",
    "tunnel_endpoint_address",
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
        'name': {
            'type': 'str',
            'required': True,
        },
        'description': {
            'type': 'str',
        },
        'format': {
            'type': 'str',
            'choices': ['draft-03']
        },
        'tunnel_endpoint_address': {
            'type': 'str',
        },
        'uuid': {
            'type': 'str',
        },
        'user_tag': {
            'type': 'str',
        },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'inbound_packet_received',
                    'inbound_frag_packet_received',
                    'inbound_addr_port_validation_failed',
                    'inbound_rev_lookup_failed', 'inbound_dest_unreachable',
                    'outbound_packet_received',
                    'outbound_frag_packet_received',
                    'outbound_addr_validation_failed',
                    'outbound_rev_lookup_failed', 'outbound_dest_unreachable',
                    'packet_mtu_exceeded', 'frag_icmp_sent',
                    'interface_not_configured', 'bmr_prefixrules_configured',
                    'helper_count', 'active_dhcpv6_leases'
                ]
            }
        },
        'health_check_gateway': {
            'type': 'dict',
            'address_list': {
                'type': 'list',
                'ipv4_gateway': {
                    'type': 'str',
                }
            },
            'ipv6_address_list': {
                'type': 'list',
                'ipv6_gateway': {
                    'type': 'str',
                }
            },
            'withdraw_route': {
                'type': 'str',
                'choices': ['all-link-failure', 'any-link-failure']
            },
            'uuid': {
                'type': 'str',
            }
        },
        'basic_mapping_rule': {
            'type': 'dict',
            'rule_ipv4_address_port_settings': {
                'type': 'str',
                'choices': ['prefix-addr', 'single-addr', 'shared-addr']
            },
            'ea_length': {
                'type': 'int',
            },
            'share_ratio': {
                'type': 'int',
            },
            'port_start': {
                'type': 'int',
            },
            'uuid': {
                'type': 'str',
            },
            'prefix_rule_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                },
                'rule_ipv6_prefix': {
                    'type': 'str',
                },
                'rule_ipv4_prefix': {
                    'type': 'str',
                },
                'ipv4_netmask': {
                    'type': 'str',
                },
                'ipv4_address_port_settings': {
                    'type': 'str',
                    'choices': ['prefix-addr', 'single-addr', 'shared-addr']
                },
                'ea_length': {
                    'type': 'int',
                },
                'share_ratio': {
                    'type': 'int',
                },
                'port_start': {
                    'type': 'int',
                },
                'uuid': {
                    'type': 'str',
                },
                'user_tag': {
                    'type': 'str',
                }
            }
        },
        'stats': {
            'type': 'dict',
            'inbound_packet_received': {
                'type': 'str',
            },
            'inbound_frag_packet_received': {
                'type': 'str',
            },
            'inbound_addr_port_validation_failed': {
                'type': 'str',
            },
            'inbound_rev_lookup_failed': {
                'type': 'str',
            },
            'inbound_dest_unreachable': {
                'type': 'str',
            },
            'outbound_packet_received': {
                'type': 'str',
            },
            'outbound_frag_packet_received': {
                'type': 'str',
            },
            'outbound_addr_validation_failed': {
                'type': 'str',
            },
            'outbound_rev_lookup_failed': {
                'type': 'str',
            },
            'outbound_dest_unreachable': {
                'type': 'str',
            },
            'packet_mtu_exceeded': {
                'type': 'str',
            },
            'frag_icmp_sent': {
                'type': 'str',
            },
            'interface_not_configured': {
                'type': 'str',
            },
            'bmr_prefixrules_configured': {
                'type': 'str',
            },
            'name': {
                'type': 'str',
                'required': True,
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/map/encapsulation/domain/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


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
    url_base = "/axapi/v3/cgnv6/map/encapsulation/domain/{name}"

    f_dict = {}
    f_dict["name"] = ""

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
        for k, v in payload["domain"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["domain"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["domain"][k] = v
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
    payload = build_json("domain", module)
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
