#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_cgnv6_map_translation_domain
description:
    - MAP Translation domain
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
        - "MAP-T domain name"
        type: str
        required: True
    description:
        description:
        - "MAP-T domain description"
        type: str
        required: False
    mtu:
        description:
        - "Domain MTU"
        type: int
        required: False
    tcp:
        description:
        - "Field tcp"
        type: dict
        required: False
        suboptions:
            mss_clamp:
                description:
                - "Field mss_clamp"
                type: dict
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
    packet_capture_template:
        description:
        - "Name of the packet capture template to be bind with this object"
        type: str
        required: False
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
    default_mapping_rule:
        description:
        - "Field default_mapping_rule"
        type: dict
        required: False
        suboptions:
            rule_ipv6_prefix:
                description:
                - "Rule IPv6 prefix"
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
                - "Starting Port, Must be Power of 2 value or zero"
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
                - "MAP-T domain name"
                type: str

'''

RETURN = r'''
modified_values:
    description:
    - Values modified (or potential changes if using check_mode) as a result of task operation
    returned: changed
    type: dict
axapi_calls:
    description: Sequential list of AXAPI calls made by the task
    returned: always
    type: list
    elements: dict
    contains:
        endpoint:
            description: The AXAPI endpoint being accessed.
            type: str
            sample:
                - /axapi/v3/slb/virtual_server
                - /axapi/v3/file/ssl-cert
        http_method:
            description:
            - HTTP method being used by the primary task to interact with the AXAPI endpoint.
            type: str
            sample:
                - POST
                - GET
        request_body:
            description: Params used to query the AXAPI
            type: complex
        response_body:
            description: Response from the AXAPI
            type: complex
'''

EXAMPLES = """
"""

import copy

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    wrapper as api_client
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    utils
from ansible_collections.a10.acos_axapi.plugins.module_utils.client import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "basic_mapping_rule",
    "default_mapping_rule",
    "description",
    "health_check_gateway",
    "mtu",
    "name",
    "packet_capture_template",
    "sampling_enable",
    "stats",
    "tcp",
    "user_tag",
    "uuid",
]


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
            type='str',
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
        'mtu': {
            'type': 'int',
        },
        'tcp': {
            'type': 'dict',
            'mss_clamp': {
                'type': 'dict',
                'mss_clamp_type': {
                    'type': 'str',
                    'choices': ['fixed', 'none', 'subtract']
                },
                'mss_value': {
                    'type': 'int',
                },
                'mss_subtract': {
                    'type': 'int',
                },
                'min': {
                    'type': 'int',
                }
            }
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
        'packet_capture_template': {
            'type': 'str',
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
        'default_mapping_rule': {
            'type': 'dict',
            'rule_ipv6_prefix': {
                'type': 'str',
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
    url_base = "/axapi/v3/cgnv6/map/translation/domain/{name}"

    f_dict = {}
    if '/' in str(module.params["name"]):
        f_dict["name"] = module.params["name"].replace("/", "%2F")
    else:
        f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/cgnv6/map/translation/domain/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["domain"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["domain"].get(k) != v:
            change_results["changed"] = True
            config_changes["domain"][k] = v

    change_results["modified_values"].update(**config_changes)
    return change_results


def create(module, result, payload={}):
    call_result = api_client.post(module.client, new_url(module), payload)
    result["axapi_calls"].append(call_result)
    result["modified_values"].update(**call_result["response_body"])
    result["changed"] = True
    return result


def update(module, result, existing_config, payload={}):
    call_result = api_client.post(module.client, existing_url(module), payload)
    result["axapi_calls"].append(call_result)
    if call_result["response_body"] == existing_config:
        result["changed"] = False
    else:
        result["modified_values"].update(**call_result["response_body"])
        result["changed"] = True
    return result


def present(module, result, existing_config):
    payload = utils.build_json("domain", module.params, AVAILABLE_PROPERTIES)
    change_results = report_changes(module, result, existing_config, payload)
    if module.check_mode:
        return change_results
    elif not existing_config:
        return create(module, result, payload)
    elif existing_config and change_results.get('changed'):
        return update(module, result, existing_config, payload)
    return result


def delete(module, result):
    try:
        call_result = api_client.delete(module.client, existing_url(module))
        result["axapi_calls"].append(call_result)
        result["changed"] = True
    except a10_ex.NotFound:
        result["changed"] = False
    return result


def absent(module, result, existing_config):
    if not existing_config:
        result["changed"] = False
        return result

    if module.check_mode:
        result["changed"] = True
        return result

    return delete(module, result)


def run_command(module):
    result = dict(changed=False,
                  messages="",
                  modified_values={},
                  axapi_calls=[],
                  ansible_facts={},
                  acos_info={})

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

    module.client = client_factory(ansible_host, ansible_port, protocol,
                                   ansible_username, ansible_password)

    valid = True

    run_errors = []
    if state == 'present':
        requires_one_of = sorted([])
        valid, validation_errors = utils.validate(module.params,
                                                  requires_one_of)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    try:
        if a10_partition:
            result["axapi_calls"].append(
                api_client.active_partition(module.client, a10_partition))

        if a10_device_context_id:
            result["axapi_calls"].append(
                api_client.switch_device_context(module.client,
                                                 a10_device_context_id))

        existing_config = api_client.get(module.client, existing_url(module))
        result["axapi_calls"].append(existing_config)
        if existing_config['response_body'] != 'NotFound':
            existing_config = existing_config["response_body"]
        else:
            existing_config = None

        if state == 'present':
            result = present(module, result, existing_config)

        if state == 'absent':
            result = absent(module, result, existing_config)

        if state == 'noop':
            if module.params.get("get_type") == "single":
                get_result = api_client.get(module.client,
                                            existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info[
                    "domain"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client,
                                                      existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info[
                    "domain-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client,
                                                       existing_url(module),
                                                       params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["domain"][
                    "stats"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()

    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
