#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_flowspec
description:
    - Configure Flowspec
author: A10 Networks
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
        - "Flowspec name"
        type: str
        required: True
    src_addr_type:
        description:
        - "'ip'= IPv4 Address; 'ipv6'= IPv6 Address;"
        type: str
        required: False
    src_ip_host:
        description:
        - "IPv4 host address"
        type: str
        required: False
    src_ip_subnet:
        description:
        - "IPv4 Subnet address"
        type: str
        required: False
    src_ipv6_host:
        description:
        - "IPv6 host address"
        type: str
        required: False
    src_ipv6_subnet:
        description:
        - "IPv6 Subnet address"
        type: str
        required: False
    dest_addr_type:
        description:
        - "'ip'= IPv4 Address; 'ipv6'= IPv6 Address;"
        type: str
        required: False
    dest_ip_host:
        description:
        - "IPv4 host address"
        type: str
        required: False
    dest_ip_subnet:
        description:
        - "IPv4 Subnet address"
        type: str
        required: False
    dest_ipv6_host:
        description:
        - "IPv6 host address"
        type: str
        required: False
    dest_ipv6_subnet:
        description:
        - "IPv6 Subnet address"
        type: str
        required: False
    tcp_flags:
        description:
        - "'match-all'= not = 0 match = 1; 'none-of'= not = 1 match = 0; 'not-match'= not
          = 1 match = 1; 'match-any'= not = 0 match = 0;"
        type: str
        required: False
    tcp_flags_bitmask:
        description:
        - "Bitmask in Hex"
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
    source_port_list:
        description:
        - "Field source_port_list"
        type: list
        required: False
        suboptions:
            port_attribute:
                description:
                - "'eq'= Match only packets on a given source port; 'gt'= Match only packets with
          a greater port number; 'lt'= Match only packets with a lower port number;
          'range'= match only packets in the range of port numbers;"
                type: str
            port_num:
                description:
                - "Specify the port number"
                type: int
            port_num_end:
                description:
                - "Specify the port number"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
    destination_port_list:
        description:
        - "Field destination_port_list"
        type: list
        required: False
        suboptions:
            port_attribute:
                description:
                - "'eq'= Match only packets on a given destination port; 'gt'= Match only packets
          with a greater port number; 'lt'= Match only packets with a lower port number;
          'range'= match only packets in the range of port numbers;"
                type: str
            port_num:
                description:
                - "Specify the port number"
                type: int
            port_num_end:
                description:
                - "Specify the port number"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
    port_list:
        description:
        - "Field port_list"
        type: list
        required: False
        suboptions:
            port_attribute:
                description:
                - "'eq'= Match only packets on a given port; 'gt'= Match only packets with a
          greater port number; 'lt'= Match only packets with a lower port number;
          'range'= match only packets in the range of port numbers;"
                type: str
            port_num:
                description:
                - "Specify the port number"
                type: int
            port_num_end:
                description:
                - "Specify the port number"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
    protocol_list:
        description:
        - "Field protocol_list"
        type: list
        required: False
        suboptions:
            proto_attribute:
                description:
                - "'eq'= Match only packets on a given protocol; 'gt'= Match only packets with a
          greater protocol number; 'lt'= Match only packets with a lower protocol number;
          'range'= match only packets in the range of protocol numbers;"
                type: str
            proto_num:
                description:
                - "Specify the protocol number(6 for TCP and 17 for UDP)"
                type: int
            proto_num_end:
                description:
                - "Specify the protocol number"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
    fragmentation_option_list:
        description:
        - "Field fragmentation_option_list"
        type: list
        required: False
        suboptions:
            frag_attribute:
                description:
                - "'is-fragment'= Is fragmented packet; 'first-fragment'= Is the first fragment
          packet; 'last-fragment'= Is the last fragment; 'dont-fragment'= Is DF bit set;"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    icmp_type_list:
        description:
        - "Field icmp_type_list"
        type: list
        required: False
        suboptions:
            icmp_type_attribute:
                description:
                - "'eq'= Match only packets on a given ICMP Type; 'gt'= Match only packets with a
          greater ICMP Type; 'lt'= Match only packets with a lower ICMP Type; 'range'=
          match only packets in the range of ICMP Types;"
                type: str
            ntype:
                description:
                - "Specify the ICMP Type"
                type: int
            type_end:
                description:
                - "Specify the ICMP Type"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
    icmp_code_list:
        description:
        - "Field icmp_code_list"
        type: list
        required: False
        suboptions:
            icmp_code_attribute:
                description:
                - "'eq'= Match only packets on a given ICMP Code; 'gt'= Match only packets with a
          greater ICMP Code; 'lt'= Match only packets with a lower ICMP Code; 'range'=
          match only packets in the range of ICMP Codes;"
                type: str
            code:
                description:
                - "Specify the ICMP Code"
                type: int
            code_end:
                description:
                - "Specify the ICMP Code"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
    packet_length_list:
        description:
        - "Field packet_length_list"
        type: list
        required: False
        suboptions:
            packet_length_attribute:
                description:
                - "'eq'= Match only packets on a given Packet Length; 'gt'= Match only packets
          with a greater Packet Length; 'lt'= Match only packets with a lower Packet
          Length; 'range'= match only packets in the range of Packet Lengths;"
                type: str
            length:
                description:
                - "Specify the Packet Length"
                type: int
            length_end:
                description:
                - "Specify the Packet Length"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
    dscp_list:
        description:
        - "Field dscp_list"
        type: list
        required: False
        suboptions:
            dscp_attribute:
                description:
                - "'eq'= Match only packets on a given DSCP; 'gt'= Match only packets with a
          greater DSCP; 'lt'= Match only packets with a lower DSCP; 'range'= match only
          packets in the range of DSCPs;"
                type: str
            dscp_val:
                description:
                - "Specify the DSCP value"
                type: int
            dscp_val_end:
                description:
                - "Specify the DSCP value"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
    filtering_action:
        description:
        - "Field filtering_action"
        type: dict
        required: False
        suboptions:
            terminal_action:
                description:
                - "Evaluation stops after this rule if not set"
                type: bool
            sample_log:
                description:
                - "Enable traffic sampling and logging"
                type: bool
            traffic_rate:
                description:
                - "Type 0x8006 - Apply rate (in Bytes per second) for this class of traffic"
                type: int
            traffic_marking:
                description:
                - "'dscp'= IPv4 DSCP; 'ipv6-traffic-class'= IPv6 Traffic Class;"
                type: str
            dscp_val:
                description:
                - "Set DSCP value"
                type: int
            traffic_class:
                description:
                - "Set IPv6 Traffic Class value"
                type: int
            redirect:
                description:
                - "'next-hop-nlri'= Type 0x0800 - IP encoded in MP_REACH_NLRI Next-hop network;
          'next-hop'= Type 0x0800 - Extended community Next-hop (Per v2 dated Feb 2015);
          'vrf-route-target'= Type 0x8008 - Redirect to VRF Route Target;"
                type: str
            next_hop_nlri_type:
                description:
                - "'ip'= Type 0x0800 - IPv4 Address; 'ipv6'= Type 0x0800 - IPv6 Address;"
                type: str
            ip_host_nlri:
                description:
                - "IPv4 host address"
                type: str
            copy_ip_host_nlri:
                description:
                - "Copy bit"
                type: bool
            ipv6_host_nlri:
                description:
                - "IPv6 host address"
                type: str
            copy_ipv6_host_nlri:
                description:
                - "Copy bit"
                type: bool
            next_hop_type:
                description:
                - "'ip'= Type 0x0800 - IPv4 Address; 'ipv6'= Type 0x0800 - IPv6 Address;"
                type: str
            ip_host:
                description:
                - "IPv4 host address"
                type: str
            copy_ip_host:
                description:
                - "Copy bit"
                type: bool
            ipv6_host:
                description:
                - "IPv6 host address"
                type: str
            copy_ipv6_host:
                description:
                - "Copy bit"
                type: bool
            vrf_target_string:
                description:
                - "Type 0x8008(ASN-2=Index), 0x8208(ASN-4=Index) - Route Target AS"
                type: str
            vrf_target_ip:
                description:
                - "'ip'= Type 0x8108 - Redirect to route-target IP;"
                type: str
            ip_host_rt:
                description:
                - "Type 0x8108 - Route Target IPv4"
                type: str
            value_ip_host:
                description:
                - "2-byte decimal value(local-administrator)"
                type: int
            ecomm_custom_hex:
                description:
                - "Custom Extended Community in Hex"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    operational_mode:
        description:
        - "Field operational_mode"
        type: dict
        required: False
        suboptions:
            mode:
                description:
                - "'enabled'= Enable the flowspec and send the prefix to BGP; 'disabled'= Disable
          the flowspec and remove the prefix from BGP;"
                type: str
            uuid:
                description:
                - "uuid of the object"
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
    "dest_addr_type", "dest_ip_host", "dest_ip_subnet", "dest_ipv6_host", "dest_ipv6_subnet", "destination_port_list", "dscp_list", "filtering_action", "fragmentation_option_list", "icmp_code_list", "icmp_type_list", "name", "operational_mode", "packet_length_list", "port_list", "protocol_list", "source_port_list", "src_addr_type", "src_ip_host",
    "src_ip_subnet", "src_ipv6_host", "src_ipv6_subnet", "tcp_flags", "tcp_flags_bitmask", "user_tag", "uuid",
    ]


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(type='str', required=False,
                           ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False,
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
        'src_addr_type': {
            'type': 'str',
            'choices': ['ip', 'ipv6']
            },
        'src_ip_host': {
            'type': 'str',
            },
        'src_ip_subnet': {
            'type': 'str',
            },
        'src_ipv6_host': {
            'type': 'str',
            },
        'src_ipv6_subnet': {
            'type': 'str',
            },
        'dest_addr_type': {
            'type': 'str',
            'choices': ['ip', 'ipv6']
            },
        'dest_ip_host': {
            'type': 'str',
            },
        'dest_ip_subnet': {
            'type': 'str',
            },
        'dest_ipv6_host': {
            'type': 'str',
            },
        'dest_ipv6_subnet': {
            'type': 'str',
            },
        'tcp_flags': {
            'type': 'str',
            'choices': ['match-all', 'none-of', 'not-match', 'match-any']
            },
        'tcp_flags_bitmask': {
            'type': 'str',
            },
        'uuid': {
            'type': 'str',
            },
        'user_tag': {
            'type': 'str',
            },
        'source_port_list': {
            'type': 'list',
            'port_attribute': {
                'type': 'str',
                'required': True,
                'choices': ['eq', 'gt', 'lt', 'range']
                },
            'port_num': {
                'type': 'int',
                'required': True,
                },
            'port_num_end': {
                'type': 'int',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'destination_port_list': {
            'type': 'list',
            'port_attribute': {
                'type': 'str',
                'required': True,
                'choices': ['eq', 'gt', 'lt', 'range']
                },
            'port_num': {
                'type': 'int',
                'required': True,
                },
            'port_num_end': {
                'type': 'int',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'port_list': {
            'type': 'list',
            'port_attribute': {
                'type': 'str',
                'required': True,
                'choices': ['eq', 'gt', 'lt', 'range']
                },
            'port_num': {
                'type': 'int',
                'required': True,
                },
            'port_num_end': {
                'type': 'int',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'protocol_list': {
            'type': 'list',
            'proto_attribute': {
                'type': 'str',
                'required': True,
                'choices': ['eq', 'gt', 'lt', 'range']
                },
            'proto_num': {
                'type': 'int',
                'required': True,
                },
            'proto_num_end': {
                'type': 'int',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'fragmentation_option_list': {
            'type': 'list',
            'frag_attribute': {
                'type': 'str',
                'required': True,
                'choices': ['is-fragment', 'first-fragment', 'last-fragment', 'dont-fragment']
                },
            'uuid': {
                'type': 'str',
                }
            },
        'icmp_type_list': {
            'type': 'list',
            'icmp_type_attribute': {
                'type': 'str',
                'required': True,
                'choices': ['eq', 'gt', 'lt', 'range']
                },
            'ntype': {
                'type': 'int',
                'required': True,
                },
            'type_end': {
                'type': 'int',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'icmp_code_list': {
            'type': 'list',
            'icmp_code_attribute': {
                'type': 'str',
                'required': True,
                'choices': ['eq', 'gt', 'lt', 'range']
                },
            'code': {
                'type': 'int',
                'required': True,
                },
            'code_end': {
                'type': 'int',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'packet_length_list': {
            'type': 'list',
            'packet_length_attribute': {
                'type': 'str',
                'required': True,
                'choices': ['eq', 'gt', 'lt', 'range']
                },
            'length': {
                'type': 'int',
                'required': True,
                },
            'length_end': {
                'type': 'int',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'dscp_list': {
            'type': 'list',
            'dscp_attribute': {
                'type': 'str',
                'required': True,
                'choices': ['eq', 'gt', 'lt', 'range']
                },
            'dscp_val': {
                'type': 'int',
                'required': True,
                },
            'dscp_val_end': {
                'type': 'int',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'filtering_action': {
            'type': 'dict',
            'terminal_action': {
                'type': 'bool',
                },
            'sample_log': {
                'type': 'bool',
                },
            'traffic_rate': {
                'type': 'int',
                },
            'traffic_marking': {
                'type': 'str',
                'choices': ['dscp', 'ipv6-traffic-class']
                },
            'dscp_val': {
                'type': 'int',
                },
            'traffic_class': {
                'type': 'int',
                },
            'redirect': {
                'type': 'str',
                'choices': ['next-hop-nlri', 'next-hop', 'vrf-route-target']
                },
            'next_hop_nlri_type': {
                'type': 'str',
                'choices': ['ip', 'ipv6']
                },
            'ip_host_nlri': {
                'type': 'str',
                },
            'copy_ip_host_nlri': {
                'type': 'bool',
                },
            'ipv6_host_nlri': {
                'type': 'str',
                },
            'copy_ipv6_host_nlri': {
                'type': 'bool',
                },
            'next_hop_type': {
                'type': 'str',
                'choices': ['ip', 'ipv6']
                },
            'ip_host': {
                'type': 'str',
                },
            'copy_ip_host': {
                'type': 'bool',
                },
            'ipv6_host': {
                'type': 'str',
                },
            'copy_ipv6_host': {
                'type': 'bool',
                },
            'vrf_target_string': {
                'type': 'str',
                },
            'vrf_target_ip': {
                'type': 'str',
                'choices': ['ip']
                },
            'ip_host_rt': {
                'type': 'str',
                },
            'value_ip_host': {
                'type': 'int',
                },
            'ecomm_custom_hex': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'operational_mode': {
            'type': 'dict',
            'mode': {
                'type': 'str',
                'choices': ['enabled', 'disabled']
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
    url_base = "/axapi/v3/flowspec/{name}"

    f_dict = {}
    if '/' in str(module.params["name"]):
        f_dict["name"] = module.params["name"].replace("/", "%2F")
    else:
        f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/flowspec"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["flowspec"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["flowspec"].get(k) != v:
            change_results["changed"] = True
            config_changes["flowspec"][k] = v

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
    payload = utils.build_json("flowspec", module.params, AVAILABLE_PROPERTIES)
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
    result = dict(changed=False, messages="", modified_values={}, axapi_calls=[], ansible_facts={}, acos_info={})

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

    module.client = client_factory(ansible_host, ansible_port, protocol, ansible_username, ansible_password)

    valid = True

    run_errors = []
    if state == 'present':
        requires_one_of = sorted([])
        valid, validation_errors = utils.validate(module.params, requires_one_of)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    try:
        if a10_partition:
            result["axapi_calls"].append(api_client.active_partition(module.client, a10_partition))

        if a10_device_context_id:
            result["axapi_calls"].append(api_client.switch_device_context(module.client, a10_device_context_id))

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
                get_result = api_client.get(module.client, existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info["flowspec"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["flowspec-list"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()

    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
