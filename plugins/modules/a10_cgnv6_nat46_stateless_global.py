#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_cgnv6_nat46_stateless_global
description:
    - Stateless NAT46 Statistics
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
                - "'all'= all; 'outbound_ipv4_received'= Outbound IPv4 packets received;
          'outbound_ipv4_drop'= Outbound IPv4 packets dropped;
          'outbound_ipv4_fragment_received'= Outbound IPv4 fragment packets received;
          'outbound_ipv6_unreachable'= Outbound IPv6 destination unreachable;
          'outbound_ipv6_fragmented'= Outbound IPv6 packets fragmented;
          'inbound_ipv6_received'= Inbound IPv6 packets received; 'inbound_ipv6_drop'=
          Inbound IPv6 packets dropped; 'inbound_ipv6_fragment_received'= Inbound IPv6
          fragment packets received; 'inbound_ipv4_unreachable'= Inbound IPv4 destination
          unreachable; 'inbound_ipv4_fragmented'= Inbound IPv4 packets fragmented;
          'packet_too_big'= Packet too big; 'fragment_error'= Fragment processing errors;
          'icmpv6_to_icmp'= ICMPv6 to ICMP; 'icmpv6_to_icmp_error'= ICMPv6 to ICMP
          errors; 'icmp_to_icmpv6'= ICMP to ICMPv6; 'icmp_to_icmpv6_error'= ICMP to
          ICMPv6 errors; 'ha_standby'= HA is standby; 'other_error'= Other errors;
          'conn_count'= conn count;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            outbound_ipv4_received:
                description:
                - "Outbound IPv4 packets received"
                type: str
            outbound_ipv4_drop:
                description:
                - "Outbound IPv4 packets dropped"
                type: str
            outbound_ipv4_fragment_received:
                description:
                - "Outbound IPv4 fragment packets received"
                type: str
            outbound_ipv6_unreachable:
                description:
                - "Outbound IPv6 destination unreachable"
                type: str
            outbound_ipv6_fragmented:
                description:
                - "Outbound IPv6 packets fragmented"
                type: str
            inbound_ipv6_received:
                description:
                - "Inbound IPv6 packets received"
                type: str
            inbound_ipv6_drop:
                description:
                - "Inbound IPv6 packets dropped"
                type: str
            inbound_ipv6_fragment_received:
                description:
                - "Inbound IPv6 fragment packets received"
                type: str
            inbound_ipv4_unreachable:
                description:
                - "Inbound IPv4 destination unreachable"
                type: str
            inbound_ipv4_fragmented:
                description:
                - "Inbound IPv4 packets fragmented"
                type: str
            packet_too_big:
                description:
                - "Packet too big"
                type: str
            fragment_error:
                description:
                - "Fragment processing errors"
                type: str
            icmpv6_to_icmp:
                description:
                - "ICMPv6 to ICMP"
                type: str
            icmpv6_to_icmp_error:
                description:
                - "ICMPv6 to ICMP errors"
                type: str
            icmp_to_icmpv6:
                description:
                - "ICMP to ICMPv6"
                type: str
            icmp_to_icmpv6_error:
                description:
                - "ICMP to ICMPv6 errors"
                type: str
            ha_standby:
                description:
                - "HA is standby"
                type: str
            other_error:
                description:
                - "Other errors"
                type: str
            conn_count:
                description:
                - "conn count"
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
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_client import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "sampling_enable",
    "stats",
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
        'uuid': {
            'type': 'str',
        },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'outbound_ipv4_received', 'outbound_ipv4_drop',
                    'outbound_ipv4_fragment_received',
                    'outbound_ipv6_unreachable', 'outbound_ipv6_fragmented',
                    'inbound_ipv6_received', 'inbound_ipv6_drop',
                    'inbound_ipv6_fragment_received',
                    'inbound_ipv4_unreachable', 'inbound_ipv4_fragmented',
                    'packet_too_big', 'fragment_error', 'icmpv6_to_icmp',
                    'icmpv6_to_icmp_error', 'icmp_to_icmpv6',
                    'icmp_to_icmpv6_error', 'ha_standby', 'other_error',
                    'conn_count'
                ]
            }
        },
        'stats': {
            'type': 'dict',
            'outbound_ipv4_received': {
                'type': 'str',
            },
            'outbound_ipv4_drop': {
                'type': 'str',
            },
            'outbound_ipv4_fragment_received': {
                'type': 'str',
            },
            'outbound_ipv6_unreachable': {
                'type': 'str',
            },
            'outbound_ipv6_fragmented': {
                'type': 'str',
            },
            'inbound_ipv6_received': {
                'type': 'str',
            },
            'inbound_ipv6_drop': {
                'type': 'str',
            },
            'inbound_ipv6_fragment_received': {
                'type': 'str',
            },
            'inbound_ipv4_unreachable': {
                'type': 'str',
            },
            'inbound_ipv4_fragmented': {
                'type': 'str',
            },
            'packet_too_big': {
                'type': 'str',
            },
            'fragment_error': {
                'type': 'str',
            },
            'icmpv6_to_icmp': {
                'type': 'str',
            },
            'icmpv6_to_icmp_error': {
                'type': 'str',
            },
            'icmp_to_icmpv6': {
                'type': 'str',
            },
            'icmp_to_icmpv6_error': {
                'type': 'str',
            },
            'ha_standby': {
                'type': 'str',
            },
            'other_error': {
                'type': 'str',
            },
            'conn_count': {
                'type': 'str',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/nat46-stateless/global"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/cgnv6/nat46-stateless/global"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["global"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["global"].get(k) != v:
            change_results["changed"] = True
            config_changes["global"][k] = v

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
    payload = utils.build_json("global", module.params, AVAILABLE_PROPERTIES)
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
                  axapi_calls=[])

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
        if existing_config['response_body'] != 'Not Found':
            existing_config = existing_config["response_body"]
        else:
            existing_config = None

        if state == 'present':
            result = present(module, result, existing_config)

        if state == 'absent':
            result = absent(module, result, existing_config)

        if state == 'noop':
            if module.params.get("get_type") == "single":
                result["axapi_calls"].append(
                    api_client.get(module.client, existing_url(module)))
            elif module.params.get("get_type") == "list":
                result["axapi_calls"].append(
                    api_client.get_list(module.client, existing_url(module)))
            elif module.params.get("get_type") == "stats":
                result["axapi_calls"].append(
                    api_client.get_stats(module.client, existing_url(module)))
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.session.session_id:
            module.client.session.close()

    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
