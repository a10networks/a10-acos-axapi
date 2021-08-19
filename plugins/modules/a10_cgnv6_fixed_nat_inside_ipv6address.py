#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_cgnv6_fixed_nat_inside_ipv6address
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
        - "IPv6 Inside User Start Address"
        type: str
        required: True
    inside_end_address:
        description:
        - "IPv6 Inside User End Address"
        type: str
        required: True
    inside_netmask:
        description:
        - "Inside User IPv6 Netmask"
        type: int
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
        'inside_start_address': {
            'type': 'str',
            'required': True,
        },
        'inside_end_address': {
            'type': 'str',
            'required': True,
        },
        'inside_netmask': {
            'type': 'int',
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
    url_base = "/axapi/v3/cgnv6/fixed-nat/inside/ipv6address/{inside-start-address}+{inside-end-address}+{inside-netmask}+{partition}"

    f_dict = {}
    f_dict["inside-start-address"] = module.params["inside_start_address"]
    f_dict["inside-end-address"] = module.params["inside_end_address"]
    f_dict["inside-netmask"] = module.params["inside_netmask"]
    f_dict["partition"] = module.params["partition"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/cgnv6/fixed-nat/inside/ipv6address/{inside-start-address}+{inside-end-address}+{inside-netmask}+{partition}"

    f_dict = {}
    f_dict["inside-start-address"] = ""
    f_dict["inside-end-address"] = ""
    f_dict["inside-netmask"] = ""
    f_dict["partition"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["ipv6address"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["ipv6address"].get(k) != v:
            change_results["changed"] = True
            config_changes["ipv6address"][k] = v

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
    payload = utils.build_json("ipv6address", module.params,
                               AVAILABLE_PROPERTIES)
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
