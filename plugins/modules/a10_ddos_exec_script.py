#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ddos_exec_script
description:
    - Execute scripts
author: A10 Networks
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
    script:
        description:
        - "Specify script to execute"
        type: str
        required: False
    mock:
        description:
        - "Use mock data"
        type: bool
        required: False
    alert_type:
        description:
        - "1= UDP Pkt Rate 2= TCP Pkt Rate 3= ICMP Pkt Rate"
        type: int
        required: False
    level:
        description:
        - "Current Level"
        type: int
        required: False
    threshold:
        description:
        - "Threshold"
        type: int
        required: False
    zone:
        description:
        - "DST Zone name"
        type: str
        required: False
    port_num:
        description:
        - "Port Number"
        type: int
        required: False
    protocol:
        description:
        - "'dns-tcp'= DNS-TCP Port; 'dns-udp'= DNS-UDP Port; 'http'= HTTP Port; 'tcp'= TCP
          Port; 'udp'= UDP Port; 'ssl-l4'= SSL-L4 Port; 'sip-tcp'= SIP-TCP Port; 'sip-
          udp'= SIP-UDP Port; 'quic'= QUIC Port;"
        type: str
        required: False
    port_other:
        description:
        - "'other'= other;"
        type: str
        required: False
    exec_script_port_other_protocol:
        description:
        - "'tcp'= TCP Port; 'udp'= UDP Port;"
        type: str
        required: False
    protocol_num:
        description:
        - "Protocol Number"
        type: int
        required: False
    exec_script_ip_portocol:
        description:
        - "'icmp-v4'= ip-proto icmp-v4; 'icmp-v6'= ip-proto icmp-v6; 'other'= ip-proto
          other; 'gre'= ip-proto gre; 'ipv4-encap'= ip-proto IPv4 Encapsulation;
          'ipv6-encap'= ip-proto IPv6 Encapsulation;"
        type: str
        required: False
    src_ip:
        description:
        - "Field src_ip"
        type: list
        required: False
        suboptions:
            ip_addr:
                description:
                - "Specify IP address"
                type: str
            subnet_ip_addr:
                description:
                - "IP Subnet"
                type: str
    src_ipv6:
        description:
        - "Field src_ipv6"
        type: list
        required: False
        suboptions:
            ip6_addr:
                description:
                - "Specify IPv6 address"
                type: str
            subnet_ipv6_addr:
                description:
                - "IPV6 Subnet"
                type: str
    timeout:
        description:
        - "Timeout (Default= 10 seconds, Mock Default= 2 seconds)"
        type: int
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
from ansible_collections.a10.acos_axapi.plugins.module_utils.client import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["alert_type", "exec_script_ip_portocol", "exec_script_port_other_protocol", "level", "mock", "port_num", "port_other", "protocol", "protocol_num", "script", "src_ip", "src_ipv6", "threshold", "timeout", "zone", ]


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present']),
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
        'script': {
            'type': 'str',
            },
        'mock': {
            'type': 'bool',
            },
        'alert_type': {
            'type': 'int',
            },
        'level': {
            'type': 'int',
            },
        'threshold': {
            'type': 'int',
            },
        'zone': {
            'type': 'str',
            },
        'port_num': {
            'type': 'int',
            },
        'protocol': {
            'type': 'str',
            'choices': ['dns-tcp', 'dns-udp', 'http', 'tcp', 'udp', 'ssl-l4', 'sip-tcp', 'sip-udp', 'quic']
            },
        'port_other': {
            'type': 'str',
            'choices': ['other']
            },
        'exec_script_port_other_protocol': {
            'type': 'str',
            'choices': ['tcp', 'udp']
            },
        'protocol_num': {
            'type': 'int',
            },
        'exec_script_ip_portocol': {
            'type': 'str',
            'choices': ['icmp-v4', 'icmp-v6', 'other', 'gre', 'ipv4-encap', 'ipv6-encap']
            },
        'src_ip': {
            'type': 'list',
            'ip_addr': {
                'type': 'str',
                },
            'subnet_ip_addr': {
                'type': 'str',
                }
            },
        'src_ipv6': {
            'type': 'list',
            'ip6_addr': {
                'type': 'str',
                },
            'subnet_ipv6_addr': {
                'type': 'str',
                }
            },
        'timeout': {
            'type': 'int',
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/ddos/exec-script"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ddos/exec-script"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["exec-script"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["exec-script"].get(k) != v:
            change_results["changed"] = True
            config_changes["exec-script"][k] = v

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
    payload = utils.build_json("exec-script", module.params, AVAILABLE_PROPERTIES)
    change_results = report_changes(module, result, existing_config, payload)
    if module.check_mode:
        return change_results
    elif not existing_config:
        return create(module, result, payload)
    elif existing_config and change_results.get('changed'):
        return update(module, result, existing_config, payload)
    return result


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

        if state == 'noop':
            if module.params.get("get_type") == "single":
                get_result = api_client.get(module.client, existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info["exec-script"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["exec-script-list"] if info != "NotFound" else info
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
