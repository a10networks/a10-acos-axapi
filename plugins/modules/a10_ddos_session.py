#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ddos_session
description:
    - session counters
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
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            sess_create_ip:
                description:
                - "IPv4 Session Created"
                type: str
            sess_create_ip6:
                description:
                - "IPv6 Session Created"
                type: str
            sess_create_tcp:
                description:
                - "TCP Sessions Created"
                type: str
            conn_tcp_est_w_syn:
                description:
                - "TCP Conn Established With SYN"
                type: str
            conn_tcp_est_w_ack:
                description:
                - "TCP Conn Established With ACK"
                type: str
            conn_tcp_est:
                description:
                - "TCP Conn Established"
                type: str
            conn_tcp_close_w_rst:
                description:
                - "TCP Conn Closed With RST"
                type: str
            conn_tcp_close_w_fin:
                description:
                - "TCP Conn Closed With FIN"
                type: str
            conn_tcp_close_w_idle:
                description:
                - "TCP Conn Closed With Idle"
                type: str
            conn_tcp_close_w_half_open:
                description:
                - "TCP Conn Closed With Half Open"
                type: str
            conn_tcp_close:
                description:
                - "TCP Conn Closed"
                type: str
            sess_create_udp:
                description:
                - "UDP Sessions Created"
                type: str
            conn_udp_est:
                description:
                - "UDP Conn Established"
                type: str
            conn_udp_close:
                description:
                - "UDP Conn Closed"
                type: str
            sess_aged_out:
                description:
                - "Session Aged Out"
                type: str
            conn_entry_mismatch:
                description:
                - "Conn Entry Mismatch Dropped"
                type: str
            conn_tcp_create_from_syn:
                description:
                - "TCP Conn Created From SYN"
                type: str
            conn_tcp_create_from_ack:
                description:
                - "TCP Conn Created From ACK"
                type: str
            sess_oom:
                description:
                - "Out of Session Memory"
                type: str
            sess_create_udp_auth:
                description:
                - "UDP Helper Auth Sessions Created"
                type: str
            sess_aged_udp_auth:
                description:
                - "UDP Helper Auth Sessions Aged Out"
                type: str
            sess_snat_failed:
                description:
                - "Session Source NAT Failure"
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
AVAILABLE_PROPERTIES = ["stats", "uuid", ]


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
        'uuid': {
            'type': 'str',
            },
        'stats': {
            'type': 'dict',
            'sess_create_ip': {
                'type': 'str',
                },
            'sess_create_ip6': {
                'type': 'str',
                },
            'sess_create_tcp': {
                'type': 'str',
                },
            'conn_tcp_est_w_syn': {
                'type': 'str',
                },
            'conn_tcp_est_w_ack': {
                'type': 'str',
                },
            'conn_tcp_est': {
                'type': 'str',
                },
            'conn_tcp_close_w_rst': {
                'type': 'str',
                },
            'conn_tcp_close_w_fin': {
                'type': 'str',
                },
            'conn_tcp_close_w_idle': {
                'type': 'str',
                },
            'conn_tcp_close_w_half_open': {
                'type': 'str',
                },
            'conn_tcp_close': {
                'type': 'str',
                },
            'sess_create_udp': {
                'type': 'str',
                },
            'conn_udp_est': {
                'type': 'str',
                },
            'conn_udp_close': {
                'type': 'str',
                },
            'sess_aged_out': {
                'type': 'str',
                },
            'conn_entry_mismatch': {
                'type': 'str',
                },
            'conn_tcp_create_from_syn': {
                'type': 'str',
                },
            'conn_tcp_create_from_ack': {
                'type': 'str',
                },
            'sess_oom': {
                'type': 'str',
                },
            'sess_create_udp_auth': {
                'type': 'str',
                },
            'sess_aged_udp_auth': {
                'type': 'str',
                },
            'sess_snat_failed': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/ddos/session"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ddos/session"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config):
    if existing_config:
        result["changed"] = True
    return result


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
    payload = utils.build_json("session", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["session"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["session-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["session"]["stats"] if info != "NotFound" else info
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
