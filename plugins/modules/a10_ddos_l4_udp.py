#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ddos_l4_udp
description:
    - l4 udp counters
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
            udp_sess_create:
                description:
                - "UDP Sessions Created"
                type: str
            inudp:
                description:
                - "UDP Total Packets Received"
                type: str
            instateless:
                description:
                - "UDP Stateless Packets"
                type: str
            udp_total_drop:
                description:
                - "UDP Total Packets Dropped"
                type: str
            udp_drop_dst:
                description:
                - "UDP Dst Packets Dropped"
                type: str
            udp_drop_src:
                description:
                - "UDP Src Packets Dropped"
                type: str
            udp_drop_black_user_cfg_src:
                description:
                - "UDP Src Blacklist User Packets Dropped"
                type: str
            udp_src_dst_drop:
                description:
                - "UDP SrcDst Packets Dropped"
                type: str
            udp_drop_black_user_cfg_src_dst:
                description:
                - "UDP SrcDst Blacklist User Packets Dropped"
                type: str
            udp_port_zero_drop:
                description:
                - "UDP Port 0 Packets Dropped"
                type: str
            udp_wellknown_src_port_drop:
                description:
                - "UDP SrcPort Wellknown Dropped"
                type: str
            udp_retry_start:
                description:
                - "UDP Retry Init"
                type: str
            udp_retry_pass:
                description:
                - "UDP Retry Passed"
                type: str
            udp_retry_fail:
                description:
                - "UDP Retry Failed"
                type: str
            udp_retry_timeout:
                description:
                - "UDP Retry Timeout"
                type: str
            udp_payload_too_big_drop:
                description:
                - "UDP Payload Too Large Dropped"
                type: str
            udp_payload_too_small_drop:
                description:
                - "UDP Payload Too Small Dropped"
                type: str
            ntp_monlist_req_drop:
                description:
                - "NTP Monlist Request Dropped"
                type: str
            ntp_monlist_resp_drop:
                description:
                - "NTP Monlist Response Dropped"
                type: str
            udp_conn_prate_drop:
                description:
                - "UDP Conn Pkt Rate Dropped"
                type: str
            dst_udp_filter_match:
                description:
                - "Dst Filter Match"
                type: str
            dst_udp_filter_not_match:
                description:
                - "Dst Filter No Match"
                type: str
            dst_udp_filter_action_blacklist:
                description:
                - "Dst Filter Action Blacklist"
                type: str
            dst_udp_filter_action_drop:
                description:
                - "Dst Filter Action Drop"
                type: str
            dst_udp_filter_action_default_pass:
                description:
                - "Dst Filter Action Default Pass"
                type: str
            dst_udp_filter_action_whitelist:
                description:
                - "Dst Filter Action WL"
                type: str
            udp_auth_pass:
                description:
                - "UDP Auth Passed"
                type: str
            src_udp_filter_match:
                description:
                - "Src Filter Match"
                type: str
            src_udp_filter_not_match:
                description:
                - "Src Filter No Match"
                type: str
            src_udp_filter_action_blacklist:
                description:
                - "Src Filter Action Blacklist"
                type: str
            src_udp_filter_action_drop:
                description:
                - "Src Filter Action Drop"
                type: str
            src_udp_filter_action_default_pass:
                description:
                - "Src Filter Action Default Pass"
                type: str
            src_udp_filter_action_whitelist:
                description:
                - "Src Filter Action WL"
                type: str
            src_dst_udp_filter_match:
                description:
                - "SrcDst Filter Match"
                type: str
            src_dst_udp_filter_not_match:
                description:
                - "SrcDst Filter No Match"
                type: str
            src_dst_udp_filter_action_blacklist:
                description:
                - "SrcDst Filter Action Blacklist"
                type: str
            src_dst_udp_filter_action_drop:
                description:
                - "SrcDst Filter Action Drop"
                type: str
            src_dst_udp_filter_action_default_pass:
                description:
                - "SrcDst Filter Action Default Pass"
                type: str
            src_dst_udp_filter_action_whitelist:
                description:
                - "SrcDst Filter Action WL"
                type: str
            udp_wellknown_src_port:
                description:
                - "UDP SrcPort Wellknown"
                type: str
            udp_wellknown_src_port_bl:
                description:
                - "UDP SrcPort Wellknown Blacklisted"
                type: str
            udp_retry_pass_wl:
                description:
                - "UDP Retry Pass WL"
                type: str
            udp_retry_fail_bl:
                description:
                - "UDP Retry Fail Blacklisted"
                type: str
            udp_payload_too_big:
                description:
                - "UDP Payload Too Large"
                type: str
            udp_payload_too_big_bl:
                description:
                - "UDP Payload Too Large Blacklisted"
                type: str
            udp_payload_too_small:
                description:
                - "UDP Payload Too Small"
                type: str
            udp_payload_too_small_bl:
                description:
                - "UDP Payload Too Small Blacklisted"
                type: str
            ntp_monlist_req:
                description:
                - "NTP Monlist Request"
                type: str
            ntp_monlist_req_bl:
                description:
                - "NTP Monlist Request Blacklisted"
                type: str
            ntp_monlist_resp:
                description:
                - "NTP Monlist Response"
                type: str
            ntp_monlist_resp_bl:
                description:
                - "NTP Monlist Response Blacklsited"
                type: str
            udp_conn_prate_exceed:
                description:
                - "UDP Conn Pkt Rate Exceeded"
                type: str
            udp_conn_prate_bl:
                description:
                - "UDP Conn Pkt Rate Blacklisted"
                type: str
            udp_any_exceed:
                description:
                - "UDP Exceeded"
                type: str
            udp_drop_bl:
                description:
                - "UDP Blacklist Packets Dropped"
                type: str
            udp_frag_rcvd:
                description:
                - "UDP Frag Received"
                type: str
            udp_frag_drop:
                description:
                - "UDP Frag Dropped"
                type: str
            udp_auth_drop:
                description:
                - "UDP Auth Dropped"
                type: str
            udp_total_bytes_rcv:
                description:
                - "UDP Total Bytes Received"
                type: str
            udp_total_bytes_drop:
                description:
                - "UDP Total Bytes Dropped"
                type: str
            udp_retry_gap_drop:
                description:
                - "UDP Retry-Gap Drop"
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
            'udp_sess_create': {
                'type': 'str',
                },
            'inudp': {
                'type': 'str',
                },
            'instateless': {
                'type': 'str',
                },
            'udp_total_drop': {
                'type': 'str',
                },
            'udp_drop_dst': {
                'type': 'str',
                },
            'udp_drop_src': {
                'type': 'str',
                },
            'udp_drop_black_user_cfg_src': {
                'type': 'str',
                },
            'udp_src_dst_drop': {
                'type': 'str',
                },
            'udp_drop_black_user_cfg_src_dst': {
                'type': 'str',
                },
            'udp_port_zero_drop': {
                'type': 'str',
                },
            'udp_wellknown_src_port_drop': {
                'type': 'str',
                },
            'udp_retry_start': {
                'type': 'str',
                },
            'udp_retry_pass': {
                'type': 'str',
                },
            'udp_retry_fail': {
                'type': 'str',
                },
            'udp_retry_timeout': {
                'type': 'str',
                },
            'udp_payload_too_big_drop': {
                'type': 'str',
                },
            'udp_payload_too_small_drop': {
                'type': 'str',
                },
            'ntp_monlist_req_drop': {
                'type': 'str',
                },
            'ntp_monlist_resp_drop': {
                'type': 'str',
                },
            'udp_conn_prate_drop': {
                'type': 'str',
                },
            'dst_udp_filter_match': {
                'type': 'str',
                },
            'dst_udp_filter_not_match': {
                'type': 'str',
                },
            'dst_udp_filter_action_blacklist': {
                'type': 'str',
                },
            'dst_udp_filter_action_drop': {
                'type': 'str',
                },
            'dst_udp_filter_action_default_pass': {
                'type': 'str',
                },
            'dst_udp_filter_action_whitelist': {
                'type': 'str',
                },
            'udp_auth_pass': {
                'type': 'str',
                },
            'src_udp_filter_match': {
                'type': 'str',
                },
            'src_udp_filter_not_match': {
                'type': 'str',
                },
            'src_udp_filter_action_blacklist': {
                'type': 'str',
                },
            'src_udp_filter_action_drop': {
                'type': 'str',
                },
            'src_udp_filter_action_default_pass': {
                'type': 'str',
                },
            'src_udp_filter_action_whitelist': {
                'type': 'str',
                },
            'src_dst_udp_filter_match': {
                'type': 'str',
                },
            'src_dst_udp_filter_not_match': {
                'type': 'str',
                },
            'src_dst_udp_filter_action_blacklist': {
                'type': 'str',
                },
            'src_dst_udp_filter_action_drop': {
                'type': 'str',
                },
            'src_dst_udp_filter_action_default_pass': {
                'type': 'str',
                },
            'src_dst_udp_filter_action_whitelist': {
                'type': 'str',
                },
            'udp_wellknown_src_port': {
                'type': 'str',
                },
            'udp_wellknown_src_port_bl': {
                'type': 'str',
                },
            'udp_retry_pass_wl': {
                'type': 'str',
                },
            'udp_retry_fail_bl': {
                'type': 'str',
                },
            'udp_payload_too_big': {
                'type': 'str',
                },
            'udp_payload_too_big_bl': {
                'type': 'str',
                },
            'udp_payload_too_small': {
                'type': 'str',
                },
            'udp_payload_too_small_bl': {
                'type': 'str',
                },
            'ntp_monlist_req': {
                'type': 'str',
                },
            'ntp_monlist_req_bl': {
                'type': 'str',
                },
            'ntp_monlist_resp': {
                'type': 'str',
                },
            'ntp_monlist_resp_bl': {
                'type': 'str',
                },
            'udp_conn_prate_exceed': {
                'type': 'str',
                },
            'udp_conn_prate_bl': {
                'type': 'str',
                },
            'udp_any_exceed': {
                'type': 'str',
                },
            'udp_drop_bl': {
                'type': 'str',
                },
            'udp_frag_rcvd': {
                'type': 'str',
                },
            'udp_frag_drop': {
                'type': 'str',
                },
            'udp_auth_drop': {
                'type': 'str',
                },
            'udp_total_bytes_rcv': {
                'type': 'str',
                },
            'udp_total_bytes_drop': {
                'type': 'str',
                },
            'udp_retry_gap_drop': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/ddos/l4-udp"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ddos/l4-udp"

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
    payload = utils.build_json("l4-udp", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["l4-udp"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["l4-udp-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["l4-udp"]["stats"] if info != "NotFound" else info
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
