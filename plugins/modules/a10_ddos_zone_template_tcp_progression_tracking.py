#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ddos_zone_template_tcp_progression_tracking
description:
    - Configure and enable TCP Progression Tracking
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
    tcp_name:
        description:
        - Key to identify parent object
        type: str
        required: True
    progression_tracking_enabled:
        description:
        - "'enable-check'= Enable Progression Tracking Check;"
        type: str
        required: True
    request_response_model:
        description:
        - "'enable'= Enable Request Response Model; 'disable'= Disable Request Response
          Model;"
        type: str
        required: False
    violation:
        description:
        - "Set the violation threshold"
        type: int
        required: False
    ignore_TLS_handshake:
        description:
        - "Ignore TLS handshake"
        type: bool
        required: False
    response_length_max:
        description:
        - "Set the maximum response length"
        type: int
        required: False
    response_length_min:
        description:
        - "Set the minimum response length"
        type: int
        required: False
    request_length_min:
        description:
        - "Set the minimum request length"
        type: int
        required: False
    request_length_max:
        description:
        - "Set the maximum request length"
        type: int
        required: False
    response_request_min_ratio:
        description:
        - "Set the minimum response to request ratio (in unit of 0.1% [1=1000])"
        type: int
        required: False
    response_request_max_ratio:
        description:
        - "Set the maximum response to request ratio (in unit of 0.1% [1=1000])"
        type: int
        required: False
    first_request_max_time:
        description:
        - "Set the maximum wait time from connection creation until the first data is
          transmitted over the connection (100 ms)"
        type: int
        required: False
    request_to_response_max_time:
        description:
        - "Set the maximum request to response time (100 ms)"
        type: int
        required: False
    response_to_request_max_time:
        description:
        - "Set the maximum response to request time (100 ms)"
        type: int
        required: False
    profiling_request_response_model:
        description:
        - "Enable auto-config progression tracking learning for Request Response model"
        type: bool
        required: False
    profiling_connection_life_model:
        description:
        - "Enable auto-config progression tracking learning for connection model"
        type: bool
        required: False
    profiling_time_window_model:
        description:
        - "Enable auto-config progression tracking learning for time window model"
        type: bool
        required: False
    progression_tracking_action_list_name:
        description:
        - "Configure action-list to take when progression tracking violation exceed"
        type: str
        required: False
    progression_tracking_action:
        description:
        - "'drop'= Drop packets for progression tracking violation exceed (Default);
          'blacklist-src'= Blacklist-src for progression tracking violation exceed;"
        type: str
        required: False
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    connection_tracking:
        description:
        - "Field connection_tracking"
        type: dict
        required: False
        suboptions:
            progression_tracking_conn_enabled:
                description:
                - "'enable-check'= Enable General Progression Tracking per Connection;"
                type: str
            conn_sent_max:
                description:
                - "Set the maximum total sent byte"
                type: int
            conn_sent_min:
                description:
                - "Set the minimum total sent byte"
                type: int
            conn_rcvd_max:
                description:
                - "Set the maximum total received byte"
                type: int
            conn_rcvd_min:
                description:
                - "Set the minimum total received byte"
                type: int
            conn_rcvd_sent_ratio_min:
                description:
                - "Set the minimum received to sent ratio (in unit of milli-, 0.001)"
                type: int
            conn_rcvd_sent_ratio_max:
                description:
                - "Set the maximum received to sent ratio (in unit of milli-, 0.001)"
                type: int
            conn_duration_max:
                description:
                - "Set the maximum duration time (in unit of 100ms, up to 24 hours)"
                type: int
            conn_duration_min:
                description:
                - "Set the minimum duration time (in unit of 100ms, up to 24 hours)"
                type: int
            conn_violation:
                description:
                - "Set the violation threshold"
                type: int
            progression_tracking_conn_action_list_name:
                description:
                - "Configure action-list to take when progression tracking violation exceed"
                type: str
            progression_tracking_conn_action:
                description:
                - "'drop'= Drop packets for progression tracking violation exceed (Default);
          'blacklist-src'= Blacklist-src for progression tracking violation exceed;"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    time_window_tracking:
        description:
        - "Field time_window_tracking"
        type: dict
        required: False
        suboptions:
            progression_tracking_win_enabled:
                description:
                - "'enable-check'= Enable Progression Tracking per Time Window;"
                type: str
            window_sent_max:
                description:
                - "Set the maximum total sent byte"
                type: int
            window_sent_min:
                description:
                - "Set the minimum total sent byte"
                type: int
            window_rcvd_max:
                description:
                - "Set the maximum total received byte"
                type: int
            window_rcvd_min:
                description:
                - "Set the minimum total received byte"
                type: int
            window_rcvd_sent_ratio_min:
                description:
                - "Set the minimum received to sent ratio (in unit of 0.1% [1=1000])"
                type: int
            window_rcvd_sent_ratio_max:
                description:
                - "Set the maximum received to sent ratio (in unit of 0.1% [1=1000])"
                type: int
            window_violation:
                description:
                - "Set the violation threshold"
                type: int
            progression_tracking_windows_action_list_name:
                description:
                - "Configure action-list to take when progression tracking violation exceed"
                type: str
            progression_tracking_windows_action:
                description:
                - "'drop'= Drop packets for progression tracking violation exceed (Default);
          'blacklist-src'= Blacklist-src for progression tracking violation exceed;"
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
    "connection_tracking", "first_request_max_time", "ignore_TLS_handshake", "profiling_connection_life_model", "profiling_request_response_model", "profiling_time_window_model", "progression_tracking_action", "progression_tracking_action_list_name", "progression_tracking_enabled", "request_length_max", "request_length_min",
    "request_response_model", "request_to_response_max_time", "response_length_max", "response_length_min", "response_request_max_ratio", "response_request_min_ratio", "response_to_request_max_time", "time_window_tracking", "uuid", "violation",
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
        'progression_tracking_enabled': {
            'type': 'str',
            'required': True,
            'choices': ['enable-check']
            },
        'request_response_model': {
            'type': 'str',
            'choices': ['enable', 'disable']
            },
        'violation': {
            'type': 'int',
            },
        'ignore_TLS_handshake': {
            'type': 'bool',
            },
        'response_length_max': {
            'type': 'int',
            },
        'response_length_min': {
            'type': 'int',
            },
        'request_length_min': {
            'type': 'int',
            },
        'request_length_max': {
            'type': 'int',
            },
        'response_request_min_ratio': {
            'type': 'int',
            },
        'response_request_max_ratio': {
            'type': 'int',
            },
        'first_request_max_time': {
            'type': 'int',
            },
        'request_to_response_max_time': {
            'type': 'int',
            },
        'response_to_request_max_time': {
            'type': 'int',
            },
        'profiling_request_response_model': {
            'type': 'bool',
            },
        'profiling_connection_life_model': {
            'type': 'bool',
            },
        'profiling_time_window_model': {
            'type': 'bool',
            },
        'progression_tracking_action_list_name': {
            'type': 'str',
            },
        'progression_tracking_action': {
            'type': 'str',
            'choices': ['drop', 'blacklist-src']
            },
        'uuid': {
            'type': 'str',
            },
        'connection_tracking': {
            'type': 'dict',
            'progression_tracking_conn_enabled': {
                'type': 'str',
                'choices': ['enable-check']
                },
            'conn_sent_max': {
                'type': 'int',
                },
            'conn_sent_min': {
                'type': 'int',
                },
            'conn_rcvd_max': {
                'type': 'int',
                },
            'conn_rcvd_min': {
                'type': 'int',
                },
            'conn_rcvd_sent_ratio_min': {
                'type': 'int',
                },
            'conn_rcvd_sent_ratio_max': {
                'type': 'int',
                },
            'conn_duration_max': {
                'type': 'int',
                },
            'conn_duration_min': {
                'type': 'int',
                },
            'conn_violation': {
                'type': 'int',
                },
            'progression_tracking_conn_action_list_name': {
                'type': 'str',
                },
            'progression_tracking_conn_action': {
                'type': 'str',
                'choices': ['drop', 'blacklist-src']
                },
            'uuid': {
                'type': 'str',
                }
            },
        'time_window_tracking': {
            'type': 'dict',
            'progression_tracking_win_enabled': {
                'type': 'str',
                'choices': ['enable-check']
                },
            'window_sent_max': {
                'type': 'int',
                },
            'window_sent_min': {
                'type': 'int',
                },
            'window_rcvd_max': {
                'type': 'int',
                },
            'window_rcvd_min': {
                'type': 'int',
                },
            'window_rcvd_sent_ratio_min': {
                'type': 'int',
                },
            'window_rcvd_sent_ratio_max': {
                'type': 'int',
                },
            'window_violation': {
                'type': 'int',
                },
            'progression_tracking_windows_action_list_name': {
                'type': 'str',
                },
            'progression_tracking_windows_action': {
                'type': 'str',
                'choices': ['drop', 'blacklist-src']
                },
            'uuid': {
                'type': 'str',
                }
            }
        })
    # Parent keys
    rv.update(dict(tcp_name=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/ddos/zone-template/tcp/{tcp_name}/progression-tracking"

    f_dict = {}
    if '/' in module.params["tcp_name"]:
        f_dict["tcp_name"] = module.params["tcp_name"].replace("/", "%2F")
    else:
        f_dict["tcp_name"] = module.params["tcp_name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ddos/zone-template/tcp/{tcp_name}/progression-tracking"

    f_dict = {}
    f_dict["tcp_name"] = module.params["tcp_name"]

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["progression-tracking"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["progression-tracking"].get(k) != v:
            change_results["changed"] = True
            config_changes["progression-tracking"][k] = v

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
    payload = utils.build_json("progression-tracking", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["progression-tracking"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["progression-tracking-list"] if info != "NotFound" else info
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