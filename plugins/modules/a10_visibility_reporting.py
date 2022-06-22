#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_visibility_reporting
description:
    - Configure reporting framework
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
    session_logging:
        description:
        - "'enable'= Enable session logging; 'disable'= Disable session logging(default);"
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
                - "'all'= all; 'log-transmit-failure'= Total log transmit failures; 'buffer-alloc-
          failure'= Total reporting buffer allocation failures; 'notif-jobs-in-queue'=
          Total notification jobs in queue; 'enqueue-fail'= Total enqueue jobs failed;
          'enqueue-pass'= Total enqueue jobs passed; 'dequeued'= Total jobs dequeued;"
                type: str
    telemetry_export_interval:
        description:
        - "Field telemetry_export_interval"
        type: dict
        required: False
        suboptions:
            value:
                description:
                - "Monitored entity telemetry data export interval in mins (Default 5 mins)"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
    template:
        description:
        - "Field template"
        type: dict
        required: False
        suboptions:
            notification:
                description:
                - "Field notification"
                type: dict
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            log_transmit_failure:
                description:
                - "Total log transmit failures"
                type: str
            buffer_alloc_failure:
                description:
                - "Total reporting buffer allocation failures"
                type: str
            notif_jobs_in_queue:
                description:
                - "Total notification jobs in queue"
                type: str
            enqueue_fail:
                description:
                - "Total enqueue jobs failed"
                type: str
            enqueue_pass:
                description:
                - "Total enqueue jobs passed"
                type: str
            dequeued:
                description:
                - "Total jobs dequeued"
                type: str
            template:
                description:
                - "Field template"
                type: dict

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
AVAILABLE_PROPERTIES = ["sampling_enable", "session_logging", "stats", "telemetry_export_interval", "template", "uuid", ]


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(type='str', required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )


def get_argspec():
    rv = get_default_argspec()
    rv.update({'session_logging': {'type': 'str', 'choices': ['enable', 'disable']},
        'uuid': {'type': 'str', },
        'sampling_enable': {'type': 'list', 'counters1': {'type': 'str', 'choices': ['all', 'log-transmit-failure', 'buffer-alloc-failure', 'notif-jobs-in-queue', 'enqueue-fail', 'enqueue-pass', 'dequeued']}},
        'telemetry_export_interval': {'type': 'dict', 'value': {'type': 'int', }, 'uuid': {'type': 'str', }},
        'template': {'type': 'dict', 'notification': {'type': 'dict', 'template_name_list': {'type': 'list', 'name': {'type': 'str', 'required': True, }, 'ipv4_address': {'type': 'str', }, 'ipv6_address': {'type': 'str', }, 'host_name': {'type': 'str', }, 'use_mgmt_port': {'type': 'bool', }, 'protocol': {'type': 'str', 'choices': ['http', 'https']}, 'http_port': {'type': 'int', }, 'https_port': {'type': 'int', }, 'relative_uri': {'type': 'str', }, 'action': {'type': 'str', 'choices': ['enable', 'disable']}, 'debug_mode': {'type': 'bool', }, 'test_connectivity': {'type': 'bool', }, 'uuid': {'type': 'str', }, 'sampling_enable': {'type': 'list', 'counters1': {'type': 'str', 'choices': ['all', 'sent_successful', 'send_fail', 'response_fail']}}, 'authentication': {'type': 'dict', 'relative_login_uri': {'type': 'str', }, 'relative_logoff_uri': {'type': 'str', }, 'auth_username': {'type': 'str', }, 'auth_password': {'type': 'bool', }, 'auth_password_string': {'type': 'str', }, 'encrypted': {'type': 'str', }, 'api_key': {'type': 'bool', }, 'api_key_string': {'type': 'str', }, 'api_key_encrypted': {'type': 'str', }, 'uuid': {'type': 'str', }}}, 'debug': {'type': 'dict', 'uuid': {'type': 'str', }}}},
        'stats': {'type': 'dict', 'log_transmit_failure': {'type': 'str', }, 'buffer_alloc_failure': {'type': 'str', }, 'notif_jobs_in_queue': {'type': 'str', }, 'enqueue_fail': {'type': 'str', }, 'enqueue_pass': {'type': 'str', }, 'dequeued': {'type': 'str', }, 'template': {'type': 'dict', }}
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/visibility/reporting"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/visibility/reporting"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["reporting"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["reporting"].get(k) != v:
            change_results["changed"] = True
            config_changes["reporting"][k] = v

    change_results["modified_values"].update(**config_changes)
    return change_results


def create(module, result, payload={}):
    call_result = api_client.post(module.client, new_url(module), payload)
    result["axapi_calls"].append(call_result)
    result["modified_values"].update(
        **call_result["response_body"])
    result["changed"] = True
    return result


def update(module, result, existing_config, payload={}):
    call_result = api_client.post(module.client, existing_url(module), payload)
    result["axapi_calls"].append(call_result)
    if call_result["response_body"] == existing_config:
        result["changed"] = False
    else:
        result["modified_values"].update(
            **call_result["response_body"])
        result["changed"] = True
    return result


def present(module, result, existing_config):
    payload = utils.build_json("reporting", module.params, AVAILABLE_PROPERTIES)
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
    result = dict(
        changed=False,
        messages="",
        modified_values={},
        axapi_calls=[],
        ansible_facts={},
        acos_info={}
    )

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

    module.client = client_factory(ansible_host, ansible_port,
                                   protocol, ansible_username,
                                   ansible_password)

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
            result["axapi_calls"].append(
                api_client.active_partition(module.client, a10_partition))

        if a10_device_context_id:
             result["axapi_calls"].append(
                api_client.switch_device_context(module.client, a10_device_context_id))

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
                result["acos_info"] = info["reporting"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["reporting-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module),
                                                       params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["reporting"]["stats"] if info != "NotFound" else info
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
