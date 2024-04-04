#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_visibility_packet_capture_object_templates_smtp_vport_tmpl_trigger_stats_rate
description:
    - Configure stats to triggers packet capture on increment
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
    smtp_vport_tmpl_name:
        description:
        - Key to identify parent object
        type: str
        required: True
    threshold_exceeded_by:
        description:
        - "Set the threshold to the number of times greater than the previous duration to
          start the capture, default is 5"
        type: int
        required: False
    duration:
        description:
        - "Time in seconds to look for the anomaly, default is 60"
        type: int
        required: False
    no_proxy:
        description:
        - "Enable automatic packet-capture for No proxy error"
        type: bool
        required: False
    parse_req_fail:
        description:
        - "Enable automatic packet-capture for Parse request failure"
        type: bool
        required: False
    server_select_fail:
        description:
        - "Enable automatic packet-capture for Server selection failure"
        type: bool
        required: False
    forward_req_fail:
        description:
        - "Enable automatic packet-capture for Forward request failure"
        type: bool
        required: False
    forward_req_data_fail:
        description:
        - "Enable automatic packet-capture for Forward REQ data failure"
        type: bool
        required: False
    snat_fail:
        description:
        - "Enable automatic packet-capture for Source NAT failure"
        type: bool
        required: False
    send_client_service_not_ready:
        description:
        - "Enable automatic packet-capture for Sent client serv-not-rdy"
        type: bool
        required: False
    recv_server_unknow_reply_code:
        description:
        - "Enable automatic packet-capture for Recv server unknown-code"
        type: bool
        required: False
    read_request_line_fail:
        description:
        - "Enable automatic packet-capture for Read request line fail"
        type: bool
        required: False
    get_all_headers_fail:
        description:
        - "Enable automatic packet-capture for Get all headers fail"
        type: bool
        required: False
    too_many_headers:
        description:
        - "Enable automatic packet-capture for Too many headers"
        type: bool
        required: False
    line_too_long:
        description:
        - "Enable automatic packet-capture for Line too long"
        type: bool
        required: False
    line_extend_fail:
        description:
        - "Enable automatic packet-capture for Line extend fail"
        type: bool
        required: False
    line_table_extend_fail:
        description:
        - "Enable automatic packet-capture for Table extend fail"
        type: bool
        required: False
    parse_request_line_fail:
        description:
        - "Enable automatic packet-capture for Parse request line fail"
        type: bool
        required: False
    insert_resonse_line_fail:
        description:
        - "Enable automatic packet-capture for Ins response line fail"
        type: bool
        required: False
    remove_resonse_line_fail:
        description:
        - "Enable automatic packet-capture for Del response line fail"
        type: bool
        required: False
    parse_resonse_line_fail:
        description:
        - "Enable automatic packet-capture for Parse response line fail"
        type: bool
        required: False
    server_STARTTLS_fail:
        description:
        - "Enable automatic packet-capture for Server side STARTTLS fail"
        type: bool
        required: False
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
from ansible_collections.a10.acos_axapi.plugins.module_utils.client import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "duration", "forward_req_data_fail", "forward_req_fail", "get_all_headers_fail", "insert_resonse_line_fail", "line_extend_fail", "line_table_extend_fail", "line_too_long", "no_proxy", "parse_req_fail", "parse_request_line_fail", "parse_resonse_line_fail", "read_request_line_fail", "recv_server_unknow_reply_code", "remove_resonse_line_fail",
    "send_client_service_not_ready", "server_select_fail", "server_STARTTLS_fail", "snat_fail", "threshold_exceeded_by", "too_many_headers", "uuid",
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
        'threshold_exceeded_by': {
            'type': 'int',
            },
        'duration': {
            'type': 'int',
            },
        'no_proxy': {
            'type': 'bool',
            },
        'parse_req_fail': {
            'type': 'bool',
            },
        'server_select_fail': {
            'type': 'bool',
            },
        'forward_req_fail': {
            'type': 'bool',
            },
        'forward_req_data_fail': {
            'type': 'bool',
            },
        'snat_fail': {
            'type': 'bool',
            },
        'send_client_service_not_ready': {
            'type': 'bool',
            },
        'recv_server_unknow_reply_code': {
            'type': 'bool',
            },
        'read_request_line_fail': {
            'type': 'bool',
            },
        'get_all_headers_fail': {
            'type': 'bool',
            },
        'too_many_headers': {
            'type': 'bool',
            },
        'line_too_long': {
            'type': 'bool',
            },
        'line_extend_fail': {
            'type': 'bool',
            },
        'line_table_extend_fail': {
            'type': 'bool',
            },
        'parse_request_line_fail': {
            'type': 'bool',
            },
        'insert_resonse_line_fail': {
            'type': 'bool',
            },
        'remove_resonse_line_fail': {
            'type': 'bool',
            },
        'parse_resonse_line_fail': {
            'type': 'bool',
            },
        'server_STARTTLS_fail': {
            'type': 'bool',
            },
        'uuid': {
            'type': 'str',
            }
        })
    # Parent keys
    rv.update(dict(smtp_vport_tmpl_name=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/visibility/packet-capture/object-templates/smtp-vport-tmpl/{smtp_vport_tmpl_name}/trigger-stats-rate"

    f_dict = {}
    if '/' in module.params["smtp_vport_tmpl_name"]:
        f_dict["smtp_vport_tmpl_name"] = module.params["smtp_vport_tmpl_name"].replace("/", "%2F")
    else:
        f_dict["smtp_vport_tmpl_name"] = module.params["smtp_vport_tmpl_name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/visibility/packet-capture/object-templates/smtp-vport-tmpl/{smtp_vport_tmpl_name}/trigger-stats-rate"

    f_dict = {}
    f_dict["smtp_vport_tmpl_name"] = module.params["smtp_vport_tmpl_name"]

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["trigger-stats-rate"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["trigger-stats-rate"].get(k) != v:
            change_results["changed"] = True
            config_changes["trigger-stats-rate"][k] = v

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
    payload = utils.build_json("trigger-stats-rate", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["trigger-stats-rate"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["trigger-stats-rate-list"] if info != "NotFound" else info
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
