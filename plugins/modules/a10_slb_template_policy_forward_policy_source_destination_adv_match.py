#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_template_policy_forward_policy_source_destination_adv_match
description:
    - Advanced match rule
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
    policy_name:
        description:
        - Key to identify parent object
        type: str
        required: True
    priority:
        description:
        - "Rule priority (1000 is highest)"
        type: int
        required: True
    match_host:
        description:
        - "Match request host (HTTP stage) or SNI/SAN (SSL stage)"
        type: str
        required: False
    match_http_content_encoding:
        description:
        - "Match the value of HTTP header 'Content-Encoding'"
        type: str
        required: False
    match_http_content_length_range_begin:
        description:
        - "Match the value of HTTP header 'Content-Length' with an inclusive range"
        type: int
        required: False
    match_http_content_length_range_end:
        description:
        - "End of the 'Content-Length' range"
        type: int
        required: False
    match_http_content_type:
        description:
        - "Match the value of HTTP header 'Content-Type'"
        type: str
        required: False
    match_http_header:
        description:
        - "Matching the name of all request headers"
        type: str
        required: False
    match_http_method_connect:
        description:
        - "Match HTTP request method CONNECT"
        type: bool
        required: False
    match_http_method_delete:
        description:
        - "Match HTTP request method DELETE"
        type: bool
        required: False
    match_http_method_get:
        description:
        - "Match HTTP request method GET"
        type: bool
        required: False
    match_http_method_head:
        description:
        - "Match HTTP request method HEAD"
        type: bool
        required: False
    match_http_method_options:
        description:
        - "Match HTTP request method OPTIONS"
        type: bool
        required: False
    match_http_method_patch:
        description:
        - "Match HTTP request method PATCH"
        type: bool
        required: False
    match_http_method_post:
        description:
        - "Match HTTP request method POST"
        type: bool
        required: False
    match_http_method_put:
        description:
        - "Match HTTP request method PUT"
        type: bool
        required: False
    match_http_method_trace:
        description:
        - "Match HTTP request method TRACE"
        type: bool
        required: False
    match_http_request_file_extension:
        description:
        - "Match file extension of URL in HTTP request line"
        type: str
        required: False
    match_http_url_regex:
        description:
        - "Match URI in HTTP request line by given regular expression"
        type: str
        required: False
    match_http_url:
        description:
        - "Match URL in HTTP request line"
        type: str
        required: False
    match_http_user_agent:
        description:
        - "Matching the value of HTTP header 'User-Agent'"
        type: str
        required: False
    match_server_address:
        description:
        - "Match target server IP address"
        type: str
        required: False
    match_server_port:
        description:
        - "Match target server port number"
        type: int
        required: False
    match_server_port_range_begin:
        description:
        - "Math targer server port range inclusively"
        type: int
        required: False
    match_server_port_range_end:
        description:
        - "End of port range"
        type: int
        required: False
    match_time_range:
        description:
        - "Enable rule in this time-range"
        type: str
        required: False
    match_web_category_list:
        description:
        - "Match web-category list"
        type: str
        required: False
    match_web_reputation_scope:
        description:
        - "Match web-reputation scope"
        type: str
        required: False
    disable_reqmod_icap:
        description:
        - "Disable REQMOD ICAP template"
        type: bool
        required: False
    disable_respmod_icap:
        description:
        - "Disable RESPMOD ICAP template"
        type: bool
        required: False
    notify_page:
        description:
        - "Send notify-page to client"
        type: str
        required: False
    action:
        description:
        - "Forwading action of this rule"
        type: str
        required: False
    dual_stack_action:
        description:
        - "Forwarding action of this rule"
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
    sampling_enable:
        description:
        - "Field sampling_enable"
        type: list
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'hits'= Number of requests hit this rule;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            hits:
                description:
                - "Number of requests hit this rule"
                type: str
            priority:
                description:
                - "Rule priority (1000 is highest)"
                type: int

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
    "action", "disable_reqmod_icap", "disable_respmod_icap", "dual_stack_action", "match_host", "match_http_content_encoding", "match_http_content_length_range_begin", "match_http_content_length_range_end", "match_http_content_type", "match_http_header", "match_http_method_connect", "match_http_method_delete", "match_http_method_get",
    "match_http_method_head", "match_http_method_options", "match_http_method_patch", "match_http_method_post", "match_http_method_put", "match_http_method_trace", "match_http_request_file_extension", "match_http_url", "match_http_url_regex", "match_http_user_agent", "match_server_address", "match_server_port", "match_server_port_range_begin",
    "match_server_port_range_end", "match_time_range", "match_web_category_list", "match_web_reputation_scope", "notify_page", "priority", "sampling_enable", "stats", "user_tag", "uuid",
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
        'priority': {
            'type': 'int',
            'required': True,
            },
        'match_host': {
            'type': 'str',
            },
        'match_http_content_encoding': {
            'type': 'str',
            },
        'match_http_content_length_range_begin': {
            'type': 'int',
            },
        'match_http_content_length_range_end': {
            'type': 'int',
            },
        'match_http_content_type': {
            'type': 'str',
            },
        'match_http_header': {
            'type': 'str',
            },
        'match_http_method_connect': {
            'type': 'bool',
            },
        'match_http_method_delete': {
            'type': 'bool',
            },
        'match_http_method_get': {
            'type': 'bool',
            },
        'match_http_method_head': {
            'type': 'bool',
            },
        'match_http_method_options': {
            'type': 'bool',
            },
        'match_http_method_patch': {
            'type': 'bool',
            },
        'match_http_method_post': {
            'type': 'bool',
            },
        'match_http_method_put': {
            'type': 'bool',
            },
        'match_http_method_trace': {
            'type': 'bool',
            },
        'match_http_request_file_extension': {
            'type': 'str',
            },
        'match_http_url_regex': {
            'type': 'str',
            },
        'match_http_url': {
            'type': 'str',
            },
        'match_http_user_agent': {
            'type': 'str',
            },
        'match_server_address': {
            'type': 'str',
            },
        'match_server_port': {
            'type': 'int',
            },
        'match_server_port_range_begin': {
            'type': 'int',
            },
        'match_server_port_range_end': {
            'type': 'int',
            },
        'match_time_range': {
            'type': 'str',
            },
        'match_web_category_list': {
            'type': 'str',
            },
        'match_web_reputation_scope': {
            'type': 'str',
            },
        'disable_reqmod_icap': {
            'type': 'bool',
            },
        'disable_respmod_icap': {
            'type': 'bool',
            },
        'notify_page': {
            'type': 'str',
            },
        'action': {
            'type': 'str',
            },
        'dual_stack_action': {
            'type': 'str',
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
                'type': 'str',
                'choices': ['all', 'hits']
                }
            },
        'stats': {
            'type': 'dict',
            'hits': {
                'type': 'str',
                },
            'priority': {
                'type': 'int',
                'required': True,
                }
            }
        })
    # Parent keys
    rv.update(dict(policy_name=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/template/policy/{policy_name}/forward-policy/source/{name}/destination/adv-match/{priority}"

    f_dict = {}
    if '/' in str(module.params["priority"]):
        f_dict["priority"] = module.params["priority"].replace("/", "%2F")
    else:
        f_dict["priority"] = module.params["priority"]
    if '/' in module.params["policy_name"]:
        f_dict["policy_name"] = module.params["policy_name"].replace("/", "%2F")
    else:
        f_dict["policy_name"] = module.params["policy_name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/template/policy/{policy_name}/forward-policy/source/{name}/destination/adv-match"

    f_dict = {}
    f_dict["priority"] = ""
    f_dict["policy_name"] = module.params["policy_name"]

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["adv-match"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["adv-match"].get(k) != v:
            change_results["changed"] = True
            config_changes["adv-match"][k] = v

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
    payload = utils.build_json("adv-match", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["adv-match"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["adv-match-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["adv-match"]["stats"] if info != "NotFound" else info
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
