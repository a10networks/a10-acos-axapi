#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_template_http_policy_multi_match_rule
description:
    - Multi-match-rule block
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
    http_policy_name:
        description:
        - Key to identify parent object
        type: str
        required: True
    multi_match:
        description:
        - "Specify a multi-match-rule name"
        type: str
        required: True
    seq_num:
        description:
        - "Specify a sequence number"
        type: int
        required: False
    host_equals_type:
        description:
        - "'equals'= Host equals to string;"
        type: str
        required: False
    host_equals_string:
        description:
        - "Host string"
        type: str
        required: False
    host_contains_type:
        description:
        - "'contains'= Host contains string;"
        type: str
        required: False
    host_contains_string:
        description:
        - "Host string"
        type: str
        required: False
    host_starts_with_type:
        description:
        - "'starts-with'= Host starts-with string;"
        type: str
        required: False
    host_starts_with_string:
        description:
        - "Host string"
        type: str
        required: False
    host_ends_with_type:
        description:
        - "'ends-with'= Host ends-with string;"
        type: str
        required: False
    host_ends_with_string:
        description:
        - "Host string"
        type: str
        required: False
    cookie_name_equals_type:
        description:
        - "'equals'= Cookie name equals to string;"
        type: str
        required: False
    cookie_name_equals_string:
        description:
        - "Cookie name string"
        type: str
        required: False
    cookie_name_contains_type:
        description:
        - "'contains'= Cookie name contains string;"
        type: str
        required: False
    cookie_name_contains_string:
        description:
        - "Cookie value string"
        type: str
        required: False
    cookie_name_starts_with_type:
        description:
        - "'starts-with'= Cookie name starts-with string;"
        type: str
        required: False
    cookie_name_starts_with_string:
        description:
        - "Cookie name string"
        type: str
        required: False
    cookie_name_ends_with_type:
        description:
        - "'ends-with'= Cookie name ends-with string;"
        type: str
        required: False
    cookie_name_ends_with_string:
        description:
        - "Cookie name string"
        type: str
        required: False
    cookie_value_equals_type:
        description:
        - "'equals'= Cookie value equals to string;"
        type: str
        required: False
    cookie_value_equals_string:
        description:
        - "Cookie value string"
        type: str
        required: False
    cookie_value_contains_type:
        description:
        - "'contains'= Cookie value contains string;"
        type: str
        required: False
    cookie_value_contains_string:
        description:
        - "Cookie value string"
        type: str
        required: False
    cookie_value_starts_with_type:
        description:
        - "'starts-with'= Cookie value starts-with string;"
        type: str
        required: False
    cookie_value_starts_with_string:
        description:
        - "Cookie value string"
        type: str
        required: False
    cookie_value_ends_with_type:
        description:
        - "'ends-with'= Cookie value ends-with string;"
        type: str
        required: False
    cookie_value_ends_with_string:
        description:
        - "Cookie value string"
        type: str
        required: False
    url_equals_type:
        description:
        - "'equals'= URL equals to string;"
        type: str
        required: False
    url_equals_string:
        description:
        - "URL string"
        type: str
        required: False
    url_contains_type:
        description:
        - "'contains'= URL contains string;"
        type: str
        required: False
    url_contains_string:
        description:
        - "URL string"
        type: str
        required: False
    url_starts_with_type:
        description:
        - "'starts-with'= URL starts-with string;"
        type: str
        required: False
    url_starts_with_string:
        description:
        - "URL string"
        type: str
        required: False
    url_ends_with_type:
        description:
        - "'ends-with'= URL ends-with string;"
        type: str
        required: False
    url_ends_with_string:
        description:
        - "URL string"
        type: str
        required: False
    header_name_equals_type:
        description:
        - "'equals'= Header name equals to string;"
        type: str
        required: False
    header_name_equals_string:
        description:
        - "Header name string"
        type: str
        required: False
    header_name_contains_type:
        description:
        - "'contains'= Header name contains string;"
        type: str
        required: False
    header_name_contains_string:
        description:
        - "Header name string"
        type: str
        required: False
    header_name_starts_with_type:
        description:
        - "'starts-with'= Header name starts-with string;"
        type: str
        required: False
    header_name_starts_with_string:
        description:
        - "Header name string"
        type: str
        required: False
    header_name_ends_with_type:
        description:
        - "'ends-with'= Header name ends-with string;"
        type: str
        required: False
    header_name_ends_with_string:
        description:
        - "Header name string"
        type: str
        required: False
    header_value_equals_type:
        description:
        - "'equals'= Header value equals to string;"
        type: str
        required: False
    header_value_equals_string:
        description:
        - "Header value string"
        type: str
        required: False
    header_value_contains_type:
        description:
        - "'contains'= Header value contains string;"
        type: str
        required: False
    header_value_contains_string:
        description:
        - "Header value string"
        type: str
        required: False
    header_value_starts_with_type:
        description:
        - "'starts-with'= Header value starts-with string;"
        type: str
        required: False
    header_value_starts_with_string:
        description:
        - "Header value string"
        type: str
        required: False
    header_value_ends_with_type:
        description:
        - "'ends-with'= Header value ends-with string;"
        type: str
        required: False
    header_value_ends_with_string:
        description:
        - "Header value string"
        type: str
        required: False
    query_param_name_equals_type:
        description:
        - "'equals'= query parameter name equals to string;"
        type: str
        required: False
    query_param_name_equals_string:
        description:
        - "query parameter name string, use '[no-name]' for empty query-param-name match"
        type: str
        required: False
    query_param_name_contains_type:
        description:
        - "'contains'= query parameter name contains string;"
        type: str
        required: False
    query_param_name_contains_string:
        description:
        - "query parameter name string"
        type: str
        required: False
    query_param_name_starts_with_type:
        description:
        - "'starts-with'= query parameter name starts-with string;"
        type: str
        required: False
    query_param_name_starts_with_string:
        description:
        - "query parameter name string"
        type: str
        required: False
    query_param_name_ends_with_type:
        description:
        - "'ends-with'= query parameter name ends-with string;"
        type: str
        required: False
    query_param_name_ends_with_string:
        description:
        - "query parameter name string"
        type: str
        required: False
    query_param_value_equals_type:
        description:
        - "'equals'= query parameter value equals to string;"
        type: str
        required: False
    query_param_value_equals_string:
        description:
        - "query parameter value string, use '[no-value]' for empty query-param-value
          match"
        type: str
        required: False
    query_param_value_contains_type:
        description:
        - "'contains'= query parameter value contains string;"
        type: str
        required: False
    query_param_value_contains_string:
        description:
        - "query parameter value string"
        type: str
        required: False
    query_param_value_starts_with_type:
        description:
        - "'starts-with'= query parameter value starts-with string;"
        type: str
        required: False
    query_param_value_starts_with_string:
        description:
        - "query parameter value string"
        type: str
        required: False
    query_param_value_ends_with_type:
        description:
        - "'ends-with'= query parameter value ends-with string;"
        type: str
        required: False
    query_param_value_ends_with_string:
        description:
        - "query parameter value string"
        type: str
        required: False
    service_group:
        description:
        - "Service Group to be used (Service Group Name)"
        type: str
        required: False
    template_waf:
        description:
        - "Waf Template to be used (Waf Template Name)"
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
    "cookie_name_contains_string", "cookie_name_contains_type", "cookie_name_ends_with_string", "cookie_name_ends_with_type", "cookie_name_equals_string", "cookie_name_equals_type", "cookie_name_starts_with_string", "cookie_name_starts_with_type", "cookie_value_contains_string", "cookie_value_contains_type", "cookie_value_ends_with_string",
    "cookie_value_ends_with_type", "cookie_value_equals_string", "cookie_value_equals_type", "cookie_value_starts_with_string", "cookie_value_starts_with_type", "header_name_contains_string", "header_name_contains_type", "header_name_ends_with_string", "header_name_ends_with_type", "header_name_equals_string", "header_name_equals_type",
    "header_name_starts_with_string", "header_name_starts_with_type", "header_value_contains_string", "header_value_contains_type", "header_value_ends_with_string", "header_value_ends_with_type", "header_value_equals_string", "header_value_equals_type", "header_value_starts_with_string", "header_value_starts_with_type", "host_contains_string",
    "host_contains_type", "host_ends_with_string", "host_ends_with_type", "host_equals_string", "host_equals_type", "host_starts_with_string", "host_starts_with_type", "multi_match", "query_param_name_contains_string", "query_param_name_contains_type", "query_param_name_ends_with_string", "query_param_name_ends_with_type",
    "query_param_name_equals_string", "query_param_name_equals_type", "query_param_name_starts_with_string", "query_param_name_starts_with_type", "query_param_value_contains_string", "query_param_value_contains_type", "query_param_value_ends_with_string", "query_param_value_ends_with_type", "query_param_value_equals_string",
    "query_param_value_equals_type", "query_param_value_starts_with_string", "query_param_value_starts_with_type", "seq_num", "service_group", "template_waf", "url_contains_string", "url_contains_type", "url_ends_with_string", "url_ends_with_type", "url_equals_string", "url_equals_type", "url_starts_with_string", "url_starts_with_type", "user_tag",
    "uuid",
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
        'multi_match': {
            'type': 'str',
            'required': True,
            },
        'seq_num': {
            'type': 'int',
            },
        'host_equals_type': {
            'type': 'str',
            'choices': ['equals']
            },
        'host_equals_string': {
            'type': 'str',
            },
        'host_contains_type': {
            'type': 'str',
            'choices': ['contains']
            },
        'host_contains_string': {
            'type': 'str',
            },
        'host_starts_with_type': {
            'type': 'str',
            'choices': ['starts-with']
            },
        'host_starts_with_string': {
            'type': 'str',
            },
        'host_ends_with_type': {
            'type': 'str',
            'choices': ['ends-with']
            },
        'host_ends_with_string': {
            'type': 'str',
            },
        'cookie_name_equals_type': {
            'type': 'str',
            'choices': ['equals']
            },
        'cookie_name_equals_string': {
            'type': 'str',
            },
        'cookie_name_contains_type': {
            'type': 'str',
            'choices': ['contains']
            },
        'cookie_name_contains_string': {
            'type': 'str',
            },
        'cookie_name_starts_with_type': {
            'type': 'str',
            'choices': ['starts-with']
            },
        'cookie_name_starts_with_string': {
            'type': 'str',
            },
        'cookie_name_ends_with_type': {
            'type': 'str',
            'choices': ['ends-with']
            },
        'cookie_name_ends_with_string': {
            'type': 'str',
            },
        'cookie_value_equals_type': {
            'type': 'str',
            'choices': ['equals']
            },
        'cookie_value_equals_string': {
            'type': 'str',
            },
        'cookie_value_contains_type': {
            'type': 'str',
            'choices': ['contains']
            },
        'cookie_value_contains_string': {
            'type': 'str',
            },
        'cookie_value_starts_with_type': {
            'type': 'str',
            'choices': ['starts-with']
            },
        'cookie_value_starts_with_string': {
            'type': 'str',
            },
        'cookie_value_ends_with_type': {
            'type': 'str',
            'choices': ['ends-with']
            },
        'cookie_value_ends_with_string': {
            'type': 'str',
            },
        'url_equals_type': {
            'type': 'str',
            'choices': ['equals']
            },
        'url_equals_string': {
            'type': 'str',
            },
        'url_contains_type': {
            'type': 'str',
            'choices': ['contains']
            },
        'url_contains_string': {
            'type': 'str',
            },
        'url_starts_with_type': {
            'type': 'str',
            'choices': ['starts-with']
            },
        'url_starts_with_string': {
            'type': 'str',
            },
        'url_ends_with_type': {
            'type': 'str',
            'choices': ['ends-with']
            },
        'url_ends_with_string': {
            'type': 'str',
            },
        'header_name_equals_type': {
            'type': 'str',
            'choices': ['equals']
            },
        'header_name_equals_string': {
            'type': 'str',
            },
        'header_name_contains_type': {
            'type': 'str',
            'choices': ['contains']
            },
        'header_name_contains_string': {
            'type': 'str',
            },
        'header_name_starts_with_type': {
            'type': 'str',
            'choices': ['starts-with']
            },
        'header_name_starts_with_string': {
            'type': 'str',
            },
        'header_name_ends_with_type': {
            'type': 'str',
            'choices': ['ends-with']
            },
        'header_name_ends_with_string': {
            'type': 'str',
            },
        'header_value_equals_type': {
            'type': 'str',
            'choices': ['equals']
            },
        'header_value_equals_string': {
            'type': 'str',
            },
        'header_value_contains_type': {
            'type': 'str',
            'choices': ['contains']
            },
        'header_value_contains_string': {
            'type': 'str',
            },
        'header_value_starts_with_type': {
            'type': 'str',
            'choices': ['starts-with']
            },
        'header_value_starts_with_string': {
            'type': 'str',
            },
        'header_value_ends_with_type': {
            'type': 'str',
            'choices': ['ends-with']
            },
        'header_value_ends_with_string': {
            'type': 'str',
            },
        'query_param_name_equals_type': {
            'type': 'str',
            'choices': ['equals']
            },
        'query_param_name_equals_string': {
            'type': 'str',
            },
        'query_param_name_contains_type': {
            'type': 'str',
            'choices': ['contains']
            },
        'query_param_name_contains_string': {
            'type': 'str',
            },
        'query_param_name_starts_with_type': {
            'type': 'str',
            'choices': ['starts-with']
            },
        'query_param_name_starts_with_string': {
            'type': 'str',
            },
        'query_param_name_ends_with_type': {
            'type': 'str',
            'choices': ['ends-with']
            },
        'query_param_name_ends_with_string': {
            'type': 'str',
            },
        'query_param_value_equals_type': {
            'type': 'str',
            'choices': ['equals']
            },
        'query_param_value_equals_string': {
            'type': 'str',
            },
        'query_param_value_contains_type': {
            'type': 'str',
            'choices': ['contains']
            },
        'query_param_value_contains_string': {
            'type': 'str',
            },
        'query_param_value_starts_with_type': {
            'type': 'str',
            'choices': ['starts-with']
            },
        'query_param_value_starts_with_string': {
            'type': 'str',
            },
        'query_param_value_ends_with_type': {
            'type': 'str',
            'choices': ['ends-with']
            },
        'query_param_value_ends_with_string': {
            'type': 'str',
            },
        'service_group': {
            'type': 'str',
            },
        'template_waf': {
            'type': 'str',
            },
        'uuid': {
            'type': 'str',
            },
        'user_tag': {
            'type': 'str',
            }
        })
    # Parent keys
    rv.update(dict(http_policy_name=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/template/http-policy/{http_policy_name}/multi_match-rule/{multi-match}"

    f_dict = {}
    if '/' in str(module.params["multi_match"]):
        f_dict["multi_match"] = module.params["multi_match"].replace("/", "%2F")
    else:
        f_dict["multi_match"] = module.params["multi_match"]
    if '/' in module.params["http_policy_name"]:
        f_dict["http_policy_name"] = module.params["http_policy_name"].replace("/", "%2F")
    else:
        f_dict["http_policy_name"] = module.params["http_policy_name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/template/http-policy/{http_policy_name}/multi-match-rule"

    f_dict = {}
    f_dict["multi_match"] = ""
    f_dict["http_policy_name"] = module.params["http_policy_name"]

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["multi-match-rule"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["multi-match-rule"].get(k) != v:
            change_results["changed"] = True
            config_changes["multi-match-rule"][k] = v

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
    payload = utils.build_json("multi-match-rule", module.params, AVAILABLE_PROPERTIES)
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

        if state == 'present' or state == 'absent':
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
            if module.params.get("get_type") == "single" or module.params.get("get_type") is None:
                get_result = api_client.get(module.client, existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info["multi-match-rule"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["multi-match-rule-list"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()

    return result


"""
    Custom class which override the _check_required_arguments function to check check required arguments based on state and get_type.
"""


class AcosAnsibleModule(AnsibleModule):

    def __init__(self, *args, **kwargs):
        super(AcosAnsibleModule, self).__init__(*args, **kwargs)

    def _check_required_arguments(self, spec=None, param=None):
        if spec is None:
            spec = self.argument_spec
        if param is None:
            param = self.params
        # skip validation if state is 'noop' and get_type is 'list'
        if not (param.get("state") == "noop" and param.get("get_type") == "list"):
            missing = []
            if spec is None:
                return missing
            # Check for missing required parameters in the provided argument spec
            for (k, v) in spec.items():
                required = v.get('required', False)
                if required and k not in param:
                    missing.append(k)
            if missing:
                self.fail_json(msg="Missing required parameters: {}".format(", ".join(missing)))


def main():
    module = AcosAnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
