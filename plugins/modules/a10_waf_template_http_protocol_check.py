#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_waf_template_http_protocol_check
description:
    - HTTP protocol compliance check
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
    template_name:
        description:
        - Key to identify parent object
        type: str
        required: True
    disable:
        description:
        - "Disable all checks for HTTP protocol compliance"
        type: bool
        required: False
    allowed_headers:
        description:
        - "Enable allowed-headers check (default disabled)"
        type: bool
        required: False
    allowed_headers_list:
        description:
        - "Allowed HTTP headers. Default 'Host Referer User-Agent Accept Accept-Encoding
          ...' (see docs for full list) (Allowed HTTP headers (default 'Host Referer
          User-Agent Accept Accept-Encoding ...' (see docs for full list)))"
        type: str
        required: False
    allowed_methods:
        description:
        - "Enable allowed-methods check (default disabled)"
        type: bool
        required: False
    allowed_methods_list:
        description:
        - "List of allowed HTTP methods. Default is 'GET POST'. (List of HTTP methods
          allowed (default 'GET POST'))"
        type: str
        required: False
    allowed_versions:
        description:
        - "Enable allowed-versions check (default disabled)"
        type: bool
        required: False
    allowed_versions_list:
        description:
        - "List of allowed HTTP versions (default '1.0 1.1 2')"
        type: str
        required: False
    bad_multipart_request:
        description:
        - "Check for bad multipart/form-data request body"
        type: bool
        required: False
    body_without_content_type:
        description:
        - "Check for Body request without Content-Type header in request"
        type: bool
        required: False
    get_with_content:
        description:
        - "Check for GET request with Content-Length headers in request"
        type: bool
        required: False
    head_with_content:
        description:
        - "Check for HEAD request with Content-Length headers in request"
        type: bool
        required: False
    host_header_with_ip:
        description:
        - "Check for Host header with IP address"
        type: bool
        required: False
    invalid_url_encoding:
        description:
        - "Check for invalid URL encoding in request"
        type: bool
        required: False
    malformed_content_length:
        description:
        - "Check for malformed content-length in request"
        type: bool
        required: False
    malformed_header:
        description:
        - "Check for malformed HTTP header"
        type: bool
        required: False
    malformed_parameter:
        description:
        - "Check for malformed HTTP query/POST parameter"
        type: bool
        required: False
    malformed_request:
        description:
        - "Check for malformed HTTP request"
        type: bool
        required: False
    malformed_request_line:
        description:
        - "Check for malformed HTTP request line"
        type: bool
        required: False
    missing_header_value:
        description:
        - "Check for missing header value in request"
        type: bool
        required: False
    missing_host_header:
        description:
        - "Check for missing Host header in HTTP/1.1 request"
        type: bool
        required: False
    multiple_content_length:
        description:
        - "Check for multiple Content-Length headers in request"
        type: bool
        required: False
    post_with_0_content:
        description:
        - "Check for POST request with Content-Length 0"
        type: bool
        required: False
    post_without_content:
        description:
        - "Check for POST request without Content-Length/Chunked Encoding headers in
          request"
        type: bool
        required: False
    post_without_content_type:
        description:
        - "Check for POST request without Content-Type header in request"
        type: bool
        required: False
    non_ssl_cookie_prefix:
        description:
        - "Check for Bad __Secure- or __Host- Cookie Name prefixes in non-ssl request"
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
    "allowed_headers",
    "allowed_headers_list",
    "allowed_methods",
    "allowed_methods_list",
    "allowed_versions",
    "allowed_versions_list",
    "bad_multipart_request",
    "body_without_content_type",
    "disable",
    "get_with_content",
    "head_with_content",
    "host_header_with_ip",
    "invalid_url_encoding",
    "malformed_content_length",
    "malformed_header",
    "malformed_parameter",
    "malformed_request",
    "malformed_request_line",
    "missing_header_value",
    "missing_host_header",
    "multiple_content_length",
    "non_ssl_cookie_prefix",
    "post_with_0_content",
    "post_without_content",
    "post_without_content_type",
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
        'disable': {
            'type': 'bool',
        },
        'allowed_headers': {
            'type': 'bool',
        },
        'allowed_headers_list': {
            'type': 'str',
        },
        'allowed_methods': {
            'type': 'bool',
        },
        'allowed_methods_list': {
            'type': 'str',
        },
        'allowed_versions': {
            'type': 'bool',
        },
        'allowed_versions_list': {
            'type': 'str',
            'choices': ['0.9', '1.0', '1.1', '2']
        },
        'bad_multipart_request': {
            'type': 'bool',
        },
        'body_without_content_type': {
            'type': 'bool',
        },
        'get_with_content': {
            'type': 'bool',
        },
        'head_with_content': {
            'type': 'bool',
        },
        'host_header_with_ip': {
            'type': 'bool',
        },
        'invalid_url_encoding': {
            'type': 'bool',
        },
        'malformed_content_length': {
            'type': 'bool',
        },
        'malformed_header': {
            'type': 'bool',
        },
        'malformed_parameter': {
            'type': 'bool',
        },
        'malformed_request': {
            'type': 'bool',
        },
        'malformed_request_line': {
            'type': 'bool',
        },
        'missing_header_value': {
            'type': 'bool',
        },
        'missing_host_header': {
            'type': 'bool',
        },
        'multiple_content_length': {
            'type': 'bool',
        },
        'post_with_0_content': {
            'type': 'bool',
        },
        'post_without_content': {
            'type': 'bool',
        },
        'post_without_content_type': {
            'type': 'bool',
        },
        'non_ssl_cookie_prefix': {
            'type': 'bool',
        },
        'uuid': {
            'type': 'str',
        }
    })
    # Parent keys
    rv.update(dict(template_name=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/waf/template/{template_name}/http-protocol-check"

    f_dict = {}
    if '/' in module.params["template_name"]:
        f_dict["template_name"] = module.params["template_name"].replace(
            "/", "%2F")
    else:
        f_dict["template_name"] = module.params["template_name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/waf/template/{template_name}/http-protocol-check"

    f_dict = {}
    f_dict["template_name"] = module.params["template_name"]

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["http-protocol-check"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["http-protocol-check"].get(k) != v:
            change_results["changed"] = True
            config_changes["http-protocol-check"][k] = v

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
    payload = utils.build_json("http-protocol-check", module.params,
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
                  axapi_calls=[],
                  ansible_facts={},
                  acos_info={})

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
                get_result = api_client.get(module.client,
                                            existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info[
                    "http-protocol-check"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client,
                                                      existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info[
                    "http-protocol-check-list"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()

    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
