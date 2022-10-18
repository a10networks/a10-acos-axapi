#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_template_reqmod_icap
description:
    - REQMOD ICAP template
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
    name:
        description:
        - "Reqmod ICAP Template Name"
        type: str
        required: True
    allowed_http_methods:
        description:
        - "List of allowed HTTP methods. Default is 'Allow All'. (List of HTTP methods
          allowed (default 'Allow All'))"
        type: str
        required: False
    include_protocol_in_uri:
        description:
        - "Include protocol and port in HTTP URI"
        type: bool
        required: False
    fail_close:
        description:
        - "When template sg is down mark vport down"
        type: bool
        required: False
    bypass_ip_cfg:
        description:
        - "Field bypass_ip_cfg"
        type: list
        required: False
        suboptions:
            bypass_ip:
                description:
                - "ip address to bypass reqmod-icap service"
                type: str
            mask:
                description:
                - "IP prefix mask"
                type: str
    failure_action:
        description:
        - "'continue'= Continue; 'drop'= Drop; 'reset'= Reset;"
        type: str
        required: False
    timeout:
        description:
        - "Timeout value 1 - 200 in units of 200ms, default is 5 (default is 1000ms) (1 -
          200 in units of 200ms, default is 5 (1000ms))"
        type: int
        required: False
    action:
        description:
        - "'continue'= Continue; 'drop'= Drop; 'reset'= Reset;"
        type: str
        required: False
    min_payload_size:
        description:
        - "min-payload-size value 0 - 65535, default is 0"
        type: int
        required: False
    preview:
        description:
        - "Preview value 1 - 32768, default is 32768"
        type: int
        required: False
    service_url:
        description:
        - "URL to send to ICAP server (Service URL Name)"
        type: str
        required: False
    service_group:
        description:
        - "Bind a Service Group to the template (Service Group Name)"
        type: str
        required: False
    tcp_proxy:
        description:
        - "TCP Proxy Template Name"
        type: str
        required: False
    shared_partition_tcp_proxy_template:
        description:
        - "Reference a TCP Proxy template from shared partition"
        type: bool
        required: False
    template_tcp_proxy_shared:
        description:
        - "TCP Proxy Template name"
        type: str
        required: False
    logging:
        description:
        - "logging template (Logging template name)"
        type: str
        required: False
    server_ssl:
        description:
        - "Server SSL template (Server SSL template name)"
        type: str
        required: False
    source_ip:
        description:
        - "Source IP persistence template (Source IP persistence template name)"
        type: str
        required: False
    shared_partition_persist_source_ip_template:
        description:
        - "Reference a persist source ip template from shared partition"
        type: bool
        required: False
    template_persist_source_ip_shared:
        description:
        - "Source IP Persistence Template Name"
        type: str
        required: False
    disable_http_server_reset:
        description:
        - "Don't reset http server"
        type: bool
        required: False
    x_auth_url:
        description:
        - "Use URL format for authentication"
        type: bool
        required: False
    log_only_allowed_method:
        description:
        - "Only log allowed HTTP method"
        type: bool
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
    "action", "allowed_http_methods", "bypass_ip_cfg", "disable_http_server_reset", "fail_close", "failure_action", "include_protocol_in_uri", "log_only_allowed_method", "logging", "min_payload_size", "name", "preview", "server_ssl", "service_group", "service_url", "shared_partition_persist_source_ip_template",
    "shared_partition_tcp_proxy_template", "source_ip", "tcp_proxy", "template_persist_source_ip_shared", "template_tcp_proxy_shared", "timeout", "user_tag", "uuid", "x_auth_url",
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
        'name': {
            'type': 'str',
            'required': True,
            },
        'allowed_http_methods': {
            'type': 'str',
            },
        'include_protocol_in_uri': {
            'type': 'bool',
            },
        'fail_close': {
            'type': 'bool',
            },
        'bypass_ip_cfg': {
            'type': 'list',
            'bypass_ip': {
                'type': 'str',
                },
            'mask': {
                'type': 'str',
                }
            },
        'failure_action': {
            'type': 'str',
            'choices': ['continue', 'drop', 'reset']
            },
        'timeout': {
            'type': 'int',
            },
        'action': {
            'type': 'str',
            'choices': ['continue', 'drop', 'reset']
            },
        'min_payload_size': {
            'type': 'int',
            },
        'preview': {
            'type': 'int',
            },
        'service_url': {
            'type': 'str',
            },
        'service_group': {
            'type': 'str',
            },
        'tcp_proxy': {
            'type': 'str',
            },
        'shared_partition_tcp_proxy_template': {
            'type': 'bool',
            },
        'template_tcp_proxy_shared': {
            'type': 'str',
            },
        'logging': {
            'type': 'str',
            },
        'server_ssl': {
            'type': 'str',
            },
        'source_ip': {
            'type': 'str',
            },
        'shared_partition_persist_source_ip_template': {
            'type': 'bool',
            },
        'template_persist_source_ip_shared': {
            'type': 'str',
            },
        'disable_http_server_reset': {
            'type': 'bool',
            },
        'x_auth_url': {
            'type': 'bool',
            },
        'log_only_allowed_method': {
            'type': 'bool',
            },
        'uuid': {
            'type': 'str',
            },
        'user_tag': {
            'type': 'str',
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/template/reqmod-icap/{name}"

    f_dict = {}
    if '/' in str(module.params["name"]):
        f_dict["name"] = module.params["name"].replace("/", "%2F")
    else:
        f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/template/reqmod-icap/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["reqmod-icap"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["reqmod-icap"].get(k) != v:
            change_results["changed"] = True
            config_changes["reqmod-icap"][k] = v

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
    payload = utils.build_json("reqmod-icap", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["reqmod-icap"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["reqmod-icap-list"] if info != "NotFound" else info
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
