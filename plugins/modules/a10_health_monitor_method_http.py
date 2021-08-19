#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_health_monitor_method_http
description:
    - HTTP type
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
    monitor_name:
        description:
        - Key to identify parent object
        type: str
        required: True
    http:
        description:
        - "HTTP type"
        type: bool
        required: False
    http_port:
        description:
        - "Specify HTTP Port (Specify port number (default 80))"
        type: int
        required: False
    http_expect:
        description:
        - "Specify what you expect from the response message"
        type: bool
        required: False
    http_response_code:
        description:
        - "Specify response code range (e.g. 200,400-430) (Format is xx,xx-xx (xx between
          [100, 899]))"
        type: str
        required: False
    response_code_regex:
        description:
        - "Specify response code range with Regex (code with Regex, such as
          [2-5][0-9][0-9])"
        type: str
        required: False
    http_text:
        description:
        - "Specify text expected"
        type: str
        required: False
    text_regex:
        description:
        - "Specify text expected  with Regex"
        type: str
        required: False
    http_host:
        description:
        - "Specify 'Host=' header used in request (enclose IPv6 address in [])"
        type: str
        required: False
    http_maintenance_code:
        description:
        - "Specify response code for maintenance (Format is xx,xx-xx (xx between [100,
          899]))"
        type: str
        required: False
    http_url:
        description:
        - "Specify URL string, default is GET /"
        type: bool
        required: False
    url_type:
        description:
        - "'GET'= HTTP GET method; 'POST'= HTTP POST method; 'HEAD'= HTTP HEAD method;"
        type: str
        required: False
    url_path:
        description:
        - "Specify URL path, default is '/'"
        type: str
        required: False
    post_path:
        description:
        - "Specify URL path, default is '/'"
        type: str
        required: False
    post_type:
        description:
        - "'postdata'= Specify the HTTP post data; 'postfile'= Specify the HTTP post data;"
        type: str
        required: False
    http_postdata:
        description:
        - "Specify the HTTP post data (Input post data here)"
        type: str
        required: False
    http_postfile:
        description:
        - "Specify the HTTP post data (Input post data file name here)"
        type: str
        required: False
    http_username:
        description:
        - "Specify the username"
        type: str
        required: False
    http_password:
        description:
        - "Specify the user password"
        type: bool
        required: False
    http_password_string:
        description:
        - "Specify password, '' means empty password"
        type: str
        required: False
    http_encrypted:
        description:
        - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The
          ENCRYPTED password string)"
        type: str
        required: False
    http_kerberos_auth:
        description:
        - "Http Kerberos Auth"
        type: bool
        required: False
    http_kerberos_realm:
        description:
        - "Specify realm of Kerberos server"
        type: str
        required: False
    http_kerberos_kdc:
        description:
        - "Field http_kerberos_kdc"
        type: dict
        required: False
        suboptions:
            http_kerberos_hostip:
                description:
                - "Kdc's hostname(length=1-31) or IP address"
                type: str
            http_kerberos_hostipv6:
                description:
                - "Server's IPV6 address"
                type: str
            http_kerberos_port:
                description:
                - "Specify the kdc port"
                type: int
            http_kerberos_portv6:
                description:
                - "Specify the kdc port"
                type: int
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

# standard ansible module imports
from ansible.module_utils.basic import AnsibleModule

from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    wrapper as api_client
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    utils
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_client import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist


# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["http", "http_encrypted", "http_expect", "http_host", "http_kerberos_auth", "http_kerberos_kdc", "http_kerberos_realm", "http_maintenance_code", "http_password", "http_password_string", "http_port", "http_postdata", "http_postfile", "http_response_code", "http_text", "http_url", "http_username", "post_path", "post_type", "response_code_regex", "text_regex", "url_path", "url_type", "uuid", ]


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
    rv.update({'http': {'type': 'bool', },
        'http_port': {'type': 'int', },
        'http_expect': {'type': 'bool', },
        'http_response_code': {'type': 'str', },
        'response_code_regex': {'type': 'str', },
        'http_text': {'type': 'str', },
        'text_regex': {'type': 'str', },
        'http_host': {'type': 'str', },
        'http_maintenance_code': {'type': 'str', },
        'http_url': {'type': 'bool', },
        'url_type': {'type': 'str', 'choices': ['GET', 'POST', 'HEAD']},
        'url_path': {'type': 'str', },
        'post_path': {'type': 'str', },
        'post_type': {'type': 'str', 'choices': ['postdata', 'postfile']},
        'http_postdata': {'type': 'str', },
        'http_postfile': {'type': 'str', },
        'http_username': {'type': 'str', },
        'http_password': {'type': 'bool', },
        'http_password_string': {'type': 'str', },
        'http_encrypted': {'type': 'str', },
        'http_kerberos_auth': {'type': 'bool', },
        'http_kerberos_realm': {'type': 'str', },
        'http_kerberos_kdc': {'type': 'dict', 'http_kerberos_hostip': {'type': 'str', }, 'http_kerberos_hostipv6': {'type': 'str', }, 'http_kerberos_port': {'type': 'int', }, 'http_kerberos_portv6': {'type': 'int', }},
        'uuid': {'type': 'str', }
    })
    # Parent keys
    rv.update(dict(
        monitor_name=dict(type='str', required=True),
    ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/health/monitor/{monitor_name}/method/http"

    f_dict = {}
    f_dict["monitor_name"] = module.params["monitor_name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/health/monitor/{monitor_name}/method/http"

    f_dict = {}
    f_dict["monitor_name"] = module.params["monitor_name"]

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["http"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["http"].get(k) != v:
            change_results["changed"] = True
            config_changes["http"][k] = v

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
    payload = utils.build_json("http", module.params, AVAILABLE_PROPERTIES)
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
        axapi_calls=[]
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
        if existing_config['response_body'] != 'Not Found':
            existing_config = existing_config["response_body"]
        else:
            existing_config = None

        if state == 'present':
            result = present(module, result, existing_config)

        if state == 'absent':
            result = absent(module, result, existing_config)

        if state == 'noop':
            if module.params.get("get_type") == "single":
                result["axapi_calls"].append(
                    api_client.get(module.client, existing_url(module)))
            elif module.params.get("get_type") == "list":
                result["axapi_calls"].append(
                    api_client.get_list(module.client, existing_url(module)))
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.session.session_id:
            module.client.session.close()

    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
