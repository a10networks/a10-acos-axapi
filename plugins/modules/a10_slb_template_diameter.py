#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_template_diameter
description:
    - diameter template
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
        - "diameter template Name"
        type: str
        required: True
    customize_cea:
        description:
        - "customizing cea response"
        type: bool
        required: False
    avp_code:
        description:
        - "avp code"
        type: int
        required: False
    avp_string:
        description:
        - "pattern to be matched in the avp string name, max length 127 bytes"
        type: str
        required: False
    service_group_name:
        description:
        - "service group name, this is the service group that the message needs to be
          copied to"
        type: str
        required: False
    dwr_time:
        description:
        - "dwr health-check timer interval (in 100 milli second unit, default is 100, 0
          means unset this option)"
        type: int
        required: False
    idle_timeout:
        description:
        - "user sesison idle timeout (in minutes, default is 5)"
        type: int
        required: False
    multiple_origin_host:
        description:
        - "allowing multiple origin-host to a single server"
        type: bool
        required: False
    origin_realm:
        description:
        - "origin-realm name avp"
        type: str
        required: False
    product_name:
        description:
        - "product name avp"
        type: str
        required: False
    vendor_id:
        description:
        - "vendor-id avp (Vendor Id)"
        type: int
        required: False
    session_age:
        description:
        - "user session age allowed (default 10), this is not idle-time (in minutes)"
        type: int
        required: False
    dwr_up_retry:
        description:
        - "number of successful dwr health-check before declaring target up"
        type: int
        required: False
    terminate_on_cca_t:
        description:
        - "remove diameter session when receiving CCA-T message"
        type: bool
        required: False
    forward_unknown_session_id:
        description:
        - "Forward server message even it has unknown session id"
        type: bool
        required: False
    forward_to_latest_server:
        description:
        - "Forward client message to the latest server that sends message with the same
          session id"
        type: bool
        required: False
    load_balance_on_session_id:
        description:
        - "Load balance based on the session id"
        type: bool
        required: False
    relaxed_origin_host:
        description:
        - "Relaxed Origin-Host Format"
        type: bool
        required: False
    message_code_list:
        description:
        - "Field message_code_list"
        type: list
        required: False
        suboptions:
            message_code:
                description:
                - "Field message_code"
                type: int
    avp_list:
        description:
        - "Field avp_list"
        type: list
        required: False
        suboptions:
            avp:
                description:
                - "customize avps for cer to the server (avp number)"
                type: int
            int32:
                description:
                - "32 bits integer"
                type: int
            int64:
                description:
                - "64 bits integer"
                type: int
            string:
                description:
                - "String (string name, max length 127 bytes)"
                type: str
            mandatory:
                description:
                - "mandatory avp"
                type: bool
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
    origin_host:
        description:
        - "Field origin_host"
        type: dict
        required: False
        suboptions:
            origin_host_name:
                description:
                - "origin-host name avp"
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
    "avp_code", "avp_list", "avp_string", "customize_cea", "dwr_time", "dwr_up_retry", "forward_to_latest_server", "forward_unknown_session_id", "idle_timeout", "load_balance_on_session_id", "message_code_list", "multiple_origin_host", "name", "origin_host", "origin_realm", "product_name", "relaxed_origin_host", "service_group_name", "session_age",
    "terminate_on_cca_t", "user_tag", "uuid", "vendor_id",
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
        'customize_cea': {
            'type': 'bool',
            },
        'avp_code': {
            'type': 'int',
            },
        'avp_string': {
            'type': 'str',
            },
        'service_group_name': {
            'type': 'str',
            },
        'dwr_time': {
            'type': 'int',
            },
        'idle_timeout': {
            'type': 'int',
            },
        'multiple_origin_host': {
            'type': 'bool',
            },
        'origin_realm': {
            'type': 'str',
            },
        'product_name': {
            'type': 'str',
            },
        'vendor_id': {
            'type': 'int',
            },
        'session_age': {
            'type': 'int',
            },
        'dwr_up_retry': {
            'type': 'int',
            },
        'terminate_on_cca_t': {
            'type': 'bool',
            },
        'forward_unknown_session_id': {
            'type': 'bool',
            },
        'forward_to_latest_server': {
            'type': 'bool',
            },
        'load_balance_on_session_id': {
            'type': 'bool',
            },
        'relaxed_origin_host': {
            'type': 'bool',
            },
        'message_code_list': {
            'type': 'list',
            'message_code': {
                'type': 'int',
                }
            },
        'avp_list': {
            'type': 'list',
            'avp': {
                'type': 'int',
                },
            'int32': {
                'type': 'int',
                },
            'int64': {
                'type': 'int',
                },
            'string': {
                'type': 'str',
                },
            'mandatory': {
                'type': 'bool',
                }
            },
        'uuid': {
            'type': 'str',
            },
        'user_tag': {
            'type': 'str',
            },
        'origin_host': {
            'type': 'dict',
            'origin_host_name': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/template/diameter/{name}"

    f_dict = {}
    if '/' in str(module.params["name"]):
        f_dict["name"] = module.params["name"].replace("/", "%2F")
    else:
        f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/template/diameter/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["diameter"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["diameter"].get(k) != v:
            change_results["changed"] = True
            config_changes["diameter"][k] = v

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
    payload = utils.build_json("diameter", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["diameter"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["diameter-list"] if info != "NotFound" else info
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
