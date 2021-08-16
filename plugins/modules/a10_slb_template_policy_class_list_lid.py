#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_template_policy_class_list_lid
description:
    - Limit ID
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
    policy_name:
        description:
        - Key to identify parent object
        type: str
        required: True
    lidnum:
        description:
        - "Specify a limit ID"
        type: int
        required: True
    conn_limit:
        description:
        - "Connection limit"
        type: int
        required: False
    conn_rate_limit:
        description:
        - "Specify connection rate limit"
        type: int
        required: False
    conn_per:
        description:
        - "Per (Specify interval in number of 100ms)"
        type: int
        required: False
    request_limit:
        description:
        - "Request limit (Specify request limit)"
        type: int
        required: False
    request_rate_limit:
        description:
        - "Request rate limit (Specify request rate limit)"
        type: int
        required: False
    request_per:
        description:
        - "Per (Specify interval in number of 100ms)"
        type: int
        required: False
    bw_rate_limit:
        description:
        - "Specify bandwidth rate limit (Bandwidth rate limit in bytes)"
        type: int
        required: False
    bw_per:
        description:
        - "Per (Specify interval in number of 100ms)"
        type: int
        required: False
    over_limit_action:
        description:
        - "Set action when exceeds limit"
        type: bool
        required: False
    action_value:
        description:
        - "'forward'= Forward the traffic even it exceeds limit; 'reset'= Reset the
          connection when it exceeds limit;"
        type: str
        required: False
    lockout:
        description:
        - "Don't accept any new connection for certain time (Lockout duration in minutes)"
        type: int
        required: False
    log:
        description:
        - "Log a message"
        type: bool
        required: False
    interval:
        description:
        - "Specify log interval in minutes, by default system will log every over limit
          instance"
        type: int
        required: False
    direct_action:
        description:
        - "Set action when match the lid"
        type: bool
        required: False
    direct_service_group:
        description:
        - "Specify a service group (Specify the service group name)"
        type: str
        required: False
    direct_pbslb_logging:
        description:
        - "Configure PBSLB logging"
        type: bool
        required: False
    direct_pbslb_interval:
        description:
        - "Specify logging interval in minutes(default is 3)"
        type: int
        required: False
    direct_fail:
        description:
        - "Only log unsuccessful connections"
        type: bool
        required: False
    direct_action_value:
        description:
        - "'drop'= drop the packet; 'reset'= Send reset back;"
        type: str
        required: False
    direct_logging_drp_rst:
        description:
        - "Configure PBSLB logging"
        type: bool
        required: False
    direct_action_interval:
        description:
        - "Specify logging interval in minute (default is 3)"
        type: int
        required: False
    response_code_rate_limit:
        description:
        - "Field response_code_rate_limit"
        type: list
        required: False
        suboptions:
            code_range_start:
                description:
                - "server response code range start"
                type: int
            code_range_end:
                description:
                - "server response code range end"
                type: int
            threshold:
                description:
                - "the times of getting the response code"
                type: int
            period:
                description:
                - "seconds"
                type: int
    dns64:
        description:
        - "Field dns64"
        type: dict
        required: False
        suboptions:
            disable:
                description:
                - "Disable"
                type: bool
            exclusive_answer:
                description:
                - "Exclusive Answer in DNS Response"
                type: bool
            prefix:
                description:
                - "IPv6 prefix"
                type: str
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

# standard ansible module imports
from ansible.module_utils.basic import AnsibleModule

from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "action_value",
    "bw_per",
    "bw_rate_limit",
    "conn_limit",
    "conn_per",
    "conn_rate_limit",
    "direct_action",
    "direct_action_interval",
    "direct_action_value",
    "direct_fail",
    "direct_logging_drp_rst",
    "direct_pbslb_interval",
    "direct_pbslb_logging",
    "direct_service_group",
    "dns64",
    "interval",
    "lidnum",
    "lockout",
    "log",
    "over_limit_action",
    "request_limit",
    "request_per",
    "request_rate_limit",
    "response_code_rate_limit",
    "user_tag",
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
        'lidnum': {
            'type': 'int',
            'required': True,
        },
        'conn_limit': {
            'type': 'int',
        },
        'conn_rate_limit': {
            'type': 'int',
        },
        'conn_per': {
            'type': 'int',
        },
        'request_limit': {
            'type': 'int',
        },
        'request_rate_limit': {
            'type': 'int',
        },
        'request_per': {
            'type': 'int',
        },
        'bw_rate_limit': {
            'type': 'int',
        },
        'bw_per': {
            'type': 'int',
        },
        'over_limit_action': {
            'type': 'bool',
        },
        'action_value': {
            'type': 'str',
            'choices': ['forward', 'reset']
        },
        'lockout': {
            'type': 'int',
        },
        'log': {
            'type': 'bool',
        },
        'interval': {
            'type': 'int',
        },
        'direct_action': {
            'type': 'bool',
        },
        'direct_service_group': {
            'type': 'str',
        },
        'direct_pbslb_logging': {
            'type': 'bool',
        },
        'direct_pbslb_interval': {
            'type': 'int',
        },
        'direct_fail': {
            'type': 'bool',
        },
        'direct_action_value': {
            'type': 'str',
            'choices': ['drop', 'reset']
        },
        'direct_logging_drp_rst': {
            'type': 'bool',
        },
        'direct_action_interval': {
            'type': 'int',
        },
        'response_code_rate_limit': {
            'type': 'list',
            'code_range_start': {
                'type': 'int',
            },
            'code_range_end': {
                'type': 'int',
            },
            'threshold': {
                'type': 'int',
            },
            'period': {
                'type': 'int',
            }
        },
        'dns64': {
            'type': 'dict',
            'disable': {
                'type': 'bool',
            },
            'exclusive_answer': {
                'type': 'bool',
            },
            'prefix': {
                'type': 'str',
            }
        },
        'uuid': {
            'type': 'str',
        },
        'user_tag': {
            'type': 'str',
        }
    })
    # Parent keys
    rv.update(dict(policy_name=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/template/policy/{policy_name}/class-list/lid/{lidnum}"

    f_dict = {}
    f_dict["lidnum"] = module.params["lidnum"]
    f_dict["policy_name"] = module.params["policy_name"]

    return url_base.format(**f_dict)


def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]


def _get(module, url, params={}):

    resp = None
    try:
        resp = module.client.get(url, params=params)
    except a10_ex.NotFound:
        resp = "Not Found"

    call_result = {
        "endpoint": url,
        "http_method": "GET",
        "request_body": params,
        "response_body": resp,
    }
    return call_result


def _post(module, url, params={}, file_content=None, file_name=None):
    resp = module.client.post(url, params=params)
    resp = resp if resp else {}
    call_result = {
        "endpoint": url,
        "http_method": "POST",
        "request_body": params,
        "response_body": resp,
    }
    return call_result


def _delete(module, url):
    call_result = {
        "endpoint": url,
        "http_method": "DELETE",
        "request_body": {},
        "response_body": module.client.delete(url),
    }
    return call_result


def _switch_device_context(module, device_id):
    call_result = {
        "endpoint": "/axapi/v3/device-context",
        "http_method": "POST",
        "request_body": {
            "device-id": device_id
        },
        "response_body": module.client.change_context(device_id)
    }
    return call_result


def _active_partition(module, a10_partition):
    call_result = {
        "endpoint": "/axapi/v3/active-partition",
        "http_method": "POST",
        "request_body": {
            "curr_part_name": a10_partition
        },
        "response_body": module.client.activate_partition(a10_partition)
    }
    return call_result


def get(module):
    return _get(module, existing_url(module))


def get_list(module):
    return _get(module, list_url(module))


def _to_axapi(key):
    return translateBlacklist(key, KW_OUT).replace("_", "-")


def _build_dict_from_param(param):
    rv = {}

    for k, v in param.items():
        hk = _to_axapi(k)
        if isinstance(v, dict):
            v_dict = _build_dict_from_param(v)
            rv[hk] = v_dict
        elif isinstance(v, list):
            nv = [_build_dict_from_param(x) for x in v]
            rv[hk] = nv
        else:
            rv[hk] = v

    return rv


def build_envelope(title, data):
    return {title: data}


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/template/policy/{policy_name}/class-list/lid/{lidnum}"

    f_dict = {}
    f_dict["lidnum"] = ""
    f_dict["policy_name"] = module.params["policy_name"]

    return url_base.format(**f_dict)


def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([
        x for x in requires_one_of if x in params and params.get(x) is not None
    ])

    errors = []
    marg = []

    if not len(requires_one_of):
        return REQUIRED_VALID

    if len(present_keys) == 0:
        rc, msg = REQUIRED_NOT_SET
        marg = requires_one_of
    elif requires_one_of == present_keys:
        rc, msg = REQUIRED_MUTEX
        marg = present_keys
    else:
        rc, msg = REQUIRED_VALID

    if not rc:
        errors.append(msg.format(", ".join(marg)))

    return rc, errors


def build_json(title, module):
    rv = {}

    for x in AVAILABLE_PROPERTIES:
        v = module.params.get(x)
        if v is not None:
            rx = _to_axapi(x)

            if isinstance(v, dict):
                nv = _build_dict_from_param(v)
                rv[rx] = nv
            elif isinstance(v, list):
                nv = [_build_dict_from_param(x) for x in v]
                rv[rx] = nv
            else:
                rv[rx] = module.params[x]

    return build_envelope(title, rv)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["lid"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["lid"].get(k) != v:
            change_results["changed"] = True
            config_changes["lid"][k] = v

    change_results["modified_values"].update(**config_changes)
    return change_results


def create(module, result, payload):
    try:
        call_result = _post(module, new_url(module), payload)
        result["axapi_calls"].append(call_result)
        result["modified_values"].update(**call_result["response_body"])
        result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def update(module, result, existing_config, payload):
    try:
        call_result = _post(module, existing_url(module), payload)
        result["axapi_calls"].append(call_result)
        if call_result["response_body"] == existing_config:
            result["changed"] = False
        else:
            result["modified_values"].update(**call_result["response_body"])
            result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def present(module, result, existing_config):
    payload = build_json("lid", module)
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
        call_result = _delete(module, existing_url(module))
        result["axapi_calls"].append(call_result)
        result["changed"] = True
    except a10_ex.NotFound:
        result["changed"] = False
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def absent(module, result, existing_config):
    if not existing_config:
        result["changed"] = False
        return result

    if module.check_mode:
        result["changed"] = True
        return result

    return delete(module, result)


def replace(module, result, existing_config, payload):
    try:
        post_result = module.client.put(existing_url(module), payload)
        if post_result:
            result.update(**post_result)
        if post_result == existing_config:
            result["changed"] = False
        else:
            result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def run_command(module):
    result = dict(changed=False,
                  messages="",
                  modified_values={},
                  axapi_calls=[])

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

    valid = True

    run_errors = []
    if state == 'present':
        valid, validation_errors = validate(module.params)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(ansible_host, ansible_port, protocol,
                                   ansible_username, ansible_password)

    if a10_partition:
        result["axapi_calls"].append(_active_partition(module, a10_partition))

    if a10_device_context_id:
        result["axapi_calls"].append(
            _switch_device_context(module, a10_device_context_id))

    existing_config = get(module)
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
            result["axapi_calls"].append(get(module))
        elif module.params.get("get_type") == "list":
            result["axapi_calls"].append(get_list(module))
    module.client.session.close()
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
