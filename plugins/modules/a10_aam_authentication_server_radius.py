#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_aam_authentication_server_radius
description:
    - RADIUS Authentication Server
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
                - "'all'= all; 'authen_success'= Total Authentication Success; 'authen_failure'=
          Total Authentication Failure; 'authorize_success'= Total Authorization Success;
          'authorize_failure'= Total Authorization Failure; 'access_challenge'= Total
          Access-Challenge Message Receive; 'timeout_error'= Total Timeout;
          'other_error'= Total Other Error; 'request'= Total Request; 'request-normal'=
          Total Normal Request; 'request-dropped'= Total Dropped Request; 'response-
          success'= Total Success Response; 'response-failure'= Total Failure Response;
          'response-error'= Total Error Response; 'response-timeout'= Total Timeout
          Response; 'response-other'= Total Other Response; 'job-start-error'= Total Job
          Start Error; 'polling-control-error'= Total Polling Control Error; 'accounting-
          request-sent'= Accounting-Request Sent; 'accounting-success'= Accounting
          Success; 'accounting-failure'= Accounting Failure;"
                type: str
    instance_list:
        description:
        - "Field instance_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Specify RADIUS authentication server name"
                type: str
            host:
                description:
                - "Field host"
                type: dict
            secret:
                description:
                - "Specify the RADIUS server's secret"
                type: bool
            secret_string:
                description:
                - "The RADIUS server's secret"
                type: str
            encrypted:
                description:
                - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The
          ENCRYPTED secret string)"
                type: str
            port:
                description:
                - "Specify the RADIUS server's authentication port, default is 1812"
                type: int
            port_hm:
                description:
                - "Check port's health status"
                type: str
            port_hm_disable:
                description:
                - "Disable configured port health check configuration"
                type: bool
            interval:
                description:
                - "Specify the interval time for resend the request (second), default is 3 seconds
          (The interval time(second), default is 3 seconds)"
                type: int
            retry:
                description:
                - "Specify the retry number for resend the request, default is 5 (The retry
          number, default is 5)"
                type: int
            health_check:
                description:
                - "Check server's health status"
                type: bool
            health_check_string:
                description:
                - "Health monitor name"
                type: str
            health_check_disable:
                description:
                - "Disable configured health check configuration"
                type: bool
            accounting_port:
                description:
                - "Specify the RADIUS server's accounting port, default is 1813"
                type: int
            acct_port_hm:
                description:
                - "Specify accounting port health check method"
                type: str
            acct_port_hm_disable:
                description:
                - "Disable configured accounting port health check configuration"
                type: bool
            auth_type:
                description:
                - "'pap'= PAP authentication. Default; 'mschapv2'= MS-CHAPv2 authentication;
          'mschapv2-pap'= Use MS-CHAPv2 first. If server doesn't support it, try PAP;"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            authen_success:
                description:
                - "Total Authentication Success"
                type: str
            authen_failure:
                description:
                - "Total Authentication Failure"
                type: str
            authorize_success:
                description:
                - "Total Authorization Success"
                type: str
            authorize_failure:
                description:
                - "Total Authorization Failure"
                type: str
            access_challenge:
                description:
                - "Total Access-Challenge Message Receive"
                type: str
            timeout_error:
                description:
                - "Total Timeout"
                type: str
            other_error:
                description:
                - "Total Other Error"
                type: str
            request:
                description:
                - "Total Request"
                type: str
            request_normal:
                description:
                - "Total Normal Request"
                type: str
            request_dropped:
                description:
                - "Total Dropped Request"
                type: str
            response_success:
                description:
                - "Total Success Response"
                type: str
            response_failure:
                description:
                - "Total Failure Response"
                type: str
            response_error:
                description:
                - "Total Error Response"
                type: str
            response_timeout:
                description:
                - "Total Timeout Response"
                type: str
            response_other:
                description:
                - "Total Other Response"
                type: str
            job_start_error:
                description:
                - "Total Job Start Error"
                type: str
            polling_control_error:
                description:
                - "Total Polling Control Error"
                type: str
            accounting_request_sent:
                description:
                - "Accounting-Request Sent"
                type: str
            accounting_success:
                description:
                - "Accounting Success"
                type: str
            accounting_failure:
                description:
                - "Accounting Failure"
                type: str
            instance_list:
                description:
                - "Field instance_list"
                type: list

'''

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "instance_list",
    "sampling_enable",
    "stats",
    "uuid",
]

from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist


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
            type='dict',
            name=dict(type='str', ),
            shared=dict(type='str', ),
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
        'uuid': {
            'type': 'str',
        },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'authen_success', 'authen_failure',
                    'authorize_success', 'authorize_failure',
                    'access_challenge', 'timeout_error', 'other_error',
                    'request', 'request-normal', 'request-dropped',
                    'response-success', 'response-failure', 'response-error',
                    'response-timeout', 'response-other', 'job-start-error',
                    'polling-control-error', 'accounting-request-sent',
                    'accounting-success', 'accounting-failure'
                ]
            }
        },
        'instance_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
            },
            'host': {
                'type': 'dict',
                'hostip': {
                    'type': 'str',
                },
                'hostipv6': {
                    'type': 'str',
                }
            },
            'secret': {
                'type': 'bool',
            },
            'secret_string': {
                'type': 'str',
            },
            'encrypted': {
                'type': 'str',
            },
            'port': {
                'type': 'int',
            },
            'port_hm': {
                'type': 'str',
            },
            'port_hm_disable': {
                'type': 'bool',
            },
            'interval': {
                'type': 'int',
            },
            'retry': {
                'type': 'int',
            },
            'health_check': {
                'type': 'bool',
            },
            'health_check_string': {
                'type': 'str',
            },
            'health_check_disable': {
                'type': 'bool',
            },
            'accounting_port': {
                'type': 'int',
            },
            'acct_port_hm': {
                'type': 'str',
            },
            'acct_port_hm_disable': {
                'type': 'bool',
            },
            'auth_type': {
                'type': 'str',
                'choices': ['pap', 'mschapv2', 'mschapv2-pap']
            },
            'uuid': {
                'type': 'str',
            },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type':
                    'str',
                    'choices': [
                        'all', 'authen_success', 'authen_failure',
                        'authorize_success', 'authorize_failure',
                        'access_challenge', 'timeout_error', 'other_error',
                        'request', 'accounting-request-sent',
                        'accounting-success', 'accounting-failure'
                    ]
                }
            }
        },
        'stats': {
            'type': 'dict',
            'authen_success': {
                'type': 'str',
            },
            'authen_failure': {
                'type': 'str',
            },
            'authorize_success': {
                'type': 'str',
            },
            'authorize_failure': {
                'type': 'str',
            },
            'access_challenge': {
                'type': 'str',
            },
            'timeout_error': {
                'type': 'str',
            },
            'other_error': {
                'type': 'str',
            },
            'request': {
                'type': 'str',
            },
            'request_normal': {
                'type': 'str',
            },
            'request_dropped': {
                'type': 'str',
            },
            'response_success': {
                'type': 'str',
            },
            'response_failure': {
                'type': 'str',
            },
            'response_error': {
                'type': 'str',
            },
            'response_timeout': {
                'type': 'str',
            },
            'response_other': {
                'type': 'str',
            },
            'job_start_error': {
                'type': 'str',
            },
            'polling_control_error': {
                'type': 'str',
            },
            'accounting_request_sent': {
                'type': 'str',
            },
            'accounting_success': {
                'type': 'str',
            },
            'accounting_failure': {
                'type': 'str',
            },
            'instance_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                },
                'stats': {
                    'type': 'dict',
                    'authen_success': {
                        'type': 'str',
                    },
                    'authen_failure': {
                        'type': 'str',
                    },
                    'authorize_success': {
                        'type': 'str',
                    },
                    'authorize_failure': {
                        'type': 'str',
                    },
                    'access_challenge': {
                        'type': 'str',
                    },
                    'timeout_error': {
                        'type': 'str',
                    },
                    'other_error': {
                        'type': 'str',
                    },
                    'request': {
                        'type': 'str',
                    },
                    'accounting_request_sent': {
                        'type': 'str',
                    },
                    'accounting_success': {
                        'type': 'str',
                    },
                    'accounting_failure': {
                        'type': 'str',
                    }
                }
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/aam/authentication/server/radius"

    f_dict = {}

    return url_base.format(**f_dict)


def stats_url(module):
    """Return the URL for statistical data of and existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/stats"


def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]


def get(module):
    return module.client.get(existing_url(module))


def get_list(module):
    return module.client.get(list_url(module))


def get_stats(module):
    if module.params.get("stats"):
        query_params = {}
        for k, v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(stats_url(module), params=query_params)
    return module.client.get(stats_url(module))


def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None


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
    url_base = "/axapi/v3/aam/authentication/server/radius"

    f_dict = {}

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
    if existing_config:
        for k, v in payload["radius"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["radius"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["radius"][k] = v
            result.update(**existing_config)
    else:
        result.update(**payload)
    return result


def create(module, result, payload):
    try:
        post_result = module.client.post(new_url(module), payload)
        if post_result:
            result.update(**post_result)
        result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def update(module, result, existing_config, payload):
    try:
        post_result = module.client.post(existing_url(module), payload)
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


def present(module, result, existing_config):
    payload = build_json("radius", module)
    changed_config = report_changes(module, result, existing_config, payload)
    if module.check_mode:
        return changed_config
    elif not existing_config:
        return create(module, result, payload)
    elif existing_config and not changed_config.get('changed'):
        return update(module, result, existing_config, payload)
    else:
        result["changed"] = True
        return result


def delete(module, result):
    try:
        module.client.delete(existing_url(module))
        result["changed"] = True
    except a10_ex.NotFound:
        result["changed"] = False
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def absent(module, result, existing_config):
    if module.check_mode:
        if existing_config:
            result["changed"] = True
            return result
        else:
            result["changed"] = False
            return result
    else:
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
    run_errors = []

    result = dict(changed=False, original_message="", message="", result={})

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
        module.client.activate_partition(a10_partition)

    if a10_device_context_id:
        module.client.change_context(a10_device_context_id)

    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)

    if state == 'absent':
        result = absent(module, result, existing_config)

    if state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
        elif module.params.get("get_type") == "stats":
            result["result"] = get_stats(module)
    module.client.session.close()
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


# standard ansible module imports
from ansible.module_utils.basic import AnsibleModule

if __name__ == '__main__':
    main()
