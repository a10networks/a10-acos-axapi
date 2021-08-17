#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_aam_authentication_server_ldap
description:
    - LDAP Authentication Server
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
                - "'all'= all; 'admin-bind-success'= Total Admin Bind Success; 'admin-bind-
          failure'= Total Admin Bind Failure; 'bind-success'= Total User Bind Success;
          'bind-failure'= Total User Bind Failure; 'search-success'= Total Search
          Success; 'search-failure'= Total Search Failure; 'authorize-success'= Total
          Authorization Success; 'authorize-failure'= Total Authorization Failure;
          'timeout-error'= Total Timeout; 'other-error'= Total Other Error; 'request'=
          Total Request; 'request-normal'= Total Normal Request; 'request-dropped'= Total
          Dropped Request; 'response-success'= Total Success Response; 'response-
          failure'= Total Failure Response; 'response-error'= Total Error Response;
          'response-timeout'= Total Timeout Response; 'response-other'= Total Other
          Response; 'job-start-error'= Total Job Start Error; 'polling-control-error'=
          Total Polling Control Error; 'ssl-session-created'= TLS/SSL Session Created;
          'ssl-session-failure'= TLS/SSL Session Failure; 'ldaps-idle-conn-num'= LDAPS
          Idle Connection Number; 'ldaps-inuse-conn-num'= LDAPS In-use Connection Number;
          'pw-expiry'= Total Password expiry; 'pw-change-success'= Total password change
          success; 'pw-change-failure'= Total password change failure;"
                type: str
    instance_list:
        description:
        - "Field instance_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Specify LDAP authentication server name"
                type: str
            host:
                description:
                - "Field host"
                type: dict
            base:
                description:
                - "Specify the LDAP server's search base"
                type: str
            port:
                description:
                - "Specify the LDAP server's authentication port, default is 389"
                type: int
            port_hm:
                description:
                - "Check port's health status"
                type: str
            port_hm_disable:
                description:
                - "Disable configured port health check configuration"
                type: bool
            pwdmaxage:
                description:
                - "Specify the LDAP server's default password expiration time (in seconds) (The
          LDAP server's default password expiration time (in seconds), default is 0 (no
          expiration))"
                type: int
            admin_dn:
                description:
                - "The LDAP server's admin DN"
                type: str
            admin_secret:
                description:
                - "Specify the LDAP server's admin secret password"
                type: bool
            secret_string:
                description:
                - "secret password"
                type: str
            encrypted:
                description:
                - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The
          ENCRYPTED secret string)"
                type: str
            timeout:
                description:
                - "Specify timout for LDAP, default is 10 seconds (The timeout, default is 10
          seconds)"
                type: int
            dn_attribute:
                description:
                - "Specify Distinguished Name attribute, default is CN"
                type: str
            default_domain:
                description:
                - "Specify default domain for LDAP"
                type: str
            bind_with_dn:
                description:
                - "Enforce using DN for LDAP binding(All user input name will be used to create
          DN)"
                type: bool
            derive_bind_dn:
                description:
                - "Field derive_bind_dn"
                type: dict
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
            protocol:
                description:
                - "'ldap'= Use LDAP (default); 'ldaps'= Use LDAP over SSL; 'starttls'= Use LDAP
          StartTLS;"
                type: str
            ca_cert:
                description:
                - "Specify the LDAPS CA cert filename (Trusted LDAPS CA cert filename)"
                type: str
            ldaps_conn_reuse_idle_timeout:
                description:
                - "Specify LDAPS connection reuse idle timeout value (in seconds) (Specify idle
          timeout value (in seconds), default is 0 (not reuse LDAPS connection))"
                type: int
            auth_type:
                description:
                - "'ad'= Active Directory. Default; 'open-ldap'= OpenLDAP;"
                type: str
            prompt_pw_change_before_exp:
                description:
                - "Prompt user to change password before expiration in N days. This option only
          takes effect when server type is AD (Prompt user to change password before
          expiration in N days, default is not to prompt the user)"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            ldaps_server_list:
                description:
                - "Field ldaps_server_list"
                type: list
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            admin_bind_success:
                description:
                - "Total Admin Bind Success"
                type: str
            admin_bind_failure:
                description:
                - "Total Admin Bind Failure"
                type: str
            bind_success:
                description:
                - "Total User Bind Success"
                type: str
            bind_failure:
                description:
                - "Total User Bind Failure"
                type: str
            search_success:
                description:
                - "Total Search Success"
                type: str
            search_failure:
                description:
                - "Total Search Failure"
                type: str
            authorize_success:
                description:
                - "Total Authorization Success"
                type: str
            authorize_failure:
                description:
                - "Total Authorization Failure"
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
            ssl_session_created:
                description:
                - "TLS/SSL Session Created"
                type: str
            ssl_session_failure:
                description:
                - "TLS/SSL Session Failure"
                type: str
            ldaps_idle_conn_num:
                description:
                - "LDAPS Idle Connection Number"
                type: str
            ldaps_inuse_conn_num:
                description:
                - "LDAPS In-use Connection Number"
                type: str
            pw_expiry:
                description:
                - "Total Password expiry"
                type: str
            pw_change_success:
                description:
                - "Total password change success"
                type: str
            pw_change_failure:
                description:
                - "Total password change failure"
                type: str
            instance_list:
                description:
                - "Field instance_list"
                type: list

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

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "instance_list",
    "oper",
    "sampling_enable",
    "stats",
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
        'uuid': {
            'type': 'str',
        },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'admin-bind-success', 'admin-bind-failure',
                    'bind-success', 'bind-failure', 'search-success',
                    'search-failure', 'authorize-success', 'authorize-failure',
                    'timeout-error', 'other-error', 'request',
                    'request-normal', 'request-dropped', 'response-success',
                    'response-failure', 'response-error', 'response-timeout',
                    'response-other', 'job-start-error',
                    'polling-control-error', 'ssl-session-created',
                    'ssl-session-failure', 'ldaps-idle-conn-num',
                    'ldaps-inuse-conn-num', 'pw-expiry', 'pw-change-success',
                    'pw-change-failure'
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
            'base': {
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
            'pwdmaxage': {
                'type': 'int',
            },
            'admin_dn': {
                'type': 'str',
            },
            'admin_secret': {
                'type': 'bool',
            },
            'secret_string': {
                'type': 'str',
            },
            'encrypted': {
                'type': 'str',
            },
            'timeout': {
                'type': 'int',
            },
            'dn_attribute': {
                'type': 'str',
            },
            'default_domain': {
                'type': 'str',
            },
            'bind_with_dn': {
                'type': 'bool',
            },
            'derive_bind_dn': {
                'type': 'dict',
                'username_attr': {
                    'type': 'str',
                }
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
            'protocol': {
                'type': 'str',
                'choices': ['ldap', 'ldaps', 'starttls']
            },
            'ca_cert': {
                'type': 'str',
            },
            'ldaps_conn_reuse_idle_timeout': {
                'type': 'int',
            },
            'auth_type': {
                'type': 'str',
                'choices': ['ad', 'open-ldap']
            },
            'prompt_pw_change_before_exp': {
                'type': 'int',
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
                        'all', 'admin-bind-success', 'admin-bind-failure',
                        'bind-success', 'bind-failure', 'search-success',
                        'search-failure', 'authorize-success',
                        'authorize-failure', 'timeout-error', 'other-error',
                        'request', 'ssl-session-created',
                        'ssl-session-failure', 'pw_expiry',
                        'pw_change_success', 'pw_change_failure'
                    ]
                }
            }
        },
        'oper': {
            'type': 'dict',
            'ldaps_server_list': {
                'type': 'list',
                'ldap_uri': {
                    'type': 'str',
                },
                'ldaps_idle_conn_num': {
                    'type': 'int',
                },
                'ldaps_idle_conn_fd_list': {
                    'type': 'str',
                },
                'ldaps_inuse_conn_num': {
                    'type': 'int',
                },
                'ldaps_inuse_conn_fd_list': {
                    'type': 'str',
                }
            }
        },
        'stats': {
            'type': 'dict',
            'admin_bind_success': {
                'type': 'str',
            },
            'admin_bind_failure': {
                'type': 'str',
            },
            'bind_success': {
                'type': 'str',
            },
            'bind_failure': {
                'type': 'str',
            },
            'search_success': {
                'type': 'str',
            },
            'search_failure': {
                'type': 'str',
            },
            'authorize_success': {
                'type': 'str',
            },
            'authorize_failure': {
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
            'ssl_session_created': {
                'type': 'str',
            },
            'ssl_session_failure': {
                'type': 'str',
            },
            'ldaps_idle_conn_num': {
                'type': 'str',
            },
            'ldaps_inuse_conn_num': {
                'type': 'str',
            },
            'pw_expiry': {
                'type': 'str',
            },
            'pw_change_success': {
                'type': 'str',
            },
            'pw_change_failure': {
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
                    'admin_bind_success': {
                        'type': 'str',
                    },
                    'admin_bind_failure': {
                        'type': 'str',
                    },
                    'bind_success': {
                        'type': 'str',
                    },
                    'bind_failure': {
                        'type': 'str',
                    },
                    'search_success': {
                        'type': 'str',
                    },
                    'search_failure': {
                        'type': 'str',
                    },
                    'authorize_success': {
                        'type': 'str',
                    },
                    'authorize_failure': {
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
                    'ssl_session_created': {
                        'type': 'str',
                    },
                    'ssl_session_failure': {
                        'type': 'str',
                    },
                    'pw_expiry': {
                        'type': 'str',
                    },
                    'pw_change_success': {
                        'type': 'str',
                    },
                    'pw_change_failure': {
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
    url_base = "/axapi/v3/aam/authentication/server/ldap"

    f_dict = {}

    return url_base.format(**f_dict)


def oper_url(module):
    """Return the URL for operational data of an existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/oper"


def stats_url(module):
    """Return the URL for statistical data of and existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/stats"


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


def get_oper(module):
    query_params = {}
    if module.params.get("oper"):
        for k, v in module.params["oper"].items():
            query_params[k.replace('_', '-')] = v
    return _get(module, oper_url(module), params=query_params)


def get_stats(module):
    query_params = {}
    if module.params.get("stats"):
        for k, v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
    return _get(module, stats_url(module), params=query_params)


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
    url_base = "/axapi/v3/aam/authentication/server/ldap"

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
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["ldap"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["ldap"].get(k) != v:
            change_results["changed"] = True
            config_changes["ldap"][k] = v

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
    finally:
        module.client.session.close()
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
    finally:
        module.client.session.close()
    return result


def present(module, result, existing_config):
    payload = build_json("ldap", module)
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
    finally:
        module.client.session.close()
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
    finally:
        module.client.session.close()
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
        elif module.params.get("get_type") == "oper":
            result["axapi_calls"].append(get_oper(module))
        elif module.params.get("get_type") == "stats":
            result["axapi_calls"].append(get_stats(module))

    module.client.session.close()
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
